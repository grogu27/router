#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include "router.h"
#include "arp.h"
#include "checksum.h"
#include "logger.h"

#define ROUTES_DIR "./routes"

int raw_sock;
pthread_t cli_thread;
int running = 1;

// Список своих IP-адресов (можно расширить)
uint32_t my_ips[10];
int my_ip_count = 0;

// Функция для получения всех IP-адресов интерфейсов
void collect_my_ips() {
    struct ifreq ifr;
    struct ifconf ifconf;
    char buf[4096];
    int tmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (tmp_sock < 0) return;
    
    ifconf.ifc_len = sizeof(buf);
    ifconf.ifc_buf = buf;
    
    if (ioctl(tmp_sock, SIOCGIFCONF, &ifconf) < 0) {
        close(tmp_sock);
        return;
    }
    
    struct ifreq *interfaces = ifconf.ifc_req;
    int num_interfaces = ifconf.ifc_len / sizeof(struct ifreq);
    
    my_ip_count = 0;
    for (int i = 0; i < num_interfaces && my_ip_count < 10; i++) {
        struct sockaddr_in *addr = (struct sockaddr_in*)&interfaces[i].ifr_addr;
        if (addr->sin_family == AF_INET) {
            my_ips[my_ip_count++] = addr->sin_addr.s_addr;
            log_message("My IP: %s", inet_ntoa(addr->sin_addr));
        }
    }
    
    close(tmp_sock);
}

// Проверка, является ли IP адресом маршрутизатора
int is_my_ip(uint32_t ip) {
    for (int i = 0; i < my_ip_count; i++) {
        if (my_ips[i] == ip) return 1;
    }
    return 0;
}

// Проверка, является ли IP шлюзом по умолчанию (заканчивается на .1)
int is_gateway_ip(uint32_t ip) {
    // Маска: последний октет = 1
    return (ip & 0xFF) == 0x01;  // 192.168.x.1
}

// Получить индекс интерфейса (обёртка)
int get_ifindex(const char *ifname) {
    int idx = if_nametoindex(ifname);
    if (idx == 0) {
        log_message("ERROR: Interface %s not found", ifname);
    }
    return idx;
}

// Отправить пакет
void send_packet(unsigned char *buf, int len, const char *interface, unsigned char *dest_mac) {
    struct sockaddr_ll dest_addr;
    int ifindex = get_ifindex(interface);
    
    if (ifindex <= 0) {
        log_message("ERROR: Invalid interface %s", interface);
        return;
    }
    
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_ifindex = ifindex;
    dest_addr.sll_halen = 6;
    memcpy(dest_addr.sll_addr, dest_mac, 6);
    
    if (sendto(raw_sock, buf, len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        log_message("ERROR: sendto failed");
    } else {
        log_message("Packet sent via %s", interface);
    }
}

int is_virtualbox_ip(uint32_t ip) {
    // Шлюзы .1
    if ((ip & 0xFF) == 0x01) return 1;
    // Мультикаст (224.0.0.0 - 239.255.255.255)
    if ((ip & 0xF0000000) == 0xE0000000) return 1;
    // Широковещательные .255
    if ((ip & 0xFF) == 0xFF) return 1;
    // Нулевой адрес
    if (ip == 0) return 1;
    // Петлевой
    if (ip == 0x0100007F) return 1;
    return 0;
}

// // Обработка одного пакета
// void process_packet(unsigned char *buf, int len) {
//     struct ethhdr *eth = (struct ethhdr*)buf;
    
//     // Только IPv4
//     if (ntohs(eth->h_proto) != ETH_P_IP) return;
    
//     struct iphdr *ip = (struct iphdr*)(buf + sizeof(struct ethhdr));
//     uint32_t dest_ip = ip->daddr;
//     uint32_t src_ip = ip->saddr;
    
//     // ========== ФИЛЬТРЫ ==========
    
//     // 1. Игнорируем петлевой интерфейс (127.0.0.1)
//     if (dest_ip == 0x0100007F) return;
    
//     // 2. Игнорируем свои IP-адреса (назначение)
//     if (is_my_ip(dest_ip)) return;
    
//     // 3. Игнорируем свои IP-адреса (источник) — чтобы не видеть свой же исходящий трафик
//     if (is_my_ip(src_ip)) return;
    
//     // 4. Игнорируем шлюзы (IP, заканчивающиеся на .1)
//     if (is_gateway_ip(dest_ip)) return;
    
//     // Игнорируем мультикаст (224.0.0.0 - 239.255.255.255)
//     if ((dest_ip & 0xF0000000) == 0xE0000000) return;

//     // Игнорируем широковещательные адреса (.255)
//     if ((dest_ip & 0xFF) == 0xFF) return;

//     // Игнорируем локальный широковещательный адрес (255.255.255.255)
//     if (dest_ip == 0xFFFFFFFF) return;
    
//     // ========== ЛОГИРУЕМ ТОЛЬКО ИНТЕРЕСНЫЕ ПАКЕТЫ ==========
    
//     log_message("Received packet: dst_ip = %u.%u.%u.%u",
//                 (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
//                 (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF);
    
//     // Проверяем контрольную сумму IP
//     if (!verify_ip_checksum(ip, ip->ihl * 4)) {
//         log_message("ERROR: IP checksum invalid");
//         return;
//     }
    
//     // Поиск маршрута
//     route_entry_t *route = find_route(dest_ip);
    
//     if (route == NULL) {
//         log_message("No route for destination");
//         return;
//     }
    
//     // Уменьшаем TTL
//     if (ip->ttl <= 1) {
//         log_message("TTL expired");
//         return;
//     }
//     ip->ttl--;
    
//     // Пересчитываем контрольную сумму
//     ip->check = 0;
//     ip->check = ip_checksum(ip, ip->ihl * 4);
    
//     // Определяем IP для ARP
//     uint32_t target_ip_for_arp;
//     if (route->nexthop == 0) {
//         target_ip_for_arp = dest_ip;
//     } else {
//         target_ip_for_arp = route->nexthop;
//     }
    
//     // Получаем MAC
//     unsigned char next_mac[6];
//     if (resolve_mac(route->interface, target_ip_for_arp, next_mac) != 0) {
//         log_message("Cannot resolve MAC for %u.%u.%u.%u, dropping packet",
//                     (target_ip_for_arp >> 0) & 0xFF,
//                     (target_ip_for_arp >> 8) & 0xFF,
//                     (target_ip_for_arp >> 16) & 0xFF,
//                     (target_ip_for_arp >> 24) & 0xFF);
//         return;
//     }
    
//     // Обновляем Ethernet-заголовок
//     unsigned char src_mac[6];
//     if (get_interface_mac(route->interface, src_mac) == 0) {
//         memcpy(eth->h_source, src_mac, 6);
//     }
//     memcpy(eth->h_dest, next_mac, 6);
    
//     // Отправляем
//     send_packet(buf, len, route->interface, next_mac);
    
//     log_message("Packet forwarded via %s", route->interface);
// }

// Обработка одного пакета
void process_packet(unsigned char *buf, int len) {
    struct ethhdr *eth = (struct ethhdr*)buf;
    
    // Только IPv4
    if (ntohs(eth->h_proto) != ETH_P_IP) return;
    
    struct iphdr *ip = (struct iphdr*)(buf + sizeof(struct ethhdr));
    uint32_t dest_ip = ip->daddr;
    uint32_t src_ip = ip->saddr;
    
    // ========== ФИЛЬТРЫ (для IP в сетевом порядке big-endian) ==========
    if (eth->h_dest[0] & 0x01)
        return;
    // 1. Петлевой интерфейс (127.0.0.1)
    if (dest_ip == 0x0100007F) return;
    
    // 2. Игнорируем свои IP-адреса (назначение)
    if (is_my_ip(dest_ip)) return;
    
    // 3. Игнорируем свои IP-адреса (источник)
    if (is_my_ip(src_ip)) return;
    
    // 4. Игнорируем шлюзы (IP, заканчивающиеся на .1)
    //    В сетевом порядке последний октет = старший байт (0x01XXXXXX)
    if ((dest_ip & 0xFF000000) == 0x01000000) return;
    
    // 5. Игнорируем мультикаст (224.0.0.0 - 239.255.255.255)
    //    Первый байт в сетевом порядке = старший байт (0xE0 - 0xEF)
    uint8_t first_byte = (dest_ip >> 24) & 0xFF;
    if (first_byte >= 224 && first_byte <= 239) return;
    
    // 6. Игнорируем широковещательные адреса (.255)
    //    В сетевом порядке последний октет = старший байт (0xFFXXXXXX)
    if ((dest_ip & 0xFF000000) == 0xFF000000) return;
    
    // 7. Игнорируем локальный широковещательный адрес (255.255.255.255)
    if (dest_ip == 0xFFFFFFFF) return;
    uint32_t dest_host = ntohl(dest_ip);

    // x.x.x.1
    if ((dest_host & 0xFF) == 1)
        return;

    // x.x.x.255
    if ((dest_host & 0xFF) == 255)
        return;
    // ========== ЛОГИРУЕМ ТОЛЬКО ИНТЕРЕСНЫЕ ПАКЕТЫ ==========
    
    uint32_t dest_ip_host = ntohl(dest_ip);
    log_message("Received packet: dst_ip = %u.%u.%u.%u",
                (dest_ip_host >> 24) & 0xFF,
                (dest_ip_host >> 16) & 0xFF,
                (dest_ip_host >> 8) & 0xFF,
                dest_ip_host & 0xFF);
    
    // Проверяем контрольную сумму IP
    if (!verify_ip_checksum(ip, ip->ihl * 4)) {
        log_message("ERROR: IP checksum invalid");
        return;
    }
    
    // Поиск маршрута
    route_entry_t *route = find_route(dest_ip);
    
    if (route == NULL) {
        log_message("No route for destination");
        return;
    }
    
    // Уменьшаем TTL
    if (ip->ttl <= 1) {
        log_message("TTL expired");
        return;
    }
    ip->ttl--;
    
    // Пересчитываем контрольную сумму
    ip->check = 0;
    ip->check = ip_checksum(ip, ip->ihl * 4);
    
    // Определяем IP для ARP
    uint32_t target_ip_for_arp;
    if (route->nexthop == 0) {
        target_ip_for_arp = dest_ip;
    } else {
        target_ip_for_arp = route->nexthop;
    }
    
    // Получаем MAC
    unsigned char next_mac[6];
    if (resolve_mac(route->interface, target_ip_for_arp, next_mac) != 0) {
        uint32_t target_host = ntohl(target_ip_for_arp);
        log_message("Cannot resolve MAC for %u.%u.%u.%u, dropping packet",
                    (target_host >> 24) & 0xFF,
                    (target_host >> 16) & 0xFF,
                    (target_host >> 8) & 0xFF,
                    target_host & 0xFF);
        return;
    }
    
    // Обновляем Ethernet-заголовок
    unsigned char src_mac[6];
    if (get_interface_mac(route->interface, src_mac) == 0) {
        memcpy(eth->h_source, src_mac, 6);
    }
    memcpy(eth->h_dest, next_mac, 6);
    
    // Отправляем
    send_packet(buf, len, route->interface, next_mac);
    
    log_message("Packet forwarded via %s", route->interface);
}

int main() {
    init_logger();
    log_message("Router starting...");
    
    // Собираем свои IP-адреса
    collect_my_ips();
    
    // Загружаем маршруты из директории
    load_routes_from_dir(ROUTES_DIR);
    
    // Создаём raw-сокет
    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock < 0) {
        log_message("ERROR: Cannot create raw socket (run with sudo)");
        return -1;
    }
    
    // Запускаем CLI в отдельном потоке
    pthread_create(&cli_thread, NULL, cli_thread_func, NULL);
    
    // Основной цикл приёма пакетов
    unsigned char buffer[BUF_SIZE];
    while (running) {
        int len = recvfrom(raw_sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len > 0 && running) {
            process_packet(buffer, len);
        }
    }
    
    close(raw_sock);
    close_logger();
    return 0;
}