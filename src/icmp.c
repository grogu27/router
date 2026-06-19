//#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include "router.h"
#include "checksum.h"
#include "logger.h"

extern int raw_sock;

void icmp_time_exc(struct ethhdr *original_eth, 
                   struct iphdr *original_ip) {
    
    int icmp_payload_len = sizeof(struct iphdr) + 8;
    int icmp_total_len = icmp_payload_len + sizeof(struct icmphdr);
    
    char reply_buff[icmp_total_len + sizeof(struct iphdr)];
    memset(reply_buff, 0, sizeof(reply_buff));
    
    // ========== IP-ЗАГОЛОВОК ==========
    struct iphdr *ip_hdr = (struct iphdr*)reply_buff;
    ip_hdr->version = 4;
    ip_hdr->ihl = 5;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + icmp_total_len);
    ip_hdr->id = htons(rand() & 0xFFFF);
    ip_hdr->frag_off = htons(0x4000);
    ip_hdr->ttl = 64;
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->saddr = original_ip->daddr;  // временно, будет заменён
    ip_hdr->daddr = original_ip->saddr;
    
    // ========== ПОИСК МАРШРУТА ==========
    route_entry_t *route = find_route(ip_hdr->daddr);
    if (route == NULL) {
        log_message("ICMP: No route for reply to %u.%u.%u.%u, dropping",
                    (ntohl(ip_hdr->daddr) >> 24) & 0xFF,
                    (ntohl(ip_hdr->daddr) >> 16) & 0xFF,
                    (ntohl(ip_hdr->daddr) >> 8) & 0xFF,
                    ntohl(ip_hdr->daddr) & 0xFF);
        return;
    }
    
    // ========== ПОЛУЧЕНИЕ IP-АДРЕСА ИНТЕРФЕЙСА ==========
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, route->interface, IFNAMSIZ - 1);
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        log_message("ICMP: Cannot create socket for ioctl");
        return;
    }
    
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        log_message("ICMP: ioctl SIOCGIFADDR failed");
        close(sock);
        return;
    }
    
    struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    ip_hdr->saddr = ipaddr->sin_addr.s_addr;  // IP источника = IP интерфейса
    close(sock);
    
    // ========== IP CHECKSUM ==========
    ip_hdr->check = 0;
    ip_hdr->check = ip_checksum(ip_hdr, ip_hdr->ihl * 4);
    
    // ========== ICMP-ЗАГОЛОВОК ==========
    struct icmphdr *icmp_hdr = (struct icmphdr*)(reply_buff + sizeof(struct iphdr));
    icmp_hdr->type = ICMP_TIME_EXCEEDED;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    
    // ========== ТЕЛО ICMP ==========
    char *payload_icmp = (char*)(icmp_hdr + 1);
    memcpy(payload_icmp, original_ip, sizeof(struct iphdr));
    char *original_payload = (char*)original_ip + (original_ip->ihl * 4);
    memcpy(payload_icmp + sizeof(struct iphdr), original_payload, 8);
    
    icmp_hdr->checksum = ip_checksum(icmp_hdr, icmp_total_len);
    
    // ========== RESOLVE MAC ==========
    unsigned char next_mac[6];
    uint32_t target_ip_for_arp;
    if (route->nexthop == 0) {
        target_ip_for_arp = ip_hdr->daddr;
    } else {
        target_ip_for_arp = route->nexthop;
    }
    
    if (resolve_mac(route->interface, target_ip_for_arp, next_mac) != 0) {
        log_message("ICMP: Cannot resolve MAC for %u.%u.%u.%u, dropping",
                    (ntohl(target_ip_for_arp) >> 24) & 0xFF,
                    (ntohl(target_ip_for_arp) >> 16) & 0xFF,
                    (ntohl(target_ip_for_arp) >> 8) & 0xFF,
                    ntohl(target_ip_for_arp) & 0xFF);
        return;
    }
    
    // ========== ETHERNET-ЗАГОЛОВОК ==========
    char frame[sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + icmp_payload_len];
    struct ethhdr *eth = (struct ethhdr*)frame;
    
    // MAC источника = MAC выходного интерфейса
    unsigned char src_mac[6];
    if (get_interface_mac(route->interface, src_mac) == 0) {
        memcpy(eth->h_source, src_mac, 6);
    } else {
        log_message("ICMP: Cannot get MAC for interface %s", route->interface);
        return;
    }
    
    // MAC назначения = MAC отправителя исходного пакета (ИСПОЛЬЗУЕМ original_eth!)
    memcpy(eth->h_dest, original_eth->h_source, 6);
    eth->h_proto = htons(ETH_P_IP);
    
    // Копируем IP+ICMP в кадр
    int ip_len = ntohs(ip_hdr->tot_len);
    memcpy(frame + sizeof(struct ethhdr), reply_buff, ip_len);
    
    // ========== ОТПРАВКА ==========
    struct sockaddr_ll dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_ifindex = if_nametoindex(route->interface);
    dest_addr.sll_halen = 6;
    memcpy(dest_addr.sll_addr, original_eth->h_source, 6);  // MAC назначения
    
    int total_len_frame = sizeof(struct ethhdr) + ip_len;
    
    ssize_t send_bytes = sendto(raw_sock, frame, total_len_frame, 0, 
                                (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    if (send_bytes < 0) {
        log_message("ICMP: sendto failed");
    } else {
        uint32_t dest_ip_host = ntohl(ip_hdr->daddr);
        log_message("ICMP Time Exceeded routed to %u.%u.%u.%u via %s",
                    (dest_ip_host >> 24) & 0xFF,
                    (dest_ip_host >> 16) & 0xFF,
                    (dest_ip_host >> 8) & 0xFF,
                    dest_ip_host & 0xFF,
                    route->interface);
    }
}