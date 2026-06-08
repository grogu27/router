#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <errno.h>

#include "arp.h"

#pragma pack(push, 1)
struct arp_packet {
    struct ethhdr eth;
    struct arphdr hdr;
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
};
#pragma pack(pop)

int get_my_mac(int sock, const char *interface_name, unsigned char *mac_buffer) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) return -1;
    memcpy(mac_buffer, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

int get_my_ip(int sock, const char *interface_name, unsigned char *ip_buffer) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) return -1;
    struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    memcpy(ip_buffer, &ipaddr->sin_addr, 4);
    return 0;
}

static int send_arp_request(int sock, const char *interface_name, const char *target_ip_str,
                     const unsigned char *src_mac, const unsigned char *src_ip) {
    struct ifreq ifr;
    struct sockaddr_ll dest_addr;
    unsigned char packet[sizeof(struct arp_packet)];
    struct arp_packet *arp = (struct arp_packet *)packet;
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) return -1;
    
    unsigned char broadcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(arp->eth.h_dest, broadcast_mac, ETH_ALEN);
    memcpy(arp->eth.h_source, src_mac, ETH_ALEN);
    arp->eth.h_proto = htons(ETH_P_ARP);
    
    arp->hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->hdr.ar_pro = htons(ETH_P_IP);
    arp->hdr.ar_hln = 6;
    arp->hdr.ar_pln = 4;
    arp->hdr.ar_op = htons(ARPOP_REQUEST);
    
    memcpy(arp->sender_mac, src_mac, 6);
    memcpy(arp->sender_ip, src_ip, 4);
    memset(arp->target_mac, 0, 6);
    
    struct in_addr target_addr;
    inet_aton(target_ip_str, &target_addr);
    memcpy(arp->target_ip, &target_addr.s_addr, 4);
    
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_protocol = htons(ETH_P_ARP);
    dest_addr.sll_ifindex = ifr.ifr_ifindex;
    
    if (sendto(sock, packet, sizeof(struct arp_packet), 0, 
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        return -1;
    }
    return 0;
}

int get_neighbor_mac(const char *interface_name, const char *target_ip, unsigned char *mac_buffer) {
    int arp_sock;
    unsigned char my_mac[6];
    unsigned char my_ip[4];
    unsigned char buffer[4096];
    struct arp_packet *response;
    fd_set fds;
    struct timeval tv;
    
    arp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (arp_sock < 0) return -1;
    
    if (get_my_mac(arp_sock, interface_name, my_mac) < 0) {
        close(arp_sock);
        return -1;
    }
    if (get_my_ip(arp_sock, interface_name, my_ip) < 0) {
        close(arp_sock);
        return -1;
    }
    
    if (send_arp_request(arp_sock, interface_name, target_ip, my_mac, my_ip) < 0) {
        close(arp_sock);
        return -1;
    }
    
    FD_ZERO(&fds);
    FD_SET(arp_sock, &fds);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    
    struct in_addr target_addr;
    inet_aton(target_ip, &target_addr);
    
    while (1) {
        int ret = select(arp_sock + 1, &fds, NULL, NULL, &tv);
        if (ret <= 0) {
            close(arp_sock);
            return -1;
        }
        
        struct sockaddr_ll src_addr;
        socklen_t addr_len = sizeof(src_addr);
        int len = recvfrom(arp_sock, buffer, sizeof(buffer), 0, 
                          (struct sockaddr *)&src_addr, &addr_len);
        if (len < 0) continue;
        
        response = (struct arp_packet *)buffer;
        if (ntohs(response->hdr.ar_op) != ARPOP_REPLY) continue;
        
        if (memcmp(response->sender_ip, &target_addr.s_addr, 4) == 0) {
            memcpy(mac_buffer, response->sender_mac, 6);
            close(arp_sock);
            return 0;
        }
    }
}