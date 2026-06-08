#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "router.h"
#include "arp.h"
#include "logger.h"

pthread_mutex_t route_mutex = PTHREAD_MUTEX_INITIALIZER;

route_entry_t route_table[MAX_ROUTES];
int route_count = 0;

arp_cache_entry_t arp_cache[ARP_CACHE_SIZE];
int arp_cache_count = 0;

uint32_t ip_to_uint32(const char *ip_str) {
    struct in_addr addr;
    inet_aton(ip_str, &addr);
    return addr.s_addr;
}

int get_interface_index(const char *ifname) {
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        log_message("ERROR: Interface %s not found", ifname);
    }
    return ifindex;
}

int get_interface_mac(const char *ifname, unsigned char *mac) {
    struct ifreq ifr;
    int tmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (tmp_sock < 0) return -1;
    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(tmp_sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(tmp_sock);
        return -1;
    }
    
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(tmp_sock);
    return 0;
}

int get_mac_from_cache(uint32_t ip, unsigned char *mac) {
    time_t now = time(NULL);
    
    for (int i = 0; i < arp_cache_count; i++) {
        if (arp_cache[i].ip == ip) {
            if (now - arp_cache[i].timestamp < 300) {
                memcpy(mac, arp_cache[i].mac, 6);
                return 0;
            } else {
                for (int j = i; j < arp_cache_count - 1; j++) {
                    arp_cache[j] = arp_cache[j + 1];
                }
                arp_cache_count--;
                return -1;
            }
        }
    }
    return -1;
}

int add_to_arp_cache(uint32_t ip, unsigned char *mac) {
    for (int i = 0; i < arp_cache_count; i++) {
        if (arp_cache[i].ip == ip) {
            memcpy(arp_cache[i].mac, mac, 6);
            arp_cache[i].timestamp = time(NULL);
            return 0;
        }
    }
    
    if (arp_cache_count < ARP_CACHE_SIZE) {
        arp_cache[arp_cache_count].ip = ip;
        memcpy(arp_cache[arp_cache_count].mac, mac, 6);
        arp_cache[arp_cache_count].timestamp = time(NULL);
        arp_cache_count++;
    } else {
        int oldest = 0;
        for (int i = 1; i < arp_cache_count; i++) {
            if (arp_cache[i].timestamp < arp_cache[oldest].timestamp) {
                oldest = i;
            }
        }
        arp_cache[oldest].ip = ip;
        memcpy(arp_cache[oldest].mac, mac, 6);
        arp_cache[oldest].timestamp = time(NULL);
    }
    return 0;
}

int resolve_mac(const char *interface_name, uint32_t ip, unsigned char *mac) {
    if (get_mac_from_cache(ip, mac) == 0) {
        log_message("MAC found in cache");
        return 0;
    }
    
    struct in_addr addr;
    addr.s_addr = ip;
    char ip_str[32];
    strcpy(ip_str, inet_ntoa(addr));
    
    log_message("Sending ARP request for %s", ip_str);
    
    if (get_neighbor_mac(interface_name, ip_str, mac) == 0) {
        add_to_arp_cache(ip, mac);
        
        char mac_str[32];
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        log_message("Resolved MAC: %s", mac_str);
        return 0;
    }
    
    log_message("ARP resolution failed for %s", ip_str);
    return -1;
}

int load_routes_from_dir(const char *dir_path) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        log_message("Cannot open routes directory: %s", dir_path);
        return -1;
    }
    
    struct dirent *entry;
    
    pthread_mutex_lock(&route_mutex);
    route_count = 0;
    
    while ((entry = readdir(dir)) != NULL && route_count < MAX_ROUTES) {
        if (entry->d_type != DT_REG) continue;
        
        char filepath[256];
        snprintf(filepath, sizeof(filepath), "%s/%s", dir_path, entry->d_name);
        
        FILE *f = fopen(filepath, "r");
        if (!f) continue;
        
        route_entry_t route;
        char network_str[32], mask_str[32], nexthop_str[32], iface[16];
        int priority;
        
        if (fscanf(f, "%s\n%s\n%s\n%s\n%d", 
                   network_str, mask_str, nexthop_str, iface, &priority) == 5) {
            route.network = ip_to_uint32(network_str);
            route.mask = ip_to_uint32(mask_str);
            route.nexthop = ip_to_uint32(nexthop_str);
            strncpy(route.interface, iface, MAX_INTERFACE_NAME - 1);
            route.priority = priority;
            
            route_table[route_count++] = route;
            log_message("Loaded route: %s/%s -> %s via %s (priority %d)",
                       network_str, mask_str, nexthop_str, iface, priority);
        }
        fclose(f);
    }
    pthread_mutex_unlock(&route_mutex);
    
    closedir(dir);
    log_message("Loaded %d routes", route_count);
    return route_count;
}

int save_route_to_file(const char *dir_path, route_entry_t *route) {
    int num = 1;
    char filepath[256];
    while (1) {
        snprintf(filepath, sizeof(filepath), "%s/%d.route", dir_path, num);
        if (access(filepath, F_OK) != 0) break;
        num++;
    }
    
    FILE *f = fopen(filepath, "w");
    if (!f) return -1;
    
    struct in_addr addr;
    addr.s_addr = route->network;
    fprintf(f, "%s\n", inet_ntoa(addr));
    addr.s_addr = route->mask;
    fprintf(f, "%s\n", inet_ntoa(addr));
    addr.s_addr = route->nexthop;
    fprintf(f, "%s\n", inet_ntoa(addr));
    fprintf(f, "%s\n", route->interface);
    fprintf(f, "%d\n", route->priority);
    
    fclose(f);
    log_message("Route saved to %s", filepath);
    return 0;
}

int add_route(route_entry_t *route) {
    pthread_mutex_lock(&route_mutex);
    
    if (route_count >= MAX_ROUTES) {
        pthread_mutex_unlock(&route_mutex);
        return -1;
    }
    route_table[route_count++] = *route;
    
    pthread_mutex_unlock(&route_mutex);
    return 0;
}

route_entry_t* find_route(uint32_t dest_ip) {
    pthread_mutex_lock(&route_mutex);
    
    route_entry_t *best = NULL;
    uint32_t best_mask = 0;
    
    for (int i = 0; i < route_count; i++) {
        if ((dest_ip & route_table[i].mask) == (route_table[i].network & route_table[i].mask)) {
            if (route_table[i].mask > best_mask) {
                best_mask = route_table[i].mask;
                best = &route_table[i];
            }
        }
    }
    
    pthread_mutex_unlock(&route_mutex);
    return best;
}

void print_routing_table() {
    pthread_mutex_lock(&route_mutex);
    
    printf("\n================================================================================\n");
    printf("| %-20s | %-20s | %-20s | %-10s | %-8s |\n", 
           "Network", "Mask", "Nexthop", "Interface", "Priority");
    printf("================================================================================\n");
    
    for (int i = 0; i < route_count; i++) {
        struct in_addr network_addr, nh_addr;
        network_addr.s_addr = route_table[i].network;
        nh_addr.s_addr = route_table[i].nexthop;
        
        // Преобразуем маску из сетевого порядка в читаемый вид
        uint32_t mask_host = ntohl(route_table[i].mask);
        char mask_str[32];
        snprintf(mask_str, sizeof(mask_str), "%u.%u.%u.%u",
                 (mask_host >> 24) & 0xFF,
                 (mask_host >> 16) & 0xFF,
                 (mask_host >> 8) & 0xFF,
                 mask_host & 0xFF);
        
        printf("| %-20s | %-20s | %-20s | %-10s | %-8d |\n",
               inet_ntoa(network_addr),
               mask_str,                          // ← используем mask_str, а не inet_ntoa(mask_addr)
               inet_ntoa(nh_addr),
               route_table[i].interface,
               route_table[i].priority);
    }
    printf("================================================================================\n");
    
    pthread_mutex_unlock(&route_mutex);
}