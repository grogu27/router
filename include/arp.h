#ifndef ARP_H
#define ARP_H

int get_my_mac(int sock, const char *interface_name, unsigned char *mac_buffer);
int get_my_ip(int sock, const char *interface_name, unsigned char *ip_buffer);
int get_neighbor_mac(const char *interface_name, const char *target_ip_str, unsigned char *mac_buffer);

#endif