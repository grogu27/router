#include <stdint.h>
#include <arpa/inet.h>

uint16_t ip_checksum(void *buf, int len) {
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)buf;
    
    for (int i = 0; i < len / 2; i++) {
        sum += *ptr;
        ptr++;
    }
    
    if (len % 2 != 0) {
        sum += *(uint8_t *)ptr;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return (uint16_t)~sum;
}

int verify_ip_checksum(void *buf, int len) {
    uint16_t received = ((uint16_t*)buf)[5]; // checksum находится в 6-м 16-битном слове
    ((uint16_t*)buf)[5] = 0;
    uint16_t calculated = ip_checksum(buf, len);
    //((uint16_t*)buf)[5] = received;
    
    return received == calculated;
}