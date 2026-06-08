#ifndef ROUTER_H
#define ROUTER_H

#include <stdint.h>
#include <pthread.h>

#define MAX_ROUTES 100
#define MAX_INTERFACE_NAME 16
#define BUF_SIZE 2048
extern pthread_mutex_t route_mutex;

// Структура записи таблицы маршрутизации 
typedef struct {
    uint32_t network;                       // IP сети назначения
    uint32_t mask;                          // Маска подсети
    uint32_t nexthop;                       // IP следующего роутера
    char interface[MAX_INTERFACE_NAME];     // Имя интерфейса
    int priority;                           // Приоритет (меньше = выше)
} route_entry_t;

// Кеш для arp 
typedef struct {
    uint32_t ip;                // IP адрес
    unsigned char mac[6];       // MAC адрес
    time_t timestamp;           // Время последнего обновления
} arp_cache_entry_t;

#define ARP_CACHE_SIZE 32

// Глобальная таблица маршрутизации
extern route_entry_t route_table[MAX_ROUTES];
extern int route_count;

// ARP кеш
extern arp_cache_entry_t arp_cache[ARP_CACHE_SIZE];
extern int arp_cache_count;

// Функции для работы с таблицей
int load_routes_from_dir(const char *dir_path);
int add_route(route_entry_t *route);
int save_route_to_file(const char *dir_path, route_entry_t *route);
void print_routing_table();
route_entry_t* find_route(uint32_t dest_ip);

// Функции для работы с ARP кешем
int get_mac_from_cache(uint32_t ip, unsigned char *mac);
int add_to_arp_cache(uint32_t ip, unsigned char *mac);
int resolve_mac(const char *interface_name, uint32_t ip, unsigned char *mac);

// Вспомогательные функции
int get_interface_index(const char *ifname);
int get_interface_mac(const char *ifname, unsigned char *mac);
uint32_t ip_to_uint32(const char *ip_str);
void* cli_thread_func(void *arg);


#endif