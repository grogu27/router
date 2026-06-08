// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <arpa/inet.h>

// #include "router.h"
// #include "logger.h"

// #define ROUTES_DIR "./routes"

// extern int running;
// extern int raw_sock;

// void* cli_thread_func(void *arg) {
//     (void)arg;
//     char command[256];
    
//     printf("\n=== Router CLI ===\n");
//     printf("Commands:\n");
//     printf("  show                      - show routing table\n");
//     printf("  add <net> <mask> <gw> <iface> <prio> - add route\n");
//     printf("  exit                      - shutdown router\n");
//     printf("=================\n\n");
    
//     while (running) {
//         printf("cli> ");
//         fflush(stdout);
        
//         if (!fgets(command, sizeof(command), stdin)) continue;
//         command[strcspn(command, "\n")] = 0;
        
//         if (strncmp(command, "show", 4) == 0) {
//             print_routing_table();
//         }
//         else if (strncmp(command, "add", 3) == 0) {
//             char network_str[32], mask_str[32], nexthop_str[32], iface[16];
//             int priority;
            
//             if (sscanf(command, "add %s %s %s %s %d", 
//                        network_str, mask_str, nexthop_str, iface, &priority) == 5) {
//                 route_entry_t new_route;
//                 new_route.network = ip_to_uint32(network_str);
//                 new_route.mask = ip_to_uint32(mask_str);
//                 new_route.nexthop = ip_to_uint32(nexthop_str);
//                 strncpy(new_route.interface, iface, MAX_INTERFACE_NAME - 1);
//                 new_route.priority = priority;
                


//                 if (add_route(&new_route) == 0) {
//                     save_route_to_file(ROUTES_DIR, &new_route);
//                     printf("Route added successfully\n");
//                     log_message("Route added via CLI: %s -> %s via %s", 
//                                network_str, nexthop_str, iface);
                    
//                     // // Опционально: предварительно разрешаем MAC (прогреваем кеш)
//                     // unsigned char tmp_mac[6];
//                     // resolve_mac(raw_sock, iface, new_route.nexthop, tmp_mac);
//                 } else {
//                     printf("Error: routing table full\n");
//                 }
//             } else {
//                 printf("Usage: add <network> <mask> <nexthop> <interface> <priority>\n");
//                 printf("Example: add 192.168.1.0 255.255.255.0 10.0.0.1 eth2 10\n");
//             }
//         }
//         else if (strncmp(command, "exit", 4) == 0) {
//             printf("Shutting down...\n");
//             running = 0;
//             break;
//         }
//         else {
//             printf("Unknown command. Available: show, add, exit\n");
//         }
//     }
    
//     return NULL;
// }

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "router.h"
#include "logger.h"

#define ROUTES_DIR "./routes"

extern int running;
extern int raw_sock;

void* cli_thread_func(void *arg) {
    (void)arg;
    char command[256];
    
    printf("\n=== Router CLI ===\n");
    printf("Commands:\n");
    printf("  show                      - show routing table\n");
    printf("  add <net> <mask> <gw> <iface> <prio> - add route\n");
    printf("  exit                      - shutdown router\n");
    printf("=================\n\n");
    
    while (running) {
        printf("cli> ");
        fflush(stdout);
        
        if (!fgets(command, sizeof(command), stdin)) continue;
        command[strcspn(command, "\n")] = 0;
        
        if (strncmp(command, "show", 4) == 0) {
            print_routing_table();
        }
        else if (strncmp(command, "add", 3) == 0) {
            char network_str[32], mask_str[32], nexthop_str[32], iface[16];
            int priority;
            
            if (sscanf(command, "add %s %s %s %s %d", 
                       network_str, mask_str, nexthop_str, iface, &priority) == 5) {
                
                route_entry_t new_route;
                new_route.network = ip_to_uint32(network_str);
                new_route.mask = ip_to_uint32(mask_str);
                new_route.nexthop = ip_to_uint32(nexthop_str);
                strncpy(new_route.interface, iface, MAX_INTERFACE_NAME - 1);
                new_route.priority = priority;

                
                if (add_route(&new_route) == 0) {
                    save_route_to_file(ROUTES_DIR, &new_route);
                    printf("Route added successfully\n");
                    log_message("Route added via CLI: %s -> %s via %s", 
                               network_str, nexthop_str, iface);
                } else {
                    printf("Error: routing table full\n");
                }
            } else {
                printf("Usage: add <network> <mask> <nexthop> <interface> <priority>\n");
                printf("Example: add 192.168.1.0 255.255.255.0 10.0.0.1 eth2 10\n");
            }
        }
        else if (strncmp(command, "exit", 4) == 0) {
            printf("Shutting down...\n");
            running = 0;
            break;
        }
        else {
            printf("Unknown command. Available: show, add, exit\n");
        }
    }
    
    return NULL;
}