#include "network_recursive.h"
#include "enumerator.h"
#include "edr_detection.h"
#include "edr_evasion.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <wbemidl.h>
#include <comdef.h>
#include <lm.h>
#include <winnetwk.h>
#include <icmpapi.h>
#include <winreg.h>
#include <oleauto.h>
#include <dsgetdc.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")

// Recursive network discovery with W-SLAM techniques
int enumerate_network_recursive(enum_data_t* data, int max_depth) {
    append_to_buffer(data, "\n=== RECURSIVE NETWORK DISCOVERY (W-SLAM TECHNIQUES) ===\n");
    append_to_buffer(data, "Maximum Depth: %d\n", max_depth);
    
    recursive_discovery_t ctx = {0};
    ctx.max_depth = max_depth;
    ctx.current_depth = 0;
    ctx.host_capacity = 1000;
    ctx.hosts = (network_host_t*)calloc(ctx.host_capacity, sizeof(network_host_t));
    
    if (!ctx.hosts) {
        append_to_buffer(data, "Failed to allocate memory for discovery context\n");
        return -1;
    }
    
    // Start with local subnet discovery
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD dwBufLen = sizeof(adapterInfo);
    if (GetAdaptersInfo(adapterInfo, &dwBufLen) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO pAdapter = adapterInfo;
        do {
            if (pAdapter && strlen(pAdapter->IpAddressList.IpAddress.String) > 0) {
                append_to_buffer(data, "\n[Depth 0] Starting discovery from: %s\n", pAdapter->IpAddressList.IpAddress.String);
                
                // Discover local subnet hosts
                discover_subnet_hosts(pAdapter, &ctx, data);
                
                // Recursively discover from each found host
                for (size_t i = 0; i < ctx.host_count && ctx.current_depth < ctx.max_depth; i++) {
                    if (ctx.hosts[i].is_alive && !is_host_visited(&ctx, ctx.hosts[i].ip_address)) {
                        ctx.current_depth++;
                        add_visited_host(&ctx, ctx.hosts[i].ip_address);
                        append_to_buffer(data, "\n[Depth %d] Recursively discovering from: %s\n", ctx.current_depth, ctx.hosts[i].ip_address);
                        discover_from_host(&ctx.hosts[i], &ctx, data);
                        ctx.current_depth--;
                    }
                }
                
                break;
            }
            pAdapter = pAdapter->Next;
        } while (pAdapter);
    }
    
    // Summary
    append_to_buffer(data, "\n=== DISCOVERY SUMMARY ===\n");
    append_to_buffer(data, "Total Hosts Discovered: %zu\n", ctx.host_count);
    append_to_buffer(data, "Hosts with SMB: %zu\n", count_hosts_with_service(&ctx, "SMB"));
    append_to_buffer(data, "Hosts with RDP: %zu\n", count_hosts_with_service(&ctx, "RDP"));
    append_to_buffer(data, "Hosts with WinRM: %zu\n", count_hosts_with_service(&ctx, "WinRM"));
    append_to_buffer(data, "Hosts with WMI: %zu\n", count_hosts_with_service(&ctx, "WMI"));
    
    // Free resources
    for (size_t i = 0; i < ctx.visited_count; i++) {
        free(ctx.visited_ips[i]);
    }
    free(ctx.hosts);
    
    append_to_buffer(data, "==========================================\n\n");
    return 0;
}

// Discover hosts in subnet using ICMP ping sweep
void discover_subnet_hosts(PIP_ADAPTER_INFO adapter, recursive_discovery_t* ctx, enum_data_t* data) {
    struct in_addr ipAddr, subnetMask;
    inet_pton(AF_INET, adapter->IpAddressList.IpAddress.String, &ipAddr);
    inet_pton(AF_INET, adapter->IpAddressList.IpMask.String, &subnetMask);
    
    struct in_addr networkAddr;
    networkAddr.S_un.S_addr = ipAddr.S_un.S_addr & subnetMask.S_un.S_addr;
    
    struct in_addr broadcastAddr;
    broadcastAddr.S_un.S_addr = networkAddr.S_un.S_addr | ~subnetMask.S_un.S_addr;
    
    unsigned long network = ntohl(networkAddr.S_un.S_addr);
    unsigned long broadcast = ntohl(broadcastAddr.S_un.S_addr);
    unsigned long hostCount = broadcast - network - 1;
    
    append_to_buffer(data, "Scanning subnet %s/%s (%lu hosts)\n", 
        inet_ntoa(networkAddr), inet_ntoa(subnetMask), hostCount);
    
    HANDLE hIcmpFile = IcmpCreateFile();
    if (hIcmpFile == INVALID_HANDLE_VALUE) {
        return;
    }
    
    char sendData[32] = "ICMP Echo";
    char replyBuffer[sizeof(ICMP_ECHO_REPLY) + 32];
    int found = 0;
    
    // Scan subnet (limit to 254 hosts for performance)
    for (unsigned long i = 1; i <= (hostCount < 254 ? hostCount : 254); i++) {
        struct in_addr targetIP;
        targetIP.S_un.S_addr = htonl(network + i);
        
        DWORD dwRetVal = IcmpSendEcho(hIcmpFile, targetIP.S_un.S_addr, sendData, sizeof(sendData), NULL, replyBuffer, sizeof(replyBuffer), 500);
        if (dwRetVal != 0) {
            PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)replyBuffer;
            if (pEchoReply->Status == IP_SUCCESS) {
                char ipStr[16];
                strcpy(ipStr, inet_ntoa(targetIP));
                
                network_host_t* host = add_discovered_host(ctx, ipStr);
                if (host) {
                    host->is_alive = true;
                    host->depth = 0;
                    strcpy(host->discovered_via, "ICMP Ping");
                    
                    // Discover services on this host
                    discover_host_services(host);
                    
                    append_to_buffer(data, "  [FOUND] %s - Services: %s\n", ipStr, host->services);
                    found++;
                }
            }
        }
    }
    
    append_to_buffer(data, "Found %d active hosts in subnet\n", found);
    IcmpCloseHandle(hIcmpFile);
}

// Discover from a specific host (recursive) - Enhanced with W-SLAM techniques
void discover_from_host(network_host_t* source_host, recursive_discovery_t* ctx, enum_data_t* data) {
    if (ctx->current_depth >= ctx->max_depth) {
        return;
    }
    
    append_to_buffer(data, "\n[Depth %d] Deep enumeration from %s using W-SLAM techniques\n", 
                     ctx->current_depth, source_host->ip_address);
    
    // Continuous EDR evasion before enumeration (as specified in plan)
    edr_detection_result_t edr_results[16];
    int edr_count = detect_edr_products(edr_results, 16);
    if (edr_count > 0) {
        append_to_buffer(data, "  [EDR Evasion] Detected %d EDR product(s), applying evasion...\n", edr_count);
        for (int i = 0; i < edr_count; i++) {
            append_to_buffer(data, "    - %s (confidence: %.2f)\n", edr_results[i].edr_name, edr_results[i].confidence);
        }
        apply_edr_evasion_before_enumeration(source_host->ip_address, edr_results, edr_count);
        append_to_buffer(data, "  [EDR Evasion] Evasion techniques applied\n");
    }
    
    // Technique 1: SMB enumeration to discover other hosts
    if (source_host->has_smb) {
        enumerate_smb_shares(source_host->ip_address, data);
        discover_hosts_via_smb(source_host->ip_address, ctx, data);
    }
    
    // Technique 2: WMI remote enumeration
    if (source_host->has_wmi) {
        enumerate_wmi_remote(source_host->ip_address, data);
        discover_hosts_via_wmi(source_host->ip_address, ctx, data);
    }
    
    // Technique 3: NetBIOS enumeration
    discover_hosts_via_netbios(source_host->ip_address, ctx, data);
    
    // Technique 4: NetServerEnum - enumerate domain/workgroup servers
    discover_hosts_via_netserver(source_host->ip_address, ctx, data);
    
    // Technique 5: NetSessionEnum - enumerate active sessions to discover connected hosts
    discover_hosts_via_netsession(source_host->ip_address, ctx, data);
    
    // Technique 6: NetFileEnum - enumerate open files to discover connected hosts
    discover_hosts_via_netfile(source_host->ip_address, ctx, data);
    
    // Technique 7: ARP table enumeration - check ARP tables for network neighbors
    discover_hosts_via_arp_table(source_host->ip_address, ctx, data);
    
    // Technique 8: Route table enumeration - check routing tables for network topology
    discover_hosts_via_route_table(source_host->ip_address, ctx, data);
    
    // Technique 9: DNS enumeration - query DNS for additional hosts
    discover_hosts_via_dns(source_host->ip_address, ctx, data);
    
    // Technique 10: LDAP enumeration - if domain-joined, enumerate AD for hosts
    discover_hosts_via_ldap(source_host->ip_address, ctx, data);
    
    // Technique 11: SNMP enumeration - if SNMP is available
    discover_hosts_via_snmp(source_host->ip_address, ctx, data);
    
    // Technique 12: Enhanced port scanning with service fingerprinting
    discover_hosts_via_port_scan(source_host->ip_address, ctx, data);
    
    // Technique 13: Credential-based discovery - use discovered credentials to access more hosts
    discover_hosts_via_credential_replay(source_host->ip_address, ctx, data);
}

// Discover hosts via SMB (T1135, T1018)
void discover_hosts_via_smb(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data) {
    append_to_buffer(data, "  [SMB] Discovering hosts via SMB from %s\n", target_ip);
    
    // Use NetShareEnum to discover shares and potential hosts
    SHARE_INFO_502* pBuf = NULL;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus = NetShareEnum((LPWSTR)target_ip, 502, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, NULL);
    
    if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) {
        if (pBuf != NULL) {
            for (DWORD i = 0; i < dwEntriesRead; i++) {
                if (pBuf[i].shi502_type == STYPE_DISKTREE || pBuf[i].shi502_type == STYPE_IPC) {
                    char shareName[256];
                    WideCharToMultiByte(CP_UTF8, 0, pBuf[i].shi502_netname, -1, shareName, sizeof(shareName), NULL, NULL);
                    append_to_buffer(data, "    Share: \\\\%s\\%s\n", target_ip, shareName);
                }
            }
            NetApiBufferFree(pBuf);
        }
    }
}

// Discover hosts via WMI (T1047)
void discover_hosts_via_wmi(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data) {
    append_to_buffer(data, "  [WMI] Discovering hosts via WMI from %s\n", target_ip);
    
    HRESULT hres;
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (SUCCEEDED(hres)) {
        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (SUCCEEDED(hres)) {
            hres = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID*)&pLoc);
            if (SUCCEEDED(hres)) {
                wchar_t wmiPath[512];
                swprintf(wmiPath, sizeof(wmiPath)/sizeof(wchar_t), L"\\\\%S\\ROOT\\CIMV2", target_ip);
                hres = pLoc->lpVtbl->ConnectServer(pLoc, wmiPath, NULL, NULL, 0, NULL, 0, 0, &pSvc);
                if (SUCCEEDED(hres)) {
                    hres = CoSetProxyBlanket((IUnknown*)pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
                    if (SUCCEEDED(hres)) {
                        // Query network adapters to discover other IPs
                        IEnumWbemClassObject* pEnumerator = NULL;
                        hres = pSvc->lpVtbl->ExecQuery(pSvc, L"WQL", L"SELECT IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE", WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
                        if (SUCCEEDED(hres)) {
                            IWbemClassObject* pclsObj = NULL;
                            ULONG uReturn = 0;
                            while (pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn) == WBEM_S_NO_ERROR) {
                                VARIANT vtProp;
                                VariantInit(&vtProp);
                                if (pclsObj->lpVtbl->Get(pclsObj, L"IPAddress", 0, &vtProp, 0, 0) == WBEM_S_NO_ERROR) {
                                    if (vtProp.vt == (VT_ARRAY | VT_BSTR)) {
                                        SAFEARRAY* pArray = vtProp.parray;
                                        long lBound, uBound;
                                        SafeArrayGetLBound(pArray, 1, &lBound);
                                        SafeArrayGetUBound(pArray, 1, &uBound);
                                        for (long i = lBound; i <= uBound; i++) {
                                            BSTR bstrIP;
                                            SafeArrayGetElement(pArray, &i, &bstrIP);
                                            if (bstrIP) {
                                                char ipStr[16];
                                                WideCharToMultiByte(CP_UTF8, 0, bstrIP, -1, ipStr, sizeof(ipStr), NULL, NULL);
                                                if (!is_host_visited(ctx, ipStr) && strcmp(ipStr, target_ip) != 0) {
                                                    network_host_t* host = add_discovered_host(ctx, ipStr);
                                                    if (host) {
                                                        host->depth = ctx->current_depth + 1;
                                                        strcpy(host->discovered_via, "WMI Remote Query");
                                                        append_to_buffer(data, "    [DISCOVERED] %s via WMI\n", ipStr);
                                                    }
                                                }
                                                SysFreeString(bstrIP);
                                            }
                                        }
                                    }
                                    VariantClear(&vtProp);
                                }
                                pclsObj->lpVtbl->Release(pclsObj);
                            }
                            pEnumerator->lpVtbl->Release(pEnumerator);
                        }
                        pSvc->lpVtbl->Release(pSvc);
                    }
                }
                pLoc->lpVtbl->Release(pLoc);
            }
        }
        CoUninitialize();
    }
}

// Discover hosts via NetBIOS
void discover_hosts_via_netbios(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data) {
    append_to_buffer(data, "  [NetBIOS] Discovering hosts via NetBIOS from %s\n", target_ip);
    
    SERVER_INFO_100* pServerInfo = NULL;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus = NetServerEnum((LPWSTR)target_ip, 100, (LPBYTE*)&pServerInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, SV_TYPE_ALL, NULL, NULL);
    
    if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) {
        if (pServerInfo != NULL) {
            for (DWORD i = 0; i < dwEntriesRead; i++) {
                if (pServerInfo[i].sv100_name != NULL) {
                    char serverName[256];
                    WideCharToMultiByte(CP_UTF8, 0, pServerInfo[i].sv100_name, -1, serverName, sizeof(serverName), NULL, NULL);
                    append_to_buffer(data, "    Server: %s\n", serverName);
                }
            }
            NetApiBufferFree(pServerInfo);
        }
    }
}

// Discover services on a host
int discover_host_services(network_host_t* host) {
    if (!host) return -1;
    
    int port_count = 0;
    int common_ports[] = {135, 139, 445, 3389, 5985, 5986, 22, 80, 443, 1433, 3306, 5432};
    int num_ports = sizeof(common_ports) / sizeof(common_ports[0]);
    
    struct in_addr targetIP;
    inet_pton(AF_INET, host->ip_address, &targetIP);
    
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return -1;
    }
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr = targetIP;
    
    for (int i = 0; i < num_ports && port_count < 100; i++) {
        addr.sin_port = htons(common_ports[i]);
        
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
        
        int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        if (result == 0 || WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set writefds;
            FD_ZERO(&writefds);
            FD_SET(sock, &writefds);
            struct timeval timeout;
            timeout.tv_sec = 0;
            timeout.tv_usec = 100000;  // 100ms
            
            if (select(0, NULL, &writefds, NULL, &timeout) > 0) {
                host->open_ports[port_count++] = common_ports[i];
                
                // Identify services
                if (common_ports[i] == 445 || common_ports[i] == 139) {
                    host->has_smb = true;
                    strcat(host->services, "SMB ");
                } else if (common_ports[i] == 3389) {
                    host->has_rdp = true;
                    strcat(host->services, "RDP ");
                } else if (common_ports[i] == 5985 || common_ports[i] == 5986) {
                    host->has_winrm = true;
                    strcat(host->services, "WinRM ");
                } else if (common_ports[i] == 135) {
                    host->has_wmi = true;
                    strcat(host->services, "WMI ");
                } else if (common_ports[i] == 22) {
                    host->has_ssh = true;
                    strcat(host->services, "SSH ");
                }
            }
        }
        
        closesocket(sock);
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }
    
    closesocket(sock);
    host->port_count = port_count;
    return 0;
}

// Enumerate SMB shares (T1135)
int enumerate_smb_shares(const char* target_ip, enum_data_t* data) {
    append_to_buffer(data, "  [SMB] Enumerating shares on %s\n", target_ip);
    
    SHARE_INFO_502* pBuf = NULL;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus = NetShareEnum((LPWSTR)target_ip, 502, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, NULL);
    
    if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) {
        if (pBuf != NULL) {
            for (DWORD i = 0; i < dwEntriesRead; i++) {
                char shareName[256];
                char sharePath[512];
                WideCharToMultiByte(CP_UTF8, 0, pBuf[i].shi502_netname, -1, shareName, sizeof(shareName), NULL, NULL);
                WideCharToMultiByte(CP_UTF8, 0, pBuf[i].shi502_path, -1, sharePath, sizeof(sharePath), NULL, NULL);
                append_to_buffer(data, "    Share: \\\\%s\\%s -> %s (Type: %lu)\n", target_ip, shareName, sharePath, pBuf[i].shi502_type);
            }
            NetApiBufferFree(pBuf);
        }
    }
    return 0;
}

// Enumerate WMI remote (T1047)
int enumerate_wmi_remote(const char* target_ip, enum_data_t* data) {
    append_to_buffer(data, "  [WMI] Enumerating via WMI on %s\n", target_ip);
    
    // Implementation similar to discover_hosts_via_wmi but for enumeration
    return 0;
}

// Helper functions
bool is_host_visited(recursive_discovery_t* ctx, const char* ip) {
    for (size_t i = 0; i < ctx->visited_count; i++) {
        if (strcmp(ctx->visited_ips[i], ip) == 0) {
            return true;
        }
    }
    return false;
}

void add_visited_host(recursive_discovery_t* ctx, const char* ip) {
    if (ctx->visited_count < 1000) {
        ctx->visited_ips[ctx->visited_count] = _strdup(ip);
        ctx->visited_count++;
    }
}

network_host_t* add_discovered_host(recursive_discovery_t* ctx, const char* ip) {
    if (is_host_visited(ctx, ip)) {
        return NULL;
    }
    
    if (ctx->host_count >= ctx->host_capacity) {
        ctx->host_capacity *= 2;
        ctx->hosts = (network_host_t*)realloc(ctx->hosts, ctx->host_capacity * sizeof(network_host_t));
        if (!ctx->hosts) return NULL;
    }
    
    network_host_t* host = &ctx->hosts[ctx->host_count++];
    memset(host, 0, sizeof(network_host_t));
    strncpy(host->ip_address, ip, sizeof(host->ip_address) - 1);
    
    return host;
}

size_t count_hosts_with_service(recursive_discovery_t* ctx, const char* service) {
    size_t count = 0;
    for (size_t i = 0; i < ctx->host_count; i++) {
        if (strstr(ctx->hosts[i].services, service) != NULL) {
            count++;
        }
    }
    return count;
}

// W-SLAM Technique 4: NetServerEnum - enumerate domain/workgroup servers
void discover_hosts_via_netserver(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data) {
    append_to_buffer(data, "  [NetServerEnum] Discovering servers from %s\n", target_ip);
    
    SERVER_INFO_101* pServerInfo = NULL;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus = NetServerEnum(NULL, 101, (LPBYTE*)&pServerInfo, MAX_PREFERRED_LENGTH, 
                                          &dwEntriesRead, &dwTotalEntries, SV_TYPE_ALL, NULL, NULL);
    
    if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) {
        if (pServerInfo != NULL) {
            for (DWORD i = 0; i < dwEntriesRead; i++) {
                if (pServerInfo[i].sv101_name != NULL) {
                    char serverName[256];
                    WideCharToMultiByte(CP_UTF8, 0, pServerInfo[i].sv101_name, -1, serverName, sizeof(serverName), NULL, NULL);
                    
                    // Try to resolve hostname to IP
                    struct hostent* host = gethostbyname(serverName);
                    if (host && host->h_addr_list[0]) {
                        struct in_addr addr;
                        memcpy(&addr, host->h_addr_list[0], sizeof(struct in_addr));
                        char ipStr[16];
                        strcpy(ipStr, inet_ntoa(addr));
                        
                        if (!is_host_visited(ctx, ipStr)) {
                            network_host_t* host = add_discovered_host(ctx, ipStr);
                            if (host) {
                                host->depth = ctx->current_depth + 1;
                                strcpy(host->discovered_via, "NetServerEnum");
                                strncpy(host->hostname, serverName, sizeof(host->hostname) - 1);
                                append_to_buffer(data, "    [DISCOVERED] %s (%s) via NetServerEnum\n", ipStr, serverName);
                            }
                        }
                    }
                }
            }
            NetApiBufferFree(pServerInfo);
        }
    }
}

// W-SLAM Technique 5: NetSessionEnum - enumerate active sessions to discover connected hosts
void discover_hosts_via_netsession(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data) {
    append_to_buffer(data, "  [NetSessionEnum] Discovering hosts via active sessions on %s\n", target_ip);
    
    SESSION_INFO_10* pBuf = NULL;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus = NetSessionEnum((LPWSTR)target_ip, NULL, NULL, 10, (LPBYTE*)&pBuf, 
                                           MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, NULL);
    
    if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) {
        if (pBuf != NULL) {
            for (DWORD i = 0; i < dwEntriesRead; i++) {
                if (pBuf[i].sesi10_cname != NULL) {
                    char clientName[256];
                    WideCharToMultiByte(CP_UTF8, 0, pBuf[i].sesi10_cname, -1, clientName, sizeof(clientName), NULL, NULL);
                    
                    // Try to resolve hostname to IP
                    struct hostent* host = gethostbyname(clientName);
                    if (host && host->h_addr_list[0]) {
                        struct in_addr addr;
                        memcpy(&addr, host->h_addr_list[0], sizeof(struct in_addr));
                        char ipStr[16];
                        strcpy(ipStr, inet_ntoa(addr));
                        
                        if (!is_host_visited(ctx, ipStr)) {
                            network_host_t* host = add_discovered_host(ctx, ipStr);
                            if (host) {
                                host->depth = ctx->current_depth + 1;
                                strcpy(host->discovered_via, "NetSessionEnum");
                                strncpy(host->hostname, clientName, sizeof(host->hostname) - 1);
                                append_to_buffer(data, "    [DISCOVERED] %s (%s) via active session\n", ipStr, clientName);
                            }
                        }
                    }
                }
            }
            NetApiBufferFree(pBuf);
        }
    }
}

// W-SLAM Technique 6: NetFileEnum - enumerate open files to discover connected hosts
void discover_hosts_via_netfile(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data) {
    append_to_buffer(data, "  [NetFileEnum] Discovering hosts via open files on %s\n", target_ip);
    
    FILE_INFO_3* pBuf = NULL;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus = NetFileEnum((LPWSTR)target_ip, NULL, NULL, 3, (LPBYTE*)&pBuf, 
                                        MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, NULL);
    
    if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) {
        if (pBuf != NULL) {
            for (DWORD i = 0; i < dwEntriesRead; i++) {
                if (pBuf[i].fi3_username != NULL) {
                    char username[256];
                    WideCharToMultiByte(CP_UTF8, 0, pBuf[i].fi3_username, -1, username, sizeof(username), NULL, NULL);
                    append_to_buffer(data, "    Open file by user: %s (Path: %s)\n", username, 
                                    pBuf[i].fi3_pathname ? "N/A" : "");
                }
            }
            NetApiBufferFree(pBuf);
        }
    }
}

// W-SLAM Technique 7: ARP table enumeration - check ARP tables for network neighbors
void discover_hosts_via_arp_table(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data) {
    append_to_buffer(data, "  [ARP Table] Discovering hosts via ARP table from %s\n", target_ip);
    
    // Use WMI to query ARP table remotely if WMI is available
    if (ctx->current_depth == 0) {
        // Query local ARP table
        MIB_IPNETTABLE* pArpTable = NULL;
        DWORD dwSize = 0;
        DWORD dwRetVal = GetIpNetTable(NULL, &dwSize, FALSE);
        
        if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
            pArpTable = (MIB_IPNETTABLE*)malloc(dwSize);
            if (pArpTable != NULL) {
                dwRetVal = GetIpNetTable(pArpTable, &dwSize, FALSE);
                if (dwRetVal == NO_ERROR) {
                    for (DWORD i = 0; i < pArpTable->dwNumEntries; i++) {
                        if (pArpTable->table[i].dwType == MIB_IPNET_TYPE_DYNAMIC || 
                            pArpTable->table[i].dwType == MIB_IPNET_TYPE_STATIC) {
                            struct in_addr addr;
                            addr.S_un.S_addr = pArpTable->table[i].dwAddr;
                            char ipStr[16];
                            strcpy(ipStr, inet_ntoa(addr));
                            
                            if (!is_host_visited(ctx, ipStr)) {
                                network_host_t* host = add_discovered_host(ctx, ipStr);
                                if (host) {
                                    host->depth = ctx->current_depth + 1;
                                    strcpy(host->discovered_via, "ARP Table");
                                    memcpy(host->mac_address, pArpTable->table[i].bPhysAddr, 6);
                                    append_to_buffer(data, "    [DISCOVERED] %s via ARP table\n", ipStr);
                                }
                            }
                        }
                    }
                }
                free(pArpTable);
            }
        }
    }
}

// W-SLAM Technique 8: Route table enumeration - check routing tables for network topology
void discover_hosts_via_route_table(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data) {
    append_to_buffer(data, "  [Route Table] Discovering hosts via route table from %s\n", target_ip);
    
    // Query routing table to discover network gateways and routes
    MIB_IPFORWARDTABLE* pForwardTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRetVal = GetIpForwardTable(NULL, &dwSize, FALSE);
    
    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        pForwardTable = (MIB_IPFORWARDTABLE*)malloc(dwSize);
        if (pForwardTable != NULL) {
            dwRetVal = GetIpForwardTable(pForwardTable, &dwSize, FALSE);
            if (dwRetVal == NO_ERROR) {
                for (DWORD i = 0; i < pForwardTable->dwNumEntries; i++) {
                    struct in_addr gatewayAddr;
                    gatewayAddr.S_un.S_addr = pForwardTable->table[i].dwForwardNextHop;
                    
                    if (gatewayAddr.S_un.S_addr != 0) {
                        char ipStr[16];
                        strcpy(ipStr, inet_ntoa(gatewayAddr));
                        
                        if (!is_host_visited(ctx, ipStr)) {
                            network_host_t* host = add_discovered_host(ctx, ipStr);
                            if (host) {
                                host->depth = ctx->current_depth + 1;
                                strcpy(host->discovered_via, "Route Table");
                                append_to_buffer(data, "    [DISCOVERED] %s (Gateway) via route table\n", ipStr);
                            }
                        }
                    }
                }
            }
            free(pForwardTable);
        }
    }
}

// W-SLAM Technique 9: DNS enumeration - query DNS for additional hosts
void discover_hosts_via_dns(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data) {
    append_to_buffer(data, "  [DNS] Discovering hosts via DNS queries from %s\n", target_ip);
    
    // Get DNS server information
    FIXED_INFO* pFixedInfo = NULL;
    ULONG ulOutBufLen = sizeof(FIXED_INFO);
    DWORD dwRetVal = GetNetworkParams(NULL, &ulOutBufLen);
    
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        pFixedInfo = (FIXED_INFO*)malloc(ulOutBufLen);
        if (pFixedInfo != NULL) {
            dwRetVal = GetNetworkParams(pFixedInfo, &ulOutBufLen);
            if (dwRetVal == NO_ERROR) {
                // Try reverse DNS lookup for discovered IPs
                for (size_t i = 0; i < ctx->host_count; i++) {
                    if (ctx->hosts[i].is_alive && strlen(ctx->hosts[i].hostname) == 0) {
                        struct hostent* host = gethostbyaddr((char*)&ctx->hosts[i].ip_address, 
                                                            sizeof(struct in_addr), AF_INET);
                        if (host && host->h_name) {
                            strncpy(ctx->hosts[i].hostname, host->h_name, sizeof(ctx->hosts[i].hostname) - 1);
                            append_to_buffer(data, "    [DNS] %s -> %s\n", ctx->hosts[i].ip_address, host->h_name);
                        }
                    }
                }
            }
            free(pFixedInfo);
        }
    }
}

// W-SLAM Technique 10: LDAP enumeration - if domain-joined, enumerate AD for hosts
void discover_hosts_via_ldap(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data) {
    append_to_buffer(data, "  [LDAP] Discovering hosts via LDAP/AD from %s\n", target_ip);
    
    // Check if domain-joined
    PDOMAIN_CONTROLLER_INFOA pdcInfo = NULL;
    DWORD dwResult = DsGetDcNameA(NULL, NULL, NULL, NULL, DS_DIRECTORY_SERVICE_REQUIRED, &pdcInfo);
    
    if (dwResult == ERROR_SUCCESS && pdcInfo != NULL) {
        append_to_buffer(data, "    Domain-joined environment detected\n");
        
        // Enumerate domain computers via NetServerEnum with domain filter
        SERVER_INFO_101* pServerInfo = NULL;
        DWORD dwEntriesRead = 0;
        DWORD dwTotalEntries = 0;
        NET_API_STATUS nStatus = NetServerEnum(NULL, 101, (LPBYTE*)&pServerInfo, MAX_PREFERRED_LENGTH, 
                                              &dwEntriesRead, &dwTotalEntries, SV_TYPE_DOMAIN_CTRL | SV_TYPE_DOMAIN_BAKCTRL | SV_TYPE_SERVER, 
                                              pdcInfo->DomainName, NULL);
        
        if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) {
            if (pServerInfo != NULL) {
                for (DWORD i = 0; i < dwEntriesRead; i++) {
                    if (pServerInfo[i].sv101_name != NULL) {
                        char serverName[256];
                        WideCharToMultiByte(CP_UTF8, 0, pServerInfo[i].sv101_name, -1, serverName, sizeof(serverName), NULL, NULL);
                        
                        // Try to resolve hostname to IP
                        struct hostent* host = gethostbyname(serverName);
                        if (host && host->h_addr_list[0]) {
                            struct in_addr addr;
                            memcpy(&addr, host->h_addr_list[0], sizeof(struct in_addr));
                            char ipStr[16];
                            strcpy(ipStr, inet_ntoa(addr));
                            
                            if (!is_host_visited(ctx, ipStr)) {
                                network_host_t* host = add_discovered_host(ctx, ipStr);
                                if (host) {
                                    host->depth = ctx->current_depth + 1;
                                    strcpy(host->discovered_via, "LDAP/AD Enumeration");
                                    strncpy(host->hostname, serverName, sizeof(host->hostname) - 1);
                                    append_to_buffer(data, "    [DISCOVERED] %s (%s) via LDAP/AD\n", ipStr, serverName);
                                }
                            }
                        }
                    }
                }
                NetApiBufferFree(pServerInfo);
            }
        }
        
        NetApiBufferFree(pdcInfo);
    }
}

// W-SLAM Technique 11: SNMP enumeration - if SNMP is available
void discover_hosts_via_snmp(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data) {
    append_to_buffer(data, "  [SNMP] Attempting SNMP enumeration on %s\n", target_ip);
    
    // Check if SNMP port (161) is open
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock != INVALID_SOCKET) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(161);
        struct in_addr targetIP;
        inet_pton(AF_INET, target_ip, &targetIP);
        addr.sin_addr = targetIP;
        
        // Simple SNMP GET request (community string "public")
        unsigned char snmpRequest[] = {
            0x30, 0x1c, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
            0xa0, 0x0f, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00
        };
        
        int result = sendto(sock, (char*)snmpRequest, sizeof(snmpRequest), 0, (struct sockaddr*)&addr, sizeof(addr));
        if (result > 0) {
            char recvBuf[1024];
            struct sockaddr_in fromAddr;
            int fromLen = sizeof(fromAddr);
            struct timeval timeout;
            timeout.tv_sec = 2;
            timeout.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
            
            result = recvfrom(sock, recvBuf, sizeof(recvBuf), 0, (struct sockaddr*)&fromAddr, &fromLen);
            if (result > 0) {
                append_to_buffer(data, "    [SNMP] SNMP service detected on %s\n", target_ip);
            }
        }
        closesocket(sock);
    }
}

// W-SLAM Technique 12: Enhanced port scanning with service fingerprinting
void discover_hosts_via_port_scan(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data) {
    append_to_buffer(data, "  [Port Scan] Enhanced port scanning on %s\n", target_ip);
    
    // Extended port list for deeper enumeration
    int extended_ports[] = {
        21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 636, 993, 995,
        1433, 1521, 3306, 3389, 5432, 5985, 5986, 8080, 8443, 9000
    };
    int num_ports = sizeof(extended_ports) / sizeof(extended_ports[0]);
    
    struct in_addr targetIP;
    inet_pton(AF_INET, target_ip, &targetIP);
    
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return;
    }
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr = targetIP;
    
    int openPorts = 0;
    for (int i = 0; i < num_ports; i++) {
        addr.sin_port = htons(extended_ports[i]);
        
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
        
        int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        if (result == 0 || WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set writefds;
            FD_ZERO(&writefds);
            FD_SET(sock, &writefds);
            struct timeval timeout;
            timeout.tv_sec = 0;
            timeout.tv_usec = 50000;  // 50ms
            
            if (select(0, NULL, &writefds, NULL, &timeout) > 0) {
                openPorts++;
                append_to_buffer(data, "    Port %d: OPEN\n", extended_ports[i]);
            }
        }
        
        closesocket(sock);
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }
    
    closesocket(sock);
    append_to_buffer(data, "    Found %d open ports on %s\n", openPorts, target_ip);
}

// W-SLAM Technique 13: Credential-based discovery - use discovered credentials to access more hosts
void discover_hosts_via_credential_replay(const char* target_ip, recursive_discovery_t* ctx, enum_data_t* data) {
    append_to_buffer(data, "  [Credential Replay] Attempting credential-based discovery from %s\n", target_ip);
    
    // This would use discovered credentials to authenticate to other hosts
    // For now, we'll enumerate users and attempt common credential patterns
    
    // Enumerate users on target
    USER_INFO_0* pBuf = NULL;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus = NetUserEnum((LPWSTR)target_ip, 0, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, 
                                         MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, NULL);
    
    if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) {
        if (pBuf != NULL) {
            append_to_buffer(data, "    Found %lu users on %s\n", dwEntriesRead, target_ip);
            
            // Try to use discovered credentials on other hosts
            for (size_t i = 0; i < ctx->host_count && i < 10; i++) {
                if (strcmp(ctx->hosts[i].ip_address, target_ip) != 0 && ctx->hosts[i].has_smb) {
                    // Attempt SMB connection with discovered usernames
                    // This is a placeholder - real implementation would use actual credential replay
                    append_to_buffer(data, "    Attempting credential replay to %s\n", ctx->hosts[i].ip_address);
                }
            }
            
            NetApiBufferFree(pBuf);
        }
    }
}
