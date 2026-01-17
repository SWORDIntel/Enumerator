#include "mdm_detection.h"
#include "enumerator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winsvc.h>

// MDM detection patterns
typedef struct {
    const char* mdm_name;
    const char* registry_keys[5];
    const char* service_names[5];
    const char* process_names[5];
    const char* driver_names[5];
} mdm_pattern_t;

static const mdm_pattern_t mdm_patterns[] = {
    {
        "Microsoft Intune",
        {
            "SOFTWARE\\Microsoft\\IntuneManagementExtension",
            "SOFTWARE\\Microsoft\\Enrollments",
            "SOFTWARE\\Microsoft\\Provisioning\\OMADM\\Accounts",
            "SOFTWARE\\Microsoft\\EnterpriseResourceManager\\Tracked",
            NULL
        },
        {
            "IntuneManagementExtension",
            "Microsoft Intune MDM",
            NULL, NULL, NULL
        },
        {
            "IntuneManagementExtension.exe",
            "mdm.exe",
            NULL, NULL, NULL
        },
        {
            "IntuneMDM",
            NULL, NULL, NULL, NULL
        }
    },
    {
        "VMware AirWatch",
        {
            "SOFTWARE\\AirWatch",
            "SOFTWARE\\AirWatch MDM",
            NULL, NULL, NULL
        },
        {
            "AirWatch Agent",
            "AirWatch MDM Agent",
            NULL, NULL, NULL
        },
        {
            "AirWatchAgent.exe",
            "AirWatchMDMAgent.exe",
            NULL, NULL, NULL
        },
        {
            "AirWatchMDM",
            NULL, NULL, NULL, NULL
        }
    },
    {
        "MobileIron",
        {
            "SOFTWARE\\MobileIron",
            "SOFTWARE\\MobileIron Core",
            NULL, NULL, NULL
        },
        {
            "MobileIron Agent",
            "MobileIron Core",
            NULL, NULL, NULL
        },
        {
            "MobileIronAgent.exe",
            "MobileIronCore.exe",
            NULL, NULL, NULL
        },
        {
            "MobileIronMDM",
            NULL, NULL, NULL, NULL
        }
    },
    {
        "Workspace ONE",
        {
            "SOFTWARE\\VMware\\AirWatch",
            "SOFTWARE\\VMware\\WorkspaceONE",
            NULL, NULL, NULL
        },
        {
            "Workspace ONE Agent",
            "WorkspaceONE Agent",
            NULL, NULL, NULL
        },
        {
            "WorkspaceONEAgent.exe",
            NULL, NULL, NULL, NULL
        },
        {
            "WorkspaceONEMDM",
            NULL, NULL, NULL, NULL
        }
    },
    {
        "Microsoft MDM",
        {
            "SOFTWARE\\Microsoft\\Enrollments",
            "SOFTWARE\\Microsoft\\Provisioning",
            NULL, NULL, NULL
        },
        {
            "mdm",
            NULL, NULL, NULL, NULL
        },
        {
            "mdm.exe",
            NULL, NULL, NULL, NULL
        },
        {
            "MDM",
            NULL, NULL, NULL, NULL
        }
    }
};

#define MDM_PATTERN_COUNT (sizeof(mdm_patterns) / sizeof(mdm_patterns[0]))

int detect_mdm_software(mdm_detection_result_t* results, int max_results) {
    if (!results || max_results <= 0) {
        return 0;
    }
    
    int detected_count = 0;
    
    // Detect via registry
    int registry_count = detect_mdm_via_registry(results, max_results);
    detected_count += registry_count;
    
    // Detect via services
    if (detected_count < max_results) {
        int service_count = detect_mdm_via_services(results + detected_count, max_results - detected_count);
        detected_count += service_count;
    }
    
    // Detect via processes
    if (detected_count < max_results) {
        int process_count = detect_mdm_via_processes(results + detected_count, max_results - detected_count);
        detected_count += process_count;
    }
    
    // Detect via drivers
    if (detected_count < max_results) {
        int driver_count = detect_mdm_via_drivers(results + detected_count, max_results - detected_count);
        detected_count += driver_count;
    }
    
    return detected_count;
}

int detect_mdm_via_registry(mdm_detection_result_t* results, int max_results) {
    int detected = 0;
    
    for (int i = 0; i < MDM_PATTERN_COUNT && detected < max_results; i++) {
        const mdm_pattern_t* pattern = &mdm_patterns[i];
        
        for (int j = 0; j < 5 && pattern->registry_keys[j] != NULL && detected < max_results; j++) {
            HKEY hKey;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, pattern->registry_keys[j], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                // MDM detected via registry
                memset(&results[detected], 0, sizeof(mdm_detection_result_t));
                strncpy(results[detected].mdm_name, pattern->mdm_name, sizeof(results[detected].mdm_name) - 1);
                results[detected].mdm_name[sizeof(results[detected].mdm_name) - 1] = '\0';
                results[detected].detected = true;
                strcpy(results[detected].detection_method, "Registry Key");
                strncpy(results[detected].registry_path, pattern->registry_keys[j], sizeof(results[detected].registry_path) - 1);
                results[detected].registry_path[sizeof(results[detected].registry_path) - 1] = '\0';
                RegCloseKey(hKey);
                detected++;
                break;  // Found this MDM, move to next
            }
        }
    }
    
    return detected;
}

int detect_mdm_via_services(mdm_detection_result_t* results, int max_results) {
    int detected = 0;
    
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == NULL) {
        return 0;
    }
    
    DWORD dwBytesNeeded = 0;
    DWORD dwServicesReturned = 0;
    DWORD dwResumeHandle = 0;
    
    // Get buffer size
    EnumServicesStatusA(hSCManager, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle);
    
    if (dwBytesNeeded > 0) {
        LPENUM_SERVICE_STATUSA pServices = (LPENUM_SERVICE_STATUSA)malloc(dwBytesNeeded);
        if (pServices != NULL) {
            if (EnumServicesStatusA(hSCManager, SERVICE_WIN32, SERVICE_STATE_ALL, pServices, dwBytesNeeded, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle)) {
                for (DWORD i = 0; i < dwServicesReturned && detected < max_results; i++) {
                    // EnumServicesStatusA returns ANSI strings, no conversion needed
                    const char* serviceName = pServices[i].lpServiceName;
                    
                    // Check against MDM patterns
                    for (int j = 0; j < MDM_PATTERN_COUNT && detected < max_results; j++) {
                        const mdm_pattern_t* pattern = &mdm_patterns[j];
                        
                        for (int k = 0; k < 5 && pattern->service_names[k] != NULL; k++) {
                            if (strstr(serviceName, pattern->service_names[k]) != NULL) {
                                // Check if already detected
                                bool already_detected = false;
                                for (int l = 0; l < detected; l++) {
                                    if (strcmp(results[l].mdm_name, pattern->mdm_name) == 0) {
                                        already_detected = true;
                                        break;
                                    }
                                }
                                
                                if (!already_detected) {
                                    memset(&results[detected], 0, sizeof(mdm_detection_result_t));
                                    strncpy(results[detected].mdm_name, pattern->mdm_name, sizeof(results[detected].mdm_name) - 1);
                                    results[detected].mdm_name[sizeof(results[detected].mdm_name) - 1] = '\0';
                                    results[detected].detected = true;
                                    strcpy(results[detected].detection_method, "Service");
                                    strncpy(results[detected].service_name, serviceName, sizeof(results[detected].service_name) - 1);
                                    results[detected].service_name[sizeof(results[detected].service_name) - 1] = '\0';
                                    detected++;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            free(pServices);
        }
    }
    
    CloseServiceHandle(hSCManager);
    return detected;
}

int detect_mdm_via_processes(mdm_detection_result_t* results, int max_results) {
    int detected = 0;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // Check against MDM patterns
            for (int i = 0; i < MDM_PATTERN_COUNT && detected < max_results; i++) {
                const mdm_pattern_t* pattern = &mdm_patterns[i];
                
                for (int j = 0; j < 5 && pattern->process_names[j] != NULL; j++) {
                    if (_stricmp(pe32.szExeFile, pattern->process_names[j]) == 0) {
                        // Check if already detected
                        bool already_detected = false;
                        for (int k = 0; k < detected; k++) {
                            if (strcmp(results[k].mdm_name, pattern->mdm_name) == 0) {
                                already_detected = true;
                                break;
                            }
                        }
                        
                        if (!already_detected) {
                            memset(&results[detected], 0, sizeof(mdm_detection_result_t));
                            strncpy(results[detected].mdm_name, pattern->mdm_name, sizeof(results[detected].mdm_name) - 1);
                            results[detected].mdm_name[sizeof(results[detected].mdm_name) - 1] = '\0';
                            results[detected].detected = true;
                            strcpy(results[detected].detection_method, "Process");
                            strncpy(results[detected].process_name, pe32.szExeFile, sizeof(results[detected].process_name) - 1);
                            results[detected].process_name[sizeof(results[detected].process_name) - 1] = '\0';
                            detected++;
                            break;
                        }
                    }
                }
            }
        } while (Process32Next(hSnapshot, &pe32) && detected < max_results);
    }
    
    CloseHandle(hSnapshot);
    return detected;
}

int detect_mdm_via_drivers(mdm_detection_result_t* results, int max_results) {
    int detected = 0;
    
    // Query loaded drivers using NtQuerySystemInformation
    typedef NTSTATUS (WINAPI *NtQuerySystemInformation_t)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );
    
    typedef struct _SYSTEM_MODULE_INFORMATION {
        ULONG Reserved[2];
        PVOID Base;
        ULONG Size;
        ULONG Flags;
        USHORT Index;
        USHORT Unknown;
        USHORT LoadCount;
        USHORT ModuleNameOffset;
        CHAR ImageName[256];
    } SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;
    
    typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
        ULONG Unknown[2];
        PVOID Base;
        ULONG Size;
        ULONG Flags;
        USHORT Index;
        USHORT NameLength;
        USHORT LoadCount;
        USHORT PathLength;
        CHAR ImageName[256];
    } SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        return 0;
    }
    
    NtQuerySystemInformation_t pNtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (pNtQuerySystemInformation == NULL) {
        return 0;
    }
    
    // Query system modules (drivers)
    ULONG bufferSize = 0;
    ULONG returnLength = 0;
    NTSTATUS status = pNtQuerySystemInformation(11, NULL, 0, &returnLength);  // SystemModuleInformation = 11
    
    if (returnLength > 0) {
        bufferSize = returnLength;
        PVOID pBuffer = malloc(bufferSize);
        if (pBuffer != NULL) {
            ULONG actualReturnLength = 0;
            status = pNtQuerySystemInformation(11, pBuffer, bufferSize, &actualReturnLength);
            if (status == 0) {
                ULONG moduleCount = *(PULONG)pBuffer;
                PSYSTEM_MODULE_INFORMATION_ENTRY pModules = (PSYSTEM_MODULE_INFORMATION_ENTRY)((PBYTE)pBuffer + sizeof(ULONG));
                
                for (ULONG i = 0; i < moduleCount && detected < max_results; i++) {
                    char* driverName = pModules[i].ImageName;
                    
                    // Check against MDM patterns
                    for (int j = 0; j < MDM_PATTERN_COUNT && detected < max_results; j++) {
                        const mdm_pattern_t* pattern = &mdm_patterns[j];
                        
                        for (int k = 0; k < 5 && pattern->driver_names[k] != NULL; k++) {
                            if (strstr(driverName, pattern->driver_names[k]) != NULL) {
                                // Check if already detected
                                bool already_detected = false;
                                for (int l = 0; l < detected; l++) {
                                    if (strcmp(results[l].mdm_name, pattern->mdm_name) == 0) {
                                        already_detected = true;
                                        break;
                                    }
                                }
                                
                                if (!already_detected) {
                                    memset(&results[detected], 0, sizeof(mdm_detection_result_t));
                                    strncpy(results[detected].mdm_name, pattern->mdm_name, sizeof(results[detected].mdm_name) - 1);
                                    results[detected].mdm_name[sizeof(results[detected].mdm_name) - 1] = '\0';
                                    results[detected].detected = true;
                                    strcpy(results[detected].detection_method, "Kernel Driver");
                                    strncpy(results[detected].driver_name, driverName, sizeof(results[detected].driver_name) - 1);
                                    results[detected].driver_name[sizeof(results[detected].driver_name) - 1] = '\0';
                                    detected++;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            free(pBuffer);
        }
    }
    
    return detected;
}
