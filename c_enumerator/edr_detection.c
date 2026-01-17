#include "edr_detection.h"
#include "enumerator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winsvc.h>

// EDR detection patterns
typedef struct {
    const char* edr_name;
    const char* registry_keys[5];
    const char* service_names[5];
    const char* process_names[5];
    const char* driver_names[5];
    float confidence_base;
} edr_pattern_t;

static const edr_pattern_t edr_patterns[] = {
    {
        "CrowdStrike Falcon",
        {
            "SOFTWARE\\CrowdStrike",
            "SOFTWARE\\CrowdStrike\\FalconSensor",
            NULL, NULL, NULL
        },
        {
            "CSFalconService",
            "CSAgent",
            NULL, NULL, NULL
        },
        {
            "CSFalconService.exe",
            "CSAgent.exe",
            "csagent.exe",
            NULL, NULL
        },
        {
            "CrowdStrike",
            "csagent",
            NULL, NULL, NULL
        },
        0.95f
    },
    {
        "SentinelOne",
        {
            "SOFTWARE\\SentinelOne",
            "SOFTWARE\\SentinelAgent",
            NULL, NULL, NULL
        },
        {
            "SentinelAgent",
            "SentinelService",
            NULL, NULL, NULL
        },
        {
            "SentinelAgent.exe",
            "SentinelService.exe",
            NULL, NULL, NULL
        },
        {
            "SentinelOne",
            "SentinelAgent",
            NULL, NULL, NULL
        },
        0.95f
    },
    {
        "Microsoft Defender for Endpoint",
        {
            "SOFTWARE\\Microsoft\\Windows Defender",
            "SOFTWARE\\Microsoft\\Windows Advanced Threat Protection",
            NULL, NULL, NULL
        },
        {
            "MsMpEng",
            "SecurityHealthService",
            "Sense",
            NULL, NULL
        },
        {
            "MsMpEng.exe",
            "SecurityHealthService.exe",
            "Sense.exe",
            NULL, NULL
        },
        {
            "WdFilter",
            "wdboot",
            NULL, NULL, NULL
        },
        0.90f
    },
    {
        "Carbon Black (VMware)",
        {
            "SOFTWARE\\Carbon Black",
            "SOFTWARE\\VMware\\Carbon Black",
            NULL, NULL, NULL
        },
        {
            "CbDefense",
            "CbSensor",
            NULL, NULL, NULL
        },
        {
            "CbDefense.exe",
            "CbSensor.exe",
            NULL, NULL, NULL
        },
        {
            "CbDefense",
            "CbSensor",
            NULL, NULL, NULL
        },
        0.95f
    },
    {
        "Trend Micro Apex One",
        {
            "SOFTWARE\\TrendMicro",
            "SOFTWARE\\TrendMicro\\Apex One",
            NULL, NULL, NULL
        },
        {
            "TMBMSRV",
            "TmListen",
            NULL, NULL, NULL
        },
        {
            "TMBMSRV.exe",
            "TmListen.exe",
            NULL, NULL, NULL
        },
        {
            "TrendMicro",
            NULL, NULL, NULL, NULL
        },
        0.90f
    },
    {
        "Bitdefender GravityZone",
        {
            "SOFTWARE\\Bitdefender",
            NULL, NULL, NULL, NULL
        },
        {
            "bdagent",
            "vsserv",
            NULL, NULL, NULL
        },
        {
            "bdagent.exe",
            "vsserv.exe",
            NULL, NULL, NULL
        },
        {
            "bdagent",
            "vsserv",
            NULL, NULL, NULL
        },
        0.90f
    },
    {
        "Sophos Intercept X",
        {
            "SOFTWARE\\Sophos",
            NULL, NULL, NULL, NULL
        },
        {
            "Sophos Agent",
            "Sophos Service",
            NULL, NULL, NULL
        },
        {
            "SophosAgent.exe",
            "SophosService.exe",
            NULL, NULL, NULL
        },
        {
            "Sophos",
            NULL, NULL, NULL, NULL
        },
        0.90f
    },
    {
        "CylancePROTECT",
        {
            "SOFTWARE\\Cylance",
            NULL, NULL, NULL, NULL
        },
        {
            "CylanceSvc",
            NULL, NULL, NULL, NULL
        },
        {
            "CylanceSvc.exe",
            NULL, NULL, NULL, NULL
        },
        {
            "Cylance",
            NULL, NULL, NULL, NULL
        },
        0.90f
    },
    {
        "FireEye Endpoint Security",
        {
            "SOFTWARE\\FireEye",
            NULL, NULL, NULL, NULL
        },
        {
            "FireEyeAgent",
            NULL, NULL, NULL, NULL
        },
        {
            "FireEyeAgent.exe",
            NULL, NULL, NULL, NULL
        },
        {
            "FireEye",
            NULL, NULL, NULL, NULL
        },
        0.85f
    },
    {
        "Palo Alto Cortex XDR",
        {
            "SOFTWARE\\Palo Alto Networks",
            NULL, NULL, NULL, NULL
        },
        {
            "Cortex XDR Agent",
            NULL, NULL, NULL, NULL
        },
        {
            "CortexXDR.exe",
            NULL, NULL, NULL, NULL
        },
        {
            "CortexXDR",
            NULL, NULL, NULL, NULL
        },
        0.90f
    },
    {
        "Elastic Endpoint Security",
        {
            "SOFTWARE\\Elastic",
            NULL, NULL, NULL, NULL
        },
        {
            "Elastic Agent",
            NULL, NULL, NULL, NULL
        },
        {
            "ElasticAgent.exe",
            NULL, NULL, NULL, NULL
        },
        {
            "Elastic",
            NULL, NULL, NULL, NULL
        },
        0.85f
    },
    {
        "Cybereason",
        {
            "SOFTWARE\\Cybereason",
            NULL, NULL, NULL, NULL
        },
        {
            "Cybereason Agent",
            NULL, NULL, NULL, NULL
        },
        {
            "CybereasonAgent.exe",
            NULL, NULL, NULL, NULL
        },
        {
            "Cybereason",
            NULL, NULL, NULL, NULL
        },
        0.85f
    },
    {
        "Secureworks Taegis",
        {
            "SOFTWARE\\Secureworks",
            NULL, NULL, NULL, NULL
        },
        {
            "Taegis Agent",
            NULL, NULL, NULL, NULL
        },
        {
            "TaegisAgent.exe",
            NULL, NULL, NULL, NULL
        },
        {
            "Taegis",
            NULL, NULL, NULL, NULL
        },
        0.85f
    },
    {
        "F-Secure",
        {
            "SOFTWARE\\F-Secure",
            NULL, NULL, NULL, NULL
        },
        {
            "F-Secure",
            NULL, NULL, NULL, NULL
        },
        {
            "fsgk32.exe",
            "fssm32.exe",
            NULL, NULL, NULL
        },
        {
            "F-Secure",
            NULL, NULL, NULL, NULL
        },
        0.85f
    },
    {
        "Kaspersky Endpoint Detection",
        {
            "SOFTWARE\\KasperskyLab",
            NULL, NULL, NULL, NULL
        },
        {
            "Kaspersky",
            NULL, NULL, NULL, NULL
        },
        {
            "avp.exe",
            "klnagent.exe",
            NULL, NULL, NULL
        },
        {
            "Kaspersky",
            NULL, NULL, NULL, NULL
        },
        0.90f
    },
    {
        "Symantec Endpoint Protection",
        {
            "SOFTWARE\\Symantec",
            NULL, NULL, NULL, NULL
        },
        {
            "Symantec Endpoint Protection",
            NULL, NULL, NULL, NULL
        },
        {
            "Rtvscan.exe",
            "Smc.exe",
            NULL, NULL, NULL
        },
        {
            "Symantec",
            NULL, NULL, NULL, NULL
        },
        0.90f
    }
};

#define EDR_PATTERN_COUNT (sizeof(edr_patterns) / sizeof(edr_patterns[0]))

int detect_edr_products(edr_detection_result_t* results, int max_results) {
    if (!results || max_results <= 0) {
        return 0;
    }
    
    int detected_count = 0;
    
    // Detect each EDR product
    for (int i = 0; i < EDR_PATTERN_COUNT && detected_count < max_results; i++) {
        memset(&results[detected_count], 0, sizeof(edr_detection_result_t));
        
        const edr_pattern_t* pattern = &edr_patterns[i];
        strncpy(results[detected_count].edr_name, pattern->edr_name, sizeof(results[detected_count].edr_name) - 1);
        results[detected_count].confidence = pattern->confidence_base;
        
        // Try detection via registry
        bool detected = false;
        for (int j = 0; j < 5 && pattern->registry_keys[j] != NULL; j++) {
            HKEY hKey;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, pattern->registry_keys[j], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                results[detected_count].detected = true;
                results[detected_count].confidence = pattern->confidence_base;
                strcpy(results[detected_count].detection_method, "Registry");
                strncpy(results[detected_count].registry_path, pattern->registry_keys[j], sizeof(results[detected_count].registry_path) - 1);
                RegCloseKey(hKey);
                detected = true;
                break;
            }
        }
        
        // Try detection via services
        if (!detected) {
            SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
            if (hSCManager != NULL) {
                for (int j = 0; j < 5 && pattern->service_names[j] != NULL; j++) {
                    SC_HANDLE hService = OpenServiceA(hSCManager, pattern->service_names[j], SERVICE_QUERY_STATUS);
                    if (hService != NULL) {
                        results[detected_count].detected = true;
                        results[detected_count].confidence = pattern->confidence_base;
                        strcpy(results[detected_count].detection_method, "Service");
                        strncpy(results[detected_count].service_name, pattern->service_names[j], sizeof(results[detected_count].service_name) - 1);
                        CloseServiceHandle(hService);
                        detected = true;
                        break;
                    }
                }
                CloseServiceHandle(hSCManager);
            }
        }
        
        // Try detection via processes
        if (!detected) {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe32;
                pe32.dwSize = sizeof(PROCESSENTRY32);
                if (Process32First(hSnapshot, &pe32)) {
                    do {
                        for (int j = 0; j < 5 && pattern->process_names[j] != NULL; j++) {
                            if (_stricmp(pe32.szExeFile, pattern->process_names[j]) == 0) {
                                results[detected_count].detected = true;
                                results[detected_count].confidence = pattern->confidence_base;
                                strcpy(results[detected_count].detection_method, "Process");
                                strncpy(results[detected_count].process_name, pe32.szExeFile, sizeof(results[detected_count].process_name) - 1);
                                detected = true;
                                break;
                            }
                        }
                        if (detected) break;
                    } while (Process32Next(hSnapshot, &pe32));
                }
                CloseHandle(hSnapshot);
            }
        }
        
        if (detected) {
            detected_count++;
        }
    }
    
    return detected_count;
}

// Individual EDR detection functions (wrapper around detect_edr_products)
int detect_crowdstrike(edr_detection_result_t* result) {
    edr_detection_result_t results[1];
    int count = detect_edr_products(results, 1);
    if (count > 0 && strstr(results[0].edr_name, "CrowdStrike") != NULL) {
        *result = results[0];
        return 0;
    }
    return -1;
}

int detect_sentinelone(edr_detection_result_t* result) {
    edr_detection_result_t results[16];
    int count = detect_edr_products(results, 16);
    for (int i = 0; i < count; i++) {
        if (strstr(results[i].edr_name, "SentinelOne") != NULL) {
            *result = results[i];
            return 0;
        }
    }
    return -1;
}

int detect_defender_endpoint(edr_detection_result_t* result) {
    edr_detection_result_t results[16];
    int count = detect_edr_products(results, 16);
    for (int i = 0; i < count; i++) {
        if (strstr(results[i].edr_name, "Defender") != NULL) {
            *result = results[i];
            return 0;
        }
    }
    return -1;
}

int detect_carbon_black(edr_detection_result_t* result) {
    edr_detection_result_t results[16];
    int count = detect_edr_products(results, 16);
    for (int i = 0; i < count; i++) {
        if (strstr(results[i].edr_name, "Carbon Black") != NULL) {
            *result = results[i];
            return 0;
        }
    }
    return -1;
}

int detect_trend_micro(edr_detection_result_t* result) {
    edr_detection_result_t results[16];
    int count = detect_edr_products(results, 16);
    for (int i = 0; i < count; i++) {
        if (strstr(results[i].edr_name, "Trend Micro") != NULL) {
            *result = results[i];
            return 0;
        }
    }
    return -1;
}

int detect_bitdefender(edr_detection_result_t* result) {
    edr_detection_result_t results[16];
    int count = detect_edr_products(results, 16);
    for (int i = 0; i < count; i++) {
        if (strstr(results[i].edr_name, "Bitdefender") != NULL) {
            *result = results[i];
            return 0;
        }
    }
    return -1;
}

int detect_sophos(edr_detection_result_t* result) {
    edr_detection_result_t results[16];
    int count = detect_edr_products(results, 16);
    for (int i = 0; i < count; i++) {
        if (strstr(results[i].edr_name, "Sophos") != NULL) {
            *result = results[i];
            return 0;
        }
    }
    return -1;
}

int detect_cylance(edr_detection_result_t* result) {
    edr_detection_result_t results[16];
    int count = detect_edr_products(results, 16);
    for (int i = 0; i < count; i++) {
        if (strstr(results[i].edr_name, "Cylance") != NULL) {
            *result = results[i];
            return 0;
        }
    }
    return -1;
}

int detect_fireeye(edr_detection_result_t* result) {
    edr_detection_result_t results[16];
    int count = detect_edr_products(results, 16);
    for (int i = 0; i < count; i++) {
        if (strstr(results[i].edr_name, "FireEye") != NULL) {
            *result = results[i];
            return 0;
        }
    }
    return -1;
}

int detect_palo_alto(edr_detection_result_t* result) {
    edr_detection_result_t results[16];
    int count = detect_edr_products(results, 16);
    for (int i = 0; i < count; i++) {
        if (strstr(results[i].edr_name, "Palo Alto") != NULL) {
            *result = results[i];
            return 0;
        }
    }
    return -1;
}

int detect_elastic(edr_detection_result_t* result) {
    edr_detection_result_t results[16];
    int count = detect_edr_products(results, 16);
    for (int i = 0; i < count; i++) {
        if (strstr(results[i].edr_name, "Elastic") != NULL) {
            *result = results[i];
            return 0;
        }
    }
    return -1;
}

int detect_cybereason(edr_detection_result_t* result) {
    edr_detection_result_t results[16];
    int count = detect_edr_products(results, 16);
    for (int i = 0; i < count; i++) {
        if (strstr(results[i].edr_name, "Cybereason") != NULL) {
            *result = results[i];
            return 0;
        }
    }
    return -1;
}

int detect_secureworks(edr_detection_result_t* result) {
    edr_detection_result_t results[16];
    int count = detect_edr_products(results, 16);
    for (int i = 0; i < count; i++) {
        if (strstr(results[i].edr_name, "Secureworks") != NULL) {
            *result = results[i];
            return 0;
        }
    }
    return -1;
}

int detect_fsecure(edr_detection_result_t* result) {
    edr_detection_result_t results[16];
    int count = detect_edr_products(results, 16);
    for (int i = 0; i < count; i++) {
        if (strstr(results[i].edr_name, "F-Secure") != NULL) {
            *result = results[i];
            return 0;
        }
    }
    return -1;
}

int detect_kaspersky(edr_detection_result_t* result) {
    edr_detection_result_t results[16];
    int count = detect_edr_products(results, 16);
    for (int i = 0; i < count; i++) {
        if (strstr(results[i].edr_name, "Kaspersky") != NULL) {
            *result = results[i];
            return 0;
        }
    }
    return -1;
}

int detect_symantec(edr_detection_result_t* result) {
    edr_detection_result_t results[16];
    int count = detect_edr_products(results, 16);
    for (int i = 0; i < count; i++) {
        if (strstr(results[i].edr_name, "Symantec") != NULL) {
            *result = results[i];
            return 0;
        }
    }
    return -1;
}
