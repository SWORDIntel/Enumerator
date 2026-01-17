#ifndef EDR_DETECTION_H
#define EDR_DETECTION_H

#include <windows.h>
#include <stdbool.h>

// EDR detection result structure
typedef struct {
    char edr_name[256];
    bool detected;
    float confidence;
    char detection_method[256];
    char version[64];
    bool has_kernel_driver;
    char driver_name[256];
    char service_name[256];
    char process_name[256];
    char registry_path[512];
} edr_detection_result_t;

// Function prototypes
int detect_edr_products(edr_detection_result_t* results, int max_results);
int detect_crowdstrike(edr_detection_result_t* result);
int detect_sentinelone(edr_detection_result_t* result);
int detect_defender_endpoint(edr_detection_result_t* result);
int detect_carbon_black(edr_detection_result_t* result);
int detect_trend_micro(edr_detection_result_t* result);
int detect_bitdefender(edr_detection_result_t* result);
int detect_sophos(edr_detection_result_t* result);
int detect_cylance(edr_detection_result_t* result);
int detect_fireeye(edr_detection_result_t* result);
int detect_palo_alto(edr_detection_result_t* result);
int detect_elastic(edr_detection_result_t* result);
int detect_cybereason(edr_detection_result_t* result);
int detect_secureworks(edr_detection_result_t* result);
int detect_fsecure(edr_detection_result_t* result);
int detect_kaspersky(edr_detection_result_t* result);
int detect_symantec(edr_detection_result_t* result);

#endif // EDR_DETECTION_H
