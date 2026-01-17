#ifndef MDM_DETECTION_H
#define MDM_DETECTION_H

#include <windows.h>
#include <stdbool.h>

// MDM detection result structure
typedef struct {
    char mdm_name[256];
    bool detected;
    char detection_method[256];
    char callback_address[64];
    bool callback_zeroed;
    char driver_name[256];
    bool driver_detached;
    char service_name[256];
    char process_name[256];
    char registry_path[512];
} mdm_detection_result_t;

// Function prototypes
int detect_mdm_software(mdm_detection_result_t* results, int max_results);
int detect_mdm_via_registry(mdm_detection_result_t* results, int max_results);
int detect_mdm_via_services(mdm_detection_result_t* results, int max_results);
int detect_mdm_via_processes(mdm_detection_result_t* results, int max_results);
int detect_mdm_via_drivers(mdm_detection_result_t* results, int max_results);

#endif // MDM_DETECTION_H
