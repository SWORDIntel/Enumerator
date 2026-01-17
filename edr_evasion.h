#ifndef EDR_EVASION_H
#define EDR_EVASION_H

#include "edr_detection.h"
#include <windows.h>
#include <stdbool.h>

// Function prototypes for EDR evasion
int apply_edr_evasion_before_enumeration(const char* target_ip, edr_detection_result_t* edr_info, int edr_count);
int zero_edr_callbacks(edr_detection_result_t* edr_info, int edr_count);
int detach_edr_minifilters(edr_detection_result_t* edr_info, int edr_count);
int blind_etw_telemetry(void);
int use_direct_syscalls_for_enumeration(void);
int bypass_amsi_if_present(void);
int unhook_edr_api_hooks(void);

// Integration with W-SLAM EDR evasion toolkit
int integrate_w_slam_evasion(void);

#endif // EDR_EVASION_H
