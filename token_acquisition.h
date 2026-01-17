#ifndef TOKEN_ACQUISITION_H
#define TOKEN_ACQUISITION_H

#include <windows.h>
#include <stdbool.h>
#include "enumerator.h"

// Token acquisition methods
bool acquire_token_via_pe5_method(token_result_t* result);
bool acquire_token_via_windows_api(token_result_t* result);
bool acquire_token_via_service_stealing(token_result_t* result);
bool acquire_token_via_scheduled_task(token_result_t* result);

// Token information extraction
void extract_token_info(HANDLE token, token_result_t* result);
void log_token_details(token_result_t* result, char* buffer, size_t buffer_size);

#endif // TOKEN_ACQUISITION_H
