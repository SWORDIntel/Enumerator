#ifndef PASTEBIN_H
#define PASTEBIN_H

#include <stdbool.h>
#include <stddef.h>

// Paste service types
typedef enum {
    PASTE_PASTEBIN,
    PASTE_HASTEBIN,
    PASTE_0X0ST,
    PASTE_FILEIO,
    PASTE_NONE
} paste_service_t;

// Upload result
typedef struct {
    bool success;
    paste_service_t service_used;
    char url[512];
    char error_message[256];
} upload_result_t;

// Function prototypes
bool test_pastebin_api(void);
upload_result_t upload_to_pastebin(const char* data, size_t data_len, const char* password);
upload_result_t upload_to_hastebin(const char* data, size_t data_len);
upload_result_t upload_to_0x0st(const char* data, size_t data_len);
upload_result_t upload_to_fileio(const char* data, size_t data_len);

#endif // PASTEBIN_H
