#ifndef PROGRESS_H
#define PROGRESS_H

#include <windows.h>
#include <stdbool.h>

// Progress bar structure
typedef struct {
    HANDLE console_handle;
    int current_percentage;
    char current_operation[256];
    bool initialized;
} progress_bar_t;

// Function prototypes
bool init_progress_bar(progress_bar_t* pb);
void update_progress(progress_bar_t* pb, int percentage, const char* operation);
void finish_progress_bar(progress_bar_t* pb);
void cleanup_progress_bar(progress_bar_t* pb);

#endif // PROGRESS_H
