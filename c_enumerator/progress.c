#include "progress.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

bool init_progress_bar(progress_bar_t* pb) {
    pb->console_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (pb->console_handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    pb->current_percentage = 0;
    pb->current_operation[0] = '\0';
    pb->initialized = true;
    
    // Set console text color to green for progress
    SetConsoleTextAttribute(pb->console_handle, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n[ENUMERATOR] Starting enumeration...\n");
    SetConsoleTextAttribute(pb->console_handle, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    
    return true;
}

void update_progress(progress_bar_t* pb, int percentage, const char* operation) {
    if (!pb->initialized) {
        return;
    }
    
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    COORD cursorPos;
    
    // Get current cursor position
    GetConsoleScreenBufferInfo(pb->console_handle, &csbi);
    cursorPos = csbi.dwCursorPosition;
    
    // Move cursor to beginning of line
    cursorPos.X = 0;
    SetConsoleCursorPosition(pb->console_handle, cursorPos);
    
    // Clear the line
    DWORD written;
    FillConsoleOutputCharacter(pb->console_handle, ' ', csbi.dwSize.X, cursorPos, &written);
    SetConsoleCursorPosition(pb->console_handle, cursorPos);
    
    // Update percentage
    pb->current_percentage = percentage;
    if (operation) {
        strncpy(pb->current_operation, operation, sizeof(pb->current_operation) - 1);
        pb->current_operation[sizeof(pb->current_operation) - 1] = '\0';
    }
    
    // Draw progress bar
    int barWidth = 50;
    int filled = (percentage * barWidth) / 100;
    
    // Color coding
    WORD color;
    if (percentage < 30) {
        color = FOREGROUND_RED | FOREGROUND_INTENSITY;
    } else if (percentage < 70) {
        color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    } else {
        color = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    }
    
    SetConsoleTextAttribute(pb->console_handle, color);
    printf("[");
    
    // Draw filled portion
    for (int i = 0; i < filled; i++) {
        printf("=");
    }
    
    // Draw empty portion
    for (int i = filled; i < barWidth; i++) {
        printf(" ");
    }
    
    printf("] %3d%%", percentage);
    
    // Reset color
    SetConsoleTextAttribute(pb->console_handle, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    
    if (operation && strlen(operation) > 0) {
        printf(" - %s", operation);
    }
    
    // Clear rest of line
    int remaining = csbi.dwSize.X - (barWidth + 10 + strlen(operation));
    for (int i = 0; i < remaining; i++) {
        printf(" ");
    }
    
    fflush(stdout);
}

void finish_progress_bar(progress_bar_t* pb) {
    if (!pb->initialized) {
        return;
    }
    
    update_progress(pb, 100, "Complete");
    printf("\n");
    
    SetConsoleTextAttribute(pb->console_handle, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("[ENUMERATOR] Enumeration complete!\n");
    SetConsoleTextAttribute(pb->console_handle, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

void cleanup_progress_bar(progress_bar_t* pb) {
    if (pb->initialized) {
        pb->initialized = false;
    }
}
