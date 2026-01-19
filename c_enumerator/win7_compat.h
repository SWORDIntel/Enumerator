#ifndef WIN7_COMPAT_H
#define WIN7_COMPAT_H

// Windows 7 compatibility defines
// Windows 7 is Windows NT 6.1
#ifndef WINVER
#define WINVER 0x0601
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x06010000
#endif

// snprintf compatibility for MSVC on Windows 7
// MSVC doesn't have snprintf until VS 2015, use _snprintf with null termination
#ifdef _MSC_VER
#if _MSC_VER < 1900
#include <stdio.h>
#include <string.h>
// Use inline function instead of macro to avoid issues with complex expressions
static inline int win7_snprintf(char* dest, size_t size, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = _vsnprintf(dest, size, format, args);
    va_end(args);
    if (ret < 0 || ret >= (int)size) {
        dest[size - 1] = '\0';
        ret = (int)size - 1;
    }
    return ret;
}
#define snprintf win7_snprintf
#endif
#endif

// vsnprintf compatibility for MSVC
#ifdef _MSC_VER
#if _MSC_VER < 1900
#include <stdarg.h>
static inline int win7_vsnprintf(char* dest, size_t size, const char* format, va_list args) {
    int ret = _vsnprintf(dest, size, format, args);
    if (ret < 0 || ret >= (int)size) {
        dest[size - 1] = '\0';
        ret = (int)size - 1;
    }
    return ret;
}
#define vsnprintf win7_vsnprintf
#endif
#endif

#endif // WIN7_COMPAT_H
