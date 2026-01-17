@echo off
REM Build script for Windows System Enumerator
REM Supports MinGW and MSVC

echo [ENUMERATOR] Building Windows System Enumerator...

REM Check for MinGW
where gcc >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo [ENUMERATOR] Using MinGW compiler...
    gcc -Wall -Wextra -std=c99 -O2 enumerator.c token_acquisition.c progress.c pastebin.c -o enumerator.exe -lws2_32 -liphlpapi -ladvapi32 -lole32 -loleaut32 -lwbemuuid -lwininet
    if %ERRORLEVEL% == 0 (
        echo [ENUMERATOR] Build successful! Output: enumerator.exe
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
    cl /W4 /O2 /Fe:enumerator.exe enumerator.c token_acquisition.c progress.c pastebin.c ws2_32.lib iphlpapi.lib advapi32.lib ole32.lib oleaut32.lib wbemuuid.lib wininet.lib
    if %ERRORLEVEL% == 0 (
        echo [ENUMERATOR] Build successful! Output: enumerator.exe
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
