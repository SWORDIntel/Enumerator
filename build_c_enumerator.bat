@echo off
REM Build script for C Enumerator (Windows Batch)
REM Requires MinGW or MSVC

setlocal

cd /d "%~dp0c_enumerator"

echo === Building C Enumerator ===
echo.

REM Check for MinGW
where gcc >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [+] Found GCC compiler
    goto :build
)

REM Check for MSVC
where cl >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [+] Found MSVC compiler
    echo [!] Note: This script uses Makefile which expects GCC
    echo [!] For MSVC, use Visual Studio or modify Makefile
    goto :build
)

echo ERROR: No compiler found
echo Please install MinGW or MSVC
exit /b 1

:build
echo [*] Cleaning previous build...
make clean 2>nul

echo [*] Building enumerator.exe...
make

if exist "enumerator.exe" (
    echo.
    echo [+] Build successful!
    echo [+] Executable: %CD%\enumerator.exe
    echo.
    echo To run:
    echo   cd c_enumerator
    echo   enumerator.exe
) else (
    echo.
    echo ERROR: Build failed - enumerator.exe not found
    exit /b 1
)

endlocal
