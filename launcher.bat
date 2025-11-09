@echo off
REM Forensic Engine Launcher - Batch Wrapper
REM This wrapper makes it easy to run the PowerShell launcher

echo.
echo ═══════════════════════════════════════════════════════
echo    Forensic Engine Launcher - Starting...
echo ═══════════════════════════════════════════════════════
echo.

REM Check if PowerShell is available
where powershell >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: PowerShell not found!
    echo Please ensure Windows PowerShell is installed.
    pause
    exit /b 1
)

REM Run the PowerShell script
powershell -ExecutionPolicy Bypass -File "%~dp0launcher.ps1"

REM Check if there was an error
if %errorlevel% neq 0 (
    echo.
    echo ERROR: Script execution failed with error code %errorlevel%
    pause
)

exit /b 0
