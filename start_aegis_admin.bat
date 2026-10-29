@echo off
setlocal
title Aegis AI Security Command Center
cd /d "%~dp0."

echo =====================================================================
echo   AEGIS AI SECURITY PLATFORM -- COMMAND CENTER
echo =====================================================================
echo.

:: Check for Administrator privileges
net session >nul 2>&1
if %errorlevel% equ 0 (
    echo  [*] Administrator Privileges: ACTIVE
    echo  [*] Host Firewall Blocking:    ACTIVE
    echo  [*] Machine Process Control:   ACTIVE
) else (
    echo  [!] Running under standard user privileges.
    echo  [*] For full automatic Windows Firewall ^& process mutation:
    echo      Right-click this file -^> "Run as administrator"
)
echo.
echo  [*] Starting Aegis AI on http://localhost:8000 ...
echo =====================================================================
echo.

python -m uvicorn server:app --host 0.0.0.0 --port 8000
pause
