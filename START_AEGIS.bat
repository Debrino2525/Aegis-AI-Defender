@echo off
title Aegis Enterprise Vulnerability Scanner
echo.
echo  ██████  AEGIS ENTERPRISE PLATFORM  ██████
echo  Starting server at http://localhost:8000
echo.
cd /d "%~dp0"
python -m uvicorn server:app --host 0.0.0.0 --port 8000
pause
