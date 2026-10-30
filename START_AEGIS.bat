@echo off
title Aegis Enterprise Vulnerability Scanner
echo.
echo  ██████  AEGIS ENTERPRISE PLATFORM  ██████
echo  Starting server at http://127.0.0.1:8000
echo  Binds to 127.0.0.1 unless AEGIS_HOST is set in the environment or .env
echo.
cd /d "%~dp0"
python server.py
pause
