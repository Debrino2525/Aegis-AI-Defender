@echo off
REM Thin host collector. Enroll with a one-time token, then heartbeat.
REM Usage:
REM   scripts\aegis-agent.bat enroll --url http://CONSOLE:8000 --token TOKEN
REM   scripts\aegis-agent.bat run
cd /d "%~dp0\.."
python -m aegis.agent %*
