@echo off
setlocal EnableExtensions
REM Production launcher for the thin Aegis host collector.
REM   scripts\aegis-agent.bat enroll --url https://CONSOLE:8000 --token TOKEN [--ca C:\path\ca.crt]
REM   scripts\aegis-agent.bat heartbeat
REM   scripts\aegis-agent.bat run
REM   scripts\aegis-agent.bat install
REM   scripts\aegis-agent.bat uninstall
REM   scripts\aegis-agent.bat start
REM   scripts\aegis-agent.bat stop
REM install registers a Windows Scheduled Task that runs the agent at startup.
REM For a real Windows service, copy scripts\aegis-agent.winsw.xml next to WinSW
REM renamed aegis-agent.exe and run: aegis-agent.exe install
REM Enroll first; the task/service only keeps an already-enrolled agent alive.

cd /d "%~dp0\.."
set "ROOT=%CD%"
set "PYTHONPATH=%ROOT%;%PYTHONPATH%"
set "PYTHONUNBUFFERED=1"
set "TASK_NAME=Aegis Host Agent"

set "PY="
where python >nul 2>&1 && set "PY=python"
if not defined PY (
  where py >nul 2>&1 && set "PY=py -3"
)
if not defined PY (
  echo Python 3.10+ is required on PATH.
  exit /b 1
)

if /I "%~1"=="" goto :help
if /I "%~1"=="-h" goto :help
if /I "%~1"=="--help" goto :help
if /I "%~1"=="help" goto :help
if /I "%~1"=="install" goto :install
if /I "%~1"=="uninstall" goto :uninstall
if /I "%~1"=="start" goto :start
if /I "%~1"=="stop" goto :stop
if /I "%~1"=="status" goto :status

%PY% -m aegis.agent %*
exit /b %ERRORLEVEL%

:help
echo Aegis host agent
echo   enroll --url URL --token TOKEN [--ca PATH]
echo   heartbeat
echo   run
echo   install ^| uninstall ^| start ^| stop ^| status
echo Enroll first, then install so the agent stays running.
exit /b 0

:install
set "TR=%PY% -m aegis.agent run"
schtasks /Create /TN "%TASK_NAME%" /TR "cmd /c cd /d \"%ROOT%\" && set PYTHONPATH=%ROOT%&& set PYTHONUNBUFFERED=1&& %TR%" /SC ONSTART /RL LIMITED /F
if errorlevel 1 (
  echo Could not create scheduled task "%TASK_NAME%".
  echo Run this from an elevated prompt, or install WinSW with scripts\aegis-agent.winsw.xml.
  exit /b 1
)
echo Installed scheduled task "%TASK_NAME%" ^(ONSTART^).
echo Enroll first if you have not: scripts\aegis-agent.bat enroll --url URL --token TOKEN
echo Start now with: scripts\aegis-agent.bat start
exit /b 0

:uninstall
schtasks /Delete /TN "%TASK_NAME%" /F
if errorlevel 1 (
  echo Could not remove scheduled task "%TASK_NAME%".
  exit /b 1
)
echo Removed scheduled task "%TASK_NAME%".
exit /b 0

:start
schtasks /Run /TN "%TASK_NAME%"
if errorlevel 1 (
  echo Task is not installed. Run scripts\aegis-agent.bat install
  exit /b 1
)
echo Started "%TASK_NAME%".
exit /b 0

:stop
schtasks /End /TN "%TASK_NAME%"
if errorlevel 1 (
  echo Could not stop "%TASK_NAME%". It may not be running.
  exit /b 1
)
echo Stopped "%TASK_NAME%".
exit /b 0

:status
schtasks /Query /TN "%TASK_NAME%" /V /FO LIST
exit /b %ERRORLEVEL%
