@echo off
setlocal enabledelayedexpansion

set "EXE=%~dp0dist\ftp_server.exe"
set "CONFIG=%~dp0config.json"

if not exist "%EXE%" (
    echo [ERROR] ftp_server.exe not found in dist\ folder.
    pause
    exit /b 1
)
if not exist "%CONFIG%" (
    echo [ERROR] config.json not found!
    echo Copy config.example.json to config.json and edit it before starting.
    pause
    exit /b 1
)

:: Auto-elevate to admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -ArgumentList '%*' -Verb RunAs -Wait"
    exit /b 0
)

if /i "%1"=="install" goto :install
if /i "%1"=="remove" goto :remove
if /i "%1"=="start" goto :start
if /i "%1"=="stop" goto :stop
if /i "%1"=="restart" goto :restart
if /i "%1"=="run" goto :run

echo Usage: %0 ^<command^>
echo.
echo Commands:
echo   install          Install as Windows service (auto-start)
echo   remove           Remove Windows service
echo   start            Start the service
echo   stop             Stop the service
echo   restart          Restart the service
echo   run              Run in console mode
pause
exit /b 0

:install
echo Installing service...
"%EXE%" install
echo.
echo Done.
pause
exit /b 0

:remove
echo Removing service...
"%EXE%" remove
pause
exit /b 0

:start
"%EXE%" start
pause
exit /b %errorlevel%

:stop
"%EXE%" stop
pause
exit /b %errorlevel%

:restart
"%EXE%" restart
pause
exit /b %errorlevel%

:run
"%EXE%" run
pause
exit /b %errorlevel%
