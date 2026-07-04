@echo off
setlocal enabledelayedexpansion

set "EXE=%~dp0dist\ftp_server.exe"
set "CONFIG=%~dp0config.json"
set "SERVICE_NAME=FtpServer"
set "SERVICE_DISPLAY=FTP Server"

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

:: Auto-elevate to admin if not already
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
echo.
echo Examples:
echo   %0 install
echo   %0 run
pause
exit /b 0

:install
echo Installing service...
sc create "%SERVICE_NAME%" binPath= "\"%EXE%\"" start= auto displayName= "%SERVICE_DISPLAY%"
sc description "%SERVICE_NAME%" "Custom FTP Server with Windows authentication"
sc failure "%SERVICE_NAME%" reset= 86400 actions= restart/10000
echo.
echo Service installed: %SERVICE_NAME%
echo Start it with: %0 start
pause
exit /b 0

:remove
echo Stopping service if running...
net stop "%SERVICE_NAME%" >nul 2>&1
sc delete "%SERVICE_NAME%"
echo Service removed.
pause
exit /b 0

:start
net start "%SERVICE_NAME%"
pause
exit /b %errorlevel%

:stop
net stop "%SERVICE_NAME%"
pause
exit /b %errorlevel%

:restart
net stop "%SERVICE_NAME%" >nul 2>&1
net start "%SERVICE_NAME%"
pause
exit /b %errorlevel%

:run
echo Starting FTP Server in console mode...
echo Config: %CONFIG%
"%EXE%"
pause
exit /b %errorlevel%
