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

:check_admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Some commands require Administrator privileges.
    echo.
)

if /i "%1"=="install" goto :install
if /i "%1"=="remove" goto :remove
if /i "%1"=="start" goto :start
if /i "%1"=="stop" goto :stop
if /i "%1"=="restart" goto :restart
if /i "%1"=="run" goto :run
if /i "%1"=="debug" goto :debug

echo Usage: %0 ^<command^>
echo.
echo Commands:
echo   install          Install as Windows service
echo   remove           Remove Windows service
echo   start            Start the service
echo   stop             Stop the service
echo   restart          Restart the service
echo   run              Run in console mode (foreground)
echo   debug            Run in debug mode (service simulation)
echo.
echo Examples:
echo   %0 install       (requires Administrator)
echo   %0 run
pause
exit /b 0

:install
echo Installing service...
"%EXE%" install
if %errorlevel% equ 0 (
    echo Service installed successfully.
    echo Run "%0 start" to start the service.
) else (
    echo Failed to install service. Try running as Administrator.
)
pause
exit /b %errorlevel%

:remove
echo Removing service...
"%EXE%" remove
pause
exit /b %errorlevel%

:start
net start FtpServer
pause
exit /b %errorlevel%

:stop
net stop FtpServer
pause
exit /b %errorlevel%

:restart
net stop FtpServer >nul 2>&1
net start FtpServer
pause
exit /b %ERRORLEVEL%

:run
echo Starting FTP Server in console mode...
"%EXE%"
pause
exit /b %ERRORLEVEL%

:debug
"%EXE%" debug
pause
exit /b %ERRORLEVEL%
