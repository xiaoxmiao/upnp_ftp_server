@echo off
setlocal enabledelayedexpansion

set "PYTHON_DIR=%TEMP%\python_portable"
set "PYTHON_ZIP=%TEMP%\python_portable\python.zip"
set "PYTHON_EXE=%PYTHON_DIR%\python\python.exe"
set "SCRIPT=%~dp0ftp_server.py"
set "CONFIG=%~dp0config.json"

if not exist "%CONFIG%" (
    echo [ERROR] config.json not found!
    echo Copy config.example.json to config.json and edit it before starting.
    pause
    exit /b 1
)

if not exist "%PYTHON_EXE%" (
    echo Downloading embedded Python...
    if not exist "%PYTHON_DIR%" mkdir "%PYTHON_DIR%"
    powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.0/python-3.12.0-embed-amd64.zip' -OutFile '%PYTHON_ZIP%' -UseBasicParsing"
    powershell -Command "Expand-Archive -Path '%PYTHON_ZIP%' -DestinationPath '%PYTHON_DIR%\python' -Force"
)

if not exist "%PYTHON_DIR%\python\Lib\site-packages\pyftpdlib" (
    echo Installing pyftpdlib...
    powershell -Command "Set-Content -Path '%PYTHON_DIR%\python\python312._pth' -Value 'python312.zip', '.', 'import site'"
    "%PYTHON_EXE%" -m pip install pyftpdlib pyasynchat pyasyncore -q
)

echo Starting FTP Server...
"%PYTHON_EXE%" "%SCRIPT%"

pause
