@echo off
setlocal
title LocalShield Launcher

echo ========================================
echo    LocalShield - Starting...
echo ========================================
echo.

:: 1. Set working directory
cd /d "%~dp0"
set "ROOT_DIR=%cd%"
echo [0/4] Working directory: %ROOT_DIR%
echo.

:: 2. Virtual environment check and creation
if exist "venv\Scripts\activate.bat" (
    echo [1/4] Virtual environment found, activating...
    call venv\Scripts\activate.bat
) else (
    echo [1/4] Virtual environment not found, creating...
    python -m venv venv
    if errorlevel 1 (
        echo ERROR: Could not create virtual environment!
        pause
        exit /b 1
    )
    call venv\Scripts\activate.bat
)

:: 3. Install dependencies (always)
echo [2/4] Checking and installing dependencies...
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo WARNING: Some dependencies could not be installed, retrying...
    pip install -r requirements.txt
)
echo Dependencies ready.
echo.

:: 4. Start Log Watcher in New Window (With Administrator Privileges)
:: Note: Log Watcher requires administrator privileges to read Windows Event Log
echo [3/4] Starting Log Watcher in background (Administrator privileges required)...
echo WARNING: Log Watcher requires administrator privileges. UAC window may open.

:: Create temporary batch file (to be run with administrator privileges)
set "TEMP_BATCH=%TEMP%\localshield_logwatcher_%RANDOM%.bat"
(
    echo @echo off
    echo cd /d "%ROOT_DIR%"
    echo call venv\Scripts\activate.bat
    echo pip install -r requirements.txt --quiet
    echo python log_watcher.py
    echo if errorlevel 1 pause
    echo del "%%~f0" ^>nul 2^>^&1
) > "%TEMP_BATCH%"

:: Start with administrator privileges using PowerShell
powershell -Command "Start-Process cmd -ArgumentList '/k \"%TEMP_BATCH%\"' -Verb RunAs"

:: Short wait (to avoid database lock)
timeout /t 3 /nobreak >nul

:: 5. Start Dashboard
echo [4/4] Starting Dashboard...
echo.
echo ========================================
echo    LocalShield Ready!
echo ========================================
echo.

call venv\Scripts\activate.bat
streamlit run dashboard.py

endlocal
