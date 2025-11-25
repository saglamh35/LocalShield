@echo off
setlocal
title LocalShield Launcher

echo ========================================
echo    LocalShield - Baslatiliyor...
echo ========================================
echo.

:: 1. Calisma dizinini sabitle
cd /d "%~dp0"
set "ROOT_DIR=%cd%"
echo [0/4] Calisma dizini: %ROOT_DIR%
echo.

:: 2. Sanal ortam kontrolu ve olusturma
if exist "venv\Scripts\activate.bat" (
    echo [1/4] Sanal ortam bulundu, aktif ediliyor...
    call venv\Scripts\activate.bat
) else (
    echo [1/4] Sanal ortam bulunamadi, olusturuluyor...
    python -m venv venv
    if errorlevel 1 (
        echo HATA: Sanal ortam olusturulamadi!
        pause
        exit /b 1
    )
    call venv\Scripts\activate.bat
)

:: 3. Bagimliliklari yukle (her zaman)
echo [2/4] Bagimliliklar kontrol ediliyor ve yukleniyor...
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo UYARI: Bazı bagimliliklar yuklenemedi, tekrar deneniyor...
    pip install -r requirements.txt
)
echo Bagimliliklar hazir.
echo.

:: 4. Log Watcher'i Yeni Pencerede Baslat (Yonetici Haklariyla)
:: Duzeltme: Log Watcher Windows Event Log okumak icin yonetici haklari gerektirir
echo [3/4] Log Watcher arka planda baslatiliyor (Yonetici haklari gerekli)...
echo UYARI: Log Watcher icin yonetici haklari gerekiyor. UAC penceresi acilabilir.

:: Gecici batch dosyasi olustur (yonetici haklariyla calistirilmak icin)
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

:: PowerShell ile yonetici haklariyla baslat
powershell -Command "Start-Process cmd -ArgumentList '/k \"%TEMP_BATCH%\"' -Verb RunAs"

:: Kisa bekleme (Database kilidi olusmamasi icin)
timeout /t 3 /nobreak >nul

:: 5. Dashboard'u Baslat
echo [4/4] Dashboard baslatiliyor...
echo.
echo ========================================
echo    LocalShield Hazir!
echo ========================================
echo.

call venv\Scripts\activate.bat
streamlit run dashboard.py

endlocal
