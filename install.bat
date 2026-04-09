@echo off
title BugHunter Pro - Windows Installer
echo.
echo ============================================================
echo    BugHunter Pro - Windows CMD Installer
echo ============================================================
echo.

REM Check for PowerShell and delegate
where powershell >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [*] Launching PowerShell installer...
    powershell -ExecutionPolicy Bypass -File "%~dp0install.ps1"
) else (
    echo [*] PowerShell not found. Running basic install...
    echo.

    echo [*] Checking Python...
    python --version 2>nul
    if %ERRORLEVEL% NEQ 0 (
        echo [-] Python not found! Install from https://python.org
        pause
        exit /b 1
    )

    echo [*] Creating virtual environment...
    python -m venv "%USERPROFILE%\.bughunter_pro_venv"

    echo [*] Activating virtual environment...
    call "%USERPROFILE%\.bughunter_pro_venv\Scripts\activate.bat"

    echo [*] Upgrading pip...
    pip install --upgrade pip setuptools wheel -q

    echo [*] Installing BugHunter Pro...
    pip install -e .

    echo [*] Downloading SecLists...
    bughunter-install

    echo.
    echo ============================================================
    echo    Installation Complete!
    echo    Usage: bughunter -d example.com
    echo ============================================================
)

pause