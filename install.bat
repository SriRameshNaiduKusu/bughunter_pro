@echo off
title BugHunter Pro - Windows Installer
echo.
echo ===========================================================
echo    BugHunter Pro - Windows Installer
echo ===========================================================
echo.

REM Check for PowerShell and delegate
where powershell >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [*] Launching PowerShell installer...
    powershell -ExecutionPolicy Bypass -File "%~dp0install.ps1"
    goto :end
)

echo [*] PowerShell not found. Running basic install...
echo.

REM Find Python
set PYTHON_CMD=
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set PYTHON_CMD=python
    goto :found_python
)
where python3 >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set PYTHON_CMD=python3
    goto :found_python
)

echo [-] Python not found!
echo     Download from: https://python.org
echo     IMPORTANT: Check "Add Python to PATH" during install!
pause
exit /b 1

:found_python
echo [+] Found Python: %PYTHON_CMD%

REM Set paths
set VENV_DIR=%USERPROFILE%\.bughunter_pro_venv
set WRAPPER_DIR=%USERPROFILE%\.local\bin
set PROJECT_DIR=%~dp0

REM Create venv
echo [*] Creating virtual environment...
if exist "%VENV_DIR%" rmdir /s /q "%VENV_DIR%"
%PYTHON_CMD% -m venv "%VENV_DIR%"

REM Activate and install
echo [*] Installing BugHunter Pro...
call "%VENV_DIR%\Scripts\activate.bat"
pip install --upgrade pip setuptools wheel -q
cd /d "%PROJECT_DIR%"
pip install -e .

REM Create wrapper scripts
echo [*] Creating wrapper scripts...
if not exist "%WRAPPER_DIR%" mkdir "%WRAPPER_DIR%"

(
echo @echo off
echo call "%VENV_DIR%\Scripts\activate.bat"
echo python -m bughunter_pro %%*
) > "%WRAPPER_DIR%\bughunter.cmd"

(
echo @echo off
echo call "%VENV_DIR%\Scripts\activate.bat"
echo python -m streamlit run "%PROJECT_DIR%\dashboard\app.py" --server.headless=true --server.port=8501 --browser.gatherUsageStats=false --theme.base=dark %%*
) > "%WRAPPER_DIR%\bughunter-dashboard.cmd"

(
echo @echo off
echo call "%VENV_DIR%\Scripts\activate.bat"
echo python -c "from bughunter_pro.installer import main; main()" %%*
) > "%WRAPPER_DIR%\bughunter-install.cmd"

echo [+] Wrapper scripts created

REM Add to PATH
echo [*] Adding to PATH...
setx PATH "%WRAPPER_DIR%;%PATH%" >nul 2>&1
set PATH=%WRAPPER_DIR%;%PATH%

REM Download SecLists
echo [*] Downloading SecLists...
python -c "from bughunter_pro.installer import download_seclists; download_seclists()" 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [!] SecLists download failed. Run 'bughunter-install' later.
)

echo.
echo ===========================================================
echo    Installation Complete!
echo ===========================================================
echo.
echo    Usage:
echo      bughunter -d example.com
echo      bughunter -d example.com --full
echo      bughunter-dashboard
echo      bughunter --help
echo.
echo    RESTART your terminal for PATH changes.
echo.

:end
pause