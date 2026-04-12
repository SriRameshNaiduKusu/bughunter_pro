#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    BugHunter Pro - Windows Installer (FIXED)
.DESCRIPTION
    Installs BugHunter Pro with wrapper scripts on Windows
#>

$ErrorActionPreference = "Stop"

# Configuration
$VenvDir = Join-Path $env:USERPROFILE ".bughunter_pro_venv"
$WrapperDir = Join-Path $env:USERPROFILE ".local\bin"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ProjectDir) { $ProjectDir = Get-Location }

function Write-Banner {
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host "          BugHunter Pro - Windows Installer v1.0" -ForegroundColor Cyan
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step  { param($msg) Write-Host "[*] $msg" -ForegroundColor Blue }
function Write-Ok    { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "[-] $msg" -ForegroundColor Red }

function Find-Python {
    Write-Step "Checking Python installation..."

    $pythonCmd = $null
    foreach ($cmd in @("python", "python3", "py -3")) {
        try {
            $cmdParts = $cmd -split ' '
            $ver = & $cmdParts[0] @($cmdParts[1..($cmdParts.Length-1)]) --version 2>&1
            if ($ver -match "Python 3\.(\d+)") {
                $minor = [int]$Matches[1]
                if ($minor -ge 9) {
                    # For "py -3", we need to handle differently
                    if ($cmd -eq "py -3") {
                        $pythonCmd = "py"
                        $script:PythonArgs = @("-3")
                    } else {
                        $pythonCmd = $cmd
                        $script:PythonArgs = @()
                    }
                    Write-Ok "Found: $ver ($cmd)"
                    return $pythonCmd
                }
            }
        } catch { }
    }

    Write-Fail "Python 3.9+ not found!"
    Write-Warn "Download from: https://www.python.org/downloads/"
    Write-Warn "IMPORTANT: Check 'Add Python to PATH' during installation!"
    Read-Host "Press Enter to exit"
    exit 1
}

function New-VirtualEnvironment {
    param($PythonCmd)

    Write-Step "Creating virtual environment at $VenvDir..."

    if (Test-Path $VenvDir) {
        Write-Ok "Removing existing virtual environment..."
        Remove-Item -Recurse -Force $VenvDir
    }

    & $PythonCmd @script:PythonArgs -m venv $VenvDir

    if (-not (Test-Path (Join-Path $VenvDir "Scripts\activate.ps1"))) {
        Write-Fail "Failed to create virtual environment!"
        exit 1
    }

    # Activate
    & (Join-Path $VenvDir "Scripts\Activate.ps1")
    Write-Ok "Virtual environment created and activated"

    # Upgrade pip
    & pip install --upgrade pip setuptools wheel -q 2>$null
}

function Install-Package {
    Write-Step "Installing BugHunter Pro..."

    Push-Location $ProjectDir
    & pip install -e . 2>&1 | Select-Object -Last 3
    Pop-Location

    Write-Ok "BugHunter Pro installed"
}

function New-WrapperScripts {
    Write-Step "Creating wrapper scripts..."

    New-Item -ItemType Directory -Force -Path $WrapperDir | Out-Null

    # ---- bughunter.cmd ----
    $bughunterCmd = @"
@echo off
REM BugHunter Pro - Auto-generated wrapper
call "$VenvDir\Scripts\activate.bat"
python -m bughunter_pro %*
"@
    Set-Content -Path (Join-Path $WrapperDir "bughunter.cmd") -Value $bughunterCmd
    Write-Ok "Created: bughunter.cmd"

    # ---- bughunter.ps1 ----
    $bughunterPs1 = @"
# BugHunter Pro - Auto-generated wrapper
`$VenvActivate = Join-Path "$VenvDir" "Scripts\Activate.ps1"
if (Test-Path `$VenvActivate) {
    & `$VenvActivate
    python -m bughunter_pro @args
} else {
    Write-Error "BugHunter Pro venv not found. Reinstall required."
}
"@
    Set-Content -Path (Join-Path $WrapperDir "bughunter.ps1") -Value $bughunterPs1
    Write-Ok "Created: bughunter.ps1"

    # ---- bughunter-dashboard.cmd ----
    $dashboardCmd = @"
@echo off
REM BugHunter Pro Dashboard - Auto-generated wrapper
call "$VenvDir\Scripts\activate.bat"
echo.
echo BugHunter Pro Dashboard
echo ==================================================
echo   URL: http://localhost:8501
echo   Press Ctrl+C to stop
echo ==================================================
echo.
python -m streamlit run "$ProjectDir\dashboard\app.py" --server.headless=true --server.port=8501 --browser.gatherUsageStats=false --theme.base=dark %*
"@
    Set-Content -Path (Join-Path $WrapperDir "bughunter-dashboard.cmd") -Value $dashboardCmd
    Write-Ok "Created: bughunter-dashboard.cmd"

    # ---- bughunter-install.cmd ----
    $installCmd = @"
@echo off
call "$VenvDir\Scripts\activate.bat"
python -c "from bughunter_pro.installer import main; main()" %*
"@
    Set-Content -Path (Join-Path $WrapperDir "bughunter-install.cmd") -Value $installCmd
    Write-Ok "Created: bughunter-install.cmd"
}

function Add-ToSystemPath {
    Write-Step "Adding wrapper directory to user PATH..."

    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")

    if ($currentPath -notlike "*$WrapperDir*") {
        [Environment]::SetEnvironmentVariable(
            "Path",
            "$WrapperDir;$currentPath",
            "User"
        )
        Write-Ok "Added $WrapperDir to user PATH"

        # Also update current session
        $env:Path = "$WrapperDir;$env:Path"
        Write-Ok "Updated current session PATH"
    } else {
        Write-Ok "Already in PATH"
    }
}

function Install-SecLists {
    Write-Step "Downloading SecLists..."

    & (Join-Path $VenvDir "Scripts\Activate.ps1")

    try {
        python -c "from bughunter_pro.installer import download_seclists; download_seclists()"
        Write-Ok "SecLists downloaded"
    } catch {
        Write-Warn "SecLists download failed. Run 'bughunter-install' later."
        try {
            python -c "
from bughunter_pro.installer import generate_fallback_wordlists, WORDLIST_DIR, setup_logging
import pathlib
pathlib.Path(str(WORDLIST_DIR)).mkdir(parents=True, exist_ok=True)
generate_fallback_wordlists(setup_logging())
"
            Write-Ok "Fallback wordlists created"
        } catch { }
    }
}

function Test-Installation {
    Write-Step "Verifying installation..."

    $allOk = $true

    # Check wrapper
    $wrapperPath = Join-Path $WrapperDir "bughunter.cmd"
    if (Test-Path $wrapperPath) {
        Write-Ok "bughunter.cmd wrapper exists"
    } else {
        Write-Fail "bughunter.cmd not found"
        $allOk = $false
    }

    # Check venv
    if (Test-Path (Join-Path $VenvDir "Scripts\python.exe")) {
        Write-Ok "Virtual environment exists"
    } else {
        Write-Fail "Virtual environment not found"
        $allOk = $false
    }

    # Check import
    & (Join-Path $VenvDir "Scripts\Activate.ps1")
    try {
        python -c "import bughunter_pro; print('OK')" 2>$null | Out-Null
        Write-Ok "bughunter_pro package importable"
    } catch {
        Write-Fail "Package not importable"
        $allOk = $false
    }

    # Check command
    try {
        & (Join-Path $WrapperDir "bughunter.cmd") --help 2>$null | Out-Null
        Write-Ok "bughunter --help works"
    } catch {
        Write-Warn "bughunter --help returned error (may still work)"
    }

    if ($allOk) {
        Write-Ok "All checks passed!"
    } else {
        Write-Warn "Some checks failed. See above."
    }
}

function Show-TorWarning {
    Write-Host ""
    Write-Warn "============================================================"
    Write-Warn "  Tor auto-configuration is NOT supported on Windows."
    Write-Warn ""
    Write-Warn "  To use --tor flag on Windows:"
    Write-Warn "    1. Download Tor Expert Bundle:"
    Write-Warn "       https://www.torproject.org/download/tor/"
    Write-Warn "    2. Extract and run tor.exe before scanning"
    Write-Warn "    3. Then: bughunter -d target.com --tor"
    Write-Warn "============================================================"
}

# =================== MAIN ===================
Write-Banner

$python = Find-Python
New-VirtualEnvironment -PythonCmd $python
Install-Package
New-WrapperScripts
Add-ToSystemPath
Install-SecLists
Show-TorWarning
Test-Installation

Write-Host ""
Write-Host "===========================================================" -ForegroundColor Green
Write-Host "           Installation Complete!" -ForegroundColor Green
Write-Host "===========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Quick Start:" -ForegroundColor White
Write-Host ""
Write-Host "    bughunter -d example.com" -ForegroundColor Cyan
Write-Host "    bughunter -d example.com --full" -ForegroundColor Cyan
Write-Host "    bughunter-dashboard" -ForegroundColor Cyan
Write-Host "    bughunter --help" -ForegroundColor Cyan
Write-Host ""
Write-Host "  NOTE: You may need to RESTART your terminal" -ForegroundColor Yellow
Write-Host "  for the PATH changes to take effect." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Installation paths:" -ForegroundColor White
Write-Host "    Venv:     $VenvDir"
Write-Host "    Wrappers: $WrapperDir"
Write-Host "    Project:  $ProjectDir"
Write-Host ""

Read-Host "Press Enter to exit"