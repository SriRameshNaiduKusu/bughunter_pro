#Requires -RunAsAdministrator
<#
.SYNOPSIS
    BugHunter Pro - Windows Installer
.DESCRIPTION
    Installs BugHunter Pro with all dependencies on Windows
#>

$ErrorActionPreference = "Stop"

function Write-Banner {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║          BugHunter Pro - Windows Installer v1.0          ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step  { param($msg) Write-Host "[*] $msg" -ForegroundColor Blue }
function Write-Ok    { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "[-] $msg" -ForegroundColor Red }

function Test-PythonInstalled {
    Write-Step "Checking Python installation..."

    $pythonCmd = $null
    foreach ($cmd in @("python", "python3", "py")) {
        try {
            $ver = & $cmd --version 2>&1
            if ($ver -match "Python 3\.(\d+)") {
                $minor = [int]$Matches[1]
                if ($minor -ge 9) {
                    $pythonCmd = $cmd
                    Write-Ok "Found: $ver ($cmd)"
                    break
                }
            }
        } catch { }
    }

    if (-not $pythonCmd) {
        Write-Fail "Python 3.9+ not found!"
        Write-Warn "Download from: https://www.python.org/downloads/"
        Write-Warn "IMPORTANT: Check 'Add Python to PATH' during installation!"
        Read-Host "Press Enter to exit"
        exit 1
    }

    return $pythonCmd
}

function Test-GitInstalled {
    Write-Step "Checking Git installation..."

    try {
        $gitVer = & git --version 2>&1
        Write-Ok "Found: $gitVer"
        return $true
    } catch {
        Write-Warn "Git not found. SecLists will be downloaded as ZIP."
        Write-Warn "Install Git from: https://git-scm.com/download/win"
        return $false
    }
}

function Install-VirtualEnv {
    param($PythonCmd)

    Write-Step "Creating virtual environment..."

    $venvPath = Join-Path $env:USERPROFILE ".bughunter_pro_venv"

    if (-not (Test-Path $venvPath)) {
        & $PythonCmd -m venv $venvPath
        Write-Ok "Virtual environment created at $venvPath"
    } else {
        Write-Ok "Virtual environment already exists"
    }

    # Activate
    $activateScript = Join-Path $venvPath "Scripts\Activate.ps1"
    if (Test-Path $activateScript) {
        & $activateScript
        Write-Ok "Virtual environment activated"
    } else {
        Write-Fail "Could not activate virtual environment"
        exit 1
    }

    # Upgrade pip
    & pip install --upgrade pip setuptools wheel -q

    return $venvPath
}

function Install-Package {
    Write-Step "Installing BugHunter Pro..."

    $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
    if (-not $scriptDir) { $scriptDir = Get-Location }

    Push-Location $scriptDir
    & pip install -e ".[dev]" 2>&1 | Select-Object -Last 5
    Pop-Location

    Write-Ok "BugHunter Pro installed"
}

function Install-SecLists {
    Write-Step "Downloading SecLists..."

    try {
        & bughunter-install
        Write-Ok "SecLists downloaded"
    } catch {
        Write-Warn "SecLists download failed. Run 'bughunter-install' manually."
    }
}

function Add-ToPath {
    param($VenvPath)

    Write-Step "Adding to system PATH..."

    $binPath = Join-Path $VenvPath "Scripts"
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")

    if ($currentPath -notlike "*$binPath*") {
        [Environment]::SetEnvironmentVariable(
            "Path",
            "$currentPath;$binPath",
            "User"
        )
        Write-Ok "Added $binPath to user PATH"
    } else {
        Write-Ok "Already in PATH"
    }
}

function Show-TorWarning {
    Write-Host ""
    Write-Warn "═══════════════════════════════════════════════════════"
    Write-Warn "  Tor is NOT auto-configured on Windows."
    Write-Warn "  Anonymous scanning (--tor) will be skipped."
    Write-Warn ""
    Write-Warn "  To use Tor on Windows:"
    Write-Warn "    1. Download Tor Expert Bundle from:"
    Write-Warn "       https://www.torproject.org/download/tor/"
    Write-Warn "    2. Extract and run tor.exe"
    Write-Warn "    3. Then use: bughunter -d target.com --tor"
    Write-Warn "═══════════════════════════════════════════════════════"
}

function Test-Installation {
    Write-Step "Verifying installation..."

    try {
        $result = & bughunter --help 2>&1
        if ($result) {
            Write-Ok "bughunter command is available"
        }
    } catch {
        Write-Warn "bughunter not in PATH yet. Restart your terminal."
    }
}

# =================== MAIN ===================
Write-Banner

$python = Test-PythonInstalled
$hasGit = Test-GitInstalled
$venvPath = Install-VirtualEnv -PythonCmd $python

Install-Package
Install-SecLists
Add-ToPath -VenvPath $venvPath
Show-TorWarning
Test-Installation

Write-Host ""
Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "  Usage:   " -NoNewline; Write-Host "bughunter -d example.com" -ForegroundColor Cyan
Write-Host "  Help:    " -NoNewline; Write-Host "bughunter --help" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Restart your terminal for PATH changes to take effect." -ForegroundColor Yellow
Write-Host ""

Read-Host "Press Enter to exit"