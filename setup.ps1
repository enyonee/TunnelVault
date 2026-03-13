#Requires -Version 5.1
<#
.SYNOPSIS
    tunnelvault setup for native Windows (PowerShell).
.DESCRIPTION
    Creates venv, installs dependencies, checks system tools.
    For MSYS2/Git Bash users: use ./setup.sh instead.
.PARAMETER NoTests
    Skip running tests after setup.
#>
param(
    [switch]$NoTests
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

function Write-Ok($msg)   { Write-Host "  + $msg" -ForegroundColor Green }
function Write-Fail($msg) { Write-Host "  x $msg" -ForegroundColor Red }
function Write-Warn($msg) { Write-Host "  ! $msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "  tunnelvault setup" -ForegroundColor Green
Write-Host "  -----------------" -ForegroundColor DarkGray
Write-Host ""

# -- Python 3.10+ --
$PythonCmd = $null
foreach ($cmd in @("python3", "python", "py")) {
    $exe = Get-Command $cmd -ErrorAction SilentlyContinue
    if (-not $exe) { continue }
    $ver = & $cmd -c "import sys; v=sys.version_info; print(f'{v.major}.{v.minor}') if v >= (3,10) else exit(1)" 2>$null
    if ($LASTEXITCODE -eq 0 -and $ver) {
        $PythonCmd = $cmd
        break
    }
}
if (-not $PythonCmd) {
    Write-Fail "Python 3.10+ not found"
    Write-Host "    winget install Python.Python.3.12" -ForegroundColor DarkGray
    exit 1
}
Write-Ok "Python $ver ($PythonCmd)"

# -- venv --
$VenvPy = ".venv\Scripts\python.exe"
$NeedVenv = $false
if (-not (Test-Path ".venv")) {
    $NeedVenv = $true
} elseif (-not (Test-Path $VenvPy)) {
    Remove-Item -Recurse -Force ".venv"
    $NeedVenv = $true
}
if ($NeedVenv) {
    & $PythonCmd -m venv .venv
    Write-Ok "venv created"
} else {
    Write-Ok "venv"
}

# -- pip --
$Pip = ".venv\Scripts\pip.exe"
if (-not (Test-Path $Pip)) {
    & $VenvPy -m ensurepip -q 2>$null
}

# -- Python deps --
& $Pip install -q rich "dnslib>=0.9" pytest pytest-xdist 2>$null
& $VenvPy -c "import tomllib" 2>$null
if ($LASTEXITCODE -ne 0) {
    & $Pip install -q tomli 2>$null
}
Write-Ok "Python deps (rich, dnslib, pytest)"

# -- System tools --
Write-Host ""
Write-Host "  System tools:" -ForegroundColor DarkGray

$Missing = 0

function Test-Tool {
    param([string]$Name, [string]$Hint)
    $found = Get-Command $Name -ErrorAction SilentlyContinue
    if ($found) {
        Write-Ok "$Name ($($found.Source))"
    } else {
        Write-Fail "$Name not found"
        if ($Hint) { Write-Host "    $Hint" -ForegroundColor DarkGray }
        $script:Missing++
    }
}

Test-Tool "openvpn"  "choco install openvpn  -or-  winget install OpenVPNTechnologies.OpenVPN"
Test-Tool "sing-box"  "https://sing-box.sagernet.org/installation/package-manager/"
Test-Tool "curl"  "(built-in on Windows 10+)"

# -- Config --
Write-Host ""
if (-not (Test-Path "config.toml") -and (Test-Path "config.toml.example")) {
    Copy-Item "config.toml.example" "config.toml"
    Write-Ok "config.toml copied from example (edit it with your settings)"
} elseif (Test-Path "config.toml") {
    Write-Ok "config.toml"
} else {
    Write-Warn "config.toml.example not found"
}

# -- Tests --
if (-not $NoTests) {
    Write-Host ""
    Write-Host "  Running tests..." -ForegroundColor DarkGray
    Write-Host ""
    & $VenvPy -m pytest tests/ -x -q
}

# -- Summary --
Write-Host ""
if ($Missing -eq 0) {
    Write-Host "  Ready!" -ForegroundColor Green
} else {
    Write-Warn "$Missing tool(s) missing. Install them and re-run .\setup.ps1"
}
Write-Host "  .\tvpn.bat              # connect (run as admin)" -ForegroundColor DarkGray
Write-Host "  .\tvpn.bat --status     # check" -ForegroundColor DarkGray
Write-Host "  .\tvpn.bat --disconnect # disconnect" -ForegroundColor DarkGray
Write-Host "  .\tvpn.bat --watch      # live traffic" -ForegroundColor DarkGray
Write-Host ""
