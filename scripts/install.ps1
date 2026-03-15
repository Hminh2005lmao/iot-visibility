param(
    [switch]$UpgradePip
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Get-PythonCommand {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        return @{ Exe = "py"; Args = @("-3") }
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        return @{ Exe = "python"; Args = @() }
    }
    throw "Python launcher not found. Install Python 3.10+ and ensure 'py' or 'python' is on PATH."
}

if (!(Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Host "[+] Creating virtual environment..."
    $pyCmd = Get-PythonCommand
    & $pyCmd.Exe @($pyCmd.Args) -m venv .venv
}

$py = ".\.venv\Scripts\python.exe"

if ($UpgradePip) {
    Write-Host "[+] Upgrading pip..."
    & $py -m pip install --upgrade pip
}

Write-Host "[+] Installing dependencies from requirements.txt..."
& $py -m pip install -r .\requirements.txt

if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
    Write-Host "[!] nmap executable not found in PATH."
    Write-Host "    Install Nmap from https://nmap.org/download.html (Windows installer)."
} else {
    Write-Host "[+] Nmap found."
}

Write-Host "[+] Install complete."
