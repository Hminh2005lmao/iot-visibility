$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (!(Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Host "[!] Virtual environment not found. Running installer..."
    & ".\scripts\install.ps1" -UpgradePip
}

$py = ".\.venv\Scripts\python.exe"
$pyw = ".\.venv\Scripts\pythonw.exe"

$hasWebView = & $py -c "import importlib.util; print('yes' if importlib.util.find_spec('webview') else 'no')"
if ($hasWebView -ne "yes") {
    Write-Host "[!] pywebview not found. Installing dependencies..."
    & ".\scripts\install.ps1"
}

if (Test-Path $pyw) {
    Start-Process -FilePath $pyw -ArgumentList ".\desktop_app.py" -WorkingDirectory $root | Out-Null
} else {
    Start-Process -FilePath $py -ArgumentList ".\desktop_app.py" -WorkingDirectory $root | Out-Null
}

Write-Host "[+] Desktop app launched."
