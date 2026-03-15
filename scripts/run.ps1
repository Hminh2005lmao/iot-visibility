param(
    [string]$CIDR = "",
    [string]$Note = "",
    [switch]$Scan,
    [switch]$OpenBrowser
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (!(Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Host "[!] Virtual environment not found. Running installer..."
    & ".\scripts\install.ps1"
}

$py = ".\.venv\Scripts\python.exe"

if ($Scan) {
    if ([string]::IsNullOrWhiteSpace($CIDR)) {
        throw "When using -Scan, provide -CIDR (example: -CIDR 192.168.1.0/24)."
    }
    Write-Host "[+] Running full scan pipeline for $CIDR ..."
    if ([string]::IsNullOrWhiteSpace($Note)) {
        & $py .\run_pipeline.py $CIDR
    } else {
        & $py .\run_pipeline.py $CIDR $Note
    }
}

$listener = Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue
if ($listener) {
    $existingPid = ($listener | Select-Object -First 1 -ExpandProperty OwningProcess)
    Write-Host "[i] Existing UI process found on :5000 (PID=$existingPid). Reusing it."
} else {
    Write-Host "[+] Starting UI on http://127.0.0.1:5000 ..."
    $waitressCheck = & $py -c "import importlib.util; print('yes' if importlib.util.find_spec('waitress') else 'no')"
    if ($waitressCheck -eq "yes") {
        $args = @("-m", "waitress", "--host", "0.0.0.0", "--port", "5000", "api.app:app")
        Start-Process -FilePath $py -ArgumentList $args -WorkingDirectory $root -WindowStyle Hidden | Out-Null
        Write-Host "[i] Started with Waitress (production WSGI)."
    } else {
        $args = @("-m", "flask", "--app", "api.app", "run", "--host", "0.0.0.0", "--port", "5000")
        Start-Process -FilePath $py -ArgumentList $args -WorkingDirectory $root -WindowStyle Hidden | Out-Null
        Write-Host "[i] Waitress not found, fell back to Flask dev server."
    }
    Start-Sleep -Seconds 2
}

Write-Host "[+] UI ready:"
Write-Host "    http://127.0.0.1:5000"

if ($OpenBrowser) {
    Start-Process "http://127.0.0.1:5000" | Out-Null
}
