$ErrorActionPreference = "Stop"

$listeners = Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue
if (-not $listeners) {
    Write-Host "[i] No running UI process on port 5000."
    exit 0
}

$pids = $listeners | Select-Object -ExpandProperty OwningProcess -Unique
foreach ($pid in $pids) {
    try {
        Stop-Process -Id $pid -Force -ErrorAction Stop
        Write-Host "[+] Stopped UI process PID=$pid"
    } catch {
        Write-Host "[!] Failed to stop PID=$pid : $($_.Exception.Message)"
    }
}
