param(
    [string]$OutputDir = "dist",
    [switch]$IncludeData
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$packageName = "iot-visibility-portable-$stamp"
$distRoot = Join-Path $root $OutputDir
$stageRoot = Join-Path $distRoot "_stage"
$stageDir = Join-Path $stageRoot "iot-visibility"
$zipPath = Join-Path $distRoot "$packageName.zip"

if (Test-Path $stageRoot) {
    Remove-Item -Path $stageRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $stageDir -Force | Out-Null

$includePaths = @(
    "api",
    "checks",
    "docs",
    "scanner",
    "scripts",
    "desktop_app.py",
    "run_pipeline.py",
    "requirements.txt",
    "start_ui.bat",
    "start_ui.vbs",
    "start_desktop.bat",
    "start_desktop.vbs",
    "stop_ui.bat"
)

foreach ($rel in $includePaths) {
    $src = Join-Path $root $rel
    if (!(Test-Path $src)) {
        continue
    }
    Copy-Item -Path $src -Destination (Join-Path $stageDir $rel) -Recurse -Force
}

# Remove local runtime/cache artifacts from package.
Get-ChildItem -Path $stageDir -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
Get-ChildItem -Path $stageDir -Recurse -File -Include "*.pyc","*.pyo" | Remove-Item -Force

$dataSrc = Join-Path $root "data"
$dataDst = Join-Path $stageDir "data"
New-Item -ItemType Directory -Path $dataDst -Force | Out-Null

if ($IncludeData -and (Test-Path $dataSrc)) {
    Copy-Item -Path (Join-Path $dataSrc "*") -Destination $dataDst -Recurse -Force
} else {
    @(
        "inventory.json",
        "inventory_labeled.json",
        "findings.json",
        "devices_report.json",
        "scan_status.json",
        "evaluation_metrics.json",
        "asset_changes.json",
        "threat_intel.json",
        "scan_meta.json"
    ) | ForEach-Object {
        $sourceFile = Join-Path $dataSrc $_
        if (Test-Path $sourceFile) {
            Copy-Item -Path $sourceFile -Destination (Join-Path $dataDst $_) -Force
        }
    }
}

$readmePath = Join-Path $stageDir "README_DEPLOY.txt"
@"
IoT Visibility - Portable Package

1) Open PowerShell in this folder.
2) Run:
   powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1 -UpgradePip
3) Start UI:
   powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 -OpenBrowser
   or double-click start_ui.bat
   or double-click start_ui.vbs (hidden launcher, no terminal window)

Desktop app mode (native window):
- double-click start_desktop.vbs (recommended)
- or double-click start_desktop.bat

Optional:
- Start with scan:
  powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 -Scan -CIDR 192.168.1.0/24 -OpenBrowser
- Set admin key:
  `$env:IOT_ADMIN_API_KEY = "change-this-secret"

Requirements:
- Windows + Python 3.10+
- Nmap installed and in PATH (https://nmap.org/download.html)
"@ | Set-Content -Path $readmePath -Encoding UTF8

New-Item -ItemType Directory -Path $distRoot -Force | Out-Null
if (Test-Path $zipPath) {
    Remove-Item -Path $zipPath -Force
}

Compress-Archive -Path (Join-Path $stageRoot "iot-visibility") -DestinationPath $zipPath -CompressionLevel Optimal -Force
Remove-Item -Path $stageRoot -Recurse -Force

Write-Host "[+] Package created: $zipPath"
