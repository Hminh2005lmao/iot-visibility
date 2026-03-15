# Deploy to Another Windows Machine

## Build a portable zip on your current machine

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\package_release.ps1
```

Output zip will be in `.\dist\` (for example: `iot-visibility-portable-20260311_101500.zip`).

If you want to include all existing scan history/data:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\package_release.ps1 -IncludeData
```

## Run on the target machine

1. Copy zip to the target machine.
2. Extract it.
3. Open PowerShell in extracted folder.
4. Install dependencies:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1 -UpgradePip
```

5. Start UI:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 -OpenBrowser
```

Or double-click:
- `start_ui.vbs` (hidden launcher, no terminal window)
- `start_ui.bat` (normal launcher)

Desktop-app mode (native window, like a standalone app):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start_desktop.ps1
```

Or double-click `start_desktop.vbs`.

## Requirements on target machine

- Windows 10/11
- Python 3.10+
- Nmap installed and available in `PATH`
  - Download: `https://nmap.org/download.html`

## Optional: secure API with admin key

```powershell
$env:IOT_ADMIN_API_KEY = "change-this-secret"
powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 -OpenBrowser
```

Keep this value private. UI/API calls use it through `X-API-Key` header.

## Stop UI

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\stop.ps1
```

Or double-click `stop_ui.bat`.
