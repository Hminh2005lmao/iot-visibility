# Quickstart

## 1) Install dependencies

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1 -UpgradePip
```

## 2) Run UI only

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 -OpenBrowser
```

By default, `scripts/run.ps1` now prefers Waitress (production WSGI) when installed.
No-terminal option: double-click `start_ui.vbs`.

## 2.1) Run as desktop app window (no browser tab)

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start_desktop.ps1
```

Or double-click `start_desktop.vbs` (recommended).

## 3) One-click scan + UI

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 -Scan -CIDR 192.168.1.0/24 -Note "home scan" -OpenBrowser
```

## 4) Direct pipeline with scan mode/profile

```powershell
.\.venv\Scripts\python.exe .\run_pipeline.py 192.168.1.0/24 "home scan" --scan-mode hybrid --discovery-profile balanced --check-profile safe
```

## 5) Optional admin key for starting scans

Set an environment variable before starting the UI:

```powershell
$env:IOT_ADMIN_API_KEY = "change-this-secret"
powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 -OpenBrowser
```

When enabled, scan forms require this key to call `POST /api/scan/start`.
Export downloads (`/export/*`, `/report/print`) and JSON API pages send this key via the `X-API-Key` header.
Read-only JSON endpoints requiring the key:
- `/api/report`
- `/api/findings`
- `/api/devices`
- `/api/evaluation`
- `/api/threat-intel`
- `/api/asset-changes`
- `/api/scan/status`

## Stop UI server

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\stop.ps1
```

Or double-click `stop_ui.bat`.

## Useful URLs

- Home: `http://127.0.0.1:5000/`
- Dashboard: `http://127.0.0.1:5000/dashboard`
- Evaluation page: `http://127.0.0.1:5000/evaluation`
- Printable report: `http://127.0.0.1:5000/report/print`
- PDF report: `http://127.0.0.1:5000/export/report.pdf`

## Package for another machine

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\package_release.ps1
```

See `docs/deploy_windows.md` for full transfer/deploy steps.

## Deploy online

See `docs/deploy_online.md` for Render/Docker deployment and security settings.
