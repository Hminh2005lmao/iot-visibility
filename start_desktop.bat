@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\start_desktop.ps1"
if errorlevel 1 (
  echo.
  echo Failed to start IoT desktop app.
  pause
)
