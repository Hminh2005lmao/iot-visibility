@echo off
setlocal
cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File ".\scripts\run.ps1" -OpenBrowser
if errorlevel 1 (
  echo.
  echo Failed to start IoT Visibility UI.
  pause
)
