@echo off
rem Double-click to remove Varta. Asks for administrator rights.
rem (no parenthesised blocks: a folder like "Varta (1)" would break them)
net session >nul 2>&1
if %errorlevel% equ 0 goto elevated
powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
exit /b
:elevated
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1"
pause
