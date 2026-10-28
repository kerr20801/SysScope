@echo off
title SysScope - Master Host Doctor
cd /d "%~dp0"

powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0launcher.ps1"
if %errorlevel% equ 0 goto end

echo.
echo ===================================================================
echo [Notice] PowerShell execution was blocked or exited.
echo [Notice] Launching SysScope Web Server directly in fallback mode...
echo ===================================================================
python server.py
if %errorlevel% neq 0 pause

:end
