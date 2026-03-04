@echo off
REM ============================================================
REM  run_all.cmd — Cyber-Aegis MA Quick Launcher
REM  Purpose : Start all services (ShopDemo + WAF + Dashboard)
REM  Author  : Cyber-Aegis MA Team
REM  Date    : 2026-03-04
REM ============================================================
title Cyber-Aegis MA — All Services
chcp 65001 > nul
cls

echo.
echo  [Cyber-Aegis MA] Starting all services...
echo.

SET "PYTHON=C:\Users\pc\AppData\Local\Programs\Python\Python313\python.exe"
SET "ROOT=%~dp0"

:: Kill any existing python processes safely
TASKLIST /FI "IMAGENAME eq python.exe" 2>nul | find /I "python.exe" >nul
IF %ERRORLEVEL%==0 (
    TASKKILL /F /FI "IMAGENAME eq python.exe" /T >nul 2>&1
    timeout /t 1 /nobreak >nul
)

:: Start services
echo  [1/3] ShopDemo     ^> http://localhost:3000
start "ShopDemo" /MIN cmd /c "%PYTHON% "%ROOT%shopdemo\app.py""
timeout /t 3 /nobreak >nul

echo  [2/3] WAF Proxy    ^> http://localhost:8080
start "Cyber-Aegis WAF" /MIN cmd /c "%PYTHON% "%ROOT%proxy_waf.py""
timeout /t 3 /nobreak >nul

echo  [3/3] Dashboard    ^> http://localhost:5050
start "Dashboard" /MIN cmd /c "%PYTHON% "%ROOT%dashboard\server.py""
timeout /t 2 /nobreak >nul

echo.
echo  [OK] All services launched.
echo.
echo   ShopDemo  : http://localhost:3000
echo   WAF       : http://localhost:8080
echo   Dashboard : http://localhost:5050
echo.
pause
EXIT /B 0
