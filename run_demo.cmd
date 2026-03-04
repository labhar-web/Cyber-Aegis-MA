@echo off
REM ============================================================
REM  run_demo.cmd — Cyber-Aegis MA Full Demo Launcher
REM  Purpose : Start ShopDemo + WAF + Dashboard for presentation
REM  Author  : Cyber-Aegis MA Team
REM  Date    : 2026-03-03
REM ============================================================

title Cyber-Aegis — Full Demo System
chcp 65001 > nul
cls

echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║         CYBER-AEGIS MA — FULL DEMO LAUNCHER             ║
echo  ║   ShopDemo (Victim)  +  WAF  +  Command Center          ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.

SET "PYTHON=C:\Users\pc\AppData\Local\Programs\Python\Python313\python.exe"
SET "ROOT=%~dp0"

:: Kill existing Python instances (only if running)
TASKLIST /FI "IMAGENAME eq python.exe" 2>nul | find /I "python.exe" >nul
IF %ERRORLEVEL%==0 (
    echo  Stopping previous instances...
    TASKKILL /F /FI "IMAGENAME eq python.exe" /T >nul 2>&1
    timeout /t 1 /nobreak >nul
)

:: ── [1/3] Start ShopDemo ──────────────────────────────────────────────────────
echo  [1/3] Starting ShopDemo on http://localhost:3000 ...
start "ShopDemo" /MIN cmd /c "%PYTHON% "%ROOT%shopdemo\app.py""
timeout /t 3 /nobreak >nul

:: ── [2/3] Start WAF Proxy ─────────────────────────────────────────────────────
echo  [2/3] Starting Cyber-Aegis WAF on http://localhost:8080 ...
start "Cyber-Aegis WAF" /MIN cmd /c "%PYTHON% "%ROOT%proxy_waf.py""
timeout /t 3 /nobreak >nul

:: ── [3/3] Start Dashboard ─────────────────────────────────────────────────────
echo  [3/3] Starting Command Center on http://localhost:5050 ...
start "Dashboard" /MIN cmd /c "%PYTHON% "%ROOT%dashboard\server.py""
timeout /t 3 /nobreak >nul

:: Open browsers
start "" "http://localhost:3000"
timeout /t 1 /nobreak >nul
start "" "http://localhost:5050"

cls
echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║             ALL SYSTEMS ONLINE                          ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.
echo   [VULN]  ShopDemo Direct  : http://localhost:3000
echo   [WAF]   ShopDemo via WAF : http://localhost:8080
echo   [DASH]  Command Center   : http://localhost:5050
echo.
echo  ══════════════════════════════════════════════════════
echo   DEMO STEPS:
echo.
echo   1. Go to http://localhost:3000/login
echo      Username:  type the SQLi payload in the field
echo      Password:  anything  ^> BYPASSES LOGIN
echo.
echo   2. Go to http://localhost:3000/search
echo      Search for XSS payload  ^> POPUP APPEARS
echo.
echo   3. Click "Enable WAF" on the red bar
echo      Try same attacks  ^> BLOCKED by Cyber-Aegis
echo.
echo   4. Watch http://localhost:5050 update in real-time
echo  ══════════════════════════════════════════════════════
echo.
pause
EXIT /B 0
