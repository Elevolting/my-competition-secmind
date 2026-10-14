@echo off
rem ============================================================
rem  start-all launcher (double-click safe, works on any Windows)
rem  Uses only %~dp0 (this folder) - no hard-coded paths.
rem  Prefers PowerShell 7 (pwsh); falls back to Windows PowerShell.
rem ============================================================
setlocal
cd /d "%~dp0"

where pwsh.exe >nul 2>nul
if %errorlevel%==0 (
  set "SHELL=pwsh.exe"
) else (
  set "SHELL=powershell.exe"
)

echo [start-all] Launching with %SHELL% (ExecutionPolicy Bypass) ...
echo.
%SHELL% -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-all.ps1" %*
set "EC=%ERRORLEVEL%"
echo.
echo [start-all] Finished with exit code %EC%
if not "%EC%"=="0" (
  echo.
  echo Something failed. Read the messages above.
  pause
)
exit /b %EC%
