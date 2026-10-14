@echo off
setlocal
set PYTHONUTF8=1
set "PYTHONPATH=%~dp0an\src;%PYTHONPATH%"
"%~dp0an\.venv\Scripts\python.exe" -m security_agent.tsec_auto --env-file "%~dp0an\.env" %*
exit /b %errorlevel%
