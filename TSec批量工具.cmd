@echo off
setlocal
cd /d "%~dp0an"
set PYTHONUTF8=1
".venv\Scripts\python.exe" -m security_agent.tsec_batch_gui
if errorlevel 1 pause
