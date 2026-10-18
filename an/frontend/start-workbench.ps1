$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
$env:VITE_DEV_BACKEND_TARGET = "http://127.0.0.1:8001"

npm run dev -- --host 127.0.0.1 --port 5173
