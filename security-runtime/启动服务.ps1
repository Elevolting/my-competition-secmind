$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$database = Join-Path $root "datas\security-runtime\security_runtime.db"
$databaseDirectory = Split-Path -Parent $database
New-Item -ItemType Directory -Path $databaseDirectory -Force | Out-Null

uv run --project (Join-Path $root "security-runtime") security-runtime serve `
    --host 127.0.0.1 `
    --port 8000 `
    --db-path $database `
    --no-access-log
