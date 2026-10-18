#requires -Version 5.1
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
& (Join-Path $root 'an\.venv\Scripts\python.exe') (Join-Path $root 'scripts\download-burp.py')
if ($LASTEXITCODE -ne 0) { throw 'Burp download or validation failed' }
foreach ($relative in @('reqable\app\Reqable.exe','reqable\app\mcp-server.exe','burp\burp-mcp-all.jar','yak\yak.exe','tscanplus\app\TscanPlus_Win_Amd64.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $root ('_runtime\tools\' + $relative)))) { throw "Bundled file missing: $relative" }
}
& (Join-Path $root 'scripts\register-security-mcp.ps1')
