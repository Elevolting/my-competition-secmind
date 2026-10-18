#requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$python=Join-Path $root 'an\.venv\Scripts\python.exe'
# Use the catalog's atomic writer, so relocation works even with the API stopped.
& $python (Join-Path $PSScriptRoot 'register-security-mcp.py')
if ($LASTEXITCODE -ne 0) { throw 'Failed to register bundled MCP servers' }
