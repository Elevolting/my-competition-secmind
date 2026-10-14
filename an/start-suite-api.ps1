$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path (Split-Path -Parent $root) 'scripts\planning-credential.ps1')
Initialize-PlanningCredential (Split-Path -Parent $root)
Set-Location $root

uv run security-agent-api
