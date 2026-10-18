$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path (Split-Path -Parent $root) 'scripts\planning-credential.ps1')
Initialize-PlanningCredential (Split-Path -Parent $root)
Set-Location $root

# Settings are loaded from the local .env by pydantic-settings. Secrets are
# never copied into this script or printed to the console.
uv run security-agent-api
