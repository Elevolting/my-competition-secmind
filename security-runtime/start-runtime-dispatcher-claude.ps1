$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
. (Join-Path (Split-Path -Parent $root) 'scripts/planning-credential.ps1')
Initialize-PlanningCredential (Split-Path -Parent $root)

# Claude remains available with the original shared platform model config.
uv run --project (Join-Path $root "security-runtime") security-runtime dispatch `
    --config (Join-Path $root "dispatch.local.yaml")
exit $LASTEXITCODE
