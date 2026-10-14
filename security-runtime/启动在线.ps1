$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Import-LocalEnv([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Missing local configuration file: $path"
    }
    Get-Content -LiteralPath $path | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
            $parts = $line -split "=", 2
            $name = $parts[0].Trim()
            $value = $parts[1].Trim().Trim('"').Trim("'")
            [Environment]::SetEnvironmentVariable($name, $value, "Process")
        }
    }
}

Import-LocalEnv (Join-Path $root ".env")

$model = [Environment]::GetEnvironmentVariable("ANTHROPIC_MODEL", "Process")
$token = [Environment]::GetEnvironmentVariable("ANTHROPIC_AUTH_TOKEN", "Process")

if ([string]::IsNullOrWhiteSpace($model)) {
    throw "ANTHROPIC_MODEL is not configured"
}
if ([string]::IsNullOrWhiteSpace($token)) {
    throw "ANTHROPIC_AUTH_TOKEN is not configured"
}

uv run --project security-runtime security-runtime dispatch --config (Join-Path $root "dispatch.local.yaml")
