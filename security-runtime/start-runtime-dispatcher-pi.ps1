param([switch]$Independent)
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path (Split-Path -Parent $root) 'scripts\planning-credential.ps1')
Initialize-PlanningCredential (Split-Path -Parent $root)
Set-Location -LiteralPath $root
$runningDispatcher = Get-CimInstance Win32_Process | Where-Object {
    $_.Name -in @('uv.exe', 'security-runtime.exe', 'python.exe') -and
    $_.CommandLine -and
    $_.CommandLine.Contains($root) -and
    $_.CommandLine.Contains('security-runtime dispatch')
}
if ($runningDispatcher) {
    throw 'A Dispatcher for this suite is already running. Stop it before starting the Pi Dispatcher.'
}
$envFile = Join-Path $root ".env.pi"
if ($Independent) {
    if (Test-Path -LiteralPath $envFile) {
        Get-Content -LiteralPath $envFile | ForEach-Object {
            $line = $_.Trim()
            if ($line -and -not $line.StartsWith('#') -and $line.Contains('=')) {
                $parts = $line -split '=', 2
                [Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim().Trim('"').Trim("'"), 'Process')
            }
        }
    }
    foreach ($name in @('PI_MODEL', 'PI_BASE_URL', 'PI_API_KEY', 'PI_PROVIDER_API')) {
        if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name, 'Process'))) {
            throw "$name is not configured for independent Pi mode"
        }
    }
    if ([string]::IsNullOrWhiteSpace($env:PI_MODEL_CONTEXT_WINDOW)) { $env:PI_MODEL_CONTEXT_WINDOW = '131072' }
}

# Both the local wrapper and npm's pi.cmd can truncate a multi-line task.
# Resolve the package's JS entry point and invoke it with Node directly.
if ([string]::IsNullOrWhiteSpace($env:PI_CLI_JS)) {
    $piCommand = (Get-Command pi -ErrorAction Stop).Source
    if ([IO.Path]::GetExtension($piCommand) -ieq '.cmd') {
        $launcher = Get-Content -LiteralPath $piCommand -Raw
        if ($launcher -match '(?im)^\s*call\s+"([^"]+\.cmd)"') {
            $piCommand = $Matches[1]
        }
    }
    $binDir = Split-Path -Parent $piCommand
    $candidates = @(
        (Join-Path $binDir 'node_modules\@mariozechner\pi-coding-agent\dist\cli.js'),
        (Join-Path (Split-Path -Parent $binDir) '@mariozechner\pi-coding-agent\dist\cli.js')
    )
    $env:PI_CLI_JS = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (-not $env:PI_CLI_JS -or -not (Test-Path -LiteralPath $env:PI_CLI_JS)) {
    throw 'Could not find the Pi CLI JavaScript entry point. Set PI_CLI_JS to its dist\cli.js path.'
}
Get-Command node -ErrorAction Stop | Out-Null

$configName = if ($Independent) { 'dispatch.pi.independent.yaml' } else { 'dispatch.pi.local.yaml' }
uv run --project (Join-Path $root 'security-runtime') security-runtime dispatch `
    --config (Join-Path $root $configName)
exit $LASTEXITCODE
