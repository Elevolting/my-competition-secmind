param(
    [switch]$BuildOnly
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker CLI is not installed or not available in PATH."
}
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Docker Engine is not running. Start Docker Desktop and retry."
}

$envPath = Join-Path $root ".env"
if (-not (Test-Path -LiteralPath $envPath)) {
    Copy-Item -LiteralPath (Join-Path $root ".env.example") -Destination $envPath
}

function Set-EnvValue([string]$Name, [string]$Value) {
    $lines = @(Get-Content -LiteralPath $envPath -Encoding UTF8)
    $prefix = "$Name="
    $updated = $false
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if ($lines[$index].StartsWith($prefix, [StringComparison]::Ordinal)) {
            $lines[$index] = "$prefix$Value"
            $updated = $true
            break
        }
    }
    if (-not $updated) {
        $lines += "$prefix$Value"
    }
    Set-Content -LiteralPath $envPath -Value $lines -Encoding UTF8
}

function Ensure-EnvSecret([string]$Name) {
    $line = Get-Content -LiteralPath $envPath -Encoding UTF8 |
        Where-Object { $_.StartsWith("$Name=", [StringComparison]::Ordinal) } |
        Select-Object -First 1
    if (-not $line -or $line -eq "$Name=") {
        $bytes = New-Object byte[] 32
        [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        Set-EnvValue $Name ([Convert]::ToHexString($bytes).ToLowerInvariant())
    }
}

Ensure-EnvSecret "SECMIND_SANDBOX_TOKEN"
Ensure-EnvSecret "SECMIND_SANDBOX_CONTROL_TOKEN"

$dockerSocket = Get-Content -LiteralPath $envPath -Encoding UTF8 |
    Where-Object { $_.StartsWith("SECMIND_DOCKER_SOCKET=", [StringComparison]::Ordinal) } |
    Select-Object -First 1
if (-not $dockerSocket -or $dockerSocket -eq "SECMIND_DOCKER_SOCKET=") {
    # Development-only Docker Desktop baseline. Competition deployments must
    # set SECMIND_ROOTLESS_DOCKER_SOCKET in docker-compose.competition.yml.
    Set-EnvValue "SECMIND_DOCKER_SOCKET" "/var/run/docker.sock"
}

docker compose --profile build-only build bandit-tool
if ($LASTEXITCODE -ne 0) { throw "Bandit tool image build failed." }
$imageId = (docker image inspect secmind-bandit:local --format '{{.Id}}').Trim()
if (-not $imageId.StartsWith("sha256:", [StringComparison]::Ordinal)) {
    throw "Could not resolve the immutable Bandit image ID."
}
Set-EnvValue "SECMIND_SANDBOX_BANDIT_IMAGE" $imageId

docker compose --profile build-only build staging-tool
if ($LASTEXITCODE -ne 0) { throw "Sandbox staging image build failed." }
$stagingImageId = (docker image inspect secmind-staging:local --format '{{.Id}}').Trim()
if (-not $stagingImageId.StartsWith("sha256:", [StringComparison]::Ordinal)) {
    throw "Could not resolve the immutable staging image ID."
}
Set-EnvValue "SECMIND_SANDBOX_STAGING_IMAGE" $stagingImageId

docker compose --profile build-only build semgrep-tool
if ($LASTEXITCODE -ne 0) { throw "Semgrep tool image build failed." }
$semgrepImageId = (docker image inspect secmind-semgrep:local --format '{{.Id}}').Trim()
if (-not $semgrepImageId.StartsWith("sha256:", [StringComparison]::Ordinal)) {
    throw "Could not resolve the immutable Semgrep image ID."
}
Set-EnvValue "SECMIND_SANDBOX_SEMGREP_IMAGE" $semgrepImageId

$manifestPath = Join-Path $root "src/secmind/tooling/external_manifests.py"
$manifestSource = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8
$digestMatch = [regex]::Match(
    $manifestSource,
    'SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST\s*=\s*"([0-9a-f]{64})"'
)
if (-not $digestMatch.Success) {
    throw "Could not resolve the approved Semgrep rule bundle digest."
}
Set-EnvValue "SECMIND_SEMGREP_SAST_RULE_BUNDLE_DIGEST" $digestMatch.Groups[1].Value

if (-not $BuildOnly) {
    docker compose up --build -d
    if ($LASTEXITCODE -ne 0) { throw "SecMind Compose startup failed." }
    docker compose ps
}

