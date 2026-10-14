$ErrorActionPreference = "Stop"

$fixtureRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$sourcePath = Join-Path $fixtureRoot "reverse_demo.c"
$buildRoot = Join-Path $fixtureRoot "build"
$outputPath = Join-Path $buildRoot "reverse_demo.exe"

if (-not (Test-Path -LiteralPath $sourcePath)) {
    throw "Source file not found: $sourcePath"
}

New-Item -ItemType Directory -Force -Path $buildRoot | Out-Null

$gcc = Get-Command gcc.exe -ErrorAction SilentlyContinue
if (-not $gcc) {
    throw "gcc.exe was not found. Install MinGW-w64 or use a compiler that produces a Windows PE executable."
}

& $gcc.Source `
    -std=c11 `
    -O2 `
    -s `
    -Wall `
    -Wextra `
    -Wpedantic `
    $sourcePath `
    -o $outputPath

if ($LASTEXITCODE -ne 0) {
    throw "Compilation failed with exit code $LASTEXITCODE"
}

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $outputPath).Hash.ToLowerInvariant()
Write-Host "Built: $outputPath"
Write-Host "SHA256: $hash"
