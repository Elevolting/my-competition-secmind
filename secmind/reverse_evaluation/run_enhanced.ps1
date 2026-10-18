$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$sample = Join-Path $repoRoot "reverse_evaluation\fixtures\safe-demo-v1\build\reverse_demo.exe"
$output = Join-Path $repoRoot "reverse_evaluation\results\enhanced"
$script = Join-Path $repoRoot "reverse_evaluation\tools\analyze_pe_sample.py"
$srcPath = Join-Path $repoRoot "src"

if (-not (Test-Path -LiteralPath $sample)) {
    throw "Sample not found: $sample"
}

$env:PYTHONPATH = if ($env:PYTHONPATH) { "$srcPath;$env:PYTHONPATH" } else { $srcPath }

python $script --input $sample --output $output

Write-Host "Enhanced report written to: $output"
