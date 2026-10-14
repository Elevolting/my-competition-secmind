#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [ValidateSet('runtime-server','dispatcher','secmind','an-api','frontend')]
    [string[]]$Only = @('runtime-server','dispatcher','secmind','an-api','frontend')
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $root 'scripts\suite-processes.ps1')
$mutex = Enter-SuiteLifecycleLock $root
$failed = $false
try {
    $owned = @(Get-SuiteProcesses $root | Where-Object { $_.Name -in $Only })
    $roots = @(Get-SuiteProcessRoots $owned)
    foreach ($process in $roots) {
        $current = Get-CimInstance Win32_Process -Filter "ProcessId=$($process.ProcessId)" -ErrorAction SilentlyContinue
        if (-not $current -or $current.CreationDate -ne $process.Created -or (Get-SuiteComponent $current $root) -ne $process.Name) { continue }
        if ($PSCmdlet.ShouldProcess("$($process.Name) pid=$($process.ProcessId)", '停止该套件的进程树')) {
            & (Join-Path $env:SystemRoot 'System32\taskkill.exe') /PID $process.ProcessId /T /F | Out-Null
            if ($LASTEXITCODE -ne 0 -and (Get-Process -Id $process.ProcessId -ErrorAction SilentlyContinue)) {
                Write-Warning "停止失败：$($process.Name) pid=$($process.ProcessId)"
                $failed = $true
            } else { Write-Host "[已停止] $($process.Name) pid=$($process.ProcessId)" -ForegroundColor Green }
        }
    }
    if ($roots.Count -eq 0) { Write-Host '没有找到本目录的目标服务进程。' }
    Write-Host '日志和数据已保留；未终止其他目录的端口占用者。'
} finally {
    try { if (-not $WhatIfPreference) { Save-SuiteProcessState $root } }
    finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
}
if ($failed) { exit 1 }


