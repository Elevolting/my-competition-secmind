#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$SkipDispatcher,
    [switch]$StartSecurityTools,
    [switch]$NoHealth,
    [ValidateSet('runtime-server','dispatcher','secmind','an-api','frontend')]
    [string[]]$Only = @('runtime-server','dispatcher','secmind','an-api','frontend')
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $root 'scripts\planning-credential.ps1')
Initialize-PlanningCredential $root
. (Join-Path $root 'scripts\suite-processes.ps1')
$mutex = Enter-SuiteLifecycleLock $root
$failed = $false
try {
    Set-Location -LiteralPath $root
    $logDir = Join-Path $root '_runtime\logs'
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    foreach ($dir in @((Join-Path $env:USERPROFILE '.local\bin'), (Join-Path $env:APPDATA 'npm\node_modules\@anthropic-ai\claude-code\bin'))) {
        if (Test-Path -LiteralPath $dir) { $env:Path = "$dir;$env:Path" }
    }
    $shellCommand = Get-Command pwsh -ErrorAction SilentlyContinue
    if (-not $shellCommand) { $shellCommand = Get-Command powershell.exe -ErrorAction Stop }
    $definitions = @(
        @{Name='runtime-server'; Script='security-runtime\start-runtime-server.ps1'; Work='security-runtime'; Port=8000; Probe='http://127.0.0.1:8000/projects'},
        @{Name='dispatcher'; Script='security-runtime\start-runtime-dispatcher.ps1'; Work='security-runtime'; Port=0; Probe=$null},
        @{Name='secmind'; Script='secmind\启动在线.ps1'; Work='secmind'; Port=8002; Probe='http://127.0.0.1:8002/health/ready'},
        @{Name='an-api'; Script='an\启动在线.ps1'; Work='an'; Port=8001; Probe='http://127.0.0.1:8001/health'},
        @{Name='frontend'; Script='an\frontend\启动前端.ps1'; Work='an\frontend'; Port=5173; Probe='http://127.0.0.1:5173/'}
    )
    foreach ($service in $definitions) {
        if ($service.Name -notin $Only -or ($SkipDispatcher -and $service.Name -eq 'dispatcher')) { continue }
        $existing = @(Get-SuiteProcesses $root | Where-Object Name -eq $service.Name)
        $roots = @(Get-SuiteProcessRoots $existing)
        if ($existing.Count -gt 0) {
            Write-Host "[已运行] $($service.Name)，进程组 $($roots.Count)" -ForegroundColor Cyan
            if ($roots.Count -gt 1) { Write-Warning '检测到重复进程组，未继续启动。请先用 stop-all.ps1 -Only 停止对应服务。' }
        } else {
            if ($service.Port -gt 0) {
                $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $service.Port -ErrorAction SilentlyContinue)
                if ($listeners.Count -gt 0) { throw "端口 $($service.Port) 被其他进程占用，未启动或终止该进程。" }
            }
            $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
            $out = Join-Path $logDir "$($service.Name)-$stamp.out.log"
            $err = Join-Path $logDir "$($service.Name)-$stamp.err.log"
            $stdin = Join-Path $logDir "$($service.Name).stdin"
            if (-not (Test-Path -LiteralPath $stdin)) { [IO.File]::WriteAllText($stdin, '') }
            $arguments = @{
                FilePath=$shellCommand.Source
                ArgumentList=('-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $root $service.Script) + '"')
                WorkingDirectory=(Join-Path $root $service.Work)
                WindowStyle='Hidden'
                RedirectStandardOutput=$out
                RedirectStandardError=$err
                RedirectStandardInput=$stdin
                PassThru=$true
            }
            $child = Start-Process @arguments
            if ($child.WaitForExit(1000)) { throw "$($service.Name) 启动后退出，退出码 $($child.ExitCode)。查看 $err" }
            Write-Host "[已启动] $($service.Name) pid=$($child.Id)，日志 $out" -ForegroundColor Green
        }
        if ($service.Probe -and -not $NoHealth) {
            $ready = $false
            for ($attempt = 0; $attempt -lt 40; $attempt++) {
                try {
                    $response = Invoke-WebRequest -Uri $service.Probe -UseBasicParsing -TimeoutSec 3
                    if ($response.StatusCode -eq 200) { $ready = $true; break }
                } catch { }
                Start-Sleep -Milliseconds 500
            }
            if (-not $ready) { throw "$($service.Name) 就绪检查失败：$($service.Probe)。请检查 _runtime\logs。" }
            Write-Host "[就绪] $($service.Name)" -ForegroundColor Green
        }
    }
    if ($StartSecurityTools) {
        & (Join-Path $root 'start-security-tools.ps1')
    }
    Write-Host '访问 http://127.0.0.1:5173；使用 -Only 可只启动指定服务。'
} catch {
    Write-Error $_ -ErrorAction Continue
    $failed = $true
} finally {
    try { Save-SuiteProcessState $root } finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
}
if ($failed) { exit 1 }




