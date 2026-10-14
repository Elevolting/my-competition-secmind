#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Force)
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $root 'scripts\suite-processes.ps1')
$owned = @(Get-SuiteProcesses $root | Where-Object Name -in @('reqable','burp'))
$processes = @(Get-SuiteProcessRoots $owned)
foreach ($p in $processes) {
    $current = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ProcessId)" -ErrorAction SilentlyContinue
    if (-not $current -or $current.CreationDate -ne $p.Created -or (Get-SuiteComponent $current $root) -ne $p.Name) { continue }
    if ($PSCmdlet.ShouldProcess("$($p.Name) pid=$($p.ProcessId)", '停止项目内置安全工具')) {
        if (-not $Force) {
            foreach ($member in @($owned | Where-Object RootProcessId -eq $p.ProcessId)) {
                $window = Get-Process -Id $member.ProcessId -ErrorAction SilentlyContinue
                if ($window -and $window.MainWindowHandle -ne [IntPtr]::Zero) {
                    $null = $window.CloseMainWindow()
                }
            }
            Write-Host "[已请求关闭] $($p.Name)，请在桌面处理可能出现的保存提示。"
            continue
        }
        & (Join-Path $env:SystemRoot 'System32\taskkill.exe') /PID $p.ProcessId /T /F | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "停止失败：$($p.Name)" }
        Write-Host "[已停止] $($p.Name) pid=$($p.ProcessId)" -ForegroundColor Green
    }
}
