#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$SkipReqable,
    [switch]$SkipBurp
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$tools = Join-Path $root '_runtime\tools'
. (Join-Path $root 'scripts\suite-processes.ps1')

function Start-IfMissing([string]$Path, [string]$WorkingDirectory, [string[]]$ArgumentList = @()) {
    $full = [IO.Path]::GetFullPath($Path)
    $component = if ($ArgumentList.Count) { 'burp' } else { 'reqable' }
    $running = @(Get-SuiteProcesses $root | Where-Object Name -eq $component)
    if ($running.Count -gt 0) { Write-Host "[已运行] $Path" -ForegroundColor Cyan; return $running[0] }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "找不到程序：$full" }
    $parameters = @{FilePath=$full; WorkingDirectory=$WorkingDirectory; WindowStyle=$(if ($component -eq 'burp') { 'Normal' } else { 'Hidden' }); PassThru=$true}
    if ($ArgumentList.Count) {
        $parameters.ArgumentList = ($ArgumentList | ForEach-Object { '"' + $_ + '"' }) -join ' '
    }
    $process = Start-Process @parameters
    if ($process.WaitForExit(1500) -and $process.ExitCode -ne 0) { throw "启动失败，退出码 $($process.ExitCode)：$full" }
    Write-Host "[已启动] $($process.Id) $full" -ForegroundColor Green
    return $process
}

if (-not $SkipReqable) {
    Start-IfMissing (Join-Path $tools 'reqable\app\Reqable.exe') (Join-Path $tools 'reqable\app') | Out-Null
}
if (-not $SkipBurp) {
    $burp = Join-Path $tools 'burp\burpsuite-community.jar'
    if (-not (Test-Path -LiteralPath $burp -PathType Leaf)) {
        throw "Burp 主程序尚未准备好：$burp。请先运行 setup-security-tools.ps1。"
    }
    $configPath = Join-Path $tools 'burp\user-config.json'
    $config = @{user_options=@{extender=@{extensions=@(@{
        extension_file=(Join-Path $tools 'burp\burp-mcp-all.jar'); extension_type='java'; loaded=$true; name='MCP Server'
    })}}}
    [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
    Start-IfMissing (Get-Command java.exe -ErrorAction Stop).Source (Split-Path $burp) @('-jar', $burp, '--use-defaults', '--disable-auto-update', ('--data-dir=' + (Join-Path $tools 'burp\data')), ('--user-config-file=' + $configPath)) | Out-Null
}
& (Join-Path $root 'scripts\register-security-mcp.ps1')
Write-Host '桌面工具已启动，MCP 配置已同步。'
Write-Host 'Burp 若显示项目向导，请点击 Next → Start Burp；MCP 扩展使用本机端口 9876。'
