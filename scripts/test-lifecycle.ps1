#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$suite = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'suite-processes.ps1')
function Assert-Equal($Actual, $Expected, [string]$Label) {
    if ($Actual -ne $Expected) { throw "$Label expected [$Expected], got [$Actual]" }
}
$cases = @(
    @{Command='"' + $suite + '\an\.venv\Scripts\python.exe" -m uvicorn security_agent.api:app'; Expected='an-api'},
    @{Command='"' + $suite + '\secmind\.venv\Scripts\python.exe" -m uvicorn secmind.api:app'; Expected='secmind'},
    @{Command='pwsh -File "' + $suite + '\security-runtime\start-runtime-dispatcher.ps1"'; Expected='dispatcher'},
    @{Command='node "' + $suite + '\an\frontend\node_modules\vite\bin\vite.js"'; Expected='frontend'},
    @{Command='"' + $suite + '-other\an\.venv\Scripts\python.exe" -m uvicorn security_agent.api:app'; Expected=$null},
    @{Command='"C:\other\python.exe" -m uvicorn security_agent.api:app'; Expected=$null}
)
foreach ($case in $cases) {
    $process = [pscustomobject]@{CommandLine=$case.Command; ExecutablePath='C:\Windows\System32\pwsh.exe'}
    Assert-Equal (Get-SuiteComponent $process $suite) $case.Expected 'Process ownership'
}
$processes = @(
    [pscustomobject]@{ProcessId=1; ParentProcessId=99},
    [pscustomobject]@{ProcessId=2; ParentProcessId=1},
    [pscustomobject]@{ProcessId=3; ParentProcessId=99}
)
Assert-Equal (@(Get-SuiteProcessRoots $processes).Count) 2 'Process groups'
foreach ($script in @('start-all.ps1','stop-all.ps1','scripts\suite-processes.ps1')) {
    $tokens = $null
    $parseErrors = $null
    [Management.Automation.Language.Parser]::ParseFile((Join-Path $suite $script), [ref]$tokens, [ref]$parseErrors) | Out-Null
    Assert-Equal (@($parseErrors).Count) 0 "Parse $script"
}
$now = [DateTime]::UtcNow
$script:FakeProcesses = @(
    [pscustomobject]@{ ProcessId=70001; ParentProcessId=0; CreationDate=$now; CommandLine='pwsh -File "' + $suite + '\an\启动在线.ps1"'; ExecutablePath='C:\pwsh.exe' },
    [pscustomobject]@{ ProcessId=70002; ParentProcessId=70001; CreationDate=$now; CommandLine='cmd /c python'; ExecutablePath='C:\Windows\System32\cmd.exe' },
    [pscustomobject]@{ ProcessId=70003; ParentProcessId=70002; CreationDate=$now; CommandLine='"' + $suite + '\an\.venv\Scripts\python.exe" -m uvicorn security_agent.api:app'; ExecutablePath='C:\python.exe' }
)
function Get-CimInstance { param($ClassName, $ErrorAction) return $script:FakeProcesses }
$grouped = @(Get-SuiteProcessRoots @(Get-SuiteProcesses $suite))
Assert-Equal $grouped.Count 1 'Intermediate launcher grouping'
Assert-Equal $grouped[0].ProcessId 70001 'Oldest owned ancestor'
Write-Output 'PASS: 6 ownership cases, direct and nested process grouping, and 3 script syntax checks.'
