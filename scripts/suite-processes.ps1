# Shared process ownership and lifecycle locking.
function Get-SuiteComponent {
    param($Process, [string]$SuiteRoot)
    $prefix = ([IO.Path]::GetFullPath($SuiteRoot).TrimEnd('\') + '\').ToLowerInvariant()
    $command = ([string]$Process.CommandLine).Replace('/', '\').ToLowerInvariant()
    $executable = ([string]$Process.ExecutablePath).Replace('/', '\').ToLowerInvariant()
    if (-not ($command.Contains($prefix) -or $executable.StartsWith($prefix))) { return $null }
    if ($executable -eq ($prefix + '_runtime\tools\reqable\app\reqable.exe')) { return 'reqable' }
    if ($Process.Name -match '^javaw?\.exe$' -and $command.Contains($prefix + '_runtime\tools\burp\burpsuite-community.jar')) { return 'burp' }
    if ($command -match 'start-runtime-dispatcher\.ps1' -or ($command -match 'security.runtime' -and $command -match '\bdispatch\b')) { return 'dispatcher' }
    if ($command -match 'start-runtime-server\.ps1' -or ($command -match 'security.runtime' -and $command -match '\bserve\b')) { return 'runtime-server' }
    if ($command -match 'security_agent\.api|security-agent-api|\\an\\(启动在线|start-suite-api)\.ps1') { return 'an-api' }
    if ($command -match 'secmind\.api|secmind-api|\\secmind\\启动在线\.ps1') { return 'secmind' }
    if ($command -match '\\an\\frontend\\.*(vite|启动前端\.ps1)') { return 'frontend' }
}
function Get-SuiteProcesses {
    param([string]$SuiteRoot)
    $snapshot = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    $byId = @{}
    $components = @{}
    foreach ($entry in $snapshot) {
        $byId[[int]$entry.ProcessId] = $entry
        $components[[int]$entry.ProcessId] = Get-SuiteComponent $entry $SuiteRoot
    }
    foreach ($process in $snapshot) {
        if ($process.ProcessId -eq $PID) { continue }
        $component = $components[[int]$process.ProcessId]
        if ($component) {
            # PowerShell, cmd and launcher shims can sit between owned
            # processes without containing the suite path themselves.
            $groupRoot = [int]$process.ProcessId
            $cursor = $process
            $visited = @{}
            while ($byId.ContainsKey([int]$cursor.ParentProcessId)) {
                $parentId = [int]$cursor.ParentProcessId
                if ($visited.ContainsKey($parentId)) { break }
                $visited[$parentId] = $true
                $parent = $byId[$parentId]
                if ($parent.CreationDate -gt $cursor.CreationDate) { break }
                if ($components[$parentId] -eq $component) { $groupRoot = $parentId }
                $cursor = $parent
            }
            [pscustomobject]@{ Name=$component; ProcessId=[int]$process.ProcessId; ParentProcessId=[int]$process.ParentProcessId; RootProcessId=$groupRoot; Created=$process.CreationDate }
        }
    }
}
function Get-SuiteProcessRoots {
    param([array]$Processes)
    $identifiers = @($Processes | ForEach-Object { $_.ProcessId })
    @($Processes | Where-Object {
        if ($null -ne $_.RootProcessId) { $_.ProcessId -eq $_.RootProcessId }
        else { $_.ParentProcessId -notin $identifiers }
    })
}
function Enter-SuiteLifecycleLock {
    param([string]$SuiteRoot)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $digest = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($SuiteRoot.ToLowerInvariant()))).Replace('-','') }
    finally { $sha.Dispose() }
    $mutex = New-Object Threading.Mutex($false, ('Local\SecMindSuite-' + $digest))
    try { $acquired = $mutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $acquired = $true }
    if (-not $acquired) { $mutex.Dispose(); throw '本套件的启动或停止操作正在进行，请稍后重试。' }
    return $mutex
}
function Save-SuiteProcessState {
    param([string]$SuiteRoot)
    $folder = Join-Path $SuiteRoot '_runtime'
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    $state = @{ Root=$SuiteRoot; UpdatedAt=[DateTime]::UtcNow.ToString('o'); Processes=@(Get-SuiteProcesses $SuiteRoot) }
    $path = Join-Path $folder 'services.json'
    [IO.File]::WriteAllText(($path + '.tmp'), ($state | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath ($path + '.tmp') -Destination $path -Force
}
