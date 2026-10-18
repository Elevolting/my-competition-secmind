#requires -Version 5.1
<#
  安全任务套件 · 一键环境检查与配置  setup-all.ps1
  用法:  powershell -ExecutionPolicy Bypass -File .\setup-all.ps1
  位置:  必须放在套件根目录（与 an/、secmind/、security-runtime/ 三个模块并列）
  功能:
    1) 检查/安装 uv（用户级，免管理员）→ 让 uv 提供 Python 3.13
    2) 检查 Node（缺失则给出安装命令，不阻塞其余步骤）
    3) 检查/安装默认 Dispatcher 所需的 Pi CLI；保留 Claude 回退检查
    4) Claude 已安装时把原生 exe 所在 bin 目录置顶到用户 PATH
    5) 补齐三个模块的 .env；为空的 Key 自动填入 an\.env 的同一个 DeepSeek Key，
       并为 security-runtime 自动生成/补全 ANTHROPIC_*(claude 密钥)
    6) 按 uv.lock 检查并修复三个 Python .venv
    7) 检查前端锁文件和 node_modules，不一致则 npm ci
  幂等：已满足的步骤会自动跳过，可重复执行。
#>
[CmdletBinding()]
param(
  [switch]$SkipVenv,      # 跳过 Python venv 重建检查
  [switch]$SkipFrontend,  # 跳过前端依赖检查
  [switch]$Quiet          # 精简输出（仍打印关键 OK/失败）
)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$hadError = $false
# 兼容旧版 Windows PowerShell：强制 TLS1.2（否则下载 GitHub/依赖会失败）
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
$uvDir = Join-Path $env:USERPROFILE '.local\bin'
if (Test-Path (Join-Path $uvDir 'uv.exe')) { $env:Path = "$uvDir;$env:Path" }

function Say  { param($c,$m) if(-not $Quiet -or $c -eq 'Red' -or $c -eq 'Green'){ Write-Host $m -ForegroundColor $c } }
function Get-EnvVal { param([string]$file,[string]$key)
  if (-not (Test-Path -LiteralPath $file)) { return $null }
  foreach ($line in (Get-Content -LiteralPath $file)) {
    $t = $line.Trim()
    if ($t -and -not $t.StartsWith('#') -and $t.Contains('=')) {
      $k = $t.Substring(0, $t.IndexOf('=')).Trim()
      if ($k -eq $key) { return $t.Substring($t.IndexOf('=') + 1).Trim().Trim('"').Trim("'") }
    }
  }
  return $null
}
function Set-EnvVal { param([string]$file,[string]$key,[string]$value)
  if (-not (Test-Path -LiteralPath $file)) { throw "缺少文件 $file" }
  $lines = @(Get-Content -LiteralPath $file); $found = $false
  for ($i = 0; $i -lt $lines.Count; $i++) {
    $t = $lines[$i].Trim()
    if ($t -and -not $t.StartsWith('#') -and $t.Contains('=')) {
      if ($t.Substring(0, $t.IndexOf('=')).Trim() -eq $key) { $lines[$i] = "$key=$value"; $found = $true }
    }
  }
  if (-not $found) { $lines += "$key=$value" }
  # 始终写“无 BOM”UTF-8：Windows PowerShell 5.1 的 Set-Content -Encoding utf8 会加 BOM，
  # 导致 .env 首行变量（如 ANTHROPIC_MODEL）被 dotenv 解析异常。
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllLines($file, $lines, $utf8NoBom)
}
function Ensure-UserPath { param([string]$dir)
  $up = [Environment]::GetEnvironmentVariable('Path', 'User')
  if ($up -notlike "*$dir*") {
    [Environment]::SetEnvironmentVariable('Path', "$dir;$up", 'User')
    Say Cyan "[设置] 已把 $dir 写入用户 PATH（新开终端生效）"
  }
}

Write-Host "================= 安全任务套件 · 一键环境检查与配置 =================" -ForegroundColor Magenta
Write-Host "套件根目录: $root" -ForegroundColor DarkGray

# ---------- 0) 目录合法性 ----------
foreach ($d in 'an', 'secmind', 'security-runtime') {
  if (-not (Test-Path (Join-Path $root $d))) { Say Red "[失败] 缺少模块目录 $d —— 请把脚本放在套件根目录（含 an/secmind/security-runtime）"; exit 1 }
}

# ---------- 1) uv ----------
if (Get-Command uv -ErrorAction SilentlyContinue) {
  $uvVer = (uv --version 2>$null | Out-String).Trim()
  Say Green "[OK]   uv 已安装: $uvVer"
} else {
  Say Cyan "[安装] 未检测到 uv，正在下载官方版本..."
  try {
    $dst = Join-Path $env:USERPROFILE '.local\bin'
    New-Item -ItemType Directory -Force -Path $dst | Out-Null
    $zip = Join-Path $env:TEMP 'uv-setup.zip'
    Invoke-WebRequest -Uri 'https://github.com/astral-sh/uv/releases/latest/download/uv-x86_64-pc-windows-msvc.zip' -OutFile $zip -UseBasicParsing
    $ex = Join-Path $env:TEMP 'uv-setup-extract'
    if (Test-Path $ex) { Remove-Item $ex -Recurse -Force }
    Expand-Archive -Path $zip -DestinationPath $ex -Force
    Copy-Item (Get-ChildItem $ex -Recurse -Filter 'uv.exe' | Select-Object -First 1).FullName (Join-Path $dst 'uv.exe') -Force
    $env:Path = "$dst;$env:Path"
    Say Green "[OK]   uv 已安装: $((uv --version 2>&1 | Out-String).Trim())"
  } catch { Say Red "[失败] uv 自动安装失败: $($_.Exception.Message)"; Say Yellow "[提示] 可手动安装: winget install --id Astral-sh.uv -e"; $hadError = $true }
}
if (Get-Command uv -ErrorAction SilentlyContinue) { Ensure-UserPath $uvDir }

# ---------- 2) Python 3.13（由 uv 托管） ----------
if (Get-Command uv -ErrorAction SilentlyContinue) {
  $py = uv python find 3.13 2>$null
  if ($LASTEXITCODE -eq 0 -and $py) { Say Green "[OK]   Python 3.13: $py" }
  else {
    Say Cyan "[安装] 让 uv 下载 Python 3.13 ..."
    & uv python install 3.13 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { Say Green "[OK]   Python 3.13 已就绪" } else { Say Red "[失败] Python 3.13 下载失败"; $hadError = $true }
  }
} else { Say Yellow "[提示] 未安装 uv，跳过 Python 检查" }

# ---------- 3) Node ----------
$node = Get-Command node -ErrorAction SilentlyContinue
if ($node) { Say Green "[OK]   Node $((node --version | Out-String).Trim())" }
else { Say Yellow "[提示] 未检测到 Node —— 前端(5173)需要它。安装: winget install --id OpenJS.NodeJS.LTS -e （装完重开终端）" }

# ---------- 4) 默认 Pi CLI 与可选 Claude CLI ----------
$pi = Get-Command pi -ErrorAction SilentlyContinue
if (-not $pi) {
  $npm = Get-Command npm -ErrorAction SilentlyContinue
  if ($npm) {
    Say Cyan '[安装] 通过 npm 安装 Pi CLI ...'
    & npm install -g @mariozechner/pi-coding-agent 2>&1 | Out-Null
    $pi = Get-Command pi -ErrorAction SilentlyContinue
    if (-not $pi) { Say Red '[失败] Pi CLI 安装后仍不可用'; $hadError = $true }
  } else { Say Red '[失败] 未检测到 npm，无法安装默认 Dispatcher 所需的 Pi CLI'; $hadError = $true }
}
if ($pi) { Say Green "[OK]   pi: $($pi.Source)" }

$claude = Get-Command claude -ErrorAction SilentlyContinue
if ($claude) { Say Green "[OK]   claude: $($claude.Source)" }
else { Say Yellow '[提示] Claude CLI 未安装；仅使用 Claude 回退配置时需要' }

# ---------- 5) claude 原生 exe 置顶 PATH（Windows 关键修复） ----------
if ($claude) {
  $native = $null
  if ($claude.Source -match '\.exe$') { $native = Split-Path $claude.Source }
  $cand = Join-Path $env:APPDATA 'npm\node_modules\@anthropic-ai\claude-code\bin'
  if (Test-Path (Join-Path $cand 'claude.exe')) { $native = $cand }
  if ($native) {
    Ensure-UserPath $native
    if ($env:Path -notlike "*$native*") { $env:Path = "$native;$env:Path" }
    Say Green "[OK]   claude 将解析为原生 exe（绕过 cmd 截断问题）: $native\claude.exe"
  } else { Say Yellow "[提示] 未找到 claude 原生 exe（bin\claude.exe）。若渗透任务解析失败，需手工将其 bin 目录置顶 PATH。" }
}

# ---------- 6) .env 补齐 + DeepSeek/claude Key 自动注入 ----------
Say Cyan "-------- 配置文件 (.env) 与密钥 --------"
$anEnv  = Join-Path $root 'an\.env'
$secEnv = Join-Path $root 'secmind\.env'
$rtEnv  = Join-Path $root 'security-runtime\.env'

if (-not (Test-Path -LiteralPath $anEnv))  { Copy-Item (Join-Path $root 'an\.env.example') $anEnv;  Say Yellow "[生成] an\.env（由 .env.example 复制，需确认模型/端口）" }
if (-not (Test-Path -LiteralPath $secEnv)) { Copy-Item (Join-Path $root 'secmind\.env.example') $secEnv; Say Yellow "[生成] secmind\.env（由 .env.example 复制，需确认模型/端口）" }

$anKey = Get-EnvVal $anEnv 'SECURITY_AGENT_MODEL_API_KEY'
if (-not (Test-Path -LiteralPath $rtEnv)) {
  $tok = if ($anKey) { $anKey } else { '' }
  $rtLines = @("ANTHROPIC_MODEL=deepseek-v4-flash", "ANTHROPIC_BASE_URL=https://api.deepseek.com/anthropic", "ANTHROPIC_AUTH_TOKEN=$tok")
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllLines($rtEnv, $rtLines, $utf8NoBom)
  Say Yellow "[生成] security-runtime\.env（含 claude 的 ANTHROPIC_* 三变量）"
}
# 空白 Key 一律复制 an 里的同一个 DeepSeek Key
$fillMap = @(
  @{ f = $anEnv;  k = 'SECURITY_AGENT_MODEL_API_KEY' },
  @{ f = $secEnv; k = 'SECMIND_DEEPSEEK_API_KEY' },
  @{ f = $secEnv; k = 'SECMIND_QWEN_API_KEY' },
  @{ f = $rtEnv;  k = 'ANTHROPIC_AUTH_TOKEN' }
)
foreach ($m in $fillMap) {
  $v = Get-EnvVal $m.f $m.k
  if ([string]::IsNullOrWhiteSpace($v)) {
    if ($anKey) { Set-EnvVal $m.f $m.k $anKey; Say Yellow "[注入] $([IO.Path]::GetFileName($m.f)) 的 $($m.k) 已填入 DeepSeek Key" }
    else { Say Yellow "[提示] $([IO.Path]::GetFileName($m.f)) 的 $($m.k) 为空且没有可复制的 Key —— 请手工填写后再启动在线功能" }
  }
}
# security-runtime 模型/URL 默认值补齐
if ([string]::IsNullOrWhiteSpace((Get-EnvVal $rtEnv 'ANTHROPIC_MODEL')))     { Set-EnvVal $rtEnv 'ANTHROPIC_MODEL' 'deepseek-v4-flash'; Say Yellow "[补齐] security-runtime\.env ANTHROPIC_MODEL=deepseek-v4-flash" }
if ([string]::IsNullOrWhiteSpace((Get-EnvVal $rtEnv 'ANTHROPIC_BASE_URL')))  { Set-EnvVal $rtEnv 'ANTHROPIC_BASE_URL' 'https://api.deepseek.com/anthropic'; Say Yellow "[补齐] security-runtime\.env ANTHROPIC_BASE_URL" }
# secmind 的 URL 纯文本校验提示
foreach ($m in @(@{f=$secEnv;k='SECMIND_QWEN_BASE_URL'}, @{f=$secEnv;k='SECMIND_TRUSTED_MODEL_BASE_URLS'}, @{f=$anEnv;k='SECURITY_AGENT_MODEL_BASE_URL'})) {
  $u = Get-EnvVal $m.f $m.k
  if ($u -and $u -notmatch '^https?://') { Say Yellow "[提示] $([IO.Path]::GetFileName($m.f)) 的 $($m.k) 不是纯 URL（$u），请修正为 https://api.deepseek.com 形式" }
}
if ([string]::IsNullOrWhiteSpace($anKey)) { Say Red "[失败] an\.env 缺少 SECURITY_AGENT_MODEL_API_KEY，无法自动注入；请先填写" ; $hadError = $true }
else { Say Green "[OK]   三处 .env 均已含可用的 DeepSeek Key（模型默认 deepseek-v4-flash，按账号可用性自行调整）" }

# ---------- 7) Python venv 同步（必要时） ----------
if (-not $SkipVenv) {
  Say Cyan "-------- Python 虚拟环境 --------"
  if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Say Red "[失败] 未安装 uv，无法检查或修复 Python 环境"
    $hadError = $true
  } else {
    foreach ($proj in @('an', 'secmind', (Join-Path 'security-runtime' 'security-runtime'))) {
      $projRoot = Join-Path $root $proj
      $py = Join-Path $projRoot '.venv\Scripts\python.exe'
      Push-Location $projRoot
      try {
        & uv sync --locked --inexact --check --offline 2>&1 | Out-Null
        $need = $LASTEXITCODE -ne 0
        if (-not $need -and (Test-Path -LiteralPath $py)) {
          & $py -c 'pass' 2>&1 | Out-Null
          $need = $LASTEXITCODE -ne 0
        } else { $need = $true }
        if ($need) {
          Say Cyan "[同步] $proj 的 .venv 与 uv.lock 不一致，正在修复..."
          & uv sync --locked --inexact 2>&1 | ForEach-Object { Write-Host $_ -ForegroundColor DarkGray }
          $code = $LASTEXITCODE
          if ($code -eq 0 -and (Test-Path -LiteralPath $py)) {
            & $py -c 'pass' 2>&1 | Out-Null
            $code = $LASTEXITCODE
          }
          if ($code -eq 0) { Say Green "[OK]   $proj .venv 已按 uv.lock 同步" }
          else { Say Red "[失败] $proj 环境同步失败 (exit=$code)"; $hadError = $true }
        } else { Say Green "[OK]   $proj .venv 与 uv.lock 一致" }
      } finally { Pop-Location }
    }
  }
}

# ---------- 8) 前端依赖 ----------
if (-not $SkipFrontend) {
  Say Cyan "-------- 前端依赖 --------"
  $vite = Join-Path $root 'an\frontend\node_modules\.bin\vite.cmd'
  if (Get-Command npm -ErrorAction SilentlyContinue) {
    Push-Location (Join-Path $root 'an\frontend')
    try {
      & npm ci --dry-run --offline --ignore-scripts --no-audit --no-fund --silent 2>&1 | Out-Null
      $lockOk = $LASTEXITCODE -eq 0
      & npm ls --depth=0 --omit=dev --silent 2>&1 | Out-Null
      $treeOk = $LASTEXITCODE -eq 0
      if ($lockOk -and $treeOk -and (Test-Path -LiteralPath $vite)) {
        Say Green "[OK]   前端依赖与 package-lock.json 一致"
      } else {
        Say Cyan "[同步] an/frontend 执行 npm ci ..."
        & npm ci 2>&1 | ForEach-Object { Write-Host $_ -ForegroundColor DarkGray }
        $code = $LASTEXITCODE
        if ($code -eq 0 -and (Test-Path -LiteralPath $vite)) { Say Green "[OK]   前端依赖就绪" }
        else { Say Red "[失败] npm ci 失败 (exit=$code)"; $hadError = $true }
      }
    } finally { Pop-Location }
  } else { Say Red "[失败] 未安装 npm，无法检查或修复前端依赖"; $hadError = $true }
}

# ---------- 汇总 ----------
Write-Host "================= 汇总 =================" -ForegroundColor Magenta
$chk = @()
$chk += "uv        : $(if(Get-Command uv -EA SilentlyContinue){(uv --version 2>&1|Out-String).Trim()}else{'缺失'})"
$chk += "Python3.13: $(if((Get-Command uv -EA SilentlyContinue) -and (uv python find 3.13 2>$null)){'就绪'}else{'缺失'})"
$chk += "Node      : $(if(Get-Command node -EA SilentlyContinue){(node --version|Out-String).Trim()}else{'缺失(前端需要)'})"
$chk += "claude    : $(if(Get-Command claude -EA SilentlyContinue){'就绪'}else{'缺失(仅渗透需要)'})"
foreach($proj in @('an','secmind','security-runtime\security-runtime')){ $py=Join-Path $root "$proj\.venv\Scripts\python.exe"; $ok=Test-Path $py; $chk += "venv ${proj}: $(if($ok){'OK'}else{'缺失'})" }
$chk += "Key       : $(if(Get-EnvVal $anEnv 'SECURITY_AGENT_MODEL_API_KEY'){'已填'}else{'缺失'})"
$chk | ForEach-Object { Write-Host "  $_" }
if ($hadError) { Write-Host "存在失败项，请按上方 [失败]/[提示] 处理；多数不影响幂等重跑，可直接再执行本脚本。" -ForegroundColor Yellow }
Write-Host ""
Write-Host "配置完成。下一步:" -ForegroundColor Cyan
Write-Host "  启动全部服务 : powershell -ExecutionPolicy Bypass -File .\start-all.ps1" -ForegroundColor White
Write-Host "  (只启服务不启渗透 Dispatcher: 加 -SkipDispatcher)" -ForegroundColor DarkGray
if ($hadError) { exit 1 }




