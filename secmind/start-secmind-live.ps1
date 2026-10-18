$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$env:SECMIND_API_HOST = "127.0.0.1"
$env:SECMIND_API_PORT = "8002"
$env:SECMIND_DEMO_MODE = "false"
$env:SECMIND_MODEL_MODE = "live"
$env:SECMIND_ALLOW_LIVE_MODELS = "true"
$env:SECMIND_UNSAFE_DEVELOPMENT_TOOLS = "true"
$env:SECMIND_MODEL_BASE_URL_PROVIDER = "deepseek"
$env:SECMIND_TRUSTED_MODEL_BASE_URLS = "https://api.deepseek.com"
$env:SECMIND_QWEN_BASE_URL = "https://api.deepseek.com"

# Provider credentials and model names continue to come from the existing
# local .env; this launcher neither contains nor prints them.
uv run secmind-api
