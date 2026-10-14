$ErrorActionPreference = "Stop"

Set-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)

$env:SECMIND_API_HOST = "127.0.0.1"
$env:SECMIND_API_PORT = "8002"
$env:SECMIND_DEMO_MODE = "false"
$env:SECMIND_MODEL_MODE = "live"
$env:SECMIND_ALLOW_LIVE_MODELS = "true"
$env:SECMIND_UNSAFE_DEVELOPMENT_TOOLS = "true"
$env:SECMIND_MODEL_BASE_URL_PROVIDER = "deepseek"
$env:SECMIND_TRUSTED_MODEL_BASE_URLS = "https://newapi.boguan.cc/v1"
$env:SECMIND_QWEN_BASE_URL = "https://newapi.boguan.cc/v1"

uv run secmind-api
