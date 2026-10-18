$ErrorActionPreference = 'Stop'
& (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'start-runtime-dispatcher-pi.ps1')
exit $LASTEXITCODE
