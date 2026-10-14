# Shared internal credential. Never pass it to a Worker CLI or print it.
function Initialize-PlanningCredential([string]$SuiteRoot) {
    if (-not [string]::IsNullOrWhiteSpace($env:SECURITY_RUNTIME_CALLBACK_TOKEN)) { return }
    $credentialDir = Join-Path $SuiteRoot '_runtime'
    New-Item -ItemType Directory -Force -Path $credentialDir | Out-Null
    $credentialPath = Join-Path $credentialDir 'planning-callback.token'
    if (-not (Test-Path -LiteralPath $credentialPath)) {
        $randomBytes = New-Object byte[] 32
        $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $generator.GetBytes($randomBytes) } finally { $generator.Dispose() }
        $temporaryCredentialPath = Join-Path $credentialDir ('planning-' + [Guid]::NewGuid().ToString('N') + '.tmp')
        try {
            [IO.File]::WriteAllText($temporaryCredentialPath, [Convert]::ToBase64String($randomBytes))
            [IO.File]::Move($temporaryCredentialPath, $credentialPath)
        } catch [IO.IOException] {
            if (-not (Test-Path -LiteralPath $credentialPath)) { throw }
        } finally {
            if (Test-Path -LiteralPath $temporaryCredentialPath) { Remove-Item -LiteralPath $temporaryCredentialPath }
        }
    }
    $env:SECURITY_RUNTIME_CALLBACK_TOKEN = [IO.File]::ReadAllText($credentialPath).Trim()
    if ($env:SECURITY_RUNTIME_CALLBACK_TOKEN.Length -lt 32) { throw 'Invalid planning callback credential file' }
}
