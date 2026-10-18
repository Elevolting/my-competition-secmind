"""Trust gate for the bundled TscanPlus executable."""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

TSCANPLUS_RELEASE_EXE_SHA256 = '5ad39426f5486d5adeba834066b425915f01f825124ddb79613b005a55c22571'


def _ps_quote(path: Path) -> str:
    return str(path).replace("'", "''")


def tscanplus_trusted(server: dict) -> bool:
    command = server.get('command')
    if not isinstance(command, str) or not command:
        return False
    path = Path(command)
    if not path.is_file() or sys.platform != 'win32':
        return False
    system_root = Path(os.environ.get('SystemRoot', r'C:\Windows'))
    powershell = system_root / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    security_module = system_root / (
        'System32/WindowsPowerShell/v1.0/Modules/'
        'Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1'
    )
    script = (f"Import-Module -Name '{_ps_quote(security_module)}' -ErrorAction Stop; "
              f"(Get-AuthenticodeSignature -LiteralPath '{_ps_quote(path)}').Status")
    try:
        result = subprocess.run(  # noqa: S603 - fixed system executable and quoted literal path
            [str(powershell), '-NoProfile', '-NonInteractive', '-Command', script],
            capture_output=True, text=True, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    if result.stdout.strip() == 'Valid':
        return True
    # The official v3.5.3 Windows archive has a mismatched PE signature.
    # Its GitHub release digest and extracted EXE digest were independently pinned.
    if result.stdout.strip() != 'HashMismatch' or path.name != 'TscanPlus_Win_Amd64.exe':
        return False
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest() == TSCANPLUS_RELEASE_EXE_SHA256
