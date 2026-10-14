from __future__ import annotations

import hashlib
from types import SimpleNamespace

from security_agent import bundled_integrity


def test_tscanplus_allows_only_pinned_release_after_signature_mismatch(tmp_path, monkeypatch):
    path = tmp_path / 'TscanPlus_Win_Amd64.exe'
    path.write_bytes(b'official release bytes')
    monkeypatch.setattr(bundled_integrity.sys, 'platform', 'win32')
    monkeypatch.setattr(bundled_integrity, 'TSCANPLUS_RELEASE_EXE_SHA256',
                        hashlib.sha256(path.read_bytes()).hexdigest())
    monkeypatch.setattr(bundled_integrity.subprocess, 'run',
                        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout='HashMismatch\n'))

    assert bundled_integrity.tscanplus_trusted({'command': str(path)})
    path.write_bytes(b'changed bytes')
    assert not bundled_integrity.tscanplus_trusted({'command': str(path)})


def test_tscanplus_rejects_unverified_signature_status(tmp_path, monkeypatch):
    path = tmp_path / 'TscanPlus_Win_Amd64.exe'
    path.write_bytes(b'unknown release')
    monkeypatch.setattr(bundled_integrity.sys, 'platform', 'win32')
    monkeypatch.setattr(bundled_integrity.subprocess, 'run',
                        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout='UnknownError\n'))
    assert not bundled_integrity.tscanplus_trusted({'command': str(path)})
