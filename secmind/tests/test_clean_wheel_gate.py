from __future__ import annotations

import importlib.util
import sys
import zipfile
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).parents[1] / "scripts" / "check_clean_wheel.py"
_SPEC = importlib.util.spec_from_file_location("check_clean_wheel", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
gate = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = gate
_SPEC.loader.exec_module(gate)


def _write_wheel(path: Path, *extra: str, duplicate: bool = False) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        members = [
            ("secmind/__init__.py", b"__version__ = '1.0'\n"),
            ("secmind-1.0.dist-info/METADATA", b"Metadata-Version: 2.3\nName: secmind\nVersion: 1.0\n"),
            ("secmind-1.0.dist-info/WHEEL", b"Wheel-Version: 1.0\nTag: py3-none-any\n"),
            ("secmind-1.0.dist-info/RECORD", b""),
        ]
        members.extend((name, b"probe") for name in extra)
        for name, content in members:
            archive.writestr(name, content)
            if duplicate and name == "secmind/__init__.py":
                archive.writestr(name, content)


def test_clean_wheel_requires_runtime_only_members(tmp_path: Path) -> None:
    wheel = tmp_path / "secmind-1.0-py3-none-any.whl"
    _write_wheel(wheel)

    result = gate.validate_wheel(wheel)

    assert result.passed
    assert result.package == "secmind"
    assert result.version == "1.0"


@pytest.mark.parametrize(
    "extra,duplicate",
    [
        (("tests/test_probe.py",), False),
        (("secmind/__pycache__/probe.pyc",), False),
        (("other-1.0.dist-info/README",), False),
        ((), True),
    ],
)
def test_clean_wheel_rejects_leaks_and_duplicate_members(
    tmp_path: Path,
    extra: tuple[str, ...],
    duplicate: bool,
) -> None:
    wheel = tmp_path / "secmind-1.0-py3-none-any.whl"
    _write_wheel(wheel, *extra, duplicate=duplicate)

    with pytest.raises(gate.WheelGateFailure):
        gate.validate_wheel(wheel)
