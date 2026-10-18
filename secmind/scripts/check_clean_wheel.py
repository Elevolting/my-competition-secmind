"""Validate that a built wheel is self-contained and contains no repository files.

The wheel gate deliberately inspects the archive rather than the editable
checkout.  This catches accidental ``tests/``/``src/`` leakage, duplicate
archive members, unsafe paths, bytecode, and import failures that an editable
installation can hide.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


class WheelGateFailure(ValueError):
    """Raised when a wheel violates the clean-package contract."""


@dataclass(frozen=True)
class WheelGateResult:
    wheel: str
    package: str
    version: str
    file_count: int
    passed: bool = True

    def as_dict(self) -> dict[str, object]:
        return {
            "gate": "clean-wheel",
            "passed": self.passed,
            "wheel": self.wheel,
            "package": self.package,
            "version": self.version,
            "file_count": self.file_count,
        }


_ALLOWED_ROOTS = {"secmind", "secmind_distribution"}
_FORBIDDEN_PARTS = {
    ".git",
    ".github",
    ".venv",
    "__pycache__",
    "src",
    "tests",
    "test",
}


def validate_wheel(wheel_path: Path) -> WheelGateResult:
    """Validate one wheel and return machine-readable gate evidence."""

    wheel_path = wheel_path.resolve()
    if wheel_path.suffix.lower() != ".whl" or not wheel_path.is_file():
        raise WheelGateFailure(f"wheel does not exist or is not a .whl file: {wheel_path}")

    try:
        archive = zipfile.ZipFile(wheel_path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise WheelGateFailure(f"cannot read wheel archive: {wheel_path}") from exc
    with archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise WheelGateFailure("wheel contains duplicate archive members")
        if not names:
            raise WheelGateFailure("wheel archive is empty")

        for name in names:
            _validate_member_name(name)

        dist_info_roots = {
            PurePosixPath(name).parts[0]
            for name in names
            if len(PurePosixPath(name).parts) > 1 and PurePosixPath(name).parts[0].endswith(".dist-info")
        }
        if len(dist_info_roots) != 1:
            raise WheelGateFailure("wheel must contain exactly one top-level dist-info directory")
        dist_info_root = next(iter(dist_info_roots))
        if not dist_info_root.startswith("secmind-"):
            raise WheelGateFailure(f"unexpected dist-info directory: {dist_info_root!r}")

        metadata_names = sorted(name for name in names if name.endswith(".dist-info/METADATA"))
        wheel_metadata_names = sorted(name for name in names if name.endswith(".dist-info/WHEEL"))
        record_names = sorted(name for name in names if name.endswith(".dist-info/RECORD"))
        if len(metadata_names) != 1 or len(wheel_metadata_names) != 1 or len(record_names) != 1:
            raise WheelGateFailure("wheel must contain exactly one METADATA, WHEEL, and RECORD")

        try:
            metadata = archive.read(metadata_names[0]).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WheelGateFailure("wheel METADATA is not valid UTF-8") from exc
        package = _metadata_value(metadata, "Name")
        version = _metadata_value(metadata, "Version")
        if package != "secmind":
            raise WheelGateFailure(f"unexpected wheel project name: {package!r}")
        if not version:
            raise WheelGateFailure("wheel metadata has no version")

        package_members = [name for name in names if name.startswith("secmind/")]
        if "secmind/__init__.py" not in package_members:
            raise WheelGateFailure("wheel is missing secmind/__init__.py")
        if not package_members:
            raise WheelGateFailure("wheel contains no runtime package")

        # A wheel import is checked from an extracted temporary directory with
        # isolated interpreter flags so the repository checkout cannot satisfy
        # the import accidentally.
        with tempfile.TemporaryDirectory(prefix="secmind-clean-wheel-") as temp_dir:
            extracted = Path(temp_dir)
            archive.extractall(extracted)
            command = [
                sys.executable,
                "-I",
                "-c",
                (
                    "import sys; "
                    "sys.path.insert(0, sys.argv[1]); "
                    "import secmind; "
                    "assert secmind.__file__.startswith(sys.argv[1])"
                ),
                str(extracted),
            ]
            # The interpreter and extracted path are controlled by this gate;
            # no shell is involved and the archive was validated above.
            completed = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603
            if completed.returncode != 0:
                detail = (completed.stderr or completed.stdout).strip()
                raise WheelGateFailure(f"isolated wheel import failed: {detail}")

    return WheelGateResult(
        wheel=str(wheel_path),
        package=package,
        version=version,
        file_count=len(names),
    )


def _validate_member_name(name: str) -> None:
    if not name or "\\" in name:
        raise WheelGateFailure(f"wheel member is not a safe POSIX path: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise WheelGateFailure(f"wheel member escapes its root: {name!r}")
    if any(part in _FORBIDDEN_PARTS for part in path.parts):
        raise WheelGateFailure(f"wheel contains repository member: {name!r}")
    if name.endswith((".pyc", ".pyo")) or "/__pycache__/" in f"/{name}":
        raise WheelGateFailure(f"wheel contains bytecode: {name!r}")
    if path.parts and path.parts[0] not in _ALLOWED_ROOTS and not path.parts[0].endswith(".dist-info"):
        raise WheelGateFailure(f"wheel contains unexpected top-level member: {name!r}")


def _metadata_value(metadata: str, field: str) -> str:
    prefix = f"{field}:"
    for line in metadata.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].strip()
    return ""


def _find_wheel(path: Path | None) -> Path:
    if path is not None:
        return path
    candidates = sorted(Path("dist").glob("*.whl"))
    if len(candidates) != 1:
        raise WheelGateFailure(f"pass --wheel when dist contains zero or multiple wheels (found {len(candidates)})")
    return candidates[0]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, help="wheel to inspect (required when dist is ambiguous)")
    parser.add_argument("--output", type=Path, help="write JSON gate evidence to this file")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    try:
        result = validate_wheel(_find_wheel(arguments.wheel))
    except WheelGateFailure as exc:
        failure_payload = {"gate": "clean-wheel", "passed": False, "failure": str(exc)}
        rendered = json.dumps(failure_payload, ensure_ascii=False, indent=2) + "\n"
        if arguments.output is not None:
            arguments.output.write_text(rendered, encoding="utf-8")
        print(rendered, end="")
        print(f"Clean-wheel gate failed: {exc}", file=sys.stderr)
        return 1

    payload = json.dumps(result.as_dict(), ensure_ascii=False, indent=2) + "\n"
    if arguments.output is not None:
        arguments.output.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
