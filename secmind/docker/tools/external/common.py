"""Small, dependency-free helpers for the immutable external-tool image."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

INPUT_ROOT = Path("/input")
OUTPUT_ROOT = Path("/output")


def input_files() -> list[Path]:
    """Return regular input files in deterministic relative-path order."""

    result: list[Path] = []
    for path in INPUT_ROOT.rglob("*"):
        if path.is_symlink():
            raise RuntimeError("symbolic links are not allowed in the scanner input")
        if path.is_file():
            result.append(path)
    return sorted(result, key=lambda value: value.relative_to(INPUT_ROOT).as_posix())


def relative_path(path: str | Path) -> str:
    candidate = Path(path).resolve()
    try:
        value = candidate.relative_to(INPUT_ROOT.resolve()).as_posix()
    except ValueError as exc:
        raise RuntimeError("scanner output path is outside /input") from exc
    if not value or value == "." or value.startswith("../") or "/../" in value:
        raise RuntimeError("scanner output path is unsafe")
    return value


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def line_count(path: Path) -> int:
    content = path.read_bytes()
    return max(1, content.count(b"\n") + (0 if content.endswith(b"\n") else 1))


def prepare_scan_input(files: list[Path]) -> tuple[Path, dict[str, Path]]:
    """Copy immutable input bytes to scanner-recognized manifest filenames.

    Calibration fixtures intentionally use descriptive names rather than
    package-manager names.  Syft and OSV identify ecosystems from filenames,
    so this creates a private, no-network staging tree without changing any
    bytes.  The returned map binds scanner source paths back to original input
    files for OSV findings.
    """

    root = Path("/tmp/secmind-scan")  # noqa: S108
    root.mkdir(parents=True, exist_ok=True)
    source_map: dict[str, Path] = {}
    for index, source in enumerate(files):
        content = source.read_bytes()
        destination_name = _recognized_manifest_name(source.name, content)
        if destination_name in source_map:
            stem = Path(destination_name).stem
            suffix = Path(destination_name).suffix
            destination_name = f"{stem}-{index}{suffix}"
        destination = root / destination_name
        destination.write_bytes(content)
        source_map[destination_name] = source
    return root, source_map


def _recognized_manifest_name(name: str, content: bytes) -> str:
    lowered = name.lower()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    if lowered.endswith(".mod") or re.search(r"(?m)^module\s+", text):
        return "go.mod"
    if "[[package]]" in text and "name =" in text:
        return "Cargo.lock"
    if lowered.endswith(".toml") and "[package]" in text:
        return "Cargo.toml"
    if lowered.endswith(".xml") or "<project" in text:
        return "pom.xml"
    if lowered.endswith(".json"):
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            value = None
        if isinstance(value, dict) and "lockfileVersion" in value:
            return "package-lock.json"
        if isinstance(value, dict) and "dependencies" in value:
            return "package.json"
    if re.search(r"(?m)^\s*[A-Za-z0-9_.-]+\s*==\s*[^\s#]+", text):
        return "requirements.txt"
    return name or "input"


def write_result(
    *,
    status: str,
    data: dict[str, Any] | None = None,
    summary: str = "",
    error_code: str | None = None,
    error_message: str | None = None,
) -> None:
    """Publish only bounded, non-sensitive JSON consumed by the runner."""

    body: dict[str, Any] = {
        "status": status,
        "summary": summary,
        "data": data or {},
    }
    if error_code:
        body["error_code"] = error_code
    if error_message:
        body["error_message"] = error_message
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    temporary = OUTPUT_ROOT / ".result.json.tmp"
    temporary.write_text(json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    os.replace(temporary, OUTPUT_ROOT / "result.json")
