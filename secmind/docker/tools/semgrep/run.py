#!/usr/bin/env python3
"""Bounded offline Semgrep adapter for the SecMind sandbox contract."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

RULES = Path("/opt/secmind-rules")
INPUT = Path("/input")
OUTPUT = Path("/output/result.json")
RAW_RESULT = Path("/tmp/semgrep-result.json")  # noqa: S108 - private sandbox tmpfs
MAX_RAW_BYTES = 16 * 1024 * 1024
MAX_FINDINGS = 2_000
MAX_CANDIDATES = 10_000
TIMEOUT_SECONDS = 170

_SEVERITY = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
_CWE = re.compile(r"(?:CWE-)?([1-9][0-9]*)", flags=re.IGNORECASE)


def main() -> int:
    os.environ.update(
        {
            "HOME": "/tmp",  # noqa: S108 - private sandbox tmpfs
            "SEMGREP_CACHE_DIR": "/tmp/semgrep-cache",  # noqa: S108 - private sandbox tmpfs
            "SEMGREP_SEND_METRICS": "off",
            "XDG_CACHE_HOME": "/tmp/xdg-cache",  # noqa: S108 - private sandbox tmpfs
        }
    )
    command = [
        "semgrep",
        "--config",
        str(RULES),
        "--json-output",
        str(RAW_RESULT),
        "--metrics",
        "off",
        "--disable-version-check",
        "--no-rewrite-rule-ids",
        "--no-git-ignore",
        "--quiet",
        str(INPUT),
    ]
    try:
        process = subprocess.run(  # noqa: S603 - command is a fixed image-owned argv
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        _write_result("timeout", [], "Semgrep timed out.", error_code="TOOL_TIMEOUT")
        return 0
    if process.returncode not in {0, 1}:
        _write_result("error", [], "Semgrep scan failed.", error_code="SEMGREP_FAILED")
        return 0
    try:
        if RAW_RESULT.stat().st_size > MAX_RAW_BYTES:
            raise ValueError("Semgrep JSON exceeds the adapter limit")
        body = json.loads(RAW_RESULT.read_text(encoding="utf-8"))
        findings, rejected = normalize_semgrep(body)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        _write_result("error", [], "Semgrep returned invalid or oversized JSON.", error_code="SEMGREP_OUTPUT_INVALID")
        return 0
    scanned = body.get("paths", {}).get("scanned", []) if isinstance(body.get("paths"), dict) else []
    incomplete = rejected > 0
    _write_result(
        "error" if incomplete else "success",
        findings,
        (
            "Semgrep output was incomplete because one or more findings were rejected."
            if incomplete
            else f"Semgrep completed with {len(findings)} bounded finding(s)."
        ),
        error_code="SEMGREP_INCOMPLETE_RESULTS" if incomplete else None,
        files_scanned=len(scanned) if isinstance(scanned, list) else 0,
        rules_run=len({item["native_rule_id"] for item in findings}),
        rejected_findings=rejected,
    )
    return 0


def normalize_semgrep(body: object) -> tuple[list[dict[str, Any]], int]:
    if not isinstance(body, dict) or not isinstance(body.get("results", []), list):
        raise ValueError("Semgrep result must contain a results array")
    errors = body.get("errors", [])
    if not isinstance(errors, list) or errors:
        raise ValueError("Semgrep reported an incomplete scan")
    results = body["results"]
    findings: list[dict[str, Any]] = []
    rejected = max(0, len(results) - MAX_CANDIDATES)
    bindings: dict[str, tuple[int, str]] = {}
    for result in results[:MAX_CANDIDATES]:
        if len(findings) >= MAX_FINDINGS:
            rejected += 1
            continue
        normalized = _normalize_finding(result, bindings)
        if normalized is None:
            rejected += 1
            continue
        findings.append(normalized)
    findings.sort(key=lambda item: (item["path"], item["line"], item["native_rule_id"]))
    return findings, rejected


def _normalize_finding(
    result: object,
    bindings: dict[str, tuple[int, str]],
) -> dict[str, Any] | None:
    if not isinstance(result, dict):
        return None
    path = _bound_input_path(result.get("path"))
    if path is None:
        return None
    try:
        line = int((result.get("start") or {}).get("line", 0))
    except (AttributeError, TypeError, ValueError):
        return None
    binding = bindings.get(path)
    if binding is None:
        binding = _file_binding(path)
        if binding is None:
            return None
        bindings[path] = binding
    line_count, file_sha256 = binding
    if line < 1:
        return None
    if line > line_count:
        return None
    extra = result.get("extra")
    extra = extra if isinstance(extra, dict) else {}
    metadata = extra.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    native_rule_id = _text(result.get("check_id"), "semgrep.unknown", 160)
    weakness_ids = _weakness_ids(metadata.get("cwe"))
    normalized_rule_id = weakness_ids[0] if weakness_ids else native_rule_id
    message = _text(extra.get("message"), native_rule_id, 2_000)
    severity = _SEVERITY.get(str(extra.get("severity", "")).upper(), "UNKNOWN")
    remediation = _text(metadata.get("remediation"), "", 2_000) or None
    return {
        "rule_id": normalized_rule_id,
        "native_rule_id": native_rule_id,
        "normalized_rule_id": normalized_rule_id,
        "weakness_ids": weakness_ids,
        "path": path,
        "line": line,
        "file_sha256": file_sha256,
        "severity": severity,
        "confidence": "HIGH" if severity == "HIGH" else "MEDIUM",
        "title": message.splitlines()[0][:300],
        "description": message,
        "remediation": remediation,
    }


def _bound_input_path(value: object) -> str | None:
    raw = str(value or "").replace("\\", "/")
    if raw.startswith("/input/"):
        raw = raw[len("/input/") :]
    elif raw.startswith("./"):
        raw = raw[2:]
    candidate = PurePosixPath(raw)
    if not raw or candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        return None
    return candidate.as_posix()


def _file_binding(path: str) -> tuple[int, str] | None:
    try:
        root = INPUT.resolve(strict=True)
        candidate = INPUT.joinpath(*PurePosixPath(path).parts)
        if candidate.is_symlink():
            return None
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        if not resolved.is_file():
            return None
        digest = hashlib.sha256()
        line_count = 0
        nonempty = False
        last_byte = b""
        with resolved.open("rb") as stream:
            while chunk := stream.read(64 * 1024):
                nonempty = True
                digest.update(chunk)
                line_count += chunk.count(b"\n")
                last_byte = chunk[-1:]
        if nonempty and last_byte != b"\n":
            line_count += 1
        return line_count, digest.hexdigest()
    except (OSError, ValueError):
        return None


def _weakness_ids(value: object) -> list[str]:
    values = value if isinstance(value, list) else [value]
    weaknesses: set[str] = set()
    for item in values:
        match = _CWE.fullmatch(str(item or "").strip())
        if match:
            weaknesses.add(f"CWE-{match.group(1)}")
    return sorted(weaknesses)[:16]


def _text(value: object, default: str, limit: int) -> str:
    return str(value if value is not None else default).replace("\x00", "")[:limit]


def _write_result(
    status: str,
    findings: list[dict[str, Any]],
    summary: str,
    *,
    error_code: str | None = None,
    **metrics: int,
) -> None:
    payload = {
        "status": status,
        "data": {"findings": findings, **metrics},
        "summary": summary,
        "error_code": error_code,
    }
    OUTPUT.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
