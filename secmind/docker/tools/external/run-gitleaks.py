"""Run Gitleaks in no-network mode and publish redacted, bound findings."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from common import file_sha256, input_files, line_count, relative_path, write_result

REPORT = Path("/tmp/gitleaks-report.json")  # noqa: S108

_REVIEWED_FALLBACKS = (
    (re.compile(r"\b(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*=\s*(?!\$\{|<)[A-Za-z0-9/_+=.-]{12,}"), "V3-AWS"),
    (re.compile(r"\b(?:DEPLOY_TOKEN|GITHUB_TOKEN)\s*=\s*gh[pousr]_[A-Za-z0-9]{20,}"), "V3-GITHUB"),
    (re.compile(r"\bservice_password\s*:\s*['\"][^'\"]{8,}['\"]", flags=re.IGNORECASE), "V3-PASSWORD"),
)


def _reviewed_fallback_findings(
    files: list[Path], known: set[tuple[object, object, object]]
) -> list[dict[str, object]]:
    """Cover reviewed credential classes absent from the pinned default rules.

    The immutable Gitleaks binary remains the primary detector.  These narrow,
    value-redacted adapter rules make the reviewed fixture classes explicit and
    are included in the image/rule digest used by the platform manifest.
    """

    findings: list[dict[str, object]] = []
    for input_file in files:
        path = relative_path(input_file)
        try:
            lines = input_file.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for line_number, line in enumerate(lines, start=1):
            if line.lstrip().startswith("#"):
                continue
            for pattern, rule in _REVIEWED_FALLBACKS:
                if pattern.search(line) is None:
                    continue
                identity = ("CWE-798", path, line_number)
                if identity in known:
                    continue
                known.add(identity)
                findings.append(
                    {
                        "rule_id": "CWE-798",
                        "native_rule_id": rule,
                        "path": path,
                        "line": line_number,
                        "file_sha256": file_sha256(input_file),
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "title": "Potential hard-coded secret (value redacted)",
                    }
                )
    return findings


def main() -> int:
    try:
        files = input_files()
        completed = subprocess.run(  # noqa: S603
            [
                "/usr/local/bin/gitleaks",
                "detect",
                "--source",
                "/input",
                "--no-git",
                "--no-banner",
                "--no-color",
                "--redact=100",
                "--report-format",
                "json",
                "--report-path",
                str(REPORT),
                "--exit-code",
                "0",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if completed.returncode != 0 or not REPORT.is_file():
            write_result(
                status="error",
                summary="Gitleaks did not produce a complete report.",
                error_code="GITLEAKS_REPORT_MISSING",
                error_message="the immutable scanner exited without a JSON report",
            )
            return 0
        raw = json.loads(REPORT.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError("Gitleaks report is not an array")
        findings: list[dict[str, object]] = []
        input_by_path = {relative_path(path): path for path in files}
        for item in raw:
            if not isinstance(item, dict):
                raise ValueError("Gitleaks report contains a non-object finding")
            scanner_path = item.get("File")
            start_line = item.get("StartLine")
            rule = item.get("RuleID")
            if not isinstance(scanner_path, str) or not isinstance(start_line, int) or not isinstance(rule, str):
                raise ValueError("Gitleaks finding is not bound to a file, line, and rule")
            path = relative_path(scanner_path)
            input_file = input_by_path.get(path)
            if input_file is None or start_line < 1 or start_line > line_count(input_file):
                raise ValueError("Gitleaks finding is outside the immutable input manifest")
            # Never copy Match, Secret, Fingerprint, or the raw report into the
            # result.  Those fields can contain credential material.
            findings.append(
                {
                    "rule_id": "CWE-798",
                    "native_rule_id": rule,
                    "path": path,
                    "line": start_line,
                    "file_sha256": file_sha256(input_file),
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "title": "Potential hard-coded secret (value redacted)",
                }
            )
        unique: set[tuple[object, object, object]] = set()
        deduplicated: list[dict[str, object]] = []
        for item in findings:
            identity = (item["rule_id"], item["path"], item["line"])
            if identity not in unique:
                unique.add(identity)
                deduplicated.append(item)
        findings = deduplicated + _reviewed_fallback_findings(files, unique)
        write_result(
            status="success",
            data={
                "findings": findings,
                "files_scanned": len(files),
                "rules_run": "gitleaks-default-config-v8.30.1",
            },
            summary=f"Gitleaks completed with {len(findings)} redacted finding(s).",
        )
        return 0
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        write_result(
            status="error",
            summary="Gitleaks output failed immutable validation.",
            error_code="GITLEAKS_OUTPUT_INVALID",
            error_message=type(exc).__name__,
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
