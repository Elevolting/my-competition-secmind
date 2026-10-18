"""Run OSV-Scanner against the image-pinned offline vulnerability databases."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from common import file_sha256, input_files, prepare_scan_input, relative_path, write_result

REPORT = Path("/tmp/osv-report.json")  # noqa: S108


def _source_file(source: object, files_by_path: dict[str, Path], source_map: dict[str, Path]) -> tuple[str, Path]:
    if not isinstance(source, dict) or not isinstance(source.get("path"), str):
        raise ValueError("OSV result has no source path")
    scanner_candidate = Path(str(source["path"])).resolve()
    try:
        scanner_path = scanner_candidate.relative_to(Path("/tmp/secmind-scan").resolve()).as_posix()  # noqa: S108
    except ValueError as exc:
        raise ValueError("OSV result source is outside the private scan tree") from exc
    path = relative_path(source_map[scanner_path]) if scanner_path in source_map else scanner_path
    input_file = files_by_path.get(path)
    if input_file is None:
        raise ValueError("OSV result source is outside the immutable input manifest")
    return path, input_file


def main() -> int:
    try:
        files = input_files()
        files_by_path = {relative_path(path): path for path in files}
        scan_root, source_map = prepare_scan_input(files)
        completed = subprocess.run(  # noqa: S603
            [
                "/usr/local/bin/osv-scanner",
                "scan",
                "source",
                "--format",
                "json",
                "--output-file",
                str(REPORT),
                "--offline",
                "--offline-vulnerabilities",
                "--allow-no-lockfiles",
                "--no-resolve",
                "--recursive",
                f"{scan_root}",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={**__import__("os").environ, "HOME": "/opt/osv-home", "XDG_CACHE_HOME": "/opt/osv-home/.cache"},
        )
        # OSV-Scanner intentionally exits 1 when vulnerabilities are found;
        # that is a valid completed scan, while a missing report is not.
        if completed.returncode not in (0, 1) or not REPORT.is_file():
            write_result(
                status="error",
                summary="OSV-Scanner did not produce a complete offline report.",
                error_code="OSV_REPORT_MISSING",
                error_message="the immutable scanner exited without a JSON report",
            )
            return 0
        document = json.loads(REPORT.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or (
            "results" in document
            and document.get("results") is not None
            and not isinstance(document.get("results"), list)
        ):
            raise ValueError("OSV report is missing results")
        findings: list[dict[str, object]] = []
        for result in document.get("results") or []:
            if not isinstance(result, dict):
                raise ValueError("OSV result is not an object")
            path, input_file = _source_file(result.get("source"), files_by_path, source_map)
            packages = result.get("packages", [])
            if not isinstance(packages, list):
                raise ValueError("OSV package list is invalid")
            for package_result in packages:
                if not isinstance(package_result, dict):
                    raise ValueError("OSV package result is not an object")
                package = package_result.get("package")
                if not isinstance(package, dict):
                    raise ValueError("OSV package is missing")
                name = package.get("name")
                version = package.get("version")
                ecosystem = package.get("ecosystem")
                vulnerabilities = package_result.get("vulnerabilities", [])
                if not isinstance(name, str) or not isinstance(version, str) or not isinstance(ecosystem, str):
                    raise ValueError("OSV package identity is incomplete")
                if not isinstance(vulnerabilities, list):
                    raise ValueError("OSV vulnerability list is invalid")
                for vulnerability in vulnerabilities:
                    if not isinstance(vulnerability, dict) or not isinstance(vulnerability.get("id"), str):
                        raise ValueError("OSV vulnerability identity is incomplete")
                    findings.append(
                        {
                            "rule_id": "CWE-1104",
                            "native_rule_id": vulnerability["id"],
                            "path": path,
                            "line": 1,
                            "file_sha256": file_sha256(input_file),
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "title": f"Known vulnerability in {name}@{version}",
                            "package": f"{ecosystem}:{name}@{version}",
                        }
                    )
        write_result(
            status="success",
            data={
                "findings": findings,
                "files_scanned": len(files),
                "database_version": "offline-osv-v2.5.1",
                "rules_run": "osv-offline-v2.5.1",
            },
            summary=f"OSV-Scanner completed with {len(findings)} vulnerability finding(s).",
        )
        return 0
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        write_result(
            status="error",
            summary="OSV-Scanner output failed immutable validation.",
            error_code="OSV_OUTPUT_INVALID",
            error_message=type(exc).__name__,
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
