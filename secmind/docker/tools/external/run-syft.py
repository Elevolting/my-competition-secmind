"""Run Syft as an offline SBOM producer."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from common import input_files, prepare_scan_input, write_result

REPORT = Path("/tmp/syft-cyclonedx.json")  # noqa: S108


def _root_component_prefixes(scan_root: Path) -> tuple[str, ...]:
    """Exclude the application itself; the gate measures third-party inventory."""

    prefixes: list[str] = []
    package_lock = scan_root / "package-lock.json"
    if package_lock.is_file():
        try:
            document = json.loads(package_lock.read_text(encoding="utf-8"))
            name = document.get("packages", {}).get("", {}).get("name")
            if isinstance(name, str) and name:
                prefixes.append(f"pkg:npm/{name}@")
        except (OSError, json.JSONDecodeError, AttributeError):
            pass
    cargo_lock = scan_root / "Cargo.lock"
    if cargo_lock.is_file():
        try:
            match = re.search(r"(?ms)^\[\[package\]\]\s*name\s*=\s*\"([^\"]+)\"", cargo_lock.read_text())
            if match:
                prefixes.append(f"pkg:cargo/{match.group(1)}@")
        except OSError:
            pass
    for pom in sorted(scan_root.rglob("pom.xml")):
        try:
            text = pom.read_text(encoding="utf-8")
            group = re.search(r"<groupId>\s*([^<]+?)\s*</groupId>", text)
            artifact = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", text)
            version = re.search(r"<version>\s*([^<]+?)\s*</version>", text)
        except OSError:
            continue
        if group and artifact and version:
            prefixes.append(f"pkg:maven/{group.group(1).strip()}/{artifact.group(1).strip()}@")
    return tuple(prefixes)


def main() -> int:
    try:
        files = input_files()
        scan_root, _ = prepare_scan_input(files)
        root_prefixes = _root_component_prefixes(scan_root)
        completed = subprocess.run(  # noqa: S603
            [
                "/usr/local/bin/syft",
                f"dir:{scan_root}",
                "-o",
                f"cyclonedx-json={REPORT}",
                "--quiet",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if completed.returncode != 0 or not REPORT.is_file():
            write_result(
                status="error",
                summary="Syft did not produce a complete CycloneDX report.",
                error_code="SYFT_REPORT_MISSING",
                error_message="the immutable scanner exited without a JSON report",
            )
            return 0
        document = json.loads(REPORT.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or (
            "components" in document and not isinstance(document.get("components"), list)
        ):
            raise ValueError("CycloneDX document is missing components")
        components: list[dict[str, str]] = []
        seen: set[str] = set()
        for item in document.get("components", []):
            if not isinstance(item, dict):
                raise ValueError("CycloneDX component is not an object")
            purl = item.get("purl")
            if not isinstance(purl, str) or not purl:
                continue
            if any(purl.startswith(prefix) for prefix in root_prefixes):
                continue
            if purl in seen:
                continue
            seen.add(purl)
            components.append(
                {
                    "purl": purl,
                    "name": str(item.get("name", "")),
                    "version": str(item.get("version", "")),
                }
            )
        write_result(
            status="success",
            data={
                "findings": [],
                "components": components,
                "components_count": len(components),
                "files_scanned": len(files),
                "rules_run": "syft-cyclonedx-1.7-v1.51.0",
            },
            summary=f"Syft completed with {len(components)} component(s).",
        )
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        write_result(
            status="error",
            summary="Syft output failed immutable validation.",
            error_code="SYFT_OUTPUT_INVALID",
            error_message=type(exc).__name__,
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
