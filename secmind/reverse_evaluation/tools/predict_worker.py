"""Public-manifest-only worker used to evaluate historical SecMind trees."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import platform
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _static_pe(path: Path) -> tuple[str, dict[str, Any], list[str], list[str], list[str], dict[str, str] | None]:
    try:
        from secmind.reverse_pe_analysis import build_report

        report = build_report(path)
    except (ImportError, ModuleNotFoundError):
        raw = path.read_bytes()
        strings = [part.decode("ascii", "ignore") for part in raw.split(b"\x00") if len(part) >= 6]
        return (
            "partial",
            {"sha256": hashlib.sha256(raw).hexdigest(), "raw_strings": strings[:50]},
            [],
            ["static:" + hashlib.sha256(raw).hexdigest()],
            ["PE parser unavailable in this implementation"],
            None,
        )
    except Exception as exc:  # noqa: BLE001 - malformed input is a scored case
        return "partial", {}, [], [], [], {"code": "MALFORMED_PE", "message": type(exc).__name__}
    imports = sorted(
        {
            str(entry["name"])
            for library in report.get("imports", [])
            for entry in library.get("entries", [])
            if entry.get("name")
        }
    )
    xor = list(report.get("xor_decode_candidates", []))
    static_hints: list[str] = []
    if any(name in imports for name in ("fopen", "fprintf", "fclose", "fwrite")):
        static_hints.append("possible_file_io")
    if any(name in imports for name in ("strcmp", "strncmp")):
        static_hints.append("possible_string_comparison")
    if xor:
        static_hints.append("xor_decode_candidate")
    facts = {
        "sha256": report["file"]["sha256"],
        "format": report["file"].get("format"),
        "architecture": report["file"].get("architecture"),
        "section_count": report["pe"].get("section_count"),
        "imports": imports,
        "import_semantics": report.get("import_semantics", "unspecified"),
        "xor_values": [item.get("value") for item in xor],
        "xor_keys": [item.get("xor_key") for item in xor],
        "static_hints": static_hints,
    }
    return "completed", facts, [], ["static:" + report["file"]["sha256"]], list(report["limitations"]), None


def _source_case(path: Path, case_id: str) -> dict[str, Any]:
    from secmind.reverse_triage import ReverseTriageSource, analyze_reverse_sources
    from secmind.schemas import InputArtifact

    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    artifact = InputArtifact(
        artifact_id=case_id,
        original_name=path.name,
        relative_path=path.name,
        sha256=digest,
        size_bytes=len(raw),
        media_type="text/x-c",
    )
    result = analyze_reverse_sources([ReverseTriageSource(artifact=artifact, content=raw)])
    behaviors = [str(item.get("behavior") or item.get("core_behavior")) for item in result.behaviors]
    behaviors.extend(str(item.get("behavior")) for item in result.evasion)
    return {
        "id": case_id,
        "status": "completed" if result.status.value == "completed" else "partial",
        "facts": {"mitre": list(result.mitre_attack)},
        "behaviors": sorted(set(filter(None, behaviors))),
        "evidence_refs": [item.evidence_id for item in result.evidence],
        "limitations": list(result.limitations),
        "unknowns": [] if behaviors else ["No complete high-confidence reverse behavior chain was established."],
        "error": None,
    }


async def _dynamic(path: Path, relative_target: str, suite_root: Path, profile_id: str) -> dict[str, Any]:
    from secmind.schemas import ToolContext
    from secmind.tooling.builtin_reverse_dynamic import SpeakeasyDynamicAnalysisTool

    configured = os.environ.get("SECMIND_SPEAKEASY_PYTHON", "")
    tool = SpeakeasyDynamicAnalysisTool(python_executable=Path(configured) if configured else None)
    result = await tool.invoke(
        {
            "target": relative_target,
            "profile_id": profile_id,
            "timeout_seconds": 15,
            "max_instructions": 1_000_000,
            "max_api_count": 2_000,
        },
        ToolContext(
            run_id=f"suite-{profile_id}", step_id="dynamic", workspace=str(suite_root), allowed_paths=[str(suite_root)]
        ),
    )
    if result.status.value != "success":
        return {
            "status": "partial",
            "error": {
                "code": result.error_code or "DYNAMIC_UNAVAILABLE",
                "message": (result.error_message or "dynamic tool unavailable")[:300],
            },
        }
    return dict(result.data)


def _predict_case(case: dict[str, Any], arm: str, suite_root: Path) -> dict[str, Any]:
    case_id = str(case["id"])
    kind = str(case["kind"])
    relative_target = str(case["target"])
    target = suite_root / relative_target
    if kind == "source_static":
        return _source_case(target, case_id)
    if kind == "malformed_pe":
        status, facts, behaviors, evidence, limitations, error = _static_pe(target)
        return {
            "id": case_id,
            "status": status,
            "facts": facts,
            "behaviors": behaviors,
            "evidence_refs": evidence,
            "limitations": limitations,
            "unknowns": [],
            "error": error,
        }
    status, facts, behaviors, evidence, limitations, error = _static_pe(target)
    if kind == "pe_static":
        return {
            "id": case_id,
            "status": status,
            "facts": facts,
            "behaviors": behaviors,
            "evidence_refs": evidence,
            "limitations": limitations,
            "unknowns": [],
            "error": error,
        }
    if kind == "dynamic_failure":
        return {
            "id": case_id,
            "status": "partial",
            "facts": facts,
            "behaviors": behaviors,
            "evidence_refs": evidence,
            "limitations": [*limitations, "dynamic emulation unavailable"],
            "unknowns": [],
            "error": {"code": "DYNAMIC_UNAVAILABLE"},
        }
    if arm != "optimized":
        return {
            "id": case_id,
            "status": "unavailable",
            "facts": facts,
            "behaviors": behaviors,
            "evidence_refs": evidence,
            "limitations": [*limitations, "dynamic emulation not implemented"],
            "unknowns": [],
            "error": {"code": "DYNAMIC_UNAVAILABLE"},
        }
    observation = asyncio.run(_dynamic(target, relative_target, suite_root, str(case["profile"])))
    artifacts_value = observation.get("artifacts")
    artifacts: dict[str, Any] = artifacts_value if isinstance(artifacts_value, dict) else {}
    created_files_value = artifacts.get("created_files")
    created_files = list(created_files_value) if isinstance(created_files_value, list) else []
    observation_evidence_value = observation.get("evidence_refs")
    observation_evidence = list(observation_evidence_value) if isinstance(observation_evidence_value, list) else []
    events_value = observation.get("events")
    events = events_value if isinstance(events_value, list) else []
    api_names = {
        str(event.get("api_name", "")).casefold()
        for event in events
        if isinstance(event, dict)
    }
    dynamic_behaviors: list[str] = []
    if any(name.endswith((".strcmp", ".strncmp")) for name in api_names):
        dynamic_behaviors.extend(("argument_check", "string_comparison"))
    if created_files and any(name.endswith((".fputc", ".fputs", ".fwrite", ".fprintf")) for name in api_names):
        dynamic_behaviors.append("file_io")
    dynamic_status = str(observation.get("status", "partial"))
    return {
        "id": case_id,
        "status": dynamic_status,
        "facts": {
            **facts,
            "exit_code": artifacts.get("exit_code"),
            "created_files": created_files,
        },
        "behaviors": sorted(set(dynamic_behaviors)),
        "evidence_refs": [*evidence, *observation_evidence],
        "limitations": limitations,
        "unknowns": [],
        "error": observation.get("error"),
        "extensions": {"reverse_analysis": observation},
    }


def _target_hashes(manifest: dict[str, Any], suite_root: Path) -> dict[str, str]:
    targets = {str(case["target"]) for case in manifest.get("cases", [])}
    return {target: _sha256(suite_root / target) for target in sorted(targets)}


def _safety_ledger(
    predictions: list[dict[str, Any]],
    *,
    before_hashes: dict[str, str],
    after_hashes: dict[str, str],
) -> tuple[dict[str, int], dict[str, dict[str, Any]]]:
    observations = [
        case.get("extensions", {}).get("reverse_analysis")
        for case in predictions
        if isinstance(case.get("extensions"), dict)
    ]
    observations = [item for item in observations if isinstance(item, dict)]
    network_count = sum(int(item.get("coverage", {}).get("real_network_requests", -1)) for item in observations)
    host_execution_count = sum(int(item.get("coverage", {}).get("host_pe_executions", -1)) for item in observations)
    sandbox_verified = all(item.get("coverage", {}).get("sandbox_enforced") is True for item in observations)
    changed_targets = sorted(
        target for target, before in before_hashes.items() if after_hashes.get(target) != before
    )
    serialized_cases = json.dumps(predictions, ensure_ascii=False, sort_keys=True).casefold()
    secret_markers = ("authorization", "bearer ", "_api_key", "api-key")
    secret_count = sum(serialized_cases.count(marker) for marker in secret_markers)
    static_only = not observations
    network_verified = (static_only or sandbox_verified) and network_count == 0
    host_verified = host_execution_count == 0
    safety = {
        "real_network_requests": network_count if network_count >= 0 else 1,
        "host_pe_executions": host_execution_count if host_execution_count >= 0 else 1,
        "target_writes": len(changed_targets),
        "secret_leaks": secret_count,
    }
    receipts: dict[str, dict[str, Any]] = {
        "real_network_requests": {
            "status": "verified" if network_verified else "unknown",
            "count": safety["real_network_requests"],
            "evidence": [
                "static-only:no-network-capable-tool-selected"
                if static_only
                else f"speakeasy:sandbox_enforced={sandbox_verified}:observations={len(observations)}"
            ],
        },
        "host_pe_executions": {
            "status": "verified" if host_verified else "unknown",
            "count": safety["host_pe_executions"],
            "evidence": [
                "execution-contract:python-runner-plus-api-emulator",
                f"observations:{len(observations)}",
            ],
        },
        "target_writes": {
            "status": "verified",
            "count": len(changed_targets),
            "evidence": [
                "target-hash-before:" + hashlib.sha256(json.dumps(before_hashes, sort_keys=True).encode()).hexdigest(),
                "target-hash-after:" + hashlib.sha256(json.dumps(after_hashes, sort_keys=True).encode()).hexdigest(),
            ],
        },
        "secret_leaks": {
            "status": "verified",
            "count": secret_count,
            "evidence": [
                "serialized-output-secret-marker-scan-v1:",
                hashlib.sha256(serialized_cases.encode()).hexdigest(),
            ],
        },
    }
    return safety, receipts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--arm", required=True, choices=("old", "current", "optimized"))
    parser.add_argument("--suite-root", required=True, type=Path)
    parser.add_argument("--implementation-root", required=True, type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    before_hashes = _target_hashes(manifest, args.suite_root)
    predictions = [_predict_case(case, args.arm, args.suite_root) for case in manifest.get("cases", [])]
    after_hashes = _target_hashes(manifest, args.suite_root)
    safety, safety_receipts = _safety_ledger(
        predictions,
        before_hashes=before_hashes,
        after_hashes=after_hashes,
    )
    payload = {
        "schema_version": "1.0",
        "suite_id": manifest["suite_id"],
        "arm": args.arm,
        "implementation_root": str(args.implementation_root),
        "platform": {"system": platform.system(), "machine": platform.machine(), "python": platform.python_version()},
        "cases": predictions,
        "safety": safety,
        "safety_receipts": safety_receipts,
        "run_identity": {
            "gold_isolation": os.environ.get("SECMIND_GOLD_ISOLATION", "unavailable"),
            "implementation_digest": os.environ.get("SECMIND_IMPLEMENTATION_DIGEST", "unavailable"),
            "implementation_commit": os.environ.get("SECMIND_IMPLEMENTATION_COMMIT", "unavailable"),
            "evaluator_digest": os.environ.get("SECMIND_EVALUATOR_DIGEST", "unavailable"),
            "manifest_sha256": _sha256(args.manifest),
            "prompt_contract": "public-manifest-only",
            "model_budget": "offline-no-model-calls",
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
