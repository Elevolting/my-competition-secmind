from __future__ import annotations

import argparse
import asyncio
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any
from uuid import uuid4

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.config import Settings
from secmind.replay import ReplayError, ReplayManager
from secmind.runtime import build_runtime
from secmind.schemas import AttachmentRef, RunStatus, TaskRequest
from secmind_dev.evaluation import (
    REQUIRED_RELEASE_TOOLS,
    BenchmarkDefinition,
    BenchmarkProfile,
    EvaluationError,
    ReplayCheck,
    RunEvaluation,
    ToolchainEvidence,
    build_evaluation_report,
    dataset_bundle_sha256,
    dataset_sha256,
)

_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_DEFAULT_SYNTHETIC_CASES = Path("evaluation/cases.json")
_DEFAULT_REAL_CASES = Path("evaluation/real-projects.json")


async def evaluate(
    repetitions: int = 3,
    *,
    profile: BenchmarkProfile = BenchmarkProfile.SYNTHETIC_SMOKE,
    cases_path: Path = _DEFAULT_SYNTHETIC_CASES,
    toolchain_evidence_path: Path | None = None,
    sandbox_runner_url: str = "",
    timeout_seconds: float = 30,
) -> dict[str, object]:
    if repetitions < 1:
        raise EvaluationError("repetitions must be positive")
    cases = _load_cases(cases_path, profile)
    dataset_digest = (
        dataset_sha256(cases_path)
        if profile is BenchmarkProfile.SYNTHETIC_SMOKE
        else dataset_bundle_sha256(cases_path, [str(case["project_path"]) for case in cases])
    )
    toolchain_evidence = _load_toolchain_evidence(profile, dataset_digest, toolchain_evidence_path)
    languages = tuple(
        sorted(
            {language for case in cases for language in case.get("languages", [])}
            or ({"python"} if profile is BenchmarkProfile.SYNTHETIC_SMOKE else set())
        )
    )
    definition = BenchmarkDefinition(
        profile=profile,
        dataset_id=f"{cases_path.stem}:{dataset_digest[:16]}",
        dataset_kind=(
            "synthetic-inline-single-file" if profile is BenchmarkProfile.SYNTHETIC_SMOKE else "real-multifile-projects"
        ),
        declared_case_count=len(cases),
        declared_repetitions=repetitions,
        languages=languages,
        required_tools=(REQUIRED_RELEASE_TOOLS if profile is BenchmarkProfile.TOOL_BACKED else frozenset()),
        toolchain_evidence=toolchain_evidence,
    )
    observations: list[RunEvaluation] = []
    with tempfile.TemporaryDirectory(prefix="secmind-evaluation-") as temporary:
        root = Path(temporary)
        settings = _evaluation_settings(root, profile, sandbox_runner_url)
        settings.prepare_directories()
        service, gateway = build_runtime(settings)
        replay_manager = ReplayManager(ContentAddressedArtifactStore(settings.artifact_root))
        try:
            await service.startup()
            for repetition in range(1, repetitions + 1):
                for case in cases:
                    attachment = _stage_case(case, cases_path, settings.input_root, repetition, profile)
                    run_id = f"eval-{uuid4()}"
                    submitted_run_id = service.submit(
                        TaskRequest(
                            client_request_id=run_id,
                            objective="audit the supplied code and produce an evidence-backed report",
                            attachments=[AttachmentRef(ref=attachment)],
                        )
                    )
                    async with asyncio.timeout(timeout_seconds):
                        while True:
                            state = service.state(submitted_run_id)
                            if state.status not in {RunStatus.PENDING, RunStatus.RUNNING}:
                                break
                            await asyncio.sleep(0.02)

                    ledger_events = service.ledger.events(submitted_run_id)
                    ledger_valid = bool(ledger_events) and service.ledger.verify(submitted_run_id)
                    evidence_ids = {item.evidence_id for item in state.evidence}
                    findings_with_evidence = sum(
                        bool(finding.evidence_ids) and set(finding.evidence_ids) <= evidence_ids
                        for finding in state.findings
                    )
                    executed_tools = tuple(
                        sorted(
                            {
                                str(event.payload["tool"])
                                for event in ledger_events
                                if event.event_type in {"tool.started", "tool.completed"}
                                and isinstance(event.payload, dict)
                                and isinstance(event.payload.get("tool"), str)
                            }
                        )
                    )
                    replay_check = ReplayCheck.NOT_EVALUATED
                    if state.replay_bundle is not None:
                        try:
                            replay_manager.verify_only(state.replay_bundle)
                        except (ReplayError, OSError, ValueError):
                            replay_check = ReplayCheck.FAILED
                        else:
                            replay_check = ReplayCheck.VERIFIED
                    expected_rule_ids = frozenset(str(item) for item in case["expected_rule_ids"])
                    found_rule_ids = frozenset(item.rule_id for item in state.findings)
                    expected_high = frozenset(str(item) for item in case.get("expected_high_critical_rule_ids", []))
                    found_high = frozenset(
                        item.rule_id for item in state.findings if item.severity in {"HIGH", "CRITICAL"}
                    )
                    observations.append(
                        RunEvaluation(
                            case_id=str(case["name"]),
                            repetition=repetition,
                            status=state.status.value,
                            expected_rule_ids=expected_rule_ids,
                            found_rule_ids=found_rule_ids,
                            finding_count=len(state.findings),
                            findings_with_valid_evidence=findings_with_evidence,
                            within_finding_limit=len(state.findings) <= int(case["max_findings"]),
                            ledger_event_count=len(ledger_events),
                            ledger_valid=ledger_valid,
                            replay_check=replay_check,
                            provider_requests=state.budget.usage.provider_requests,
                            model_cost_units=state.budget.usage.cost_units,
                            execution_backend=(
                                "host-subprocess-development"
                                if profile is BenchmarkProfile.SYNTHETIC_SMOKE
                                else "sandbox-runner"
                            ),
                            executed_tools=executed_tools,
                            expected_high_critical_rule_ids=expected_high,
                            found_high_critical_rule_ids=found_high,
                        )
                    )
                print(
                    f"[{profile.value}] completed repetition {repetition}/{repetitions} "
                    f"({len(observations)}/{len(cases) * repetitions} runs)",
                    file=sys.stderr,
                    flush=True,
                )
        finally:
            await service.shutdown()
            await gateway.close()
    report = build_evaluation_report(definition, observations)
    report["command_gate"] = _command_gate(profile, report)
    return report


def _evaluation_settings(root: Path, profile: BenchmarkProfile, sandbox_runner_url: str) -> Settings:
    if profile is BenchmarkProfile.TOOL_BACKED and not sandbox_runner_url:
        sandbox_runner_url = Settings().sandbox_runner_url
    if profile is BenchmarkProfile.TOOL_BACKED and not sandbox_runner_url:
        raise EvaluationError("tool-backed benchmark requires an explicit sandbox runner URL")
    return Settings(
        env="development",
        runtime_role="embedded",
        demo_mode=True,
        model_mode="offline",
        allow_live_models=False,
        max_model_tier=5.4,
        unsafe_development_tools=profile is BenchmarkProfile.SYNTHETIC_SMOKE,
        sandbox_runner_url=sandbox_runner_url if profile is BenchmarkProfile.TOOL_BACKED else "",
        database_url=f"sqlite:///{(root / 'evaluation.db').as_posix()}",
        input_root=root / "inputs",
        upload_root=root / "uploads",
        run_root=root / "runs",
        artifact_root=root / "artifacts",
    )


def _load_cases(path: Path, profile: BenchmarkProfile) -> list[dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvaluationError(f"evaluation dataset is unavailable or invalid: {path}") from exc
    if not isinstance(raw, list) or not raw:
        raise EvaluationError("evaluation dataset must be a non-empty JSON array")
    cases: list[dict[str, Any]] = []
    names: set[str] = set()
    for raw_case in raw:
        if not isinstance(raw_case, dict):
            raise EvaluationError("every evaluation case must be a JSON object")
        name = raw_case.get("name")
        expected = raw_case.get("expected_rule_ids")
        maximum = raw_case.get("max_findings")
        if not isinstance(name, str) or not _CASE_ID.fullmatch(name) or name in names:
            raise EvaluationError("evaluation case names must be unique canonical identifiers")
        if not isinstance(expected, list) or not all(isinstance(item, str) and item for item in expected):
            raise EvaluationError(f"case {name} has invalid expected_rule_ids")
        if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 0:
            raise EvaluationError(f"case {name} has invalid max_findings")
        if profile is BenchmarkProfile.SYNTHETIC_SMOKE:
            if not isinstance(raw_case.get("source"), str) or "project_path" in raw_case:
                raise EvaluationError(f"synthetic case {name} must contain inline source only")
        else:
            languages = raw_case.get("languages")
            if "source" in raw_case or not isinstance(raw_case.get("project_path"), str):
                raise EvaluationError(f"tool-backed case {name} must reference a project_path, not inline source")
            if not isinstance(languages, list) or not languages or not all(isinstance(item, str) for item in languages):
                raise EvaluationError(f"tool-backed case {name} must declare languages")
        names.add(name)
        cases.append(raw_case)
    return cases


def _load_toolchain_evidence(
    profile: BenchmarkProfile,
    dataset_digest: str,
    evidence_path: Path | None,
) -> ToolchainEvidence | None:
    if profile is BenchmarkProfile.SYNTHETIC_SMOKE:
        if evidence_path is not None:
            raise EvaluationError("synthetic smoke cannot accept toolchain evidence")
        return None
    if evidence_path is None:
        raise EvaluationError("tool-backed benchmark requires --toolchain-evidence")
    evidence = ToolchainEvidence.load(evidence_path)
    expected = evidence.dataset_digest.removeprefix("sha256:")
    if expected != dataset_digest:
        raise EvaluationError("toolchain evidence dataset digest does not match the manifest and project contents")
    return evidence


def _stage_case(
    case: dict[str, Any],
    cases_path: Path,
    input_root: Path,
    repetition: int,
    profile: BenchmarkProfile,
) -> str:
    name = str(case["name"])
    destination_name = f"r{repetition}-{name}"
    if profile is BenchmarkProfile.SYNTHETIC_SMOKE:
        destination = input_root / f"{destination_name}.py"
        destination.write_text(str(case["source"]), encoding="utf-8")
        return destination.name

    dataset_root = cases_path.resolve().parent
    source = (dataset_root / str(case["project_path"])).resolve()
    try:
        source.relative_to(dataset_root)
    except ValueError as exc:
        raise EvaluationError(f"case {name} project_path escapes the dataset directory") from exc
    if not source.exists():
        raise EvaluationError(f"case {name} project_path does not exist")
    destination = input_root / destination_name
    if source.is_dir():
        shutil.copytree(source, destination)
    elif source.is_file():
        destination.mkdir()
        shutil.copy2(source, destination / source.name)
    else:
        raise EvaluationError(f"case {name} project_path is not a regular file or directory")
    return destination.name


def _command_gate(profile: BenchmarkProfile, report: dict[str, Any]) -> dict[str, Any]:
    if profile is BenchmarkProfile.TOOL_BACKED:
        passed = bool(report["release_gate_eligible"])
        return {
            "name": "v0.4-tool-backed-candidate",
            "passed": passed,
            "scope": (
                "Candidate evidence for the release checklist; external recovery and adversarial gates remain separate."
            ),
        }
    metrics = report["metrics"]
    counts = report["counts"]
    coverage = report["coverage"]
    passed = bool(
        coverage["complete"]
        and metrics["safe_terminal_rate"] is not None
        and metrics["safe_terminal_rate"] >= 0.95
        and metrics["precision"] is not None
        and metrics["precision"] >= 0.90
        and metrics["recall"] is not None
        and metrics["recall"] >= 0.90
        and metrics["finding_to_evidence_completeness"] == 1.0
        and metrics["ledger_verification_rate"] == 1.0
        and counts["provider_requests"] == 0
        and counts["model_cost_units"] == 0.0
    )
    return {
        "name": "synthetic-offline-safe-convergence-smoke",
        "passed": passed,
        "scope": (
            "Regression smoke only; PARTIAL counts as safe convergence but never as release completion. "
            "Replay and real toolchain release gates are intentionally excluded."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a truthfully classified SecMind code-audit evaluation")
    parser.add_argument("--profile", choices=[item.value for item in BenchmarkProfile], default="synthetic-smoke")
    parser.add_argument("--cases", type=Path)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--toolchain-evidence", type=Path)
    parser.add_argument("--sandbox-runner-url", default="")
    parser.add_argument("--timeout-seconds", type=float, default=30)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    profile = BenchmarkProfile(arguments.profile)
    cases_path = arguments.cases or (
        _DEFAULT_SYNTHETIC_CASES if profile is BenchmarkProfile.SYNTHETIC_SMOKE else _DEFAULT_REAL_CASES
    )
    try:
        report = asyncio.run(
            evaluate(
                arguments.repetitions,
                profile=profile,
                cases_path=cases_path,
                toolchain_evidence_path=arguments.toolchain_evidence,
                sandbox_runner_url=arguments.sandbox_runner_url,
                timeout_seconds=arguments.timeout_seconds,
            )
        )
    except EvaluationError as exc:
        parser.error(str(exc))
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)
    if not report["command_gate"]["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
