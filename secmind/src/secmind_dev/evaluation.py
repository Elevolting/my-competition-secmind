from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from secmind.schemas import SCHEMA_VERSION

_SHA256 = re.compile(r"^(?:sha256:)?[a-f0-9]{64}$")
REQUIRED_RELEASE_TOOLS = frozenset(
    {
        "bandit_python_audit",
        "semgrep_sast",
        "gitleaks_secret_scan",
        "syft_sbom",
        "osv_dependency_audit",
    }
)


class EvaluationError(ValueError):
    pass


class BenchmarkProfile(StrEnum):
    SYNTHETIC_SMOKE = "synthetic-smoke"
    TOOL_BACKED = "tool-backed"


class ReplayCheck(StrEnum):
    NOT_EVALUATED = "not-evaluated"
    VERIFIED = "verified"
    FAILED = "failed"


@dataclass(frozen=True)
class ToolchainEvidence:
    """Operator-supplied deployment evidence, not a cryptographic attestation."""

    platform: str
    runner_isolation: str
    images: dict[str, str]
    staging_image_digest: str
    semgrep_rule_bundle_digest: str
    osv_database_digest: str
    dataset_digest: str
    source_path: str

    @classmethod
    def load(cls, path: Path) -> ToolchainEvidence:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvaluationError("toolchain evidence must be readable UTF-8 JSON") from exc
        if not isinstance(raw, dict):
            raise EvaluationError("toolchain evidence must be a JSON object")
        images = raw.get("images")
        if not isinstance(images, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in images.items()
        ):
            raise EvaluationError("toolchain evidence images must be a string map")
        evidence = cls(
            platform=str(raw.get("platform", "")),
            runner_isolation=str(raw.get("runner_isolation", "")),
            images=dict(images),
            staging_image_digest=str(raw.get("staging_image_digest", "")),
            semgrep_rule_bundle_digest=str(raw.get("semgrep_rule_bundle_digest", "")),
            osv_database_digest=str(raw.get("osv_database_digest", "")),
            dataset_digest=str(raw.get("dataset_digest", "")),
            source_path=path.name,
        )
        evidence.validate()
        return evidence

    def validate(self) -> None:
        if self.platform != "linux/amd64":
            raise EvaluationError("tool-backed release benchmark requires platform linux/amd64")
        if self.runner_isolation != "dedicated-rootless":
            raise EvaluationError("tool-backed release benchmark requires a dedicated rootless runner")
        missing = REQUIRED_RELEASE_TOOLS - set(self.images)
        if missing:
            raise EvaluationError(f"toolchain evidence is missing required tools: {', '.join(sorted(missing))}")
        digests = {
            **{f"image:{name}": digest for name, digest in self.images.items()},
            "staging_image": self.staging_image_digest,
            "semgrep_rule_bundle": self.semgrep_rule_bundle_digest,
            "osv_database": self.osv_database_digest,
            "dataset": self.dataset_digest,
        }
        invalid = sorted(name for name, digest in digests.items() if not _valid_digest(digest))
        if invalid:
            raise EvaluationError(f"toolchain evidence contains invalid SHA-256 digests: {', '.join(invalid)}")

    def report_view(self) -> dict[str, Any]:
        return {
            "kind": "operator-supplied-deployment-evidence",
            "cryptographically_attested": False,
            "platform": self.platform,
            "runner_isolation": self.runner_isolation,
            "images": dict(sorted(self.images.items())),
            "staging_image_digest": self.staging_image_digest,
            "semgrep_rule_bundle_digest": self.semgrep_rule_bundle_digest,
            "osv_database_digest": self.osv_database_digest,
            "dataset_digest": self.dataset_digest,
            "source_file": Path(self.source_path).name,
        }


@dataclass(frozen=True)
class BenchmarkDefinition:
    profile: BenchmarkProfile
    dataset_id: str
    dataset_kind: str
    declared_case_count: int
    declared_repetitions: int
    languages: tuple[str, ...]
    required_tools: frozenset[str] = field(default_factory=frozenset)
    toolchain_evidence: ToolchainEvidence | None = None

    def __post_init__(self) -> None:
        if not self.dataset_id or self.declared_case_count < 1 or self.declared_repetitions < 1:
            raise EvaluationError("benchmark definition is incomplete")
        if self.profile is BenchmarkProfile.SYNTHETIC_SMOKE and self.toolchain_evidence is not None:
            raise EvaluationError("synthetic smoke must not claim toolchain evidence")
        if self.profile is BenchmarkProfile.TOOL_BACKED and self.toolchain_evidence is None:
            raise EvaluationError("tool-backed benchmark requires toolchain evidence")


@dataclass(frozen=True)
class RunEvaluation:
    case_id: str
    repetition: int
    status: str
    expected_rule_ids: frozenset[str]
    found_rule_ids: frozenset[str]
    finding_count: int
    findings_with_valid_evidence: int
    within_finding_limit: bool
    ledger_event_count: int
    ledger_valid: bool
    replay_check: ReplayCheck
    provider_requests: int
    model_cost_units: float
    execution_backend: str
    executed_tools: tuple[str, ...] = ()
    expected_high_critical_rule_ids: frozenset[str] = field(default_factory=frozenset)
    found_high_critical_rule_ids: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        counts = (
            self.repetition,
            self.finding_count,
            self.findings_with_valid_evidence,
            self.ledger_event_count,
            self.provider_requests,
        )
        if not self.case_id or any(value < 0 for value in counts) or self.repetition < 1:
            raise EvaluationError("run evaluation contains invalid identifiers or counts")
        if self.findings_with_valid_evidence > self.finding_count or self.model_cost_units < 0:
            raise EvaluationError("run evaluation contains inconsistent finding or cost counts")

    @property
    def functional_passed(self) -> bool:
        return bool(
            self.status == "completed"
            and self.expected_rule_ids == self.found_rule_ids
            and self.within_finding_limit
            and self.findings_with_valid_evidence == self.finding_count
            and self.ledger_event_count > 0
            and self.ledger_valid
        )

    @property
    def safely_converged(self) -> bool:
        """Whether a smoke run reached an honest, evidence-bound terminal result.

        ``partial`` is deliberately not a release completion.  It is nevertheless
        a valid regression-smoke outcome when the runtime failed closed because an
        independent evidence requirement could not be satisfied.  Recovery,
        cancellation, denial, and failure never count as safe convergence here.
        """

        return bool(
            self.status in {"completed", "partial"}
            and self.expected_rule_ids == self.found_rule_ids
            and self.within_finding_limit
            and self.findings_with_valid_evidence == self.finding_count
            and self.ledger_event_count > 0
            and self.ledger_valid
        )

    def report_view(self) -> dict[str, Any]:
        return {
            "case": self.case_id,
            "repetition": self.repetition,
            "status": self.status,
            "findings": self.finding_count,
            "found_rule_ids": sorted(self.found_rule_ids),
            "expected_rule_ids": sorted(self.expected_rule_ids),
            "finding_evidence_complete": self.findings_with_valid_evidence == self.finding_count,
            "ledger_event_count": self.ledger_event_count,
            "ledger_valid": self.ledger_valid,
            "replay_check": self.replay_check.value,
            "execution_backend": self.execution_backend,
            "executed_tools": list(self.executed_tools),
            "passed": self.functional_passed,
            "safely_converged": self.safely_converged,
        }


def build_evaluation_report(definition: BenchmarkDefinition, runs: list[RunEvaluation]) -> dict[str, Any]:
    keys = [(run.case_id, run.repetition) for run in runs]
    duplicate_run_keys = sorted(key for key, count in Counter(keys).items() if count > 1)
    observed_cases = sorted({run.case_id for run in runs})
    expected_runs = definition.declared_case_count * definition.declared_repetitions
    coverage_complete = bool(
        len(runs) == expected_runs
        and len(observed_cases) == definition.declared_case_count
        and not duplicate_run_keys
        and all(
            {run.repetition for run in runs if run.case_id == case_id}
            == set(range(1, definition.declared_repetitions + 1))
            for case_id in observed_cases
        )
    )

    true_positives = sum(len(run.found_rule_ids & run.expected_rule_ids) for run in runs)
    false_positives = sum(len(run.found_rule_ids - run.expected_rule_ids) for run in runs)
    false_negatives = sum(len(run.expected_rule_ids - run.found_rule_ids) for run in runs)
    high_true_positives = sum(
        len(run.found_high_critical_rule_ids & run.expected_high_critical_rule_ids) for run in runs
    )
    high_false_negatives = sum(
        len(run.expected_high_critical_rule_ids - run.found_high_critical_rule_ids) for run in runs
    )
    findings = sum(run.finding_count for run in runs)
    linked_findings = sum(run.findings_with_valid_evidence for run in runs)
    ledger_evaluated = sum(run.ledger_event_count > 0 for run in runs)
    ledger_verified = sum(run.ledger_event_count > 0 and run.ledger_valid for run in runs)
    replay_evaluated = sum(run.replay_check is not ReplayCheck.NOT_EVALUATED for run in runs)
    replay_verified = sum(run.replay_check is ReplayCheck.VERIFIED for run in runs)
    passed = sum(run.functional_passed for run in runs)
    safely_converged = sum(run.safely_converged for run in runs)
    observed_tools = sorted({tool for run in runs for tool in run.executed_tools})
    observed_backends = sorted({run.execution_backend for run in runs})
    provider_requests = sum(run.provider_requests for run in runs)
    model_cost_units = sum(run.model_cost_units for run in runs)

    metrics = {
        "process_success_rate": _ratio(passed, len(runs)),
        "safe_terminal_rate": _ratio(safely_converged, len(runs)),
        "precision": _ratio(true_positives, true_positives + false_positives),
        "recall": _ratio(true_positives, true_positives + false_negatives),
        "high_critical_recall": _ratio(
            high_true_positives,
            high_true_positives + high_false_negatives,
        ),
        "finding_to_evidence_completeness": _ratio(linked_findings, findings),
        "ledger_verification_rate": _ratio(ledger_verified, ledger_evaluated),
        "replay_verification_rate": _ratio(replay_verified, replay_evaluated),
    }
    release_eligible, blockers = _release_eligibility(
        definition,
        runs,
        coverage_complete=coverage_complete,
        observed_tools=set(observed_tools),
        metrics=metrics,
    )
    limitations = _limitations(definition, coverage_complete, replay_evaluated, observed_tools)
    exact_forty_by_three = bool(
        definition.declared_case_count == 40
        and definition.declared_repetitions == 3
        and len(runs) == 120
        and coverage_complete
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "report_format": "secmind-evaluation-v2",
        "profile": definition.profile.value,
        "benchmark_classification": (
            "synthetic-process-smoke"
            if definition.profile is BenchmarkProfile.SYNTHETIC_SMOKE
            else "real-project-tool-backed-candidate"
        ),
        "dataset": {
            "dataset_id": definition.dataset_id,
            "kind": definition.dataset_kind,
            "declared_cases": definition.declared_case_count,
            "declared_repetitions": definition.declared_repetitions,
            "languages": list(definition.languages),
        },
        "coverage": {
            "expected_runs": expected_runs,
            "observed_runs": len(runs),
            "observed_cases": len(observed_cases),
            "duplicate_run_keys": [list(key) for key in duplicate_run_keys],
            "complete": coverage_complete,
            "exact_40x3_executed": exact_forty_by_three,
        },
        "counts": {
            "passed": passed,
            "safely_converged": safely_converged,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "findings": findings,
            "findings_with_valid_evidence": linked_findings,
            "ledger_evaluated_runs": ledger_evaluated,
            "ledger_verified_runs": ledger_verified,
            "replay_evaluated_runs": replay_evaluated,
            "replay_verified_runs": replay_verified,
            "provider_requests": provider_requests,
            "model_cost_units": model_cost_units,
        },
        "metrics": metrics,
        "execution": {
            "observed_backends": observed_backends,
            "observed_tools": observed_tools,
            "required_tools": sorted(definition.required_tools),
            "toolchain_evidence": (
                definition.toolchain_evidence.report_view() if definition.toolchain_evidence else None
            ),
        },
        "release_gate_eligible": release_eligible,
        "release_gate_blockers": blockers,
        "limitations": limitations,
        "results": [run.report_view() for run in runs],
    }


def dataset_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dataset_bundle_sha256(manifest_path: Path, project_refs: list[str]) -> str:
    """Bind a real-project manifest to every referenced regular file."""

    dataset_root = manifest_path.resolve().parent
    if len(project_refs) != len(set(project_refs)):
        raise EvaluationError("real-project dataset contains duplicate project references")
    digest = hashlib.sha256()
    _update_digest(digest, "manifest.json", manifest_path.read_bytes())
    for reference in sorted(project_refs):
        source = (dataset_root / reference).resolve()
        try:
            source.relative_to(dataset_root)
        except ValueError as exc:
            raise EvaluationError("real-project dataset reference escapes its directory") from exc
        if not source.exists() or source.is_symlink():
            raise EvaluationError("real-project dataset reference is absent or a symbolic link")
        files = [source] if source.is_file() else sorted(item for item in source.rglob("*") if item.is_file())
        for item in files:
            if item.is_symlink():
                raise EvaluationError("real-project dataset contains a symbolic link")
            logical_path = item.relative_to(dataset_root).as_posix()
            _update_digest(digest, logical_path, item.read_bytes())
    return digest.hexdigest()


def _release_eligibility(
    definition: BenchmarkDefinition,
    runs: list[RunEvaluation],
    *,
    coverage_complete: bool,
    observed_tools: set[str],
    metrics: dict[str, float | None],
) -> tuple[bool, list[str]]:
    blockers: list[str] = []
    if definition.profile is not BenchmarkProfile.TOOL_BACKED:
        blockers.append("synthetic smoke is not a release benchmark")
    if definition.dataset_kind != "real-multifile-projects":
        blockers.append("dataset is not classified as real multi-file projects")
    if definition.declared_case_count < 40 or definition.declared_repetitions < 3 or not coverage_complete:
        blockers.append("at least 40 complete cases x 3 repetitions were not observed")
    if len(set(definition.languages)) < 3:
        blockers.append("dataset covers fewer than three languages")
    if definition.toolchain_evidence is None:
        blockers.append("toolchain deployment evidence is absent")
    if not definition.required_tools.issubset(observed_tools):
        blockers.append("not every required scanner was observed in ledger-backed executions")
    if any(run.execution_backend != "sandbox-runner" for run in runs):
        blockers.append("one or more runs did not use sandbox-runner")
    if not runs or any(run.replay_check is not ReplayCheck.VERIFIED for run in runs):
        blockers.append("Replay verification did not pass for every run")
    thresholds = {
        "process_success_rate": 0.95,
        "precision": 0.90,
        "recall": 0.90,
        "high_critical_recall": 0.95,
        "finding_to_evidence_completeness": 1.0,
        "ledger_verification_rate": 1.0,
        "replay_verification_rate": 1.0,
    }
    for name, threshold in thresholds.items():
        value = metrics[name]
        if value is None or value < threshold:
            blockers.append(f"metric {name} is absent or below {threshold:.2f}")
    return not blockers, blockers


def _limitations(
    definition: BenchmarkDefinition,
    coverage_complete: bool,
    replay_evaluated: int,
    observed_tools: list[str],
) -> list[str]:
    limitations: list[str] = []
    if definition.profile is BenchmarkProfile.SYNTHETIC_SMOKE:
        limitations.extend(
            [
                "Inline single-file synthetic fixtures do not measure real repository audit quality.",
                (
                    "Host subprocess execution does not validate Docker, rootless isolation, immutable tool images, "
                    "or offline OSV data."
                ),
                "This report must not be cited as the v0.4 real-project 40x3 release benchmark.",
            ]
        )
    if not coverage_complete:
        limitations.append("The declared case/repetition matrix is incomplete.")
    if replay_evaluated == 0:
        limitations.append("Replay verification was not evaluated; its rate is null, not 100%.")
    missing_tools = sorted(definition.required_tools - set(observed_tools))
    if missing_tools:
        limitations.append(f"Required tools were not observed: {', '.join(missing_tools)}.")
    return limitations


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _valid_digest(value: str) -> bool:
    if not _SHA256.fullmatch(value):
        return False
    normalized = value.removeprefix("sha256:")
    return normalized != "0" * 64


def _update_digest(digest: Any, path: str, content: bytes) -> None:
    encoded_path = path.encode("utf-8")
    digest.update(len(encoded_path).to_bytes(8, "big"))
    digest.update(encoded_path)
    digest.update(len(content).to_bytes(8, "big"))
    digest.update(content)
