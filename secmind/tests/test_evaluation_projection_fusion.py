from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from secmind.admission import AdmissionService
from secmind.evaluation_projection import (
    EvaluationProjectionError,
    ProjectionLimits,
    clamp_test3_budget,
    project_test3_result,
    project_test3_v082_result,
)
from secmind.schemas import (
    AgentReport,
    AgentState,
    Evidence,
    Finding,
    InputArtifact,
    RunStatus,
    Scenario,
    SealedAdmissionSnapshot,
    TaskRequest,
)


def _load_test3_scorer() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts" / "score_comprehensive_offline.py"
    spec = importlib.util.spec_from_file_location("secmind_test3_scorer", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Test3 scorer could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scorer = _load_test3_scorer()

INPUT_SHA = "a" * 64
_EVIDENCE_BYTES = b"evaluation projection evidence\n"
EVIDENCE_SHA = hashlib.sha256(_EVIDENCE_BYTES).hexdigest()


def _artifact(*, path: str = "src/app.py", sha256: str = INPUT_SHA) -> InputArtifact:
    return InputArtifact(
        artifact_id="input-app",
        original_name="app.py",
        relative_path=path,
        sha256=sha256,
        size_bytes=24,
        media_type="text/x-python",
    )


def _evidence(
    *,
    evidence_id: str = "evidence-1",
    path: str = "src/app.py",
    line: int = 7,
    file_sha256: str = INPUT_SHA,
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        source="scanner:1",
        summary="Untrusted input reaches eval.",
        artifact_ref=EVIDENCE_SHA,
        sha256=EVIDENCE_SHA,
        metadata={
            "evidence_type": "sast_finding",
            "path": path,
            "line": line,
            "file_sha256": file_sha256,
            "tool_name": "scanner",
            "tool_version": "1",
        },
    )


def _finding(
    *,
    finding_id: str = "finding-1",
    evidence_ids: list[str] | None = None,
    path: str = "src/app.py",
    line: int | None = 7,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        rule_id="CWE-95",
        severity="HIGH",
        confidence="HIGH",
        path=path,
        line=line,
        title="Unsafe evaluation",
        description="Request data reaches eval.",
        remediation="Use a strict parser.",
        evidence_ids=evidence_ids or ["evidence-1"],
        raw={
            "native_rule_id": "B307",
            "normalized_rule_id": "CWE-95",
            "weakness_ids": ["CWE-95"],
            "root_cause": "dynamic evaluation",
            "data_flow": "request payload reaches the evaluation sink",
            "preconditions": "an attacker controls the request payload",
            "impact": "arbitrary code execution in the application process",
        },
    )


def _report(
    *,
    status: RunStatus = RunStatus.COMPLETED,
    findings: list[Finding] | None = None,
    evidence: list[Evidence] | None = None,
) -> AgentReport:
    return AgentReport(
        run_id="run-sealed",
        status=status,
        executive_summary="One evidence-backed finding.",
        findings=[_finding()] if findings is None else findings,
        evidence=[_evidence()] if evidence is None else evidence,
        limitations=["Offline rules only."],
        coverage={"checked_files": 1},
    )


def _snapshot(
    report: AgentReport,
    admission_stores: tuple[object, object],
) -> SealedAdmissionSnapshot:
    artifact_store, capsule_store = admission_stores
    artifact_store.put(  # type: ignore[union-attr]
        _EVIDENCE_BYTES,
        expected_sha256=EVIDENCE_SHA,
        run_id=report.run_id,
        media_type="application/vnd.secmind.test-evidence",
    )
    state = AgentState(
        run_id=report.run_id,
        task=TaskRequest(objective="Audit the supplied code", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        status=report.status,
        findings=[item.model_copy(deep=True) for item in report.findings],
        evidence=[item.model_copy(deep=True) for item in report.evidence],
        report=report.model_copy(deep=True),
    )
    return AdmissionService.seal(
        state,
        report,
        artifact_store=artifact_store,  # type: ignore[arg-type]
        capsule_store=capsule_store,  # type: ignore[arg-type]
    )


def test_projection_is_deterministic_and_binds_every_finding_to_the_manifest(monkeypatch, admission_stores) -> None:
    second_evidence = _evidence(evidence_id="evidence-2")
    second_finding = _finding(finding_id="finding-2", evidence_ids=["evidence-2"])
    report = _report(
        findings=[second_finding, _finding()],
        evidence=[second_evidence, _evidence()],
    )
    snapshot = _snapshot(report, admission_stores)
    v082_snapshot = _snapshot(_report(), admission_stores)

    def forbid_workspace_read(*_args, **_kwargs):
        raise AssertionError("sealed projection must not read the workspace")

    monkeypatch.setattr("pathlib.Path.open", forbid_workspace_read)
    first = project_test3_result(
        task_id="case-1",
        snapshot=snapshot,
        input_manifest=[_artifact(sha256=INPUT_SHA.upper())],
    )
    replay = project_test3_result(
        task_id="case-1",
        snapshot=snapshot,
        input_manifest=[_artifact()],
    )

    assert first.projection_id == replay.projection_id
    assert [item.finding_id for item in first.findings] == ["finding-1", "finding-2"]
    assert [item.evidence_id for item in first.evidence] == ["evidence-1", "evidence-2"]
    assert first.findings[0].path == "src/app.py"
    assert first.findings[0].line == 7
    assert first.findings[0].input_sha256 == INPUT_SHA
    assert first.findings[0].evidence_ids == ["evidence-1"]
    assert first.evidence[0].finding_ids == ["finding-1"]
    assert first.evidence[0].path == "src/app.py"
    assert first.evidence[0].input_sha256 == INPUT_SHA
    assert first.run_proof.source_contract == "sealed_report_evidence_input_manifest"
    v082 = project_test3_v082_result(
        task_id="task-1",
        input_manifest=[_artifact()],
        snapshot=v082_snapshot,
    )
    assert v082.schema_version == "secmind-evaluation-projection-v0.8.2"
    assert v082.findings[0].path == "input/src/app.py"
    assert v082.findings[0].file_sha256 == INPUT_SHA
    assert v082.evidence[0].finding_id == "finding-1"
    assert first.answer.coverage == {}


def test_projection_preserves_bounded_top_level_fields_used_by_test3_scorer(
    tmp_path: Path,
    admission_stores,
) -> None:
    source = tmp_path / "app.py"
    source.write_text("\n" * 8, encoding="utf-8")
    projected = project_test3_result(
        task_id="case-score",
        snapshot=_snapshot(_report(), admission_stores),
        input_manifest=[_artifact()],
    ).model_dump(mode="json")

    score, components, _details = scorer.score_security(
        projected,
        {
            "vulnerability_expected": True,
            "acceptable_cwes": ["CWE-95"],
            "acceptable_labels": [],
            "weights": {
                "classification": 0.2,
                "evidence": 0.2,
                "root_cause": 0.2,
                "impact": 0.2,
                "remediation": 0.2,
            },
        },
        {"src/app.py": source},
    )

    assert score == 1.0
    assert components["root_cause"] == 1.0
    assert components["impact"] == 1.0


def test_snapshot_is_validated_before_projection(admission_stores) -> None:
    report = _report()
    snapshot = _snapshot(report, admission_stores)

    projected = project_test3_result(task_id="case-snapshot", snapshot=snapshot, input_manifest=[_artifact()])

    assert projected.status == "SUCCESS"
    assert projected.run_proof.snapshot_id == snapshot.snapshot_id

    tampered = snapshot.model_copy(update={"final_semantic_digest": "0" * 64})
    with pytest.raises(EvaluationProjectionError, match="snapshot is invalid"):
        project_test3_result(task_id="case-snapshot", snapshot=tampered, input_manifest=[_artifact()])


def test_tampered_nested_report_is_not_accepted_as_sealed(admission_stores) -> None:
    report = _report()
    snapshot = _snapshot(report, admission_stores)
    replacement = report.model_copy(deep=True)
    replacement.evidence[0].summary = "Different evidence content."
    tampered = snapshot.model_copy(update={"report": replacement})

    with pytest.raises(EvaluationProjectionError, match="snapshot is invalid"):
        project_test3_result(
            task_id="case-mismatch",
            snapshot=tampered,
            input_manifest=[_artifact()],
        )


@pytest.mark.parametrize(
    ("evidence", "finding", "message"),
    [
        (_evidence(file_sha256="0" * 64), _finding(), "SHA-256 does not match"),
        (_evidence(line=8), _finding(), "line does not match"),
        (_evidence(path="src/other.py"), _finding(), "path is missing"),
        (_evidence(), _finding(line=None), "has no source line"),
    ],
)
def test_invalid_finding_evidence_bindings_fail_closed(
    evidence: Evidence,
    finding: Finding,
    message: str,
    admission_stores,
) -> None:
    report = _report(findings=[finding], evidence=[evidence])

    with pytest.raises(EvaluationProjectionError, match=message):
        project_test3_result(
            task_id="case-invalid",
            snapshot=_snapshot(report, admission_stores),
            input_manifest=[_artifact()],
        )


def test_admission_rejection_cannot_be_reintroduced_by_projection(admission_stores) -> None:
    report = _report(findings=[_finding(evidence_ids=["missing"])], evidence=[_evidence()])
    snapshot = _snapshot(report, admission_stores)

    projected = project_test3_result(
        task_id="case-rejected",
        snapshot=snapshot,
        input_manifest=[_artifact()],
    )

    assert snapshot.admitted_finding_ids == []
    assert snapshot.rejected_finding_ids == ["finding-1"]
    assert projected.findings == []
    assert projected.evidence == []


def test_suffix_only_and_unsafe_manifest_paths_are_rejected(admission_stores) -> None:
    report = _report()
    duplicate_name = _artifact(path="vendor/src/app.py")
    duplicate_name.artifact_id = "input-vendor"

    with pytest.raises(EvaluationProjectionError, match="missing"):
        project_test3_result(
            task_id="case-multiple-suffixes",
            snapshot=_snapshot(report, admission_stores),
            input_manifest=[_artifact(path="project/src/app.py"), duplicate_name],
        )

    with pytest.raises(EvaluationProjectionError, match="missing"):
        project_test3_result(
            task_id="case-unique-suffix",
            snapshot=_snapshot(report, admission_stores),
            input_manifest=[_artifact(path="project/src/app.py")],
        )

    with pytest.raises(EvaluationProjectionError, match="unsafe"):
        project_test3_result(
            task_id="case-unsafe",
            snapshot=_snapshot(report, admission_stores),
            input_manifest=[_artifact(path="../app.py")],
        )


def test_partial_is_never_promoted_and_empty_results_do_not_gain_fallback_findings(admission_stores) -> None:
    report = _report(status=RunStatus.PARTIAL, findings=[], evidence=[])

    projected = project_test3_result(
        task_id="case-partial",
        snapshot=_snapshot(report, admission_stores),
        input_manifest=[_artifact()],
    )

    assert projected.status == "PARTIAL"
    assert projected.findings == []
    assert projected.evidence == []


def test_nonterminal_report_and_excess_counts_are_rejected(admission_stores) -> None:
    running = _report(status=RunStatus.RUNNING)
    with pytest.raises(EvaluationProjectionError, match="not terminal"):
        project_test3_result(
            task_id="case-running",
            snapshot=_snapshot(running, admission_stores),
            input_manifest=[_artifact()],
        )

    second_evidence = _evidence(evidence_id="evidence-2")
    report = _report(
        findings=[_finding(), _finding(finding_id="finding-2", evidence_ids=["evidence-2"])],
        evidence=[_evidence(), second_evidence],
    )
    with pytest.raises(EvaluationProjectionError, match="finding count"):
        project_test3_result(
            task_id="case-bounded",
            snapshot=_snapshot(report, admission_stores),
            input_manifest=[_artifact()],
            limits=ProjectionLimits(max_findings=1),
        )


def test_budget_clamp_applies_platform_ceilings_and_rejects_invalid_types() -> None:
    budget = clamp_test3_budget(
        {
            "wall_time_cap_seconds": 10_500,
            "provider_request_cap": -5,
            "model_token_cap": 99_000_000,
            "tool_call_cap": 800,
        }
    )

    assert budget.wall_time_cap_seconds == 7_200
    assert budget.provider_request_cap == 0
    assert budget.model_token_cap == 2_000_000
    assert budget.tool_call_cap == 100

    with pytest.raises(EvaluationProjectionError, match="must be an integer"):
        clamp_test3_budget({"wall_time_cap_seconds": True})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_projection_rejects_non_finite_finding_metadata(value: float, admission_stores) -> None:
    finding = _finding()
    finding.raw["impact"] = value

    with pytest.raises(EvaluationProjectionError, match="non-finite"):
        project_test3_result(
            task_id="case-non-finite",
            snapshot=_snapshot(_report(findings=[finding]), admission_stores),
            input_manifest=[_artifact()],
        )
