from __future__ import annotations

import hashlib

import pytest

from secmind.admission import AdmissionError, AdmissionService, _normalized_repository_path, _valid_sha256
from secmind.schemas import AgentReport, AgentState, Finding, InputArtifact, RunStatus, TaskRequest


def _state() -> AgentState:
    state = AgentState(
        run_id="run-admission-boundary",
        task=TaskRequest(objective="review immutable input"),
        status=RunStatus.COMPLETED,
    )
    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.COMPLETED,
        executive_summary="No publishable findings were produced.",
        limitations=["deterministic fixture"],
        coverage={"fixture": True},
    )
    return state


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("src\\Auth.JAVA", "src/auth.java"),
        ("éxample.java", "éxample.java"),
        ("", None),
        ("/absolute.java", None),
        ("C:/absolute.java", None),
        ("src/../secret.java", None),
        ("src/\x00bad.java", None),
        (42, None),
    ],
)
def test_admission_repository_path_normalization_is_cross_platform_and_fail_closed(
    value: object,
    expected: str | None,
) -> None:
    assert _normalized_repository_path(value) == expected


@pytest.mark.parametrize(
    ("value", "valid"),
    [("a" * 64, True), ("A" * 64, True), ("g" * 64, False), ("a" * 63, False), (None, False)],
)
def test_admission_sha256_validation_rejects_noncanonical_material(value: object, valid: bool) -> None:
    assert _valid_sha256(value) is valid


def test_public_snapshot_is_deep_copied_and_restores_the_only_public_view(admission_stores) -> None:
    state = _state()
    artifact_store, capsule_store = admission_stores
    snapshot = AdmissionService.seal(state, artifact_store=artifact_store, capsule_store=capsule_store)
    assert AdmissionService.has_public_report(state)

    public_copy = AdmissionService.public_snapshot(state)
    public_copy.report.executive_summary = "caller mutation"
    assert state.sealed_admission is not None
    assert state.sealed_admission.report.executive_summary != "caller mutation"

    state.report = None
    state.findings = []
    state.audit_coverage = {}
    restored = AdmissionService.restore_sealed_view(state)
    assert restored == AdmissionService.project(snapshot)
    assert state.report == restored
    assert state.audit_coverage == restored.coverage


def test_public_boundary_fails_closed_without_a_sealed_snapshot() -> None:
    state = _state()
    state.sealed_admission = None
    assert not AdmissionService.has_public_report(state)
    with pytest.raises(AdmissionError, match="not available"):
        AdmissionService.public_report(state)
    with pytest.raises(AdmissionError, match="not available"):
        AdmissionService.public_snapshot(state)


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("run_id", "another run"),
        ("finding_reference", "references mismatch"),
        ("duplicate_admitted", "not unique"),
        ("duplicate_rejected", "not unique"),
        ("overlap", "overlap"),
        ("semantic", "semantic digest mismatch"),
        ("integrity", "integrity mismatch"),
        ("identity", "identity mismatch"),
    ],
)
def test_snapshot_validation_names_each_corruption_boundary(mutation: str, reason: str, admission_stores) -> None:
    state = _state()
    artifact_store, capsule_store = admission_stores
    finding = Finding(
        finding_id="finding-1",
        rule_id="CWE-20",
        title="Validated fixture",
        severity="LOW",
        confidence="HIGH",
        path="src/input.py",
        line=1,
        description="fixture",
        evidence_ids=[],
    )
    snapshot = AdmissionService.seal(state, artifact_store=artifact_store, capsule_store=capsule_store)
    damaged = snapshot.model_copy(deep=True)
    if mutation == "run_id":
        damaged.report.run_id = "other-run"
    elif mutation == "finding_reference":
        damaged = damaged.model_copy(update={"admitted_finding_ids": ["finding-1"]}, deep=True)
    elif mutation == "duplicate_admitted":
        damaged.report.findings = [finding, finding.model_copy(deep=True)]
        damaged = damaged.model_copy(update={"admitted_finding_ids": ["finding-1", "finding-1"]}, deep=True)
    elif mutation == "duplicate_rejected":
        damaged = damaged.model_copy(update={"rejected_finding_ids": ["rejected", "rejected"]}, deep=True)
    elif mutation == "overlap":
        damaged.report.findings = [finding]
        damaged = damaged.model_copy(
            update={"admitted_finding_ids": ["finding-1"], "rejected_finding_ids": ["finding-1"]},
            deep=True,
        )
    elif mutation == "semantic":
        damaged = damaged.model_copy(update={"final_semantic_digest": "0" * 64}, deep=True)
    elif mutation == "integrity":
        damaged.report.executive_summary = "tampered"
    elif mutation == "identity":
        damaged = damaged.model_copy(update={"snapshot_id": "admission-snapshot-forged"}, deep=True)

    valid, observed = AdmissionService.validate_snapshot(damaged)
    assert not valid
    assert observed is not None and reason in observed
    with pytest.raises(AdmissionError, match="snapshot is invalid"):
        AdmissionService.project(damaged)


def test_java_manifest_is_bounded_to_safe_target_and_file_budget() -> None:
    state = _state()
    state.input_artifacts = [
        InputArtifact(
            original_name="Main.java",
            relative_path="src/Main.java",
            sha256=hashlib.sha256(b"main").hexdigest(),
            size_bytes=100,
        ),
        InputArtifact(
            original_name="Large.java",
            relative_path="src/Large.java",
            sha256=hashlib.sha256(b"large").hexdigest(),
            size_bytes=3 * 1024 * 1024,
        ),
        InputArtifact(
            original_name="Test.java",
            relative_path="test/Test.java",
            sha256=hashlib.sha256(b"test").hexdigest(),
            size_bytes=100,
        ),
        InputArtifact(
            original_name="readme.txt",
            relative_path="src/readme.txt",
            sha256=hashlib.sha256(b"readme").hexdigest(),
            size_bytes=100,
        ),
    ]
    from secmind.schemas import PlanStep

    manifest = AdmissionService._java_input_manifest(
        state,
        PlanStep(step_id="scan", objective="scan", agent_role="sast_specialist", inputs={"target": "src"}),
    )
    assert manifest is not None
    assert manifest[1] == 1
    assert (
        AdmissionService._java_input_manifest(
            state,
            PlanStep(step_id="bad", objective="scan", agent_role="sast_specialist", inputs={"target": "../outside"}),
        )
        is None
    )


def test_immutable_input_matching_rejects_ambiguous_suffix_and_accepts_exact_hash() -> None:
    digest = hashlib.sha256(b"same").hexdigest()
    state = _state()
    state.input_artifacts = [
        InputArtifact(original_name="Main.java", relative_path="one/Main.java", sha256=digest, size_bytes=4),
        InputArtifact(original_name="Main.java", relative_path="two/Main.java", sha256=digest, size_bytes=4),
    ]
    assert not AdmissionService._matches_immutable_input(state, "Main.java", digest)
    assert AdmissionService._matches_immutable_input(state, "one/Main.java", digest)
    assert not AdmissionService._matches_immutable_input(state, "one/Main.java", "0" * 64)


def test_fallback_report_and_gain_adjudication_preserve_state_contract(
    monkeypatch: pytest.MonkeyPatch,
    admission_stores,
) -> None:
    state = _state()
    state.report = None
    state.completion_reasons = ["bounded completion"]
    fallback = AdmissionService._fallback_report(state)
    assert fallback.run_id == state.run_id
    assert fallback.limitations == ["bounded completion"]

    sentinel = object()
    monkeypatch.setattr(
        "secmind.admission.ToolGainGate.apply",
        lambda received, **_kwargs: sentinel if received is state else None,
    )
    artifact_store, capsule_store = admission_stores
    assert (
        AdmissionService.adjudicate_deltas(
            state,
            artifact_store=artifact_store,
            capsule_store=capsule_store,
        )
        is sentinel
    )
