from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from secmind.admission import AdmissionService
from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.quarantine import (
    CapsuleConflictError,
    CapsuleIntegrityError,
    FailureCapsule,
    FailureCapsuleStore,
)
from secmind.schemas import AgentReport, AgentState, Evidence, Finding, RunStatus, Scenario, TaskRequest
from secmind.tool_assurance import independently_rehash_evidence
from secmind.tool_gain_gate import ToolGainGate
from secmind.tooling.core import PYTHON_DATAFLOW_RULE_BUNDLE_DIGEST


def _finding(identifier: str = "candidate-bad") -> Finding:
    return Finding(
        finding_id=identifier,
        rule_id="CWE-79",
        severity="HIGH",
        confidence="HIGH",
        path="src/app.py",
        line=12,
        title="cross-site scripting",
        description="password=sk-abcdefghijklmnopqrstuvwxyz " + ("large body " * 1_000),
        evidence_ids=["evidence-1"],
        raw={"password": "sk-abcdefghijklmnopqrstuvwxyz", "body": "x" * 100_000},
    )


def test_failure_capsule_scrubs_and_bounds_raw_candidate() -> None:
    capsule = FailureCapsule.from_candidate(
        _finding(),
        run_id="run-1",
        reason_code="not_authorized",
        evidence_refs=("evidence-1",),
        transition={"version": 1, "from_state": "proposed", "to_state": "quarantined"},
        fence={"run_fence": 4, "step_fence": 2},
        tool_name="scanner",
        tool_version="1.2.3",
        rule_digest="a" * 64,
    )
    payload = json.dumps(capsule.to_dict(), ensure_ascii=False)
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in payload
    assert "x" * 1_000 not in payload
    assert len(capsule.to_json_bytes()) < 64 * 1024
    assert capsule.payload_digest
    assert capsule.transition_digest
    assert capsule.fence_digest
    assert capsule.rule_id == "CWE-79"


def test_capsule_store_replays_and_rejects_payload_conflict(tmp_path: Path) -> None:
    store = FailureCapsuleStore(tmp_path / "capsules")
    first = FailureCapsule.from_candidate(_finding(), run_id="run-1", reason_code="not_authorized")
    assert store.append(first).capsule_id == first.capsule_id
    assert store.append(first).capsule_id == first.capsule_id
    assert [item.capsule_id for item in store.replay()] == [first.capsule_id]
    conflicting = FailureCapsule.from_candidate(
        _finding(),
        run_id="run-1",
        reason_code="different_reason",
    )
    with pytest.raises(CapsuleConflictError, match="payload conflict"):
        store.append(conflicting)


def test_sensitive_identifiers_are_hashed_without_collapsing_idempotency(tmp_path: Path) -> None:
    store = FailureCapsuleStore(tmp_path / "capsules")
    first = FailureCapsule.from_candidate(
        {
            "candidate_id": "9f4e5c1a7b8d3e2f6a0c9d1b4e7f8a2c",
            "finding_id": "8e3d1a7b9c2f4e6d0a5b8c1d3f7e9a2b",
            "rule_id": "RULE-1",
        },
        run_id="run-identities",
        reason_code="quarantined",
    )
    second = FailureCapsule.from_candidate(
        {
            "candidate_id": "7a2d9c4e1b6f8a3d5c0e2b7f9a1d4c6e",
            "finding_id": "6d1a8c3f9e2b5d7a0c4e1f8b3a6d9c2e",
            "rule_id": "RULE-1",
        },
        run_id="run-identities",
        reason_code="quarantined",
    )
    assert first.candidate_id.startswith("candidate-sha256-")
    assert second.candidate_id.startswith("candidate-sha256-")
    assert first.candidate_id != second.candidate_id
    assert first.finding_id != second.finding_id
    assert first.dedupe_key != second.dedupe_key
    store.append(first)
    store.append(second)
    assert len(store.replay()) == 2


def test_capsule_batch_replays_existing_index_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = FailureCapsuleStore(tmp_path / "capsules")
    items = tuple(
        FailureCapsule.from_candidate(
            {
                "candidate_id": f"candidate-{index}",
                "finding_id": f"finding-{index}",
                "rule_id": "RULE-1",
            },
            run_id="run-batch",
            reason_code="quarantined",
        )
        for index in range(128)
    )
    original = store._existing  # noqa: SLF001
    calls = 0

    def counted_existing():
        nonlocal calls
        calls += 1
        return original()

    monkeypatch.setattr(store, "_existing", counted_existing)
    stored = store.append_many(items)
    assert calls == 1
    assert len(stored) == 128
    assert len({item.dedupe_key for item in stored}) == 128


def test_capsule_store_detects_tampered_object(tmp_path: Path) -> None:
    store = FailureCapsuleStore(tmp_path / "capsules")
    capsule = store.append(FailureCapsule.from_candidate(_finding(), run_id="run-1", reason_code="bad"))
    path = store._path_for(capsule.capsule_digest)  # noqa: SLF001
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["reason"] = "tampered"
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    with pytest.raises(CapsuleIntegrityError):
        store.replay()
    assert store.verify() is False


def test_independent_rehash_does_not_accept_tool_reported_digest(tmp_path: Path) -> None:
    store = ContentAddressedArtifactStore(tmp_path / "cas")
    content = b"immutable evidence bytes"
    artifact = store.put(content, run_id="run-1")
    evidence = Evidence(
        evidence_id="evidence-1",
        source="scanner:1",
        summary="tool result",
        artifact_ref=artifact.artifact_id,
        sha256=artifact.sha256,
        metadata={"file_sha256": "0" * 64},
    )
    assert independently_rehash_evidence(evidence, store, run_id="run-1").ok
    forged = evidence.model_copy(update={"sha256": "0" * 64})
    failed = independently_rehash_evidence(forged, store, run_id="run-1")
    assert failed.ok is False
    assert failed.reason == "EVIDENCE_DIGEST_MISMATCH"


def test_cas_key_mismatch_is_not_hidden_by_declared_digest(tmp_path: Path) -> None:
    class ForgedStore:
        def read(self, _artifact_id: str) -> bytes:
            return b"different bytes"

    digest = hashlib.sha256(b"expected bytes").hexdigest()
    evidence = Evidence(
        evidence_id="evidence-1",
        source="scanner:1",
        summary="tool result",
        artifact_ref=digest,
        sha256=digest,
    )
    result = independently_rehash_evidence(evidence, ForgedStore(), run_id="run-1")
    assert result.ok is False
    assert result.reason == "CAS_KEY_DIGEST_MISMATCH"


def test_mixed_good_bad_candidates_keep_good_and_quarantine_bad(tmp_path: Path) -> None:
    cas = ContentAddressedArtifactStore(tmp_path / "cas")
    capsules = FailureCapsuleStore(tmp_path / "capsules")
    artifact = cas.put(b"source bytes", run_id="run-mixed")

    def candidate(identifier: str, line: int, declared_sha: str) -> tuple[Finding, Evidence]:
        finding = Finding(
            finding_id=identifier,
            rule_id="PYFLOW-SQL-001",
            severity="HIGH",
            confidence="HIGH",
            path="app.py",
            line=line,
            title="unsafe query",
            description="source reaches sink",
            evidence_ids=[f"evidence-{identifier}"],
        )
        evidence = Evidence(
            evidence_id=f"evidence-{identifier}",
            source="python_taint_audit",
            summary="bounded flow",
            artifact_ref=artifact.artifact_id,
            sha256=declared_sha,
            metadata={
                "tool_name": "python_taint_audit",
                "tool_version": "1",
                "path": "app.py",
                "line": line,
                "file_sha256": artifact.sha256,
                "rule_bundle_digest": PYTHON_DATAFLOW_RULE_BUNDLE_DIGEST,
                "native_rule_id": "PYFLOW-SQL-001",
                "normalized_rule_id": "PYFLOW-SQL-001",
                "evidence_type": "sast_flow",
                "semantic_corroboration": True,
                "data_flow": "request -> sink",
            },
        )
        return finding, evidence

    good, good_evidence = candidate("good", 2, artifact.sha256)
    bad, bad_evidence = candidate("bad", 3, "0" * 64)
    state = AgentState(
        run_id="run-mixed",
        task=TaskRequest(objective="mixed candidate audit"),
        scenario=Scenario.CODE_AUDIT,
        status=RunStatus.RUNNING,
        findings=[good, bad],
        evidence=[good_evidence, bad_evidence],
        audit_coverage={
            "direct_anchor_pipeline": True,
            "canonical_primary_attempted": True,
            "canonical_primary_completed": False,
        },
    )
    state.report = AgentReport(
        run_id=state.run_id,
        status=state.status,
        executive_summary="mixed candidates",
        findings=[good, bad],
        evidence=[good_evidence, bad_evidence],
    )

    summary = ToolGainGate.apply(state, artifact_store=cas, capsule_store=capsules)
    snapshot = AdmissionService.seal(state, state.report, artifact_store=cas, capsule_store=capsules)
    assert summary.accepted_new == 1
    assert summary.quarantined_finding_ids == ("bad",)
    assert snapshot.admitted_finding_ids == ["good"]
    assert snapshot.rejected_finding_ids == ["bad"]
    assert any(item.finding_id == "bad" for item in capsules.replay())
