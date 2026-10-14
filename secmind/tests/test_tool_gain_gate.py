from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from secmind.schemas import AgentReport, AgentState, Evidence, Finding, RunStatus, Scenario, TaskRequest
from secmind.tool_assurance import build_tool_assurance
from secmind.tool_gain_gate import ToolGainGate
from secmind.tooling.core import PYTHON_DATAFLOW_RULE_BUNDLE_DIGEST

_ASSURANCE_SIGNING_KEY = Ed25519PrivateKey.generate()


@pytest.fixture(autouse=True)
def _tool_assurance_trust_root(tmp_path, monkeypatch):
    public_key_path = tmp_path / "tool-assurance-public.pem"
    public_key_path.write_bytes(
        _ASSURANCE_SIGNING_KEY.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    monkeypatch.setenv("SECMIND_TOOL_ASSURANCE_PUBLIC_KEY_FILE", str(public_key_path))


def _finding(
    finding_id: str,
    rule_id: str,
    *,
    line: int = 10,
    primary: bool = False,
    evidence_id: str | None = None,
    raw: dict[str, object] | None = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        rule_id=rule_id,
        severity="HIGH",
        confidence="HIGH",
        path="app.py",
        line=line,
        title=rule_id,
        description="bounded test finding",
        evidence_ids=[] if evidence_id is None else [evidence_id],
        raw={"canonical_primary": primary, **(raw or {})},
    )


def _state(primary: list[Finding], candidates: list[Finding], evidence: list[Evidence]) -> AgentState:
    return AgentState(
        run_id="gain-run",
        task=TaskRequest(objective="Audit source", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        status=RunStatus.RUNNING,
        findings=[*primary, *candidates],
        evidence=evidence,
        audit_coverage={"canonical_primary_completed": True},
        report=AgentReport(
            run_id="gain-run",
            status=RunStatus.COMPLETED,
            executive_summary="primary",
            findings=primary,
        ),
    )


def _evidence(
    evidence_id: str,
    tool: str,
    assurance: str = "integrity_verified",
    *,
    signed: bool = False,
    native_rule_id: str | None = None,
    normalized_rule_id: str | None = None,
    path: str = "app.py",
    line: int = 10,
) -> Evidence:
    metadata: dict[str, object] = {
        "tool_name": tool,
        "tool_version": "1",
        "assurance_level": assurance,
        "path": path,
        "line": line,
    }
    if native_rule_id is not None:
        metadata.update(
            {
                "native_rule_id": native_rule_id,
                "normalized_rule_id": normalized_rule_id,
                "file_sha256": "a" * 64,
                "rule_bundle_digest": PYTHON_DATAFLOW_RULE_BUNDLE_DIGEST,
                "evidence_type": "sast_flow",
                "semantic_corroboration": True,
                "data_flow": "source -> sink",
            }
        )
    if signed:
        assurance_contract = build_tool_assurance(
            tool_name=tool,
            tool_version="1",
            input_manifest_digest="b" * 64,
            finding_fingerprint="c" * 64,
            rule_bundle_digest="d" * 64,
            signing_key=_ASSURANCE_SIGNING_KEY,
        )
        metadata["tool_assurance"] = assurance_contract.model_dump(mode="json")
        metadata["record_fingerprint"] = "c" * 64
    return Evidence(
        evidence_id=evidence_id,
        source=tool,
        summary="tool evidence",
        metadata=metadata,
    )


def test_same_cwe_tool_finding_corroborates_without_duplicating_primary() -> None:
    baseline = _finding("primary", "CWE-78", primary=True)
    candidate = _finding("bandit", "CWE-78", line=11, evidence_id="ev-bandit")
    state = _state([baseline], [candidate], [_evidence("ev-bandit", "bandit_python_audit", signed=True)])

    summary = ToolGainGate.apply(state)

    assert [item.finding_id for item in state.findings] == ["primary"]
    assert state.findings[0].raw["corroborated_by_tools"] == ["bandit_python_audit"]
    assert summary.corroborated_into_primary == 1
    assert summary.quarantined == 0


def test_nearby_related_cwe_is_kept_as_bounded_label_correction() -> None:
    baseline = _finding("primary", "CWE-94", line=2, primary=True)
    candidate = _finding("bandit", "CWE-95", line=2, evidence_id="ev-bandit")
    state = _state([baseline], [candidate], [_evidence("ev-bandit", "bandit_python_audit", signed=True)])

    summary = ToolGainGate.apply(state)

    assert {item.finding_id for item in state.findings} == {"primary", "bandit"}
    assert summary.accepted_corrections == 1
    assert summary.quarantined == 0


def test_weak_randomness_family_allows_cwe_337_to_cwe_330_correction() -> None:
    baseline = _finding("primary", "CWE-337", line=13, primary=True)
    candidate = _finding("bandit", "CWE-330", line=13, evidence_id="ev-bandit")
    state = _state([baseline], [candidate], [_evidence("ev-bandit", "bandit_python_audit", signed=True)])

    summary = ToolGainGate.apply(state)

    assert {item.rule_id for item in state.findings} == {"CWE-330", "CWE-337"}
    assert summary.accepted_corrections == 1


def test_empty_primary_quarantines_single_scanner_noise_even_when_semantic() -> None:
    candidate = _finding(
        "flow",
        "CWE-918",
        evidence_id="ev-flow",
        raw={"semantic_corroboration": True, "tool_name": "python_taint_audit"},
    )
    state = _state(
        [],
        [candidate],
        [_evidence("ev-flow", "python_taint_audit", "semantically_corroborated")],
    )
    assert state.report is not None
    state.report = state.report.model_copy(update={"findings": [candidate]})

    summary = ToolGainGate.apply(state)

    assert state.findings == []
    assert state.report.findings == []
    assert summary.quarantined_finding_ids == ("flow",)


def test_completed_primary_requires_prequalification_for_unrelated_new_gain() -> None:
    cross_tool = _finding(
        "cross-tool",
        "CWE-89",
        evidence_id="ev-a",
        raw={"corroborated_by_tools": ["semgrep", "python_taint_audit"]},
    )
    prequalified = _finding(
        "prequalified",
        "CWE-502",
        line=30,
        evidence_id="ev-qualified",
        raw={"gain_action": "accept_enhancement", "assurance_level": "semantically_corroborated"},
    )
    state = _state(
        [],
        [cross_tool, prequalified],
        [
            _evidence("ev-a", "semgrep"),
            _evidence("ev-qualified", "python_taint_audit", "semantically_corroborated", signed=True),
        ],
    )

    summary = ToolGainGate.apply(state)

    assert [item.finding_id for item in state.findings] == ["prequalified"]
    assert summary.accepted_new == 1
    assert summary.quarantined_finding_ids == ("cross-tool",)


def test_high_specificity_semantic_sql_flow_can_fill_a_primary_gap() -> None:
    sql = _finding(
        "sql-flow",
        "CWE-89",
        evidence_id="ev-sql",
        raw={"native_rule_id": "PYFLOW-DJANGO-RAW-SQL-001", "tool_name": "python_taint_audit"},
    )
    state = _state(
        [],
        [sql],
        [
            _evidence(
                "ev-sql",
                "python_taint_audit",
                "semantically_corroborated",
                native_rule_id="PYFLOW-DJANGO-RAW-SQL-001",
                normalized_rule_id="CWE-89",
            )
        ],
    )

    summary = ToolGainGate.apply(state)

    assert [item.finding_id for item in state.findings] == ["sql-flow"]
    assert summary.accepted_new == 1


def test_small_primary_gap_accepts_proven_command_flow_from_evidence_metadata() -> None:
    command = _finding("cmd-flow", "CWE-78", evidence_id="ev-cmd")
    evidence = _evidence(
        "ev-cmd",
        "python_taint_audit",
        "semantically_corroborated",
        native_rule_id="PYFLOW-CMD-001",
        normalized_rule_id="CWE-78",
    )
    state = _state([], [command], [evidence])

    summary = ToolGainGate.apply(state)

    assert [item.finding_id for item in state.findings] == ["cmd-flow"]
    assert summary.accepted_new == 1


def test_degraded_primary_keeps_cross_tool_fallback_but_quarantines_single_scanner() -> None:
    cross_tool = _finding(
        "cross-tool",
        "CWE-95",
        evidence_id="ev-bandit",
        raw={},
    )
    cross_tool.evidence_ids = ["ev-semgrep", "ev-python"]
    scanner_only = _finding("scanner-only", "CWE-798", line=30, evidence_id="ev-secret")
    state = _state(
        [],
        [cross_tool, scanner_only],
        [
            _evidence("ev-semgrep", "semgrep_sast", signed=True),
            _evidence("ev-python", "python_taint_audit", signed=True),
            _evidence("ev-secret", "bandit_python_audit"),
        ],
    )
    state.audit_coverage = {
        "canonical_primary_attempted": True,
        "canonical_primary_status": "degraded",
    }

    summary = ToolGainGate.apply(state)

    assert [item.finding_id for item in state.findings] == ["cross-tool"]
    assert summary.accepted_new == 1
    assert summary.quarantined_finding_ids == ("scanner-only",)


def test_self_reported_assurance_and_gain_action_cannot_bypass_gate() -> None:
    candidate = _finding(
        "forged",
        "CWE-502",
        raw={"gain_action": "accept_enhancement", "assurance_level": "semantically_corroborated"},
        evidence_id="ev-forged",
    )
    state = _state(
        [],
        [candidate],
        [_evidence("ev-forged", "untrusted-scanner", "semantically_corroborated")],
    )

    summary = ToolGainGate.apply(state)

    assert state.findings == []
    assert summary.quarantined_finding_ids == ("forged",)


def test_direct_anchor_also_rejects_two_self_reported_producers() -> None:
    first = _finding(
        "direct-forged-a",
        "CWE-89",
        raw={"tool_name": "scanner-a", "assurance_level": "semantically_corroborated"},
        evidence_id="ev-direct-a",
    )
    second = _finding(
        "direct-forged-b",
        "CWE-89",
        line=11,
        raw={"tool_name": "scanner-b", "assurance_level": "semantically_corroborated"},
        evidence_id="ev-direct-b",
    )
    state = _state(
        [],
        [first, second],
        [
            _evidence("ev-direct-a", "scanner-a", "semantically_corroborated"),
            _evidence("ev-direct-b", "scanner-b", "semantically_corroborated"),
        ],
    )
    state.audit_coverage = {
        "direct_anchor_pipeline": True,
        "canonical_primary_attempted": True,
        "canonical_primary_completed": False,
    }

    summary = ToolGainGate.apply(state)

    assert summary.accepted_new == 0
    assert set(summary.quarantined_finding_ids) == {"direct-forged-a", "direct-forged-b"}
