from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from secmind.admission import AdmissionService
from secmind.direct_anchor_pipeline import TypedDelta
from secmind.guardrail import Guardrail
from secmind.ledger import LedgerStore
from secmind.llm import QwenGateway
from secmind.orchestrator import SecMindOrchestrator
from secmind.primary_baseline import publish_primary_baseline
from secmind.schemas import (
    AgentReport,
    AgentState,
    AttachmentRef,
    Evidence,
    Finding,
    InputArtifact,
    PlanStep,
    RunStatus,
    Scenario,
    TaskRequest,
)
from secmind.task_specs import TaskSpecCompiler
from secmind.tool_affinity import route_tools_by_affinity
from secmind.tool_assurance import bind_evidence_to_input_cas
from secmind.tool_gain_gate import ToolGainGate
from secmind.tools import ToolBroker, ToolContext, ToolStatus, WebWorkflowAuditTool, default_registry
from secmind.web_static_audit import (
    CAPTCHA_STAGE_BYPASS_RULE,
    PASSWORD_CHANGE_WITHOUT_REAUTH_RULE,
    RULE_BUNDLE_DIGEST,
    WEAK_PASSWORD_HASH_RULE,
    analyze_web_source,
)

VULNERABLE_WORKFLOW = """<?php
if (isset($_POST['submit']) && $_POST['stage'] === 'verify') {
    $ok = recaptcha_check_answer($_POST['captcha']);
    if (!$ok) { return; }
    $html .= '<input type="hidden" name="stage" value="commit">';
}
if (isset($_POST['submit']) && $_POST['stage'] === 'commit') {
    $query = "UPDATE users SET enabled = 1";
    mysqli_query($db, $query);
}
?>
"""

WEB_CREDENTIAL_FLOW_SAMPLE = """<?php
if (isset($_POST['Change']) && $_POST['step'] === '2') {
    $pass_new = $_POST['password_new'];
    $pass_conf = $_POST['password_conf'];
    if ($pass_new == $pass_conf) {
        $pass_new = md5($pass_new);
        $query = "UPDATE users SET password = '$pass_new' WHERE user = '" . ProjectCurrentUser() . "'";
        mysqli_query($db, $query);
    }
}
?>
"""


def test_analyzer_proves_client_controlled_gate_bypass_with_exact_sink() -> None:
    findings = analyze_web_source(VULNERABLE_WORKFLOW)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.native_rule_id == CAPTCHA_STAGE_BYPASS_RULE
    assert finding.rule_id == "CWE-840"
    assert finding.line == 7
    assert finding.sink_line == 8
    assert finding.data_flow == (
        "request:POST.stage=commit",
        "branch:stage=commit",
        "sink:mutating_sql@8",
    )


def test_analyzer_proves_password_change_without_current_credential() -> None:
    findings = analyze_web_source(WEB_CREDENTIAL_FLOW_SAMPLE)

    assert len(findings) == 2
    finding = next(item for item in findings if item.native_rule_id == PASSWORD_CHANGE_WITHOUT_REAUTH_RULE)
    assert finding.native_rule_id == PASSWORD_CHANGE_WITHOUT_REAUTH_RULE
    assert finding.rule_id == "CWE-620"
    assert finding.line == 7
    assert finding.sink_line == 8
    assert finding.weakness_ids == ("CWE-620",)
    assert finding.data_flow == (
        "request:POST.password_new",
        "confirmation:POST.password_conf",
        "equality_gate@5",
        "sink:password_update@7",
    )

    weak_hash = next(item for item in findings if item.native_rule_id == WEAK_PASSWORD_HASH_RULE)
    assert weak_hash.rule_id == "CWE-327"
    assert weak_hash.line == 6
    assert weak_hash.sink_line == 7
    assert weak_hash.weakness_ids == ("CWE-327", "CWE-916")
    assert weak_hash.data_flow == (
        "request:POST.password_new",
        "weak_digest:md5@6",
        "sink:password_update@7",
    )


def test_modern_password_hash_suppresses_only_the_weak_hash_rule() -> None:
    source = WEB_CREDENTIAL_FLOW_SAMPLE.replace(
        "md5($pass_new)",
        "password_hash($pass_new, PASSWORD_ARGON2ID)",
    )

    findings = analyze_web_source(source)

    assert [item.native_rule_id for item in findings] == [PASSWORD_CHANGE_WITHOUT_REAUTH_RULE]


@pytest.mark.parametrize(
    "source",
    [
        WEB_CREDENTIAL_FLOW_SAMPLE.replace(
            "$pass_new = $_POST['password_new'];",
            "$current = $_POST['current_password'];\n    $pass_new = $_POST['password_new'];",
        ),
        WEB_CREDENTIAL_FLOW_SAMPLE.replace(
            "if ($pass_new == $pass_conf) {",
            "if (authenticate($_POST['password']) && $pass_new == $pass_conf) {",
        ),
        WEB_CREDENTIAL_FLOW_SAMPLE.replace(
            "if ($pass_new == $pass_conf) {",
            "if (password_verify($_POST['current_password'], $stored) && $pass_new == $pass_conf) {",
        ),
        WEB_CREDENTIAL_FLOW_SAMPLE.replace(
            "if ($pass_new == $pass_conf) {",
            "if ($_SESSION['password_reauth_verified'] && $pass_new == $pass_conf) {",
        ),
        WEB_CREDENTIAL_FLOW_SAMPLE.replace("ProjectCurrentUser()", "$_POST['target_user']"),
        WEB_CREDENTIAL_FLOW_SAMPLE.replace("UPDATE users SET password", "SELECT password"),
        WEB_CREDENTIAL_FLOW_SAMPLE.replace("$pass_new == $pass_conf", "$pass_new != ''"),
        """<?php
// $pass_new = $_POST['password_new']; $pass_conf = $_POST['password_conf'];
// if ($pass_new == $pass_conf) UPDATE users SET password = '$pass_new';
echo 'safe';
?>""",
    ],
)
def test_password_change_rule_rejects_incomplete_or_verified_flows(source: str) -> None:
    assert analyze_web_source(source) == ()


@pytest.mark.parametrize(
    "source",
    [
        # The state-changing branch repeats a server-bound transition check.
        VULNERABLE_WORKFLOW.replace(
            '$query = "UPDATE users SET enabled = 1";',
            "if (!$_SESSION['captcha_ok']) { return; }\n    $query = \"UPDATE users SET enabled = 1\";",
        ),
        # A later branch without a mutating operation is not a vulnerability.
        VULNERABLE_WORKFLOW.replace("UPDATE users SET enabled = 1", "SELECT enabled FROM users"),
        # Security vocabulary in comments is never executable evidence.
        "<?php // recaptcha stage=verify, hidden stage commit, UPDATE users\n echo 'safe'; ?>",
        # A hidden field alone does not prove that a verification branch exists.
        '<?php $html = \'<input type="hidden" name="stage" value="commit">\'; ?>',
        # Calling a challenge API without enforcing its result is not a proven gate.
        VULNERABLE_WORKFLOW.replace("if (!$ok) { return; }", "$audit_log = $ok;"),
        # Branch-shaped text inside a string must never become executable evidence.
        """<?php
$decoy = "if ($_POST['stage'] === 'verify') { recaptcha_check(); return; "
       . "<input type='hidden' name='stage' value='commit'>; }";
if ($_POST['stage'] === 'commit') {
    $query = "UPDATE users SET enabled = 1";
    mysqli_query($db, $query);
}
?>""",
    ],
)
def test_analyzer_rejects_incomplete_or_server_bound_workflow_claims(source: str) -> None:
    assert analyze_web_source(source) == ()


@pytest.mark.asyncio
async def test_registered_web_tool_emits_hash_and_line_bound_evidence(tmp_path: Path) -> None:
    target = tmp_path / "change.php"
    payload = VULNERABLE_WORKFLOW.encode()
    target.write_bytes(payload)
    tool = WebWorkflowAuditTool()

    result = await tool.invoke(
        {"target": "."},
        ToolContext(
            run_id="web-run",
            step_id="scan-web",
            workspace=str(tmp_path),
            allowed_paths=[str(tmp_path)],
            invocation_id="web-invocation",
        ),
    )

    assert result.status == ToolStatus.SUCCESS
    assert result.invocation_id == "web-invocation"
    assert result.data["parse_failures"] == 0
    assert result.data["coverage"]["complete"] is True
    assert len(result.data["findings"]) == 1
    finding = Finding.model_validate(result.data["findings"][0])
    evidence = result.evidence[0]
    assert finding.rule_id == "CWE-840"
    assert finding.path == "change.php"
    assert finding.line == 7
    assert evidence.metadata["path"] == finding.path
    assert evidence.metadata["line"] == finding.line
    assert evidence.metadata["file_sha256"] == hashlib.sha256(payload).hexdigest()
    assert evidence.metadata["native_rule_id"] == CAPTCHA_STAGE_BYPASS_RULE
    assert evidence.metadata["normalized_rule_id"] == "CWE-840"
    assert evidence.metadata["weakness_ids"] == ["CWE-840", "CWE-841", "CWE-602"]
    assert evidence.metadata["semantic_corroboration"] is True


@pytest.mark.asyncio
async def test_degraded_primary_accepts_closed_password_reauth_rule(tmp_path: Path) -> None:
    target = tmp_path / "change.php"
    target.write_text(
        WEB_CREDENTIAL_FLOW_SAMPLE.replace("md5($pass_new)", "password_hash($pass_new, PASSWORD_ARGON2ID)"),
        encoding="utf-8",
    )
    result = await WebWorkflowAuditTool().invoke(
        {"target": "."},
        ToolContext(
            run_id="password-gain",
            step_id="scan-web",
            workspace=str(tmp_path),
            allowed_paths=[str(tmp_path)],
            invocation_id="password-invocation",
        ),
    )
    candidate = Finding.model_validate(result.data["findings"][0])
    state = AgentState(
        run_id="password-gain",
        task=TaskRequest(objective="Audit the password-change workflow", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        status=RunStatus.RUNNING,
        findings=[candidate],
        evidence=list(result.evidence),
        audit_coverage={
            "canonical_primary_attempted": True,
            "canonical_primary_completed": False,
            "direct_anchor_pipeline": True,
            "direct_anchor_strict": True,
        },
        report=AgentReport(
            run_id="password-gain",
            status=RunStatus.PARTIAL,
            executive_summary="Primary degraded safely.",
        ),
    )

    summary = ToolGainGate.apply(state)

    assert summary.accepted_new == 1
    assert summary.quarantined == 0
    assert [item.rule_id for item in state.findings] == ["CWE-620"]
    evidence = state.evidence[0]
    assert evidence.metadata["native_rule_id"] == PASSWORD_CHANGE_WITHOUT_REAUTH_RULE
    assert evidence.metadata["weakness_ids"] == ["CWE-620"]


def test_php_affinity_selects_web_workflow_tool_instead_of_incompatible_scanners(tmp_path: Path) -> None:
    target = tmp_path / "change.php"
    payload = VULNERABLE_WORKFLOW.encode()
    target.write_bytes(payload)
    artifact = InputArtifact(
        original_name=target.name,
        relative_path=target.name,
        sha256=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
        media_type="application/x-httpd-php",
    )
    registry = default_registry()
    step = PlanStep(
        step_id="sast",
        objective="audit web workflow",
        agent_role="sast_specialist",
        capability="sast",
        tool_candidates=[
            "bandit_python_audit",
            "python_taint_audit",
            "java_semantic_sast",
            "web_workflow_audit",
        ],
        inputs={"target": "."},
        success_criteria=["evidence is bound"],
    )

    routed = route_tools_by_affinity(
        workspace=tmp_path,
        artifacts=[artifact],
        steps=[step],
        manifests={item.name: item for item in registry.manifests()},
    )

    assert routed.steps[0].tool_candidates == ["web_workflow_audit"]
    assert routed.scores["web_workflow_audit"] >= 90


@pytest.mark.asyncio
async def test_degraded_primary_accepts_closed_native_web_rule(tmp_path: Path) -> None:
    target = tmp_path / "change.php"
    target.write_text(VULNERABLE_WORKFLOW, encoding="utf-8")
    result = await WebWorkflowAuditTool().invoke(
        {"target": "."},
        ToolContext(
            run_id="web-gain",
            step_id="scan-web",
            workspace=str(tmp_path),
            allowed_paths=[str(tmp_path)],
        ),
    )
    candidate = Finding.model_validate(result.data["findings"][0])
    state = AgentState(
        run_id="web-gain",
        task=TaskRequest(objective="Audit the web workflow", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        status=RunStatus.RUNNING,
        findings=[candidate],
        evidence=list(result.evidence),
        audit_coverage={
            "canonical_primary_attempted": True,
            "canonical_primary_completed": False,
            "direct_anchor_pipeline": True,
            "direct_anchor_strict": True,
        },
        report=AgentReport(
            run_id="web-gain",
            status=RunStatus.PARTIAL,
            executive_summary="Primary degraded safely.",
        ),
    )

    summary = ToolGainGate.apply(state)

    assert summary.accepted_new == 1
    assert summary.quarantined == 0
    assert len(summary.typed_delta_ids) == 1
    assert [item.rule_id for item in state.findings] == ["CWE-840"]


@pytest.mark.asyncio
async def test_completed_unrelated_primary_accepts_unique_cas_bound_web_rule(
    tmp_path: Path,
    admission_stores,
) -> None:
    runner_input = tmp_path / "runner" / "input"
    runner_input.mkdir(parents=True)
    target = runner_input / "subject.php"
    payload = VULNERABLE_WORKFLOW.encode()
    target.write_bytes(payload)
    result = await WebWorkflowAuditTool().invoke(
        {"target": "."},
        ToolContext(
            run_id="web-independent-gain",
            step_id="scan-web",
            workspace=str(runner_input.parent),
            allowed_paths=[str(runner_input.parent)],
        ),
    )
    candidate = Finding.model_validate(result.data["findings"][0])
    input_digest = hashlib.sha256(payload).hexdigest()
    artifact = InputArtifact(
        original_name="subject.php",
        relative_path="upload-namespace/input/subject.php",
        sha256=input_digest,
        size_bytes=len(payload),
        media_type="application/x-httpd-php",
    )
    bound_evidence = bind_evidence_to_input_cas(list(result.evidence), [candidate], [artifact])
    artifact_store, _ = admission_stores
    artifact_store.put(
        payload,
        expected_sha256=input_digest,
        run_id="web-independent-gain",
        media_type="application/x-httpd-php",
    )
    primary = Finding(
        finding_id="canonical-xss",
        rule_id="CWE-79",
        severity="HIGH",
        confidence="HIGH",
        path="subject.php",
        line=6,
        title="reflected input",
        description="unrelated canonical finding",
        raw={"canonical_primary": True},
    )
    state = AgentState(
        run_id="web-independent-gain",
        task=TaskRequest(objective="Audit the web workflow", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        status=RunStatus.RUNNING,
        input_artifacts=[artifact],
        findings=[primary, candidate],
        evidence=bound_evidence,
        audit_coverage={
            "canonical_primary_attempted": True,
            "canonical_primary_completed": True,
            "direct_anchor_pipeline": True,
            "direct_anchor_strict": True,
        },
        report=AgentReport(
            run_id="web-independent-gain",
            status=RunStatus.PARTIAL,
            executive_summary="Primary completed without workflow coverage.",
            findings=[primary],
        ),
    )

    summary = ToolGainGate.apply(state, artifact_store=artifact_store)

    assert summary.accepted_new == 1
    assert summary.quarantined == 0
    assert {item.rule_id for item in state.findings} == {"CWE-79", "CWE-840"}
    assert state.audit_coverage["typed_deltas"][0]["action"] == "added"
    assert state.audit_coverage["typed_deltas"][0]["reason_code"] == "single_producer_high_assurance_admission"
    assert state.audit_coverage["tool_gain_gate_diagnostics"]["failed_semantic_check_counts"] == {}


@pytest.mark.asyncio
async def test_completed_primary_accepts_cas_bound_native_web_rule(tmp_path: Path, admission_stores) -> None:
    input_directory = tmp_path / "input"
    input_directory.mkdir()
    target = input_directory / "subject.php"
    target.write_text(VULNERABLE_WORKFLOW, encoding="utf-8")
    target_payload = target.read_bytes()
    artifact_store, capsule_store = admission_stores
    broker = ToolBroker(default_registry(), Guardrail(), artifact_store=artifact_store)
    try:
        result = await broker.execute(
            "web_workflow_audit",
            {"target": "."},
            ToolContext(
                run_id="web-live-gain",
                step_id="scan-web",
                workspace=str(tmp_path),
                allowed_paths=[str(tmp_path)],
                invocation_id="web-live-invocation",
                idempotency_key="web-live-idempotency",
            ),
            autonomy_policy="automatic",
        )
    finally:
        broker.close()
    candidate = Finding.model_validate(result.data["findings"][0])
    primary_evidence = Evidence(
        evidence_id="canonical-workflow-evidence",
        source="secmind:canonical-primary:test",
        summary="The client-controlled stage reaches the state-changing branch.",
        artifact_ref=hashlib.sha256(target_payload).hexdigest(),
        sha256=hashlib.sha256(target_payload).hexdigest(),
        metadata={
            "path": "subject.php",
            "file_sha256": hashlib.sha256(target_payload).hexdigest(),
            "line": candidate.line,
        },
    )
    primary = Finding(
        finding_id="canonical-workflow",
        rule_id="CWE-602",
        severity="HIGH",
        confidence="HIGH",
        path="subject.php",
        line=candidate.line,
        title="Client-controlled workflow",
        description="The model identified a workflow weakness.",
        remediation="Bind workflow state to the server-side session.",
        evidence_ids=[primary_evidence.evidence_id],
        raw={"canonical_primary": True},
    )
    state = AgentState(
        run_id="web-live-gain",
        task=TaskRequest(objective="Audit the web workflow", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        status=RunStatus.RUNNING,
        input_artifacts=[
            InputArtifact(
                original_name="subject.php",
                relative_path="input/subject.php",
                sha256=hashlib.sha256(target_payload).hexdigest(),
                size_bytes=len(target_payload),
                media_type="application/x-httpd-php",
            )
        ],
        findings=[primary, candidate],
        evidence=[primary_evidence, *result.evidence],
        audit_coverage={
            "canonical_primary_attempted": True,
            "canonical_primary_completed": True,
            "direct_anchor_pipeline": True,
            "direct_anchor_strict": True,
        },
        report=AgentReport(
            run_id="web-live-gain",
            status=RunStatus.PARTIAL,
            executive_summary="Primary completed with a broader taxonomy label.",
            findings=[primary],
            evidence=[primary_evidence],
        ),
    )
    primary_response = b"sealed primary response"
    primary_response_sha256 = hashlib.sha256(primary_response).hexdigest()
    artifact_store.put(
        target_payload,
        expected_sha256=hashlib.sha256(target_payload).hexdigest(),
        run_id=state.run_id,
        media_type="application/x-httpd-php",
    )
    artifact_store.put(
        primary_response,
        expected_sha256=primary_response_sha256,
        run_id=state.run_id,
        media_type="application/vnd.secmind.canonical-primary+json",
    )
    publish_primary_baseline(
        state,
        model_id="gpt-5.6-terra",
        prompt_version="canonical-primary-test",
        prompt_artifact_id=None,
        request_sha256="1" * 64,
        response_sha256=primary_response_sha256,
        response_schema_sha256="2" * 64,
        context_sha256="3" * 64,
        response_artifact_id=primary_response_sha256,
        provider_requests=1,
        input_tokens=10,
        output_tokens=10,
        cost_units=0,
        status=RunStatus.COMPLETED,
        executive_summary="Primary completed with a broader taxonomy label.",
        findings=[primary],
        evidence=[primary_evidence],
        decisions=[],
        limitations=[],
        coverage=state.audit_coverage,
    )

    summary = ToolGainGate.apply(state, artifact_store=artifact_store)

    assert summary.accepted_new == 0
    assert summary.accepted_corrections == 1
    assert summary.corroborated_into_primary == 0
    assert summary.quarantined == 0
    assert {item.rule_id for item in state.findings} == {"CWE-602", "CWE-840"}
    delta = state.audit_coverage["typed_deltas"][0]
    assert delta["action"] == "corrected"
    assert delta["target_finding_id"] == primary.finding_id
    refinement = TypedDelta.model_validate(delta).finding
    assert refinement is not None
    assert refinement.rule_id == "CWE-840"
    assert refinement.path == "input/subject.php"
    evidence_by_id = {item.evidence_id: item for item in state.evidence}
    assert evidence_by_id[refinement.evidence_ids[0]].metadata["path"] == "input/subject.php"
    assert AdmissionService._direct_delta_authorizes(
        state,
        TypedDelta.model_validate(delta),
        refinement,
        set(refinement.evidence_ids),
        evidence_by_id,
        rehashed_evidence_ids=set(refinement.evidence_ids),
    )
    assert not AdmissionService._direct_delta_authorizes(
        state,
        TypedDelta.model_validate(delta),
        refinement,
        set(refinement.evidence_ids),
        evidence_by_id,
        rehashed_evidence_ids=set(),
    )
    forged_manifest = state.model_copy(deep=True)
    forged_manifest.input_artifacts[0] = forged_manifest.input_artifacts[0].model_copy(update={"sha256": "f" * 64})
    assert not AdmissionService._direct_delta_authorizes(
        forged_manifest,
        TypedDelta.model_validate(delta),
        refinement,
        set(refinement.evidence_ids),
        evidence_by_id,
        rehashed_evidence_ids=set(refinement.evidence_ids),
    )
    assert state.audit_coverage["gain_gate_cas_rehash"]["failures"] == {}
    assert state.audit_coverage["tool_path_canonicalization"] == {
        "version": "manifest-path-canonicalization-1.1",
        "canonicalized_count": 1,
        "primary": {
            "version": "manifest-path-canonicalization-1.1",
            "canonicalized_count": 1,
            "unchanged_count": 0,
            "ambiguous_count": 0,
            "invalid_manifest": False,
        },
        "candidates": {
            "version": "manifest-path-canonicalization-1.1",
            "canonicalized_count": 0,
            "unchanged_count": 1,
            "ambiguous_count": 0,
            "invalid_manifest": False,
        },
    }
    diagnostics = state.audit_coverage["tool_gain_gate_diagnostics"]
    assert diagnostics["accepted_count"] == 1
    assert diagnostics["corroborated_count"] == 0
    assert diagnostics["reason_counts"] == {"bounded_native_taxonomy_normalization": 1}
    assert diagnostics["failed_semantic_check_counts"] == {}
    assert diagnostics["cas_rehash_failure_counts"] == {}
    assert "candidate_id" not in diagnostics

    snapshot = AdmissionService.seal(
        state,
        state.report,
        artifact_store=artifact_store,
        capsule_store=capsule_store,
    )
    assert [item.rule_id for item in snapshot.report.findings] == ["CWE-840"]
    assert result.evidence[0].evidence_id in snapshot.report.findings[0].evidence_ids
    assert result.evidence[0].evidence_id in {item.evidence_id for item in snapshot.report.evidence}


@pytest.mark.parametrize(
    ("candidate_path", "artifacts"),
    [
        (
            "subject.php",
            [
                ("a/subject.php", "1" * 64),
                ("b/subject.php", "1" * 64),
            ],
        ),
        ("../subject.php", [("subject.php", "1" * 64)]),
        ("input/subject.php", [("subject.php", "2" * 64)]),
    ],
)
def test_manifest_path_canonicalization_rejects_ambiguity_traversal_and_forged_digest(
    candidate_path: str,
    artifacts: list[tuple[str, str]],
) -> None:
    evidence = Evidence(
        evidence_id="candidate-evidence",
        source="web_workflow_audit:1.0",
        summary="bounded workflow evidence",
        metadata={"path": candidate_path, "file_sha256": "1" * 64},
    )
    candidate = Finding(
        finding_id="candidate",
        rule_id="CWE-841",
        severity="HIGH",
        confidence="HIGH",
        path=candidate_path,
        line=7,
        title="workflow bypass",
        description="bounded",
        evidence_ids=[evidence.evidence_id],
    )
    state = AgentState(
        run_id="path-boundary",
        task=TaskRequest(objective="audit source", autonomy_policy="automatic"),
        input_artifacts=[
            InputArtifact(
                original_name=Path(path).name,
                relative_path=path,
                sha256=sha256,
                size_bytes=1,
            )
            for path, sha256 in artifacts
        ],
    )

    prepared, prepared_evidence, diagnostics = ToolGainGate._canonicalize_manifest_bound_paths(
        state,
        [candidate],
        {evidence.evidence_id: evidence},
    )

    assert prepared[0].path == candidate_path
    assert prepared_evidence[evidence.evidence_id].metadata["path"] == candidate_path
    assert diagnostics["canonicalized_count"] == 0


def test_manifest_path_canonicalization_converges_distinct_trusted_namespaces() -> None:
    evidence = Evidence(
        evidence_id="candidate-evidence",
        source="web_workflow_audit:1.0",
        summary="bounded workflow evidence",
        metadata={
            "path": "subject.php",
            "file_sha256": "1" * 64,
            "line": 37,
            "tool_name": "web_workflow_audit",
            "native_rule_id": CAPTCHA_STAGE_BYPASS_RULE,
            "normalized_rule_id": "CWE-840",
            "rule_bundle_digest": RULE_BUNDLE_DIGEST,
            "evidence_type": "sast_flow",
            "semantic_corroboration": True,
            "data_flow": ["request:POST.step=2", "sink:mutating_sql@47"],
        },
    )
    candidate = Finding(
        finding_id="candidate",
        rule_id="CWE-840",
        severity="HIGH",
        confidence="HIGH",
        path="input/subject.php",
        line=37,
        title="workflow bypass",
        description="bounded",
        evidence_ids=[evidence.evidence_id],
    )
    state = AgentState(
        run_id="path-prefixes",
        task=TaskRequest(objective="audit source", autonomy_policy="automatic"),
        input_artifacts=[
            InputArtifact(
                original_name="subject.php",
                relative_path="upload-namespace/input/subject.php",
                sha256="1" * 64,
                size_bytes=1,
            )
        ],
    )

    prepared, prepared_evidence, diagnostics = ToolGainGate._canonicalize_manifest_bound_paths(
        state,
        [candidate],
        {evidence.evidence_id: evidence},
    )

    canonical_path = "upload-namespace/input/subject.php"
    assert prepared[0].path == canonical_path
    assert prepared_evidence[evidence.evidence_id].metadata["path"] == canonical_path
    assert diagnostics == {
        "version": "manifest-path-canonicalization-1.1",
        "canonicalized_count": 1,
        "unchanged_count": 0,
        "ambiguous_count": 0,
        "invalid_manifest": False,
    }
    assert (
        ToolGainGate._deterministic_builtin_rule(
            prepared[0],
            prepared_evidence,
        )
        == CAPTCHA_STAGE_BYPASS_RULE
    )


def test_builtin_rule_accepts_cas_verified_namespace_suffix_only() -> None:
    evidence = Evidence(
        evidence_id="candidate-evidence",
        source="web_workflow_audit:1",
        summary="bounded workflow evidence",
        metadata={
            "path": "subject.php",
            "line": 37,
            "file_sha256": "1" * 64,
            "tool_name": "web_workflow_audit",
            "native_rule_id": CAPTCHA_STAGE_BYPASS_RULE,
            "normalized_rule_id": "CWE-840",
            "rule_bundle_digest": RULE_BUNDLE_DIGEST,
            "evidence_type": "sast_flow",
            "semantic_corroboration": True,
            "data_flow": ["request:POST.step=2", "sink:mutating_sql@47"],
        },
    )
    candidate = Finding(
        finding_id="candidate",
        rule_id="CWE-840",
        severity="HIGH",
        confidence="HIGH",
        path="upload/input/subject.php",
        line=37,
        title="workflow bypass",
        description="bounded",
        evidence_ids=[evidence.evidence_id],
    )

    assert ToolGainGate._deterministic_builtin_rule(candidate, {evidence.evidence_id: evidence}) is None
    assert (
        ToolGainGate._deterministic_builtin_rule(
            candidate,
            {evidence.evidence_id: evidence},
            rehashed_evidence_ids={evidence.evidence_id},
        )
        == CAPTCHA_STAGE_BYPASS_RULE
    )
    assert (
        ToolGainGate._deterministic_builtin_rule(
            candidate,
            {evidence.evidence_id: evidence},
            rehashed_evidence_ids=set(),
        )
        is None
    )
    forged_bundle = evidence.model_copy(
        update={"metadata": {**evidence.metadata, "rule_bundle_digest": "f" * 64}},
        deep=True,
    )
    assert (
        ToolGainGate._deterministic_builtin_rule(
            candidate,
            {forged_bundle.evidence_id: forged_bundle},
            rehashed_evidence_ids={forged_bundle.evidence_id},
        )
        is None
    )


@pytest.mark.parametrize("reported_path", ["../subject.php", "subject.php.bak", "other/subject.php.bak"])
def test_builtin_rule_rejects_unsafe_or_non_component_path_even_after_cas_rehash(reported_path: str) -> None:
    evidence = Evidence(
        evidence_id="candidate-evidence",
        source="web_workflow_audit:1",
        summary="bounded workflow evidence",
        metadata={
            "path": reported_path,
            "line": 37,
            "file_sha256": "1" * 64,
            "tool_name": "web_workflow_audit",
            "native_rule_id": CAPTCHA_STAGE_BYPASS_RULE,
            "normalized_rule_id": "CWE-840",
            "rule_bundle_digest": RULE_BUNDLE_DIGEST,
            "evidence_type": "sast_flow",
            "semantic_corroboration": True,
            "data_flow": ["request:POST.step=2", "sink:mutating_sql@47"],
        },
    )
    candidate = Finding(
        finding_id="candidate",
        rule_id="CWE-840",
        severity="HIGH",
        confidence="HIGH",
        path="upload/input/subject.php",
        line=37,
        title="workflow bypass",
        description="bounded",
        evidence_ids=[evidence.evidence_id],
    )

    assert (
        ToolGainGate._deterministic_builtin_rule(
            candidate,
            {evidence.evidence_id: evidence},
            rehashed_evidence_ids={evidence.evidence_id},
        )
        is None
    )


def test_default_registry_exposes_php_workflow_capability() -> None:
    manifest = default_registry().get("web_workflow_audit").manifest
    assert manifest.supported_languages == ["php"]
    assert manifest.evidence_types == ["sast_flow"]
    assert manifest.requires_network is False
    assert manifest.idempotent is True


def test_task_spec_recognizes_language_between_audit_action_and_source() -> None:
    spec = TaskSpecCompiler().compile(
        "php-audit-intent",
        TaskRequest(objective="Audit the PHP source and produce a vulnerability report"),
        [],
        [],
    )

    assert spec.primary_scenario == Scenario.CODE_AUDIT


def test_task_spec_does_not_treat_plain_php_extraction_as_audit() -> None:
    spec = TaskSpecCompiler().compile(
        "php-exact-intent",
        TaskRequest(objective="Extract the exact constant from this PHP source"),
        [],
        [],
    )

    assert spec.primary_scenario == Scenario.UNKNOWN


def test_task_spec_does_not_treat_report_substring_as_repository() -> None:
    spec = TaskSpecCompiler().compile(
        "report-exact-intent",
        TaskRequest(objective="Audit the vulnerability report and extract the exact decision"),
        [],
        [],
    )

    assert spec.primary_scenario == Scenario.UNKNOWN


@pytest.mark.asyncio
async def test_offline_orchestrator_executes_php_tool_and_publishes_finding(settings) -> None:
    settings.prepare_directories()
    (settings.input_root / "change.php").write_text(VULNERABLE_WORKFLOW, encoding="utf-8")
    ledger = LedgerStore(settings.database_url)
    broker = ToolBroker(default_registry(), Guardrail())
    orchestrator = SecMindOrchestrator(settings, ledger, QwenGateway(settings), broker)
    try:
        state = await orchestrator.start(
            TaskRequest(
                objective="Audit the PHP source and produce an evidence-backed vulnerability report",
                attachments=[AttachmentRef(ref="change.php")],
                target_scope=["change.php"],
                autonomy_policy="automatic",
                interaction_mode="unattended",
            ),
            "php-workflow-e2e",
        )
    finally:
        broker.close()
        ledger.close()

    assert state.report is not None, {
        "status": state.status,
        "error": state.last_error,
        "pending_clarification": state.pending_clarification,
        "clarifications": [item.model_dump(mode="json") for item in state.clarifications],
        "decisions": [item.decision for item in state.decisions],
        "coverage": state.audit_coverage,
    }
    assert "tool_routing" in state.report.coverage, {
        "status": state.status,
        "error": state.last_error,
        "report": state.report.model_dump(mode="json"),
        "audit_coverage": state.audit_coverage,
        "plan": [item.model_dump(mode="json") for item in state.plan],
    }
    routing = state.report.coverage["tool_routing"]
    assert "web_workflow_audit" in routing["planned"]
    assert "web_workflow_audit" in routing["executed"]
    assert "web_workflow_audit" in routing["succeeded"]
    assert any(item.rule_id == "CWE-840" and item.line == 7 for item in state.report.findings)
    assert state.report.coverage["admitted_new_finding_count"] == 1
    assert state.status == RunStatus.COMPLETED
