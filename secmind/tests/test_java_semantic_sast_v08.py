from __future__ import annotations

import hashlib
import time
from pathlib import Path

import pytest

from secmind.admission import AdmissionService
from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.evidence_gap import EvidenceGapCompiler
from secmind.evidence_graph import make_claim
from secmind.guardrail import Guardrail
from secmind.java_semantic_sast import (
    NATIVE_RULE_ID,
    SEMANTIC_SIGNAL,
    TOOL_NAME,
    TOOL_VERSION,
    JavaSource,
    analyze_java_sources,
)
from secmind.primary_baseline import publish_primary_baseline
from secmind.schemas import (
    AgentReport,
    AgentState,
    ClaimStatus,
    Finding,
    InputArtifact,
    PlanStep,
    RepositoryIndexRef,
    RunStatus,
    Scenario,
    StepRuntime,
    StepStatus,
    TaskRequest,
    ToolContext,
    ToolStatus,
)
from secmind.tool_gain_gate import ToolGainGate
from secmind.tools import JavaSemanticSastTool, ToolBroker, default_registry


def _source(value: str, path: str = "src/PasswordStore.java") -> JavaSource:
    return JavaSource(path=path, source=value, sha256=hashlib.sha256(value.encode()).hexdigest())


SENSITIVE_MD5_JAVA = """
import java.security.MessageDigest;
class PasswordStore {
    byte[] hashPassword(String password) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return digest.digest(password.getBytes());
    }
}
"""


@pytest.mark.parametrize(
    "source",
    [
        """
        class CacheEntry {
            byte[] checksum(byte[] content) throws Exception {
                return MessageDigest.getInstance("MD5").digest(content);
            }
        }
        """,
        """
        class HttpCache {
            byte[] makeETag(byte[] response) throws Exception {
                return MessageDigest.getInstance("SHA-1").digest(response);
            }
        }
        """,
        """
        class PasswordStore {
            byte[] hashPassword(String password) throws Exception {
                return MessageDigest.getInstance("SHA-512").digest(password.getBytes());
            }
        }
        """,
    ],
)
def test_java_semantic_sast_rejects_non_security_and_strong_digest_uses(source: str) -> None:
    evidence, findings = analyze_java_sources(run_id="run-java-negative", sources=(_source(source),))

    assert evidence == []
    assert findings == []


def test_java_semantic_sast_emits_one_hash_bound_sensitive_digest_finding() -> None:
    evidence, findings = analyze_java_sources(
        run_id="run-java-positive",
        sources=(_source(SENSITIVE_MD5_JAVA), _source(SENSITIVE_MD5_JAVA, "src/Second.java")),
    )

    assert len(findings) == len(evidence) == 1
    finding = Finding.model_validate(findings[0])
    assert finding.rule_id == "CWE-328"
    assert finding.raw["native_rule_id"] == NATIVE_RULE_ID
    assert finding.raw["file_sha256"] == hashlib.sha256(SENSITIVE_MD5_JAVA.encode()).hexdigest()
    assert finding.evidence_ids == [evidence[0].evidence_id]
    assert evidence[0].metadata["semantic_signal"] == SEMANTIC_SIGNAL
    assert evidence[0].metadata["assurance_level"] == "semantically_corroborated"
    assert evidence[0].metadata["flow_id"].startswith("flow-")


def test_java_semantic_sast_proves_digest_output_reaches_sensitive_writer() -> None:
    source = """
    import java.io.FileWriter;
    import java.security.MessageDigest;
    class LegacyStore {
        void checksum(byte[] input) throws Exception {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(input);
            byte[] result = md.digest();
            String passwordFile = "passwordFile.txt";
            FileWriter fw = new FileWriter(passwordFile, true);
            fw.write(new String(result));
        }
    }
    """

    evidence, findings = analyze_java_sources(run_id="run-java-output-flow", sources=(_source(source),))

    assert len(evidence) == len(findings) == 1
    assert evidence[0].metadata["proof_kind"] == "sensitive_sink"
    assert evidence[0].metadata["sink"] == "fw.write"
    assert evidence[0].metadata["data_flow"][-1] == "security_sensitive_sink:fw.write"


def test_java_semantic_sast_tracks_file_target_alias_and_wrapped_digest_output() -> None:
    source = """
    package evaluation.subject;

    public class Subject {
        public void doPost(Object bar) throws Exception {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] input = {(byte) '?'};
            Object inputParam = bar;
            if (inputParam instanceof String) input = ((String) inputParam).getBytes();
            md.update(input);

            byte[] result = md.digest();
            java.io.File fileTarget =
                    new java.io.File(
                            new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR),
                            "passwordFile.txt");
            java.io.FileWriter fw = new java.io.FileWriter(fileTarget, true);
            fw.write(
                    "hash_value="
                            + org.owasp.esapi.ESAPI.encoder().encodeForBase64(result, true)
                            + "\\n");
            fw.close();
        }
    }
    """

    evidence, findings = analyze_java_sources(run_id="run-java-public-dev-regression", sources=(_source(source),))

    assert len(evidence) == len(findings) == 1
    assert evidence[0].metadata["proof_kind"] == "sensitive_sink"
    assert evidence[0].metadata["sensitive_identifier"] == "passwordfile.txt"
    assert evidence[0].metadata["sink"] == "fw.write"


@pytest.mark.parametrize(
    "source",
    [
        """
        class DocumentationChecksum {
            byte[] checksum(byte[] input) throws Exception {
                String documentation = "password storage documentation only";
                MessageDigest md = MessageDigest.getInstance("MD5");
                md.update(input);
                return md.digest();
            }
        }
        """,
        """
        class BoundaryChecksum {
            byte[] checksum(byte[] secretary, byte[] passwordPolicy) throws Exception {
                MessageDigest md = MessageDigest.getInstance("SHA-1");
                md.update(secretary);
                md.update(passwordPolicy);
                return md.digest();
            }
        }
        """,
    ],
)
def test_java_semantic_sast_requires_def_use_not_sensitive_word_cooccurrence(source: str) -> None:
    evidence, findings = analyze_java_sources(run_id="run-java-cooccurrence-negative", sources=(_source(source),))

    assert evidence == []
    assert findings == []


@pytest.mark.parametrize(
    "source",
    [
        """
        class ReassignedCredential {
            byte[] digestValue(String password) throws Exception {
                password = "public-constant";
                return MessageDigest.getInstance("MD5").digest(password.getBytes());
            }
        }
        """,
        """
        class ReassignedDigestOutput {
            void checksum(byte[] input) throws Exception {
                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] result = md.digest(input);
                result = new byte[0];
                String passwordFile = "passwordFile.txt";
                FileWriter fw = new FileWriter(passwordFile);
                fw.write(result);
            }
        }
        """,
    ],
)
def test_java_semantic_sast_assignment_kills_stale_def_use_facts(source: str) -> None:
    evidence, findings = analyze_java_sources(run_id="run-java-assignment-kill", sources=(_source(source),))

    assert evidence == []
    assert findings == []


@pytest.mark.parametrize(
    "sink",
    [
        "verifyChecksum(result)",
        "verifyETag(result)",
        "cache.verify(result)",
        "dedup.verify(result)",
    ],
)
def test_java_semantic_sast_excludes_non_security_digest_sinks(sink: str) -> None:
    source = f"""
    class NonSecurityDigest {{
        void checksum(byte[] input) throws Exception {{
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] result = md.digest(input);
            {sink};
        }}
    }}
    """

    evidence, findings = analyze_java_sources(run_id="run-java-non-security-sink", sources=(_source(source),))

    assert evidence == []
    assert findings == []


def test_java_semantic_sast_tracks_sensitive_field_input() -> None:
    source = """
    class PasswordRecord {
        private byte[] password;

        byte[] digestValue() throws Exception {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return md.digest(this.password);
        }
    }
    """

    evidence, findings = analyze_java_sources(run_id="run-java-field-flow", sources=(_source(source),))

    assert len(evidence) == len(findings) == 1
    assert evidence[0].metadata["proof_kind"] == "sensitive_input"
    assert evidence[0].metadata["sensitive_identifier"] == "password"


def test_java_semantic_sast_large_source_remains_bounded() -> None:
    methods = "\n".join(
        f"""
        byte[] checksum{index}(byte[] input) throws Exception {{
            String passwordPolicy = "password documentation";
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(input);
            return md.digest();
        }}
        """
        for index in range(2_000)
    )
    source = f"class LargeChecksumSuite {{ {methods} }}"

    started = time.perf_counter()
    evidence, findings = analyze_java_sources(run_id="run-java-linear-performance", sources=(_source(source),))
    elapsed = time.perf_counter() - started

    assert evidence == []
    assert findings == []
    # GitHub's shared Linux runner is consistently ~3.1 s under coverage
    # instrumentation. Keep a tight bound that still detects superlinear
    # regressions without turning runner variance into a release failure.
    assert elapsed < 4.0


def test_java_semantic_sast_nested_anonymous_classes_do_not_rescan_parent_bodies() -> None:
    depth = 800
    source = (
        "class Nested { void outer() {"
        + " Object value = new Runnable() {" * depth
        + ' public void run() { MessageDigest md = MessageDigest.getInstance("MD5"); md.digest(input); }'
        + "};" * depth
        + "} }"
    )

    started = time.perf_counter()
    evidence, findings = analyze_java_sources(run_id="run-java-nested-performance", sources=(_source(source),))
    elapsed = time.perf_counter() - started

    assert evidence == []
    assert findings == []
    assert elapsed < 1.0


@pytest.mark.asyncio
async def test_registered_java_tool_is_read_only_and_bounded(tmp_path: Path) -> None:
    target = tmp_path / "PasswordStore.java"
    target.write_text(SENSITIVE_MD5_JAVA, encoding="utf-8")
    tool = JavaSemanticSastTool()

    result = await tool.invoke(
        {"target": "."},
        ToolContext(
            run_id="run-java-tool",
            step_id="scan-java",
            workspace=str(tmp_path),
            allowed_paths=[str(tmp_path)],
        ),
    )

    assert result.status == ToolStatus.SUCCESS
    assert result.data["finding_limit"] == 9
    assert len(result.data["findings"]) == 1
    assert default_registry().get("java_semantic_sast").manifest.supported_languages == ["java"]


def _completed_empty_state(tmp_path: Path) -> AgentState:
    target = tmp_path / "PasswordStore.java"
    payload = target.read_bytes()
    state = AgentState(
        run_id="run-java-admission",
        task=TaskRequest(objective="Audit Java source", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        status=RunStatus.RUNNING,
        workspace=str(tmp_path),
        input_artifacts=[
            InputArtifact(
                original_name=target.name,
                relative_path=target.relative_to(tmp_path).as_posix(),
                sha256=hashlib.sha256(payload).hexdigest(),
                size_bytes=len(payload),
                media_type="text/x-java-source",
            )
        ],
        repository_index=RepositoryIndexRef(
            index_id="java-index",
            run_id="run-java-admission",
            artifact_id="a" * 64,
            digest="a" * 64,
            file_count=1,
            languages=["java"],
        ),
        audit_coverage={
            "canonical_primary_attempted": True,
            "canonical_primary_completed": True,
            "primary_answer_status": "completed",
            "input_count": 1,
            "viewed_count": 1,
            "omitted_count": 0,
            "unbound_primary_candidate_count": 0,
            "negative_coverage_complete": True,
            "repository_snapshot_digest": "a" * 64,
            "primary_static_signals": [SEMANTIC_SIGNAL],
        },
        report=AgentReport(
            run_id="run-java-admission",
            status=RunStatus.COMPLETED,
            executive_summary="Primary completed with no findings.",
        ),
    )
    publish_primary_baseline(
        state,
        model_id="deepseek-v4-flash",
        prompt_version="canonical-primary-v2",
        prompt_artifact_id="b" * 64,
        request_sha256="c" * 64,
        response_sha256="d" * 64,
        response_schema_sha256="e" * 64,
        context_sha256="f" * 64,
        response_artifact_id="d" * 64,
        provider_requests=1,
        input_tokens=1,
        output_tokens=1,
        cost_units=0,
        status=RunStatus.COMPLETED,
        executive_summary="Primary completed with no findings.",
        findings=[],
        evidence=[],
        decisions=[],
        limitations=[],
        coverage=state.audit_coverage,
    )
    return state


def _persist_java_observation(state: AgentState, tmp_path: Path, artifact_store: ContentAddressedArtifactStore) -> None:
    broker = ToolBroker(
        default_registry(),
        Guardrail(),
        artifact_store=artifact_store,
    )
    try:
        persisted = broker._persist_result_artifacts(  # noqa: SLF001
            state.observations[0],
            ToolContext(
                run_id=state.run_id,
                step_id="scan-java-semantic",
                workspace=str(tmp_path),
                allowed_paths=[str(tmp_path)],
                invocation_id="java-test-invocation",
            ),
        )
    finally:
        broker.close()
    state.observations = [persisted]
    state.evidence = list(persisted.evidence)


async def _execute_ticketed_java_delta(
    state: AgentState,
    tmp_path: Path,
    artifact_store: ContentAddressedArtifactStore | None = None,
) -> Finding:
    step = PlanStep(
        step_id="scan-java-semantic",
        objective="Verify a security-sensitive weak digest.",
        agent_role="sast_specialist",
        capability="sast",
        dependencies=["inventory-project"],
        tool_candidates=["java_semantic_sast"],
        inputs={"target": "."},
        success_criteria=["One bounded finding or an explicit negative result is returned."],
        estimated_tool_calls=1,
    )
    compiled = EvidenceGapCompiler().compile(state, [step], default_registry().manifests())
    state.evidence_gap_tickets = list(compiled.tickets)
    state.plan = list(compiled.steps)
    result = await JavaSemanticSastTool().invoke(
        {"target": "."},
        ToolContext(
            run_id=state.run_id,
            step_id=step.step_id,
            workspace=str(tmp_path),
            allowed_paths=[str(tmp_path)],
            invocation_id="java-test-invocation",
        ),
    )
    finding = Finding.model_validate(result.data["findings"][0])
    state.findings = [finding]
    state.evidence = list(result.evidence)
    state.observations = [result]
    state.step_runtime = {
        step.step_id: StepRuntime(
            step_id=step.step_id,
            status=StepStatus.SUCCEEDED,
            attempt=1,
            actual_tool_calls=1,
            tool_invocation_ids=[result.invocation_id or "java-test-invocation"],
            actual_tool_name=TOOL_NAME,
            actual_tool_version=TOOL_VERSION,
            observation_indexes=[0],
        )
    }
    if artifact_store is not None:
        _persist_java_observation(state, tmp_path, artifact_store)

    gain = ToolGainGate.apply(state)
    assert gain.accepted_new == 1
    claim = make_claim(
        claim_type="sast.finding",
        statement=finding.description,
        subject_ref=finding.finding_id,
        producer=step.step_id,
        severity=finding.severity,
        confidence=0.95,
    )
    state.claims = [claim.model_copy(update={"status": ClaimStatus.VERIFIED})]
    state.status = RunStatus.COMPLETED
    return finding


@pytest.mark.asyncio
async def test_completed_empty_primary_admits_exactly_one_ticketed_java_gain(tmp_path: Path, admission_stores) -> None:
    target = tmp_path / "PasswordStore.java"
    target.write_text(SENSITIVE_MD5_JAVA, encoding="utf-8")
    state = _completed_empty_state(tmp_path)
    artifact_store, capsule_store = admission_stores
    step = PlanStep(
        step_id="scan-java-semantic",
        objective="Verify a security-sensitive weak digest.",
        agent_role="sast_specialist",
        capability="sast",
        dependencies=["inventory-project"],
        tool_candidates=["java_semantic_sast"],
        inputs={"target": "."},
        success_criteria=["One bounded finding or an explicit negative result is returned."],
        estimated_tool_calls=1,
    )
    compiled = EvidenceGapCompiler().compile(state, [step], default_registry().manifests())
    assert EvidenceGapCompiler().gap_codes(state) == ("security_sensitive_weak_digest",)
    assert compiled.gap_codes == ("security_sensitive_weak_digest",)
    assert len(compiled.tickets) == 1
    assert compiled.tickets[0].release_policy == "authoritative"
    assert compiled.steps[0].dependencies == []
    assert compiled.steps[0].context_requirements["repository_snapshot_prerequisite"] == "sealed"

    state.evidence_gap_tickets = list(compiled.tickets)
    state.plan = list(compiled.steps)
    result = await JavaSemanticSastTool().invoke(
        {"target": "."},
        ToolContext(
            run_id=state.run_id,
            step_id=step.step_id,
            workspace=str(tmp_path),
            allowed_paths=[str(tmp_path)],
            invocation_id="java-test-invocation",
        ),
    )
    finding = Finding.model_validate(result.data["findings"][0])
    state.findings = [finding]
    state.evidence = list(result.evidence)
    state.observations = [result]
    state.step_runtime = {
        step.step_id: StepRuntime(
            step_id=step.step_id,
            status=StepStatus.SUCCEEDED,
            attempt=1,
            actual_tool_calls=1,
            tool_invocation_ids=[result.invocation_id or "java-test-invocation"],
            actual_tool_name=TOOL_NAME,
            actual_tool_version=TOOL_VERSION,
            observation_indexes=[0],
        )
    }
    _persist_java_observation(state, tmp_path, artifact_store)

    gain = ToolGainGate.apply(state)
    assert gain.accepted_new == 1
    claim = make_claim(
        claim_type="sast.finding",
        statement=finding.description,
        subject_ref=finding.finding_id,
        producer=step.step_id,
        severity=finding.severity,
        confidence=0.95,
    )
    state.claims = [claim.model_copy(update={"status": ClaimStatus.VERIFIED})]
    state.status = RunStatus.COMPLETED
    snapshot = AdmissionService.seal(
        state,
        artifact_store=artifact_store,
        capsule_store=capsule_store,
    )

    assert snapshot.admitted_finding_ids == [finding.finding_id]
    assert snapshot.rejected_finding_ids == []
    assert snapshot.report.findings[0].rule_id == "CWE-328"


@pytest.mark.asyncio
async def test_admission_accepts_broker_persisted_java_evidence(tmp_path: Path, admission_stores) -> None:
    target = tmp_path / "PasswordStore.java"
    target.write_text(SENSITIVE_MD5_JAVA, encoding="utf-8")
    state = _completed_empty_state(tmp_path)
    artifact_store, capsule_store = admission_stores
    finding = await _execute_ticketed_java_delta(state, tmp_path, artifact_store)
    persisted = state.observations[0]

    snapshot = AdmissionService.seal(
        state,
        artifact_store=artifact_store,
        capsule_store=capsule_store,
    )

    assert persisted.evidence[0].artifact_ref is not None
    assert persisted.evidence[0].sha256 == persisted.evidence[0].artifact_ref
    assert snapshot.admitted_finding_ids == [finding.finding_id]


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["description", "severity", "raw"])
async def test_admission_rejects_java_candidate_changed_after_tool_return(
    tmp_path: Path,
    field: str,
    admission_stores,
) -> None:
    target = tmp_path / "PasswordStore.java"
    target.write_text(SENSITIVE_MD5_JAVA, encoding="utf-8")
    state = _completed_empty_state(tmp_path)
    artifact_store, capsule_store = admission_stores
    finding = await _execute_ticketed_java_delta(state, tmp_path, artifact_store)

    if field == "raw":
        value: object = {**finding.raw, "attacker_controlled": True}
    elif field == "severity":
        value = "CRITICAL"
    else:
        value = "A downstream component replaced the tool-authored description."
    tampered = finding.model_copy(update={field: value})
    state.findings = [tampered]
    assert state.report is not None
    state.report = state.report.model_copy(update={"findings": [tampered]})

    snapshot = AdmissionService.seal(state, artifact_store=artifact_store, capsule_store=capsule_store)

    assert snapshot.admitted_finding_ids == []
    assert snapshot.rejected_finding_ids == [finding.finding_id]


@pytest.mark.asyncio
async def test_admission_rejects_java_result_from_drifted_live_workspace(tmp_path: Path, admission_stores) -> None:
    target = tmp_path / "PasswordStore.java"
    target.write_text(SENSITIVE_MD5_JAVA, encoding="utf-8")
    state = _completed_empty_state(tmp_path)
    artifact_store, capsule_store = admission_stores
    target.write_text(f"{SENSITIVE_MD5_JAVA}\n// changed after immutable ingest\n", encoding="utf-8")

    finding = await _execute_ticketed_java_delta(state, tmp_path, artifact_store)
    snapshot = AdmissionService.seal(state, artifact_store=artifact_store, capsule_store=capsule_store)

    assert finding.raw["file_sha256"] != state.input_artifacts[0].sha256
    assert snapshot.admitted_finding_ids == []
    assert snapshot.rejected_finding_ids == [finding.finding_id]


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["evidence_digest", "input_manifest_digest", "unit_id"])
async def test_admission_recomputes_java_evidence_identity(
    tmp_path: Path,
    tamper: str,
    admission_stores,
) -> None:
    target = tmp_path / "PasswordStore.java"
    target.write_text(SENSITIVE_MD5_JAVA, encoding="utf-8")
    state = _completed_empty_state(tmp_path)
    artifact_store, capsule_store = admission_stores
    finding = await _execute_ticketed_java_delta(state, tmp_path, artifact_store)
    evidence = state.evidence[0]
    if tamper == "evidence_digest":
        tampered = evidence.model_copy(update={"sha256": "0" * 64})
    else:
        metadata = dict(evidence.metadata)
        metadata[tamper] = ("unit-" if tamper == "unit_id" else "") + "0" * 64
        tampered = evidence.model_copy(update={"metadata": metadata})
    state.evidence = [tampered]
    state.observations[0].evidence = [tampered]

    snapshot = AdmissionService.seal(state, artifact_store=artifact_store, capsule_store=capsule_store)

    assert snapshot.admitted_finding_ids == []
    assert snapshot.rejected_finding_ids == [finding.finding_id]


@pytest.mark.asyncio
@pytest.mark.parametrize("authority_drift", ["tool_calls", "run_fence", "step_fence"])
async def test_admission_rejects_java_runtime_authority_drift(
    tmp_path: Path,
    authority_drift: str,
    admission_stores,
) -> None:
    target = tmp_path / "PasswordStore.java"
    target.write_text(SENSITIVE_MD5_JAVA, encoding="utf-8")
    state = _completed_empty_state(tmp_path)
    artifact_store, capsule_store = admission_stores
    finding = await _execute_ticketed_java_delta(state, tmp_path, artifact_store)
    runtime = state.step_runtime["scan-java-semantic"]
    if authority_drift == "tool_calls":
        ticket_limit = next(
            item.max_tool_calls for item in state.evidence_gap_tickets if item.step_id == "scan-java-semantic"
        )
        runtime.actual_tool_calls = ticket_limit + 1
        runtime.tool_invocation_ids.extend(f"extra-invocation-{index}" for index in range(ticket_limit))
    elif authority_drift == "run_fence":
        runtime.lease_fence = 7
        runtime.run_fence = 8
        runtime.step_fence = 1
    else:
        runtime.run_fence = 7
        runtime.lease_fence = 7
        runtime.step_fence = 0

    snapshot = AdmissionService.seal(state, artifact_store=artifact_store, capsule_store=capsule_store)

    assert snapshot.admitted_finding_ids == []
    assert snapshot.rejected_finding_ids == [finding.finding_id]


@pytest.mark.asyncio
@pytest.mark.parametrize("manifest_failure", ["missing", "hash_drift", "ambiguous_suffix"])
async def test_admission_fails_closed_on_unbound_java_input_manifest(
    tmp_path: Path,
    manifest_failure: str,
    admission_stores,
) -> None:
    target = tmp_path / "PasswordStore.java"
    target.write_text(SENSITIVE_MD5_JAVA, encoding="utf-8")
    state = _completed_empty_state(tmp_path)
    artifact_store, capsule_store = admission_stores
    finding = await _execute_ticketed_java_delta(state, tmp_path, artifact_store)
    artifact = state.input_artifacts[0]
    if manifest_failure == "missing":
        state.input_artifacts = []
    elif manifest_failure == "hash_drift":
        state.input_artifacts = [artifact.model_copy(update={"sha256": "0" * 64})]
    else:
        state.input_artifacts = [
            artifact.model_copy(update={"artifact_id": "left-input", "relative_path": "left/PasswordStore.java"}),
            artifact.model_copy(update={"artifact_id": "right-input", "relative_path": "right/PasswordStore.java"}),
        ]

    snapshot = AdmissionService.seal(state, artifact_store=artifact_store, capsule_store=capsule_store)

    assert snapshot.admitted_finding_ids == []
    assert snapshot.rejected_finding_ids == [finding.finding_id]


def test_admission_resolves_one_normalized_suffix_input_match(tmp_path: Path) -> None:
    target = tmp_path / "PasswordStore.java"
    target.write_text(SENSITIVE_MD5_JAVA, encoding="utf-8")
    state = _completed_empty_state(tmp_path)
    artifact = state.input_artifacts[0]
    state.input_artifacts = [artifact.model_copy(update={"relative_path": "Submission\\PasswordStore.java"})]

    assert AdmissionService._matches_immutable_input(  # noqa: SLF001
        state,
        "PasswordStore.java",
        artifact.sha256,
    )
