from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from secmind_dev.v082_aggregate import (
    TaskScore,
    aggregate_scores,
    compare_arms,
    finding_metrics,
    randomized_blocks,
)
from secmind_dev.v082_bridge import BridgeConfig, BridgeInvocation, ProcessBridge
from secmind_dev.v082_cas import CASStore, EvaluationSealStore
from secmind_dev.v082_contracts import (
    AgentReport,
    AttemptRecord,
    FailureCapsule,
    InputArtifactRecord,
    InputManifest,
    RunIdentity,
    build_run_identity,
)
from secmind_dev.v082_scorer import score_report

INPUT_SHA = hashlib.sha256(b"print('ok')\n").hexdigest()


def _manifest() -> InputManifest:
    return InputManifest((InputArtifactRecord("input-1", "src/app.py", INPUT_SHA, 13),))


def _report(status: str = "SUCCESS") -> AgentReport:
    return AgentReport.from_dict(
        {
            "task_id": "task-1",
            "run_id": "run-1",
            "status": status,
            "findings": [
                {
                    "finding_id": "finding-1",
                    "rule_id": "CWE-89",
                    "title": "SQL injection",
                    "path": "input/src/app.py",
                    "line": 1,
                    "file_sha256": INPUT_SHA,
                    "evidence_ids": ["evidence-1"],
                }
            ],
            "evidence": [
                {
                    "evidence_id": "evidence-1",
                    "finding_id": "finding-1",
                    "source": "agent",
                    "summary": "A tainted query reaches the sink.",
                    "path": "src/app.py",
                    "line": 1,
                    "file_sha256": INPUT_SHA,
                }
            ],
        }
    )


def test_evidence_contract_emits_scorer_top_level_fields() -> None:
    report = _report()
    payload = report.to_dict(scorer_path=True)
    finding = payload["findings"][0]
    evidence = payload["evidence"][0]
    assert finding["path"] == "input/src/app.py"
    assert finding["file"] == "input/src/app.py"
    assert finding["file_sha256"] == INPUT_SHA
    assert evidence["path"] == "input/src/app.py"
    assert evidence["file"] == "input/src/app.py"
    assert evidence["line"] == 1
    assert evidence["file_sha256"] == INPUT_SHA
    assert evidence["finding_id"] == "finding-1"
    assert report.validate_evidence(_manifest()).valid


def test_evidence_contract_allows_code_excerpt_whitespace_but_rejects_terminal_controls() -> None:
    report = AgentReport.from_dict(
        {
            "task_id": "task-1",
            "run_id": "run-1",
            "status": "PARTIAL",
            "findings": [],
            "evidence": [
                {
                    "evidence_id": "evidence-1",
                    "source": "scanner",
                    "summary": "if vulnerable:\n\tcall_sink()\r\n",
                }
            ],
        }
    )
    assert "\n\t" in report.evidence[0].summary

    with pytest.raises(ValueError, match="control character"):
        AgentReport.from_dict(
            {
                "task_id": "task-1",
                "run_id": "run-1",
                "status": "PARTIAL",
                "findings": [],
                "evidence": [{"evidence_id": "evidence-1", "source": "scanner", "summary": "bad\x1b[2J"}],
            }
        )


def test_cas_seal_binds_manifest_and_is_idempotent(tmp_path: Path) -> None:
    manifest = _manifest()
    store = EvaluationSealStore(CASStore(tmp_path / "cas"))
    identity = RunIdentity("candidate", "0.8.2")
    bridge_execution = {
        "schema_version": "secmind-bridge-v0.8.2",
        "status": "SUCCESS",
        "stdout": {"sha256": "c" * 64},
        "stderr": {"sha256": "d" * 64},
    }
    first = store.seal(
        identity=identity,
        report=_report(),
        input_manifest=manifest,
        bridge_executions=(bridge_execution,),
    )
    second = store.seal(
        identity=identity,
        report=_report(),
        input_manifest=manifest,
        bridge_executions=(bridge_execution,),
    )
    assert first.seal_id == second.seal_id
    assert first.identity.input_manifest_digest == manifest.digest
    assert first.bridge_execution_sha256 is not None
    assert store.verify(first.seal_id)["valid"] is True


def test_cas_seal_recovers_unique_finding_digest_from_linked_evidence(tmp_path: Path) -> None:
    payload = _report().to_dict()
    payload["findings"][0].pop("file_sha256")
    report = AgentReport.from_dict(payload)
    assert report.findings[0].file_sha256 == ""

    store = EvaluationSealStore(CASStore(tmp_path / "cas"))
    sealed = store.seal(
        identity=RunIdentity("candidate", "0.8.2"),
        report=report,
        input_manifest=_manifest(),
    )

    assert sealed.evidence_validation.valid is True
    assert store.verify(sealed.seal_id)["report"]["findings"][0]["file_sha256"] == INPUT_SHA


def test_bridge_retains_stream_hashes_and_failure_capsule(tmp_path: Path) -> None:
    cas = CASStore(tmp_path / "cas")
    bridge = ProcessBridge(BridgeConfig(timeout_seconds=10), cas=cas)
    invocation = BridgeInvocation(
        (
            sys.executable,
            "-c",
            "import json, sys; print(json.dumps({'status': 'SUCCESS'})); print('diagnostic', file=sys.stderr)",
        ),
        {"task_id": "task-1", "run_id": "run-1"},
    )
    run = bridge.run_with_fallback((invocation,))
    assert run.status == "SUCCESS"
    execution = run.executions[0]
    assert execution.stdout.sha256
    assert execution.stderr.sha256
    assert execution.attempt.stdout_sha256 == execution.stdout.sha256
    assert execution.attempt.stderr_sha256 == execution.stderr.sha256
    assert execution.stdout.cas_digest is not None
    assert execution.stderr.cas_digest is not None

    timeout = ProcessBridge(BridgeConfig(timeout_seconds=0.1), cas=cas).run(
        BridgeInvocation((sys.executable, "-c", "import time; time.sleep(2)"), {"task_id": "task-1"})
    )
    assert timeout.status == "TIMEOUT"
    assert timeout.failure_capsule is not None
    assert timeout.failure_capsule.final_error_type == "timeout"


def test_bridge_fallback_uses_a_distinct_request_digest(tmp_path: Path) -> None:
    command = (
        sys.executable,
        "-c",
        "import json, sys; request=json.loads(sys.stdin.readline()); "
        "print('malformed' if not request.get('fallback') else json.dumps({'status': 'SUCCESS'}))",
    )
    bridge = ProcessBridge(BridgeConfig(timeout_seconds=10), cas=CASStore(tmp_path / "cas"))
    run = bridge.run_with_fallback(
        (
            BridgeInvocation(command, {"task_id": "task-1", "fallback": False}),
            BridgeInvocation(command, {"task_id": "task-1", "fallback": True}, attempt_type="fallback"),
        )
    )
    assert run.status == "SUCCESS"
    assert [item.attempt.error_type for item in run.executions] == ["parse", None]
    assert run.attempts[0].request_digest != run.attempts[1].request_digest


def test_aggregate_separates_22_capability_from_60_engineering() -> None:
    rows = [
        TaskScore("cap-1", score=10, outcome_score=80, engineering_score=20, evidence_completeness=1.0),
        TaskScore("cap-2", score=10, outcome_score=60, engineering_score=40, evidence_completeness=0.5),
    ]
    result = aggregate_scores(rows, capability_task_ids=["cap-1", "cap-2"], engineering_task_ids=["cap-1", "cap-2"])
    assert result["capability"]["score"] == 70.0
    assert result["engineering"]["score"] == 30.0
    assert result["capability"]["score_field"] == "outcome_score"
    assert result["engineering"]["score_field"] == "engineering_score"


def test_aggregate_scores_uses_all_rounds_instead_of_last_round() -> None:
    rows = [
        TaskScore(
            "cap-1",
            score=20,
            outcome_score=20,
            engineering_score=20,
            round_number=1,
        ),
        TaskScore(
            "cap-1",
            score=80,
            outcome_score=80,
            engineering_score=80,
            round_number=2,
        ),
    ]

    result = aggregate_scores(rows, capability_task_ids=["cap-1"], engineering_task_ids=["cap-1"])

    assert result["capability"]["score"] == 50.0
    assert result["engineering"]["score"] == 50.0
    assert [item["round"] for item in result["rounds"]] == [1, 2]


def test_randomized_blocks_and_paired_statistics_are_explicit() -> None:
    plans = randomized_blocks(["anchor", "enhanced"], ["t1", "t2"], block_count=5, seed=42, scheme="abba")
    assert len(plans) == 5
    left = [TaskScore("t1", score=40, outcome_score=40, block=index) for index in range(1, 6)]
    right = [TaskScore("t1", score=60, outcome_score=60, block=index) for index in range(1, 6)]
    identity_values = {
        "agent_git_sha": "g" * 40,
        "agent_git_dirty": False,
        "bridge_sha": "b" * 64,
        "bridge_version": "v0.8.2",
        "adapter_sha": "a" * 64,
        "adapter_version": "v0.8.2",
        "dependency_digest": "d" * 64,
        "lockfile_digest": "l" * 64,
        "model_profile": "profile",
        "model_id": "model",
        "model_parameters_digest": "p" * 64,
        "prompt_digest": "p" * 64,
        "schema_digest": "s" * 64,
        "rule_digest": "r" * 64,
        "input_manifest_digest": "i" * 64,
        "task_order_seed": 42,
        "provider_seed": 43,
    }
    identities = {
        "anchor": RunIdentity("anchor", "1", **identity_values),
        "enhanced": RunIdentity("enhanced", "1", **identity_values),
    }
    result = compare_arms(
        {"anchor": left, "enhanced": right},
        anchor="anchor",
        enhanced="enhanced",
        identities=identities,
        bootstrap_iterations=100,
    )
    assert result["controlled_comparison"] is True
    assert result["success_conditional_semantics"]["delta_mean"] == 20.0
    assert result["success_conditional_semantics"]["paired_sign_test"]["positive"] == 5
    interval = result["success_conditional_semantics"]["cluster_bootstrap_95_ci"]
    assert interval["confidence"] == 0.95
    assert interval["unit"] == "task_cluster"
    assert interval["lower"] == interval["upper"] == 20.0

    mismatched = RunIdentity(
        "enhanced",
        "1",
        **{**identity_values, "bridge_version": "v0.8.1"},
    )
    incomparable = compare_arms(
        {"anchor": left, "enhanced": right},
        anchor="anchor",
        enhanced="enhanced",
        identities={"anchor": identities["anchor"], "enhanced": mismatched},
        bootstrap_iterations=100,
    )
    assert incomparable["controlled_comparison"] is False
    assert incomparable["status"] == "MISMATCH"
    assert any(
        item["field"] == "bridge_version" and item["status"] == "MISMATCH" for item in incomparable["control"]["fields"]
    )


def test_finding_metrics_deduplicate_and_only_count_verified_precision() -> None:
    result = finding_metrics(
        [
            {"fingerprint": "same", "expected": True, "verified": True, "evidence_valid": True},
            {"fingerprint": "same", "expected": True, "verified": False},
            {"fingerprint": "fp", "expected": False, "verified": False, "evidence_valid": True},
        ]
    )
    assert result["unique_fingerprints"] == 2
    assert result["verified_precision"] == 1.0
    assert result["evidence_completeness"] == 1.0


def test_report_scorer_returns_capability_row_without_inventing_engineering_score() -> None:
    report = _report()
    expected = [report.findings[0].to_dict()]
    row = score_report(report, _manifest(), expected_findings=expected)
    assert row.outcome_score == 100.0
    assert row.engineering_score is None
    assert "verified_precision" in row.metadata


def test_failure_capsule_serializes_after_attempt_cleanup(tmp_path: Path) -> None:
    manifest = _manifest()
    request_sha = "b" * 64
    attempt = AttemptRecord(
        attempt_ordinal=1,
        attempt_type="primary",
        status="TIMEOUT",
        duration_ms=101,
        stage="read_idle",
        retryable=True,
        request_digest=request_sha,
        error_type="timeout",
    )
    capsule = FailureCapsule(
        task_id="task-1",
        status="TIMEOUT",
        final_error_type="timeout",
        stage="read_idle",
        retryable=True,
        request_digest=request_sha,
        attempt_ordinals=(1,),
        message="provider read idle timeout",
    )
    store = EvaluationSealStore(CASStore(tmp_path / "cas"))
    sealed = store.seal(
        identity=RunIdentity("candidate", "0.8.2"),
        report=_report("TIMEOUT"),
        input_manifest=manifest,
        attempts=(attempt,),
        failure_capsules=(capsule,),
    )
    exported = store.export_failure_capsule(sealed.seal_id, tmp_path / "failure.json")
    payload = json.loads(exported.read_text(encoding="utf-8"))
    assert payload["capsules"][0]["final_error_type"] == "timeout"


def test_build_run_identity_records_actual_bridge_and_adapter_versions(tmp_path: Path) -> None:
    bridge = tmp_path / "bridge.py"
    adapter = tmp_path / "adapter.json"
    bridge.write_text("BRIDGE_VERSION = '1.2.0'\n", encoding="utf-8")
    adapter.write_text('{"version":"0.8.2"}\n', encoding="utf-8")

    identity = build_run_identity(
        candidate_id="secmind-v0.8.2",
        candidate_version="0.8.2",
        bridge_path=bridge,
        bridge_version="1.2.0",
        adapter_path=adapter,
        adapter_version="agent-adapter-1.0/v0.8.2",
    )

    assert identity.bridge_version == "1.2.0"
    assert identity.adapter_version == "agent-adapter-1.0/v0.8.2"
    assert identity.bridge_sha == hashlib.sha256(bridge.read_bytes()).hexdigest()
    assert identity.adapter_sha == hashlib.sha256(adapter.read_bytes()).hexdigest()
