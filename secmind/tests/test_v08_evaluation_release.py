from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import analyze_v08_release as analyzer  # noqa: E402
import evaluate_comprehensive_public as evaluator  # noqa: E402
import score_comprehensive_offline as scorer  # noqa: E402


def test_evaluation_attachments_preserve_manifest_top_level_paths() -> None:
    refs = evaluator.evaluation_attachment_refs(
        {
            "inputs": [
                {"path": "input/src/app.py"},
                {"path": "input/README.md"},
                {"path": "policy.json"},
            ]
        },
        "case-random-staging-name",
    )

    assert [item.model_dump(mode="json", exclude_none=True) for item in refs] == [
        {"ref": "case-random-staging-name/input"},
        {"ref": "case-random-staging-name/policy.json", "name": "policy.json"},
    ]


@pytest.mark.parametrize("path", ["../escape.py", "/absolute.py"])
def test_evaluation_attachments_reject_unsafe_manifest_paths(path: str) -> None:
    with pytest.raises(ValueError, match="unsafe public input path"):
        evaluator.evaluation_attachment_refs({"inputs": [{"path": path}]}, "case-staging")


def test_primary_tracking_seals_receipt_admission_projection_and_prompt() -> None:
    state = SimpleNamespace(
        run_id="run-1",
        raw_primary_receipt={
            "run_id": "run-1",
            "receipt_id": "receipt-1",
            "prompt_version": "prompt-v1",
            "prompt_artifact_id": "artifact-1",
            "model_id": "deepseek-v4-flash",
            "request_sha256": "a" * 64,
            "response_sha256": "b" * 64,
            "response_schema_sha256": "c" * 64,
            "context_sha256": "d" * 64,
        },
        baseline_admission={
            "run_id": "run-1",
            "receipt_id": "receipt-1",
            "admission_id": "admission-1",
            "semantic_digest": "e" * 64,
        },
        published_baseline={
            "run_id": "run-1",
            "receipt_id": "receipt-1",
            "admission_id": "admission-1",
            "projection_id": "projection-1",
            "semantic_digest": "e" * 64,
            "integrity_digest": "f" * 64,
        },
        audit_coverage={"primary_preserved": True},
    )

    trace = evaluator.primary_tracking(state)

    assert trace["lineage"]["baseline_chain_complete"] is True
    assert trace["lineage"]["baseline_chain_consistent"] is True
    assert trace["lineage"]["primary_preserved"] is True
    assert trace["prompt"]["prompt_artifact_id"] == "artifact-1"
    assert trace["prompt"]["request_sha256"] == "a" * 64


def test_exact_cwe_matching_counts_duplicate_as_false_positive() -> None:
    expected = {
        "vulnerability_expected": True,
        "acceptable_cwes": "CWE-89",
        "path": "src/app.py",
        "line": 10,
    }
    result = {
        "findings": [
            {"cwe": "CWE-89", "path": "src/app.py", "line": 10},
            {"classification": "CWE-89", "path": "src/app.py", "line": 10},
            {"cwe": "CWE-79", "path": "src/app.py", "line": 10},
        ]
    }

    assert scorer.exact_cwe_counts(result, expected) == {
        "exact_cwe_tp": 1,
        "exact_cwe_fp": 2,
        "exact_cwe_fn": 0,
        "exact_cwe_tn": 0,
    }


def test_exact_cwe_wrong_class_is_false_positive_and_false_negative() -> None:
    expected = {"vulnerability_expected": True, "acceptable_cwes": ["CWE-89"]}
    result = {"findings": [{"cwe": "CWE-79", "remediation": "Also review CWE-89 controls."}]}

    counts = scorer.exact_cwe_counts(result, expected)

    assert counts["exact_cwe_tp"] == 0
    assert counts["exact_cwe_fp"] == 1
    assert counts["exact_cwe_fn"] == 1


def test_evidence_completeness_verifies_reference_and_excludes_policy_pseudo_findings(
    tmp_path: Path,
) -> None:
    source = tmp_path / "app.py"
    source.write_text("dangerous_call()\n", encoding="utf-8")
    result = {
        "findings": [{"path": "src/app.py", "line": 1, "evidence_ids": ["evidence-1"]}],
        "evidence": [{"evidence_id": "evidence-1"}],
    }

    assert scorer.evidence_completeness(result, "security_finding", {"src/app.py": source}) == (1, 1)
    assert scorer.evidence_completeness(result, "agent_policy_compliance", {}) == (0, 0)


def _sealed_arm(arm: str) -> dict[str, object]:
    result = {"task_id": "case-1", "status": "completed", "findings": []}
    submission = {"dataset_version": scorer.DATASET_VERSION, "results": [result]}
    submission_hash = scorer.canonical_sha256(submission)
    rounds = [
        {
            "repetition": 1,
            "records": [{"task_id": "case-1", "result": result}],
            "submission_sha256": submission_hash,
        }
    ]
    return {
        "protocol": "secmind-comprehensive-blind-v2",
        "dataset_version": scorer.DATASET_VERSION,
        "arm": arm,
        "case_count": 1,
        "case_ids": ["case-1"],
        "model": {"id": "deepseek-v4-flash"},
        "controls": {
            "timeout_seconds_per_task": 420,
            "concurrency": 4,
            "input_execution": "forbidden",
            "input_network": "forbidden",
            "shared_binary_preprocessor": "printable-ascii-and-utf16le-v1",
            "public_manifest_sha256": "a" * 64,
            "evaluator_sha256": "b" * 64,
            "source_commit": "c" * 40,
            "source_tree_oid": "d" * 40,
            "source_dirty": "false",
        },
        "rounds": rounds,
        "prediction_commitment_sha256": scorer.canonical_sha256(
            [{"repetition": 1, "submission_sha256": submission_hash}]
        ),
    }


def test_generic_v071_v080_seals_share_release_cohort(tmp_path: Path) -> None:
    sealed_by_arm: dict[str, dict[str, object]] = {}
    for arm in ("v071", "v080"):
        path = tmp_path / f"{arm}.json"
        evaluator.write_json(path, _sealed_arm(arm))
        sealed_by_arm[arm] = scorer.load_and_verify_seal(path, arm)

    scorer._verify_common_cohort(sealed_by_arm, allow_legacy=False)


def _aggregate(
    *,
    score: float,
    exact_f1: float,
    exact_tp: int,
    exact_fp: int,
    exact_fn: int,
    requests: int,
    tokens: int,
    duration: int,
    candidate: bool,
) -> dict[str, object]:
    return {
        "overall_score": score,
        "exact_cwe": {
            "f1": exact_f1,
            "recall": exact_tp / (exact_tp + exact_fn),
            "tp": exact_tp,
            "fp": exact_fp,
            "fn": exact_fn,
        },
        "timeout_rate": 0.0,
        "operational_failure_rate": 0.0,
        "ledger_valid_rate": 1.0,
        "finding_evidence_completeness": 1.0,
        "baseline_chain_complete_rate": 1.0 if candidate else None,
        "baseline_chain_consistent_rate": 1.0 if candidate else None,
        "primary_preserved_rate": 1.0 if candidate else None,
        "usage": {
            "provider_requests": requests,
            "total_tokens": tokens,
            "summed_task_duration_ms": duration,
        },
    }


def test_release_gate_accepts_measured_quality_gain_with_bounded_cost() -> None:
    scores = {
        "protocol": "secmind-v08-release-score-v1",
        "offline_only": True,
        "dataset_version": scorer.DATASET_VERSION,
        "case_count": 15,
        "repetitions": 2,
        "arms": {
            "v071": {
                "aggregate": _aggregate(
                    score=0.72,
                    exact_f1=0.70,
                    exact_tp=7,
                    exact_fp=3,
                    exact_fn=3,
                    requests=100,
                    tokens=1000,
                    duration=1000,
                    candidate=False,
                )
            },
            "v080": {
                "aggregate": _aggregate(
                    score=0.78,
                    exact_f1=0.80,
                    exact_tp=8,
                    exact_fp=2,
                    exact_fn=2,
                    requests=110,
                    tokens=1200,
                    duration=1200,
                    candidate=True,
                )
            },
        },
    }

    release = analyzer.analyze_release(scores, baseline_arm="v071", candidate_arm="v080")

    assert release["release_gate_passed"] is True
    assert release["failed_checks"] == []
    assert release["deltas"]["exact_cwe_tp"] == 1


def test_release_gate_rejects_score_regression() -> None:
    baseline = _aggregate(
        score=0.80,
        exact_f1=0.80,
        exact_tp=8,
        exact_fp=2,
        exact_fn=2,
        requests=100,
        tokens=1000,
        duration=1000,
        candidate=False,
    )
    scores = {
        "protocol": "secmind-v08-release-score-v1",
        "offline_only": True,
        "arms": {
            "v071": {"aggregate": baseline},
            "v080": {
                "aggregate": _aggregate(
                    score=0.79,
                    exact_f1=0.75,
                    exact_tp=7,
                    exact_fp=2,
                    exact_fn=3,
                    requests=100,
                    tokens=1000,
                    duration=1000,
                    candidate=True,
                )
            },
        },
    }

    release = analyzer.analyze_release(scores, baseline_arm="v071", candidate_arm="v080")

    assert release["release_gate_passed"] is False
    assert "overall_score_gain" in release["failed_checks"]
    assert "exact_cwe_f1_gain" in release["failed_checks"]
