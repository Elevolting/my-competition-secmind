from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import compare_sealed_fusion as comparator  # noqa: E402

BASE_SOURCE = ("1" * 40, "2" * 40)
FUSION_SOURCE = ("3" * 40, "4" * 40)


def _public_dataset(root: Path, task_ids: list[str]) -> Path:
    public = root / "public"
    cases: list[dict[str, Any]] = []
    for task_id in task_ids:
        case = public / "cases" / task_id
        case.mkdir(parents=True)
        content = b"dangerous_call(user_input)\n"
        (case / "app.py").write_bytes(content)
        task = {
            "task_id": task_id,
            "prompt": "Audit the repository",
            "domain": "code_audit",
            "fold": 1,
            "inputs": [
                {
                    "path": "app.py",
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size_bytes": len(content),
                    "media_type": "text/x-python",
                }
            ],
        }
        raw_task = json.dumps(task, sort_keys=True, separators=(",", ":")).encode()
        (case / "task.json").write_bytes(raw_task)
        cases.append({"task_id": task_id, "task_sha256": hashlib.sha256(raw_task).hexdigest()})
    dataset = {
        "schema_version": "1.0",
        "dataset_version": comparator.scorer.DATASET_VERSION,
        "task_count": len(cases),
        "cases": cases,
    }
    (public / "dataset.json").write_text(json.dumps(dataset, sort_keys=True), encoding="utf-8")
    return public


def _ledger(run_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    event = {
        "schema_version": "1.7",
        "event_id": f"event-{run_id}",
        "run_id": run_id,
        "sequence": 1,
        "event_type": "run.completed",
        "timestamp": "2026-08-07T00:00:00+00:00",
        "actor": "system",
        "dedupe_key": f"completed:{run_id}",
        "payload": {"status": "completed"},
        "prev_hash": comparator.ZERO_HASH,
    }
    event["hash"] = comparator.scorer.canonical_sha256(
        {key: value for key, value in event.items() if key not in {"schema_version", "hash"}}
    )
    exported = [event]
    receipt = {
        "schema_version": comparator.LEDGER_RECEIPT_SCHEMA,
        "run_id": run_id,
        "event_count": 1,
        "head_hash": event["hash"],
        "events_sha256": comparator.scorer.canonical_sha256(exported),
        "chain_verified": True,
    }
    return exported, receipt


def _projection(task_id: str, input_sha: str, *, quality: float) -> dict[str, Any]:
    run_id = f"run-{task_id}"
    finding_id = f"finding-{task_id}"
    evidence_id = f"evidence-{task_id}"
    manifest_hash = comparator.scorer.canonical_sha256(
        [
            {
                "artifact_id": f"public-{input_sha[:32]}",
                "path": "app.py",
                "sha256": input_sha,
                "size_bytes": len(b"dangerous_call(user_input)\n"),
            }
        ]
    )
    payload: dict[str, Any] = {
        "schema_version": comparator.EXPECTED_PROJECTION_SCHEMA,
        "task_id": task_id,
        "run_id": run_id,
        "status": "SUCCESS",
        "answer": {"summary": "Evidence-backed result", "coverage": {"quality": quality}},
        "findings": [
            {
                "id": finding_id,
                "finding_id": finding_id,
                "title": "Command injection",
                "classification": "CWE-78",
                "cwe": "CWE-78",
                "rule_id": "CWE-78",
                "severity": "HIGH",
                "confidence": "HIGH",
                "file": "app.py",
                "path": "app.py",
                "line": 1,
                "input_artifact_id": f"public-{input_sha[:32]}",
                "input_sha256": input_sha,
                "description": "Untrusted input reaches a command sink.",
                "remediation": "Use a fixed argv and strict allowlist validation.",
                "evidence_ids": [evidence_id],
                "details": {
                    "root_cause": "Untrusted input reaches the command execution sink.",
                    "impact": "An attacker can execute arbitrary operating system commands.",
                },
            }
        ],
        "evidence": [
            {
                "id": evidence_id,
                "evidence_id": evidence_id,
                "source": "fixture",
                "summary": "Bound source evidence",
                "artifact_ref": None,
                "sha256": input_sha,
                "file": "app.py",
                "path": "app.py",
                "line": 1,
                "input_artifact_id": f"public-{input_sha[:32]}",
                "input_sha256": input_sha,
                "finding_ids": [finding_id],
                "metadata": {},
            }
        ],
        "limitations": [],
        "decisions": [],
        "run_proof": {
            "source_contract": "sealed_report_evidence_input_manifest",
            "snapshot_id": f"snapshot-{task_id}",
            "report_integrity_sha256": "a" * 64,
            "input_manifest_sha256": manifest_hash,
            "input_artifact_count": 1,
            "finding_count": 1,
            "evidence_count": 1,
            "unused_evidence_count": 0,
        },
    }
    return {"projection_id": f"test3-projection-{comparator.scorer.canonical_sha256(payload)}", **payload}


def _seal_payload(
    task_ids: list[str],
    *,
    source: tuple[str, str],
    public_manifest_sha256: str,
    quality: float,
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for task_id in task_ids:
        input_sha = hashlib.sha256(b"dangerous_call(user_input)\n").hexdigest()
        result = _projection(task_id, input_sha, quality=quality)
        run_id = result["run_id"]
        ledger_export, ledger_receipt = _ledger(run_id)
        records.append(
            {
                "task_id": task_id,
                "run_id": run_id,
                "runtime_status": "completed",
                "queue_status": "completed",
                "timed_out": False,
                "operational_error": None,
                "duration_ms": 1,
                "provider_attempts": [
                    {
                        "model_id": comparator.EXPECTED_MODEL_ID,
                        "succeeded": True,
                        "input_tokens": 10,
                        "output_tokens": 5,
                    }
                ],
                "primary_trace": {
                    "lineage": {
                        "baseline_chain_complete": True,
                        "baseline_chain_consistent": True,
                        "primary_preserved": True,
                    }
                },
                "ledger_event_count": 1,
                "ledger_head_hash": ledger_receipt["head_hash"],
                "ledger_valid": True,
                "ledger_export": ledger_export,
                "ledger_receipt": ledger_receipt,
                "result": result,
            }
        )
    submission = {
        "dataset_version": comparator.scorer.DATASET_VERSION,
        "results": [record["result"] for record in records],
    }
    submission_hash = comparator.scorer.canonical_sha256(submission)
    rounds = [{"repetition": 1, "records": records, "submission_sha256": submission_hash}]
    evaluator_hash = comparator.scorer.file_sha256(SCRIPTS / "evaluate_comprehensive_public.py")
    projection_hash = comparator.scorer.file_sha256(
        Path(__file__).resolve().parents[1] / "src" / "secmind" / "evaluation_projection.py"
    )
    sealed: dict[str, Any] = {
        "schema_version": comparator.EXPECTED_SEAL_SCHEMA,
        "protocol": comparator.EXPECTED_SEAL_PROTOCOL,
        "dataset_version": comparator.scorer.DATASET_VERSION,
        "arm": comparator.EXPECTED_ARM,
        "product_version": "0.8.0",
        "case_count": len(task_ids),
        "case_ids": task_ids,
        "model": {"id": comparator.EXPECTED_MODEL_ID, "base_url": comparator.EXPECTED_MODEL_BASE_URL},
        "controls": {
            "timeout_seconds_per_task": 420,
            "concurrency": 1,
            "input_execution": "forbidden",
            "input_network": "forbidden",
            "shared_binary_preprocessor": "printable-ascii-and-utf16le-v1",
            "public_manifest_sha256": public_manifest_sha256,
            "evaluator_sha256": evaluator_hash,
            "sealed_projection_sha256": projection_hash,
            "source_commit": source[0],
            "source_tree_oid": source[1],
            "source_dirty": "false",
            "source_identity_method": "git",
            "source_identity_enforced": True,
            "task_selection": "explicit_task_ids",
            "augmentation": "enabled",
        },
        "rounds": rounds,
        "prediction_commitment_sha256": comparator.scorer.canonical_sha256(
            [{"repetition": 1, "submission_sha256": submission_hash}]
        ),
    }
    sealed[comparator.ENVELOPE_FIELD] = comparator.scorer.canonical_sha256(sealed)
    return sealed


def _write_seal(
    path: Path,
    *,
    task_ids: list[str],
    source: tuple[str, str],
    public_manifest_sha256: str,
    quality: float = 0.8,
) -> None:
    path.write_text(
        json.dumps(
            _seal_payload(
                task_ids,
                source=source,
                public_manifest_sha256=public_manifest_sha256,
                quality=quality,
            )
        ),
        encoding="utf-8",
    )


def _reseal(value: dict[str, Any]) -> None:
    commitment_rows: list[dict[str, Any]] = []
    for round_data in value["rounds"]:
        submission = {
            "dataset_version": comparator.scorer.DATASET_VERSION,
            "results": [record["result"] for record in round_data["records"]],
        }
        round_data["submission_sha256"] = comparator.scorer.canonical_sha256(submission)
        commitment_rows.append(
            {"repetition": round_data["repetition"], "submission_sha256": round_data["submission_sha256"]}
        )
    value["prediction_commitment_sha256"] = comparator.scorer.canonical_sha256(commitment_rows)
    value.pop(comparator.ENVELOPE_FIELD, None)
    value[comparator.ENVELOPE_FIELD] = comparator.scorer.canonical_sha256(value)


def _fake_score_one(record: dict[str, Any], private: dict[str, Any], public_root: Path) -> dict[str, Any]:
    quality = record["result"]["answer"]["coverage"]["quality"]
    return {
        "task_id": record["task_id"],
        "domain": "source_review",
        "project": "fixture",
        "language": "Python",
        "scoring_mode": "security_finding",
        "score": quality,
        "result_status": record["result"]["status"],
        "runtime_status": record["runtime_status"],
        "operational_error": record["operational_error"],
        "timed_out": record["timed_out"],
        "duration_ms": 1,
        "provider_requests": len(record["provider_attempts"]),
        "input_tokens": 10,
        "output_tokens": 5,
        "finding_count": 1,
        "evidence_complete_findings": 1,
        "evidence_scope_finding_count": 1,
        "ledger_valid": record["ledger_valid"],
        "expected_positive": True,
        "predicted_positive": True,
        "classification_match": True,
        "exact_cwe_tp": 1,
        "exact_cwe_fp": 0,
        "exact_cwe_tn": 0,
        "exact_cwe_fn": 0,
        "baseline_chain_complete": True,
        "baseline_chain_consistent": True,
        "primary_preserved": True,
    }


def test_claim_free_operational_failure_is_scoreable_but_cannot_publish_evidence() -> None:
    failure = {
        "task_id": "case-failed",
        "status": "blocked",
        "findings": [],
        "limitations": ["Operational failure: missing_or_invalid_sealed_admission"],
        "projection_error": "AdmissionError",
    }

    assert comparator._is_sealed_operational_failure(failure)
    assert comparator._verify_finding_evidence(failure, {}, label="failure") == (0, 0)

    failure["findings"] = [{"finding_id": "unsealed"}]
    assert not comparator._is_sealed_operational_failure(failure)
    with pytest.raises(SystemExit, match="not a sealed evaluation projection"):
        comparator._verify_finding_evidence(failure, {}, label="failure")


def _stub_private_scoring(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        comparator,
        "_load_private_checked",
        lambda private_root, selected_ids: {task_id: {} for task_id in selected_ids},
    )
    monkeypatch.setattr(comparator.scorer, "score_one", _fake_score_one)


def _pair(tmp_path: Path, *, baseline_quality: float = 0.8, fusion_quality: float = 0.8):
    task_ids = ["task-1"]
    public = _public_dataset(tmp_path, task_ids)
    manifest_hash, _inputs = comparator._validate_public_dataset(public, task_ids)
    baseline = tmp_path / "baseline.json"
    fusion = tmp_path / "fusion.json"
    _write_seal(
        baseline,
        task_ids=task_ids,
        source=BASE_SOURCE,
        public_manifest_sha256=manifest_hash,
        quality=baseline_quality,
    )
    _write_seal(
        fusion,
        task_ids=task_ids,
        source=FUSION_SOURCE,
        public_manifest_sha256=manifest_hash,
        quality=fusion_quality,
    )
    return task_ids, public, baseline, fusion


def _compare(
    tmp_path: Path,
    task_ids: list[str],
    public: Path,
    baseline: Path,
    fusion: Path,
):
    return comparator.compare_sealed_runs(
        {"baseline": baseline, "fusion": fusion},
        expected_sources={"baseline": BASE_SOURCE, "fusion": FUSION_SOURCE},
        expected_task_ids=task_ids,
        expected_repetitions=[1],
        public_root=public,
        private_root=tmp_path / "private",
        output_dir=tmp_path / "output",
    )


def test_comparator_accepts_equal_metrics_with_two_v080_source_bound_seals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    task_ids, public, baseline, fusion = _pair(tmp_path)
    _stub_private_scoring(monkeypatch)

    scores, gate = _compare(tmp_path, task_ids, public, baseline, fusion)

    assert gate["non_regression_passed"] is True
    assert gate["deltas"] == {"overall_score": 0.0, "exact_cwe_f1": 0.0, "operational_success_rate": 0.0}
    assert scores["arms"]["baseline"]["sealed_arm"] == "v080"
    assert scores["arms"]["fusion"]["sealed_arm"] == "v080"
    assert scores["arms"]["baseline"]["source_commit"] == BASE_SOURCE[0]
    assert scores["arms"]["fusion"]["source_commit"] == FUSION_SOURCE[0]
    assert {path.name for path in (tmp_path / "output").iterdir()} == {
        "scores.json",
        "task-scores.csv",
        "non-regression.json",
    }
    with (tmp_path / "output" / "task-scores.csv").open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert [(row["label"], row["sealed_arm"]) for row in rows] == [("baseline", "v080"), ("fusion", "v080")]


def test_comparator_records_quality_and_strict_status_regressions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    task_ids, public, baseline, fusion = _pair(tmp_path, baseline_quality=0.8, fusion_quality=0.7)
    payload = json.loads(fusion.read_text(encoding="utf-8"))
    payload["rounds"][0]["records"][0]["runtime_status"] = "failed"
    _reseal(payload)
    fusion.write_text(json.dumps(payload), encoding="utf-8")
    _stub_private_scoring(monkeypatch)

    _scores, gate = _compare(tmp_path, task_ids, public, baseline, fusion)

    assert gate["non_regression_passed"] is False
    assert "overall_score_non_regression" in gate["failed_checks"]
    assert "fusion_operational_success_rate" in gate["failed_checks"]


def test_comparator_rejects_uncommitted_operational_tampering_before_private_gold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    task_ids, public, baseline, fusion = _pair(tmp_path)
    tampered = json.loads(fusion.read_text(encoding="utf-8"))
    tampered["rounds"][0]["records"][0]["ledger_valid"] = False
    fusion.write_text(json.dumps(tampered), encoding="utf-8")
    monkeypatch.setattr(
        comparator,
        "_load_private_checked",
        lambda *_args, **_kwargs: pytest.fail("private Gold opened before envelope validation"),
    )

    with pytest.raises(SystemExit, match="envelope commitment mismatch"):
        _compare(tmp_path, task_ids, public, baseline, fusion)


def test_comparator_rejects_swapped_sources_and_duplicate_seals(tmp_path: Path) -> None:
    task_ids, public, baseline, fusion = _pair(tmp_path)
    manifest_hash, inputs = comparator._validate_public_dataset(public, task_ids)

    with pytest.raises(SystemExit, match="does not match label"):
        comparator.load_verified_seals(
            {"baseline": baseline, "fusion": fusion},
            expected_sources={"baseline": FUSION_SOURCE, "fusion": BASE_SOURCE},
            expected_task_ids=task_ids,
            expected_repetitions=[1],
            public_manifest_sha256=manifest_hash,
            public_inputs=inputs,
        )
    with pytest.raises(SystemExit, match="distinct sealed artifacts"):
        comparator.load_verified_seals(
            {"baseline": baseline, "fusion": baseline},
            expected_sources={"baseline": BASE_SOURCE, "fusion": FUSION_SOURCE},
            expected_task_ids=task_ids,
            expected_repetitions=[1],
            public_manifest_sha256=manifest_hash,
            public_inputs=inputs,
        )


def test_comparator_rejects_missing_evidence_chain_even_after_resealing(tmp_path: Path) -> None:
    task_ids, public, baseline, fusion = _pair(tmp_path)
    payload = json.loads(fusion.read_text(encoding="utf-8"))
    result = payload["rounds"][0]["records"][0]["result"]
    result["findings"][0]["evidence_ids"] = []
    projection_payload = {key: value for key, value in result.items() if key != "projection_id"}
    result["projection_id"] = f"test3-projection-{comparator.scorer.canonical_sha256(projection_payload)}"
    _reseal(payload)
    fusion.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SystemExit, match="incomplete Evidence reference chain"):
        comparator.load_verified_seals(
            {"baseline": baseline, "fusion": fusion},
            expected_sources={"baseline": BASE_SOURCE, "fusion": FUSION_SOURCE},
            expected_task_ids=task_ids,
            expected_repetitions=[1],
            public_manifest_sha256=comparator._validate_public_dataset(public, task_ids)[0],
            public_inputs=comparator._validate_public_dataset(public, task_ids)[1],
        )


def test_comparator_rejects_forged_input_artifact_binding_after_resealing(tmp_path: Path) -> None:
    task_ids, public, baseline, fusion = _pair(tmp_path)
    payload = json.loads(fusion.read_text(encoding="utf-8"))
    result = payload["rounds"][0]["records"][0]["result"]
    result["findings"][0]["input_artifact_id"] = "forged-artifact"
    projection_payload = {key: value for key, value in result.items() if key != "projection_id"}
    result["projection_id"] = f"test3-projection-{comparator.scorer.canonical_sha256(projection_payload)}"
    _reseal(payload)
    fusion.write_text(json.dumps(payload), encoding="utf-8")
    manifest_hash, inputs = comparator._validate_public_dataset(public, task_ids)

    with pytest.raises(SystemExit, match="finding input SHA-256 mismatch"):
        comparator.load_verified_seals(
            {"baseline": baseline, "fusion": fusion},
            expected_sources={"baseline": BASE_SOURCE, "fusion": FUSION_SOURCE},
            expected_task_ids=task_ids,
            expected_repetitions=[1],
            public_manifest_sha256=manifest_hash,
            public_inputs=inputs,
        )


def test_comparator_rejects_public_input_mutation_before_private_gold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    task_ids, public, baseline, fusion = _pair(tmp_path)
    (public / "cases" / task_ids[0] / "app.py").write_text("changed", encoding="utf-8")
    monkeypatch.setattr(
        comparator,
        "_load_private_checked",
        lambda *_args, **_kwargs: pytest.fail("private Gold opened before public input validation"),
    )

    with pytest.raises(SystemExit, match="public input hash mismatch"):
        _compare(tmp_path, task_ids, public, baseline, fusion)


def test_comparator_requires_v080_deepseek_and_a_successful_provider_attempt(tmp_path: Path) -> None:
    task_ids, public, baseline, fusion = _pair(tmp_path)
    payload = json.loads(fusion.read_text(encoding="utf-8"))
    payload["arm"] = "v071"
    _reseal(payload)
    fusion.write_text(json.dumps(payload), encoding="utf-8")
    manifest_hash, inputs = comparator._validate_public_dataset(public, task_ids)
    with pytest.raises(SystemExit, match="arm must be v080"):
        comparator.load_verified_seals(
            {"baseline": baseline, "fusion": fusion},
            expected_sources={"baseline": BASE_SOURCE, "fusion": FUSION_SOURCE},
            expected_task_ids=task_ids,
            expected_repetitions=[1],
            public_manifest_sha256=manifest_hash,
            public_inputs=inputs,
        )


def test_comparator_fails_gate_when_deepseek_attempt_did_not_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    task_ids, public, baseline, fusion = _pair(tmp_path)
    payload = json.loads(fusion.read_text(encoding="utf-8"))
    payload["rounds"][0]["records"][0]["provider_attempts"][0]["succeeded"] = False
    _reseal(payload)
    fusion.write_text(json.dumps(payload), encoding="utf-8")
    _stub_private_scoring(monkeypatch)

    _scores, gate = _compare(tmp_path, task_ids, public, baseline, fusion)

    assert gate["non_regression_passed"] is False
    assert "fusion_live_provider_success_rate" in gate["failed_checks"]


def test_comparator_recomputes_ledger_export_commitment_after_resealing(tmp_path: Path) -> None:
    task_ids, public, baseline, fusion = _pair(tmp_path)
    payload = json.loads(fusion.read_text(encoding="utf-8"))
    record = payload["rounds"][0]["records"][0]
    record["ledger_export"][0]["payload"]["status"] = "tampered"
    _reseal(payload)
    fusion.write_text(json.dumps(payload), encoding="utf-8")
    manifest_hash, inputs = comparator._validate_public_dataset(public, task_ids)

    with pytest.raises(SystemExit, match="ledger export commitment mismatch"):
        comparator.load_verified_seals(
            {"baseline": baseline, "fusion": fusion},
            expected_sources={"baseline": BASE_SOURCE, "fusion": FUSION_SOURCE},
            expected_task_ids=task_ids,
            expected_repetitions=[1],
            public_manifest_sha256=manifest_hash,
            public_inputs=inputs,
        )


def test_sealed_details_are_lifted_only_in_the_legacy_scorer_view() -> None:
    result = {"findings": [{"details": {"root_cause": "bound cause", "impact": "bound impact"}}]}

    view = comparator._scoring_result(result)

    assert view["findings"][0]["root_cause"] == "bound cause"
    assert view["findings"][0]["impact"] == "bound impact"
    assert "root_cause" not in result["findings"][0]


def test_lifted_sealed_details_reach_the_real_security_scorer(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("dangerous_call(user_input)\n", encoding="utf-8")
    input_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    sealed_result = _projection("task-1", input_sha, quality=0.8)
    expected = {
        "vulnerability_expected": True,
        "acceptable_cwes": ["CWE-78"],
        "acceptable_labels": ["command injection"],
        "weights": {
            "classification": 0.2,
            "evidence": 0.2,
            "root_cause": 0.2,
            "impact": 0.2,
            "remediation": 0.2,
        },
    }

    score, components, _details = comparator.scorer.score_security(
        comparator._scoring_result(sealed_result), expected, {"app.py": source}
    )

    assert score == 1.0
    assert set(components.values()) == {1.0}
    assert "root_cause" not in sealed_result["findings"][0]


def test_cohort_manifest_is_fixed_and_hashed() -> None:
    manifest = Path(__file__).resolve().parents[1] / "evaluation" / "team-fusion-cohort.json"

    task_ids, repetitions, digest = comparator.load_cohort_manifest(manifest)

    assert len(task_ids) == 12
    assert repetitions == [1]
    assert comparator.HEX_64.fullmatch(digest)
