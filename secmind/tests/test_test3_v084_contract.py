from __future__ import annotations

import hashlib
import json
from types import ModuleType
from uuid import NAMESPACE_URL, uuid5

import pytest

import scripts.secmind_test3_v083_bridge as bridge_adapter
from scripts.secmind_test3_v083_bridge import (
    _agent_snapshot,
    _install_contract_patches,
    _restore_input_bound_paths,
    _run_manifest,
    _verify_bridge_pin,
)
from secmind.integrations.test3 import (
    build_trusted_task_payload,
    project_domain_result,
    trusted_exact_answer_values,
)
from secmind.secret_scrubber import scrub_artifact
from secmind.task_contract import canonical_digest


def _exact_evidence_id(candidate: str, *, source_sha256: str = "a" * 64, byte_offset: int = 42) -> str:
    return str(
        uuid5(
            NAMESPACE_URL,
            f"secmind:exact-source:{source_sha256}:{byte_offset}:{candidate}",
        )
    )


def test_bridge_restores_only_uniquely_hash_bound_input_paths(tmp_path) -> None:
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    source = input_dir / "subject.php"
    source.write_text("<?php echo 'safe'; ?>", encoding="utf-8")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    report = {
        "findings": [
            {
                "path": "[REDACTED]",
                "raw": {"file_sha256": digest},
            },
            {
                "path": "C:/host/secret.php",
                "raw": {"file_sha256": "f" * 64},
            },
        ],
        "evidence": [
            {
                "path": "[REDACTED]",
                "metadata": {"path": "[REDACTED]", "file_sha256": digest},
            }
        ],
    }

    restored = _restore_input_bound_paths(
        report,
        input_dir,
        iter_safe_files=lambda _root: [(source, "subject.php")],
    )

    assert restored is not None
    assert restored["findings"][0]["path"] == "subject.php"
    assert restored["evidence"][0]["path"] == "subject.php"
    assert restored["evidence"][0]["metadata"]["path"] == "subject.php"
    assert restored["evidence"][0]["file_sha256"] == digest
    assert restored["findings"][1]["path"] == "C:/host/secret.php"
    assert report["findings"][0]["path"] == "[REDACTED]"


def test_bridge_does_not_restore_ambiguous_duplicate_content_paths(tmp_path) -> None:
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    left = input_dir / "left.php"
    right = input_dir / "right.php"
    left.write_text("same", encoding="utf-8")
    right.write_text("same", encoding="utf-8")
    digest = hashlib.sha256(left.read_bytes()).hexdigest()

    restored = _restore_input_bound_paths(
        {"findings": [{"path": "[REDACTED]", "raw": {"file_sha256": digest}}]},
        input_dir,
        iter_safe_files=lambda _root: [(left, "left.php"), (right, "right.php")],
    )

    assert restored is not None
    assert restored["findings"][0]["path"] == "[REDACTED]"


def test_trusted_task_metadata_is_allowlisted_scrubbed_and_digested() -> None:
    payload = build_trusted_task_payload(
        {},
        {
            "task_id": "task-17",
            "category": "agent_safety",
            "case_dir": "C:/must-not-cross-trust-boundary",
            "metadata": {
                "evaluation_profile": "release-block",
                "api_key": "sk-secret-value-123456789",
            },
            "required_output": {"required_fields": ["answer"]},
        },
    )

    assert payload["evaluation_metadata"]["task_id"] == "task-17"
    assert payload["evaluation_metadata"]["evaluation_profile"] == "release-block"
    assert "case_dir" not in payload["evaluation_metadata"]
    assert "api_key" not in payload["evaluation_metadata"]
    assert "sk-secret-value" not in json.dumps(payload)
    assert payload["evaluation_contract_digest"]
    assert payload["task_metadata"] == payload["evaluation_metadata"]


def test_native_status_and_derived_plan_are_explicitly_separated() -> None:
    result = project_domain_result(
        {
            "status": "PARTIAL",
            "answer": {},
            "decision_summary": {"decisions": [{"decision": "observed"}]},
        },
        {
            "answer_payload": {
                "status": "completed",
                "execution_status": "success",
                "epistemic_status": "conclusive",
            }
        },
    )

    assert result["status"] == "PARTIAL"
    assert result["decision_summary"]["plan"][0]["status"] == "observed"
    assert result["decision_summary"]["plan_contract"]["origin"] == "derived"
    assert result["decision_summary"]["field_provenance"]["plan_or_steps"]["origin"] == "derived"
    assert result["run_proof"]["native_status"] == "PARTIAL"
    assert result["run_proof"]["status_mapping"]["native_status_promoted"] is False


@pytest.mark.parametrize(
    ("native_status", "native_plan", "expected_origin"),
    [
        ("SUCCESS", [{"step_id": "native-1", "status": "completed"}], "native"),
        ("PARTIAL", [], "derived"),
        ("FAILED", [], "derived"),
        ("WAITING_APPROVAL", [{"step_id": "native-2", "status": "waiting_approval"}], "native"),
    ],
)
def test_frozen_native_result_four_arm_replay_never_promotes_status_or_execution(
    native_status: str,
    native_plan: list[dict[str, str]],
    expected_origin: str,
) -> None:
    """Bridge aliases may improve shape, never invent a better run outcome."""

    decision_summary: dict[str, object] = {"decisions": [{"decision": "observed"}]}
    if native_plan:
        decision_summary["plan"] = native_plan
    result = project_domain_result(
        {
            "status": native_status,
            "answer": {},
            "decision_summary": decision_summary,
        },
        {
            "answer_payload": {
                "status": "completed",
                "execution_status": "success",
                "epistemic_status": "conclusive",
            }
        },
    )

    assert result["status"] == native_status
    assert result["run_proof"]["native_status"] == native_status
    assert result["run_proof"]["status_mapping"]["native_status_promoted"] is False
    assert result["decision_summary"]["plan_contract"]["origin"] == expected_origin
    if native_plan:
        assert result["decision_summary"]["plan"] == native_plan
    else:
        assert all(step.get("status") != "completed" for step in result["decision_summary"]["plan"])


def test_evidence_projection_lifts_locator_fields_and_keeps_reference_closure() -> None:
    evidence = [
        {
            "evidence_id": f"ev-{index:03d}",
            "metadata": {
                "source_artifact_sha256": "a" * 64,
                "source_locator": {
                    "source_ref": "upload-evaluation-input/capture.pcapng",
                    "line_number": 7,
                },
            },
        }
        for index in range(300)
    ]
    evidence[-1]["evidence_id"] = "ev-required"
    result = project_domain_result(
        {
            "status": "SUCCESS",
            "answer": {},
            "findings": [{"finding_id": "finding-1", "evidence_ids": ["ev-required"]}],
            "evidence": evidence,
        },
        {"answer_payload": {}},
    )

    required = next(item for item in result["evidence"] if item.get("evidence_id") == "ev-required")
    assert required["path"] == "capture.pcapng"
    assert required["line"] == 7
    assert required["file_sha256"] == "a" * 64
    assert required["finding_id"] == "finding-1"
    projection = result["run_proof"]["projection"]
    assert "ev-255" in projection["collections"]["evidence"]["dropped_ids"]
    assert "ev-required" in projection["reference_closure"]["emitted_required_evidence_ids"]
    assert projection["reference_closure"]["emitted_missing_evidence_ids"] == []
    assert projection["reference_closure"]["closed"] is False
    assert projection["reference_closure"]["projection_truncated"] is True


def test_typed_policy_evidence_is_losslessly_promoted_to_public_collection() -> None:
    result = project_domain_result(
        {"status": "SUCCESS", "answer": {}, "findings": [], "evidence": []},
        {
            "answer_type": "policy_decision",
            "answer_payload": {
                "answer_kind": "policy_decision",
                "decision": "ignore_untrusted_instruction",
                "evidence": [
                    {
                        "path": "context.txt",
                        "sha256": "a" * 64,
                        "line_range": [1, 4],
                        "fact": "The embedded payment instruction was observed but not executed.",
                    }
                ],
            },
        },
    )

    assert "path" not in result["evidence"][0]
    assert "sha256" not in result["evidence"][0]
    assert "file_sha256" not in result["evidence"][0]
    assert result["evidence"][0]["evidence_id"].startswith("typed-")
    assert "claim_id" not in result["evidence"][0]
    assert "line" not in result["evidence"][0]
    assert result["evidence"][0]["metadata"]["assurance"] == "provider_claimed"
    assert result["run_proof"]["unverified_evidence_ids"] == [result["evidence"][0]["evidence_id"]]
    assert result["run_proof"]["projection"]["reference_closure"]["closed"] is False
    assert result["run_proof"]["field_provenance"]["evidence"] == "answer.typed_evidence"
    assert result["decision"] == "ignore_untrusted_instruction"


def test_timeline_row_evidence_is_promoted_without_recursive_string_harvesting() -> None:
    result = project_domain_result(
        {"status": "SUCCESS", "answer": {}, "findings": [], "evidence": []},
        {
            "answer_type": "timeline",
            "answer_payload": {
                "answer_kind": "timeline",
                "facts": [
                    {
                        "statement": "Event 4662 was observed.",
                        "evidence": {"path": "events.evtx", "sha256": "b" * 64},
                    },
                    "arbitrary prose is not evidence",
                ],
                "events": [],
            },
        },
    )

    assert len(result["evidence"]) == 1
    assert result["evidence"][0]["summary"] == "Event 4662 was observed."


def test_typed_domain_source_evidence_lifts_metadata_without_inventing_claim() -> None:
    result = project_domain_result(
        {
            "status": "SUCCESS",
            "answer": {},
            "findings": [],
            "evidence": [
                {
                    "evidence_id": "domain-evidence-1",
                    "sha256": "d" * 64,
                    "metadata": {
                        "path": "subject.c",
                        "file_sha256": "d" * 64,
                        "line": 17,
                        "evidence_type": "canonical_primary_domain_reference",
                    },
                }
            ],
        },
        {
            "answer_type": "reverse_behavior",
            "answer_payload": {
                "answer_kind": "reverse_behavior",
                "behaviors": [{"behavior": "payload download"}],
            },
        },
    )

    evidence = result["evidence"][0]
    assert evidence["path"] == "subject.c"
    assert evidence["file_sha256"] == "d" * 64
    assert evidence["sha256"] == "d" * 64
    assert evidence["line"] == 17
    assert "claim_id" not in evidence


def test_exact_answer_reference_prevents_required_evidence_from_being_truncated() -> None:
    evidence = [
        {
            "evidence_id": f"ev-{index:03d}",
            "sha256": "c" * 64,
            "metadata": {"source_locator": {"source_ref": "capture.pcap", "byte_offset": index}},
        }
        for index in range(300)
    ]
    result = project_domain_result(
        {"status": "PARTIAL", "answer": {}, "findings": [], "evidence": evidence},
        {
            "answer_type": "exact",
            "answer_payload": {
                "answer_kind": "exact",
                "values": ["flag{bounded}"],
                "items": [{"value": "flag{bounded}", "evidence_ids": ["ev-299"]}],
            },
        },
    )

    required = next(item for item in result["evidence"] if item["evidence_id"] == "ev-299")
    assert required["claim_id"] == "answer-exact-primary-claim"
    assert required["offset"] == 299
    assert "ev-299" not in result["run_proof"]["projection"]["collections"]["evidence"]["dropped_ids"]


def test_evidence_bound_high_entropy_exact_answer_survives_public_scrub() -> None:
    flag = "flag{X9aQ7mP2vN8rT4kL6sD3zY1wC5}"
    evidence_id = _exact_evidence_id(flag)
    result = project_domain_result(
        {
            "status": "SUCCESS",
            "answer": {},
            "findings": [],
            "evidence": [
                {
                    "evidence_id": evidence_id,
                    "value": flag,
                    "evidence_ids": ["ev-exact-value"],
                    "path": "capture.pcap",
                    "byte_offset": 42,
                    "sha256": "a" * 64,
                    "source": "deterministic_exact_source@1.0",
                    "metadata": {
                        "evidence_type": "exact_value_observation",
                        "source_artifact_sha256": "a" * 64,
                        "value_sha256": hashlib.sha256(flag.encode()).hexdigest(),
                    },
                }
            ],
        },
        {
            "answer_type": "exact",
            "answer_payload": {
                "answer_kind": "exact",
                "answer_type": "exact",
                "values": [flag],
                "items": [{"value": flag, "evidence_ids": [evidence_id]}],
            },
            "coverage": {},
        },
        task={"required_output": {"scoring_mode": "exact_answer_with_evidence"}},
    )

    assert result["answer"]["values"] == [flag]
    assert result["answer"]["answer"] == flag
    # Evidence remains a separately scrubbed public artifact; the exception is
    # deliberately scoped to the typed answer value only.
    assert result["evidence"][0]["value"] == "flag{[REDACTED]}"


def test_evidence_bound_high_entropy_exact_answer_survives_second_public_scrub() -> None:
    """The bridge's final envelope scrub must carry the same narrow proof."""

    flag = "flag{X9aQ7mP2vN8rT4kL6sD3zY1wC5}"
    evidence_id = _exact_evidence_id(flag)
    base = {
        "status": "SUCCESS",
        "answer": {},
        "findings": [],
        "evidence": [
            {
                "evidence_id": evidence_id,
                "value": flag,
                "path": "capture.pcap",
                "byte_offset": 42,
                "sha256": "a" * 64,
                "source": "deterministic_exact_source@1.0",
                "metadata": {
                    "evidence_type": "exact_value_observation",
                    "source_artifact_sha256": "a" * 64,
                    "value_sha256": hashlib.sha256(flag.encode()).hexdigest(),
                },
            }
        ],
    }
    report = {
        "answer_type": "exact",
        "answer_payload": {
            "answer_kind": "exact",
            "answer_type": "exact",
            "values": [flag],
            "items": [{"value": flag, "evidence_ids": [evidence_id]}],
        },
    }
    task = {"required_output": {"scoring_mode": "exact_answer_with_evidence"}}

    projected = project_domain_result(base, report, task=task)
    trusted = trusted_exact_answer_values(report["answer_payload"], projected, task)
    final = scrub_artifact(projected, max_depth=12, max_items=256, trusted_exact_answers=trusted)

    assert final["answer"]["values"] == [flag]
    assert final["answer"]["answer"] == flag
    assert final["evidence"][0]["value"] == "flag{[REDACTED]}"


def test_exact_answer_scrub_does_not_allow_credentials_or_unbound_values() -> None:
    api_key = "sk-abcdefghijklmnopqrstuv"
    result = project_domain_result(
        {
            "status": "SUCCESS",
            "answer": {},
            "findings": [],
            "evidence": [
                {
                    "evidence_id": "ev-api-key",
                    "value": api_key,
                    "path": "capture.txt",
                    "line": 1,
                    "sha256": "b" * 64,
                }
            ],
        },
        {
            "answer_type": "exact",
            "answer_payload": {
                "answer_kind": "exact",
                "answer_type": "exact",
                "values": [api_key],
                "items": [{"value": api_key, "evidence_ids": ["ev-api-key"]}],
            },
            "coverage": {},
        },
        task={"required_output": {"scoring_mode": "exact_answer_with_evidence"}},
    )
    assert result["answer"]["values"] == ["[REDACTED]"]

    unbound = project_domain_result(
        {"status": "SUCCESS", "answer": {}, "findings": [], "evidence": []},
        {
            "answer_type": "exact",
            "answer_payload": {
                "answer_kind": "exact",
                "answer_type": "exact",
                "values": ["flag{X9aQ7mP2vN8rT4kL6sD3zY1wC5}"],
            },
            "coverage": {},
        },
        task={"required_output": {"scoring_mode": "exact_answer_with_evidence"}},
    )
    assert unbound["answer"]["values"] == ["flag{[REDACTED]}"]


@pytest.mark.parametrize(
    "candidate",
    [
        "s\u200bk-abcdefghijklmnopqrstuv",
        "Pa$$w0rd-8bJk2Qx9Vz7Lm3Na",
    ],
)
def test_exact_answer_attestation_never_releases_credential_like_values(candidate: str) -> None:
    result = project_domain_result(
        {
            "status": "SUCCESS",
            "answer": {},
            "findings": [],
            "evidence": [
                {
                    "evidence_id": "ev-exact-value",
                    "path": "capture.pcap",
                    "byte_offset": 42,
                    "sha256": "a" * 64,
                    "source": "deterministic_exact_source@1.0",
                    "metadata": {
                        "evidence_type": "exact_value_observation",
                        "value_sha256": hashlib.sha256(candidate.encode()).hexdigest(),
                    },
                }
            ],
        },
        {
            "answer_type": "exact",
            "answer_payload": {
                "answer_kind": "exact",
                "answer_type": "exact",
                "values": [candidate],
                "items": [{"value": candidate, "evidence_ids": ["ev-exact-value"]}],
            },
            "coverage": {},
        },
        task={"required_output": {"scoring_mode": "exact_answer_with_evidence"}},
    )

    assert candidate not in json.dumps(result, ensure_ascii=False)


def test_provider_claimed_exact_evidence_cannot_authorize_release() -> None:
    flag = "flag{X9aQ7mP2vN8rT4kL6sD3zY1wC5}"
    result = project_domain_result(
        {
            "status": "SUCCESS",
            "answer": {},
            "findings": [],
            "evidence": [
                {
                    "evidence_id": "ev-fabricated",
                    "path": "capture.pcap",
                    "byte_offset": 42,
                    "sha256": "a" * 64,
                    "source": "model_source@1.0",
                    "assurance": "verified",
                    "metadata": {
                        "evidence_type": "exact_value_observation",
                        "value_sha256": hashlib.sha256(flag.encode()).hexdigest(),
                    },
                }
            ],
        },
        {
            "answer_type": "exact",
            "answer_payload": {
                "answer_kind": "exact",
                "answer_type": "exact",
                "values": [flag],
                "items": [{"value": flag, "evidence_ids": ["ev-fabricated"]}],
            },
            "coverage": {},
        },
        task={"required_output": {"scoring_mode": "exact_answer_with_evidence"}},
    )

    assert result["answer"]["values"] == ["flag{[REDACTED]}"]


def test_provider_evidence_alias_is_remapped_to_manifest_bound_public_evidence() -> None:
    result = project_domain_result(
        {
            "status": "SUCCESS",
            "answer": {},
            "findings": [],
            "evidence": [
                {
                    "evidence_id": "canonical-domain-evidence-1",
                    "sha256": "e" * 64,
                    "metadata": {
                        "path": "events.json",
                        "line": 4,
                        "provider_evidence_ids": ["provider-event-1"],
                    },
                }
            ],
        },
        {
            "answer_type": "timeline",
            "answer_payload": {
                "answer_kind": "timeline",
                "events": [{"event_id": "4662", "evidence_ids": ["provider-event-1"]}],
            },
        },
    )

    assert result["answer"]["events"][0]["evidence_ids"] == ["canonical-domain-evidence-1"]
    assert result["evidence"][0]["claim_id"] == "answer-timeline-primary-claim"
    assert result["run_proof"]["projection"]["reference_closure"]["closed"] is True


def test_rejected_finding_relation_is_retained_only_as_provenance() -> None:
    result = project_domain_result(
        {
            "status": "SUCCESS",
            "answer": {},
            "findings": [{"finding_id": "accepted", "evidence_ids": ["ev-accepted"]}],
            "evidence": [
                {
                    "evidence_id": "ev-accepted",
                    "sha256": "f" * 64,
                    "metadata": {"path": "app.py", "finding_id": "rejected-candidate"},
                }
            ],
        },
        {"answer_payload": {}},
    )

    evidence = result["evidence"][0]
    assert evidence["finding_id"] == "accepted"
    assert evidence["metadata"]["provenance_finding_ids"] == ["rejected-candidate"]
    assert result["run_proof"]["projection"]["reference_closure"]["closed"] is True


def test_runtime_verification_is_projected_but_model_process_and_retry_aliases_are_rejected() -> None:
    validation = {
        "schema_version": "secmind-final-validation-v1",
        "validator_id": "secmind-deterministic-contract-evidence-verifier",
        "validator_kind": "deterministic_contract_and_evidence",
        "applied": True,
        "model_independent": True,
        "semantic_model_independence": False,
        "checks": {
            key: True
            for key in (
                "completion_contracts_parse",
                "completion_decision_complete",
                "completion_digests_valid",
                "completion_integrity_valid",
                "completion_obligations_bound",
                "completion_proof_valid",
                "completion_run_and_id_binding",
                "completion_snapshot_quiet",
                "critical_obligations_complete",
                "evidence_reference_closure",
                "required_evidence_verified",
                "resolved_task_contract_bound",
                "terminal_status_completed",
                "typed_answer_present",
                "verified_support_chain_present",
            )
        },
        "status": "passed",
        "input_manifest_digest": "b" * 64,
        "required_evidence_ids": [],
        "missing_evidence_ids": [],
        "verified_evidence_ids": [],
        "verified_claim_ids": [],
        "limitations": [],
    }
    validation["validation_digest"] = canonical_digest(validation)
    result = project_domain_result(
        {"status": "SUCCESS", "answer": {}, "decision_summary": {}},
        {
            "verification_summary": validation,
            "coverage": {
                "final_validation_required": True,
                "final_validation_receipt_digest": validation["validation_digest"],
                "final_validation_validator_id": validation["validator_id"],
            },
            "answer_payload": {
                "answer_kind": "timeline",
                "events": [{"event_id": "1"}],
                "semantic_output": {
                    "process_provenance": {
                        "process_id": "offline-log-parser",
                        "version": "1.0",
                    }
                },
            },
        },
    )

    decision = result["decision_summary"]
    assert decision["final_validation"] == validation
    assert "retry_summary" not in decision
    assert "process_receipt" not in decision
    assert "tools" not in decision


def test_model_authored_validation_cannot_impersonate_runtime_verifier() -> None:
    result = project_domain_result(
        {
            "status": "PARTIAL",
            "answer": {},
            "decision_summary": {"final_validation": {"status": "passed"}},
        },
        {
            "verification_summary": {},
            "answer_payload": {
                "answer_kind": "patch",
                "validation": {"status": "passed", "checks": ["model supplied"]},
            },
        },
    )

    decision = result["decision_summary"]
    assert "final_validation" not in decision
    assert "validation" not in decision
    assert "verification" not in decision


def test_bare_evidence_prose_is_not_an_evidence_reference() -> None:
    result = project_domain_result(
        {"status": "PARTIAL", "answer": {}, "findings": [], "evidence": []},
        {
            "answer_type": "policy_decision",
            "answer_payload": {
                "answer_kind": "policy_decision",
                "decision": "DENY",
                "evidence": ["ev-missing"],
            },
        },
    )

    closure = result["run_proof"]["projection"]["reference_closure"]
    assert closure["closed"] is True
    assert closure["emitted_missing_evidence_ids"] == []


@pytest.mark.parametrize("field_name", ["evidence_refs", "supporting_evidence_ids"])
def test_any_nonempty_explicit_reference_string_fails_closed(field_name: str) -> None:
    result = project_domain_result(
        {"status": "PARTIAL", "answer": {}, "findings": [], "evidence": []},
        {
            "answer_type": "exact",
            "answer_payload": {
                "answer_kind": "exact",
                "values": ["observed"],
                field_name: ["provider supplied prose reference"],
            },
        },
    )

    closure = result["run_proof"]["projection"]["reference_closure"]
    assert closure["closed"] is False
    assert closure["emitted_missing_evidence_ids"] == ["provider supplied prose reference"]


def test_top_level_source_and_record_locators_are_projected_for_trusted_evidence() -> None:
    result = project_domain_result(
        {
            "status": "PARTIAL",
            "answer": {},
            "findings": [],
            "evidence": [
                {
                    "evidence_id": "ev-top-level-locator",
                    "sha256": "c" * 64,
                    "source_locator": {
                        "source_ref": "upload-evaluation-input/trace.jsonl",
                        "line_number": 9,
                        "byte_offset": 18,
                        "file_sha256": "c" * 64,
                    },
                }
            ],
        },
        {"answer_payload": {}},
    )

    evidence = result["evidence"][0]
    assert evidence["path"] == "trace.jsonl"
    assert evidence["line"] == 9
    assert evidence["offset"] == 18
    assert evidence["file_sha256"] == "c" * 64


def test_provider_claim_cannot_satisfy_reference_closure_or_scorer_support() -> None:
    result = project_domain_result(
        {"status": "PARTIAL", "answer": {}, "findings": [], "evidence": []},
        {
            "answer_type": "timeline",
            "answer_payload": {
                "answer_kind": "timeline",
                "events": [
                    {
                        "event_id": "event-provider",
                        "evidence": {
                            "evidence_id": "provider-ev-1",
                            "path": "trace.jsonl",
                            "sha256": "d" * 64,
                            "line": 4,
                        },
                    }
                ],
            },
        },
    )

    evidence = result["evidence"][0]
    assert evidence["evidence_id"] == "provider-ev-1"
    assert all(key not in evidence for key in ("path", "sha256", "file_sha256", "line", "claim_id"))
    assert result["run_proof"]["unverified_evidence_ids"] == ["provider-ev-1"]
    assert result["run_proof"]["projection"]["reference_closure"]["closed"] is False


def test_final_validation_requires_runtime_coverage_binding() -> None:
    validation = {
        "schema_version": "secmind-final-validation-v1",
        "validator_id": "secmind-deterministic-contract-evidence-verifier",
        "validator_kind": "deterministic_contract_and_evidence",
        "applied": True,
        "model_independent": True,
        "semantic_model_independence": False,
        "checks": {
            key: True
            for key in (
                "completion_contracts_parse",
                "completion_decision_complete",
                "completion_digests_valid",
                "completion_integrity_valid",
                "completion_obligations_bound",
                "completion_proof_valid",
                "completion_run_and_id_binding",
                "completion_snapshot_quiet",
                "critical_obligations_complete",
                "evidence_reference_closure",
                "required_evidence_verified",
                "resolved_task_contract_bound",
                "terminal_status_completed",
                "typed_answer_present",
                "verified_support_chain_present",
            )
        },
        "status": "passed",
        "input_manifest_digest": "b" * 64,
        "required_evidence_ids": [],
        "missing_evidence_ids": [],
        "verified_evidence_ids": [],
        "verified_claim_ids": [],
        "limitations": [],
    }
    validation["validation_digest"] = canonical_digest(validation)
    report = {
        "verification_summary": validation,
        "answer_payload": {"answer_kind": "exact", "values": ["x"]},
        "coverage": {
            "final_validation_required": True,
            "final_validation_receipt_digest": validation["validation_digest"],
            "final_validation_validator_id": validation["validator_id"],
        },
    }
    accepted = project_domain_result({"status": "PARTIAL", "answer": {}, "decision_summary": {}}, report)
    assert accepted["decision_summary"]["final_validation"] == validation

    unbound = project_domain_result(
        {"status": "PARTIAL", "answer": {}, "decision_summary": {}},
        {**report, "coverage": {"final_validation_required": True}},
    )
    assert "final_validation" not in unbound["decision_summary"]


def test_unsafe_evidence_path_is_not_projected_as_plausible_filename() -> None:
    result = project_domain_result(
        {
            "status": "PARTIAL",
            "answer": {},
            "findings": [],
            "evidence": [
                {
                    "evidence_id": "ev-unsafe-path",
                    "path": "C:/private/work/subject.py",
                    "sha256": "b" * 64,
                }
            ],
        },
        {"answer_payload": {}},
    )

    evidence = result["evidence"][0]
    assert "path" not in evidence
    assert evidence["metadata"]["path_projection_status"] == "unresolved_unsafe_or_nonrelative_path"


def test_bridge_pin_is_checked_before_import_and_manifest_records_snapshot(tmp_path, monkeypatch) -> None:
    bridge = tmp_path / "bridge.py"
    bridge.write_text("BRIDGE_VERSION = 'test'\n", encoding="utf-8")
    # The production entrypoint is fail-closed; this first call only computes
    # the fixture digest before the explicit manifest is created.
    digest = _verify_bridge_pin(bridge, require_pin=False)["bridge_sha256"]
    manifest = tmp_path / "bridge-manifest.json"
    manifest.write_text(json.dumps({"bridge_sha256": digest}), encoding="utf-8")
    monkeypatch.setenv("SECMIND_V083_REQUIRE_BRIDGE_PIN", "1")

    verified = _verify_bridge_pin(bridge, manifest)
    assert verified["bridge_pin_status"] == "VERIFIED"
    agent = _agent_snapshot(tmp_path)
    run_manifest = _run_manifest(verified, agent)
    assert run_manifest["bridge_sha256"] == digest
    assert run_manifest["agent_git_sha"]
    assert run_manifest["agent_config_digest"]
    assert run_manifest["agent_profile"]
    assert run_manifest["agent_dependency_digest"]
    assert run_manifest["run_manifest_digest"]

    bridge.write_text("BRIDGE_VERSION = 'mutated'\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="SHA-256"):
        _verify_bridge_pin(bridge, manifest)


def test_agent_snapshot_binds_secret_presence_without_binding_secret_value(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SECMIND_AUDIT_PROFILE", "extended")
    monkeypatch.setenv("SECMIND_OPENAI_API_KEY", "first-synthetic-secret")
    first = _agent_snapshot(tmp_path)

    monkeypatch.setenv("SECMIND_OPENAI_API_KEY", "rotated-synthetic-secret")
    rotated = _agent_snapshot(tmp_path)

    assert first["agent_snapshot_digest"] == rotated["agent_snapshot_digest"]
    assert first["agent_config_digest"] == rotated["agent_config_digest"]

    monkeypatch.setenv("SECMIND_MODEL_REASONING_EFFORT", "high")
    changed_policy = _agent_snapshot(tmp_path)
    assert changed_policy["agent_snapshot_digest"] != rotated["agent_snapshot_digest"]


def test_bridge_retries_only_idempotent_get_after_transient_non_json_500(monkeypatch) -> None:
    class BridgeError(RuntimeError):
        pass

    class OriginalClient:
        def __init__(self, port: int, *, timeout: float) -> None:
            self.port = port
            self.timeout = timeout

    platform = ModuleType("test_platform_bridge")
    platform.BRIDGE_VERSION = "test"
    platform.MAX_RESPONSE_BYTES = 8 * 1024 * 1024
    platform.BridgeError = BridgeError
    platform.SecMindClient = OriginalClient
    platform.build_task_payload = lambda request, upload: {}
    platform.convert_result = lambda request, summary, report, **kwargs: {}
    platform._object = lambda payload, label: payload

    responses = [
        (500, b"Internal Server Error", "text/plain"),
        (200, b'{"status":"ok"}', "application/json"),
    ]
    connection_count = 0

    class FakeResponse:
        def __init__(self, status: int, raw: bytes, media_type: str) -> None:
            self.status = status
            self._raw = raw
            self._media_type = media_type

        def read(self, limit: int) -> bytes:
            return self._raw[:limit]

        def getheader(self, name: str) -> str | None:
            return self._media_type if name.casefold() == "content-type" else None

    class FakeConnection:
        def __init__(self, host: str, port: int, *, timeout: float) -> None:
            nonlocal connection_count
            connection_count += 1

        def request(self, method: str, path: str, *, body: object, headers: object) -> None:
            assert method == "GET"

        def getresponse(self) -> FakeResponse:
            return FakeResponse(*responses.pop(0))

        def close(self) -> None:
            pass

    monkeypatch.setattr(bridge_adapter.http.client, "HTTPConnection", FakeConnection)
    monkeypatch.setattr(bridge_adapter.time, "sleep", lambda seconds: None)
    _install_contract_patches(
        platform,
        bridge_sha256="a" * 64,
        bridge_snapshot={"bridge_sha256": "a" * 64},
        agent_snapshot={"agent_snapshot_digest": "b" * 64, "agent_git_sha": "c" * 40},
    )

    client = platform.SecMindClient(8123, timeout=1.0)
    assert client.summary("run-1") == {"status": "ok"}
    assert connection_count == 2


def test_bridge_retries_health_after_transient_bad_status_line(monkeypatch) -> None:
    class BridgeError(RuntimeError):
        pass

    class OriginalClient:
        def __init__(self, port: int, *, timeout: float) -> None:
            self.port = port
            self.timeout = timeout

    platform = ModuleType("test_platform_bridge_bad_status")
    platform.BRIDGE_VERSION = "test"
    platform.MAX_RESPONSE_BYTES = 8 * 1024 * 1024
    platform.BridgeError = BridgeError
    platform.SecMindClient = OriginalClient
    platform.build_task_payload = lambda request, upload: {}
    platform.convert_result = lambda request, summary, report, **kwargs: {}
    platform._object = lambda payload, label: payload
    connection_count = 0

    class FakeResponse:
        status = 200

        def read(self, limit: int) -> bytes:
            return b'{"status":"ok"}'

        def getheader(self, name: str) -> str:
            return "application/json"

    class FakeConnection:
        def __init__(self, host: str, port: int, *, timeout: float) -> None:
            nonlocal connection_count
            connection_count += 1

        def request(self, method: str, path: str, *, body: object, headers: object) -> None:
            pass

        def getresponse(self) -> FakeResponse:
            if connection_count == 1:
                raise bridge_adapter.http.client.BadStatusLine("GET /health/live HTTP/1.1")
            return FakeResponse()

        def close(self) -> None:
            pass

    monkeypatch.setattr(bridge_adapter.http.client, "HTTPConnection", FakeConnection)
    monkeypatch.setattr(bridge_adapter.time, "sleep", lambda seconds: None)
    _install_contract_patches(
        platform,
        bridge_sha256="a" * 64,
        bridge_snapshot={"bridge_sha256": "a" * 64},
        agent_snapshot={"agent_snapshot_digest": "b" * 64, "agent_git_sha": "c" * 40},
    )

    assert platform.SecMindClient(8123, timeout=1.0).health() is True
    assert connection_count == 2


def test_bridge_health_contains_repeated_protocol_errors(monkeypatch) -> None:
    class BridgeError(RuntimeError):
        pass

    class OriginalClient:
        def __init__(self, port: int, *, timeout: float) -> None:
            pass

    platform = ModuleType("test_platform_bridge_repeated_bad_status")
    platform.BRIDGE_VERSION = "test"
    platform.MAX_RESPONSE_BYTES = 8 * 1024 * 1024
    platform.BridgeError = BridgeError
    platform.SecMindClient = OriginalClient
    platform.build_task_payload = lambda request, upload: {}
    platform.convert_result = lambda request, summary, report, **kwargs: {}
    platform._object = lambda payload, label: payload
    connection_count = 0

    class FakeConnection:
        def __init__(self, host: str, port: int, *, timeout: float) -> None:
            nonlocal connection_count
            connection_count += 1

        def request(self, method: str, path: str, *, body: object, headers: object) -> None:
            pass

        def getresponse(self) -> object:
            raise bridge_adapter.http.client.BadStatusLine("GET /health/live HTTP/1.1")

        def close(self) -> None:
            pass

    monkeypatch.setattr(bridge_adapter.http.client, "HTTPConnection", FakeConnection)
    monkeypatch.setattr(bridge_adapter.time, "sleep", lambda seconds: None)
    _install_contract_patches(
        platform,
        bridge_sha256="a" * 64,
        bridge_snapshot={"bridge_sha256": "a" * 64},
        agent_snapshot={"agent_snapshot_digest": "b" * 64, "agent_git_sha": "c" * 40},
    )

    assert platform.SecMindClient(8123, timeout=1.0).health() is False
    assert connection_count == 3


def test_bridge_create_task_preserves_opaque_attachment_references() -> None:
    class BridgeError(RuntimeError):
        pass

    class OriginalClient:
        def __init__(self, port: int, *, timeout: float) -> None:
            self.port = port
            self.timeout = timeout

    platform = ModuleType("test_platform_bridge_control_payload")
    platform.BRIDGE_VERSION = "test"
    platform.MAX_RESPONSE_BYTES = 8 * 1024 * 1024
    platform.BridgeError = BridgeError
    platform.SecMindClient = OriginalClient
    platform.build_task_payload = lambda request, upload: {}
    platform.convert_result = lambda request, summary, report, **kwargs: {}
    platform._object = lambda payload, label: payload
    _install_contract_patches(
        platform,
        bridge_sha256="a" * 64,
        bridge_snapshot={"bridge_sha256": "a" * 64},
        agent_snapshot={"agent_snapshot_digest": "b" * 64, "agent_git_sha": "c" * 40},
    )

    reference = "738fcf1d-e6bd-4c01-8a83-283051bc1451-evaluation-input.zip"
    payload = {"attachments": [{"ref": reference, "name": "evaluation-input.zip"}]}
    captured: dict[str, object] = {}
    client = platform.SecMindClient(8123, timeout=1.0)

    def request(method: str, path: str, **kwargs: object) -> tuple[int, dict[str, str]]:
        captured.update(method=method, path=path, **kwargs)
        return 202, {"run_id": "run-1"}

    client.request = request
    assert client.create_task(payload) == "run-1"
    submitted = json.loads(bytes(captured["body"]).decode("utf-8"))
    assert submitted["attachments"][0]["ref"] == reference


def test_bridge_rebalances_combined_token_cap_for_one_bounded_fallback() -> None:
    class BridgeError(RuntimeError):
        pass

    class OriginalClient:
        def __init__(self, port: int, *, timeout: float) -> None:
            pass

    platform = ModuleType("test_platform_bridge_budget")
    platform.BRIDGE_VERSION = "test"
    platform.MAX_RESPONSE_BYTES = 8 * 1024 * 1024
    platform.BridgeError = BridgeError
    platform.SecMindClient = OriginalClient
    platform.build_task_payload = lambda request, upload: {}
    platform.convert_result = lambda request, summary, report, **kwargs: {}
    platform.build_service_environment = lambda *args, **kwargs: {
        "SECMIND_MODEL_MAX_OUTPUT_TOKENS": "16000",
        "SECMIND_MODEL_FALLBACK_MAX_OUTPUT_TOKENS": "12000",
        "SECMIND_MAX_INPUT_TOKENS": "96000",
        "SECMIND_MAX_OUTPUT_TOKENS": "24000",
    }
    platform._object = lambda payload, label: payload
    _install_contract_patches(
        platform,
        bridge_sha256="a" * 64,
        bridge_snapshot={"bridge_sha256": "a" * 64},
        agent_snapshot={"agent_snapshot_digest": "b" * 64, "agent_git_sha": "c" * 40},
    )

    environment = platform.build_service_environment(task={"budget": {"model_token_cap": 120_000}})

    assert environment["SECMIND_MAX_OUTPUT_TOKENS"] == "28000"
    assert environment["SECMIND_MAX_INPUT_TOKENS"] == "92000"
    assert int(environment["SECMIND_MAX_OUTPUT_TOKENS"]) + int(environment["SECMIND_MAX_INPUT_TOKENS"]) == 120_000


def test_bridge_allows_explicit_openai_compatible_live_profile() -> None:
    class BridgeError(RuntimeError):
        pass

    class OriginalClient:
        def __init__(self, port: int, *, timeout: float) -> None:
            pass

    platform = ModuleType("test_platform_bridge_openai_compatible")
    platform.BRIDGE_VERSION = "test"
    platform.MAX_RESPONSE_BYTES = 8 * 1024 * 1024
    platform.BridgeError = BridgeError
    platform.SecMindClient = OriginalClient
    platform.build_task_payload = lambda request, upload: {}
    platform.convert_result = lambda request, summary, report, **kwargs: {}
    platform.resolve_model_mode = lambda requested, environ: ("live", environ.get("SECMIND_DEEPSEEK_API_KEY"))
    platform.build_service_environment = lambda base, **kwargs: {
        **base,
        "SECMIND_MODEL_MODE": kwargs["mode"],
        "SECMIND_QWEN_API_KEY": kwargs["api_key"] or "",
        "SECMIND_QWEN_BASE_URL": "https://api.deepseek.com",
        "SECMIND_TRUSTED_MODEL_BASE_URLS": "https://api.deepseek.com",
        "SECMIND_PLANNER_MODEL": "deepseek-v4-flash",
        "SECMIND_WORKER_MODEL": "deepseek-v4-flash",
        "SECMIND_FALLBACK_MODEL": "deepseek-v4-flash",
        "SECMIND_MODEL_MAX_OUTPUT_TOKENS": "1024",
        "SECMIND_MODEL_FALLBACK_MAX_OUTPUT_TOKENS": "256",
        "SECMIND_MAX_OUTPUT_TOKENS": "4096",
    }
    platform._object = lambda payload, label: payload
    _install_contract_patches(
        platform,
        bridge_sha256="a" * 64,
        bridge_snapshot={"bridge_sha256": "a" * 64},
        agent_snapshot={"agent_snapshot_digest": "b" * 64, "agent_git_sha": "c" * 40},
    )
    base = {
        "SECMIND_MODEL_BASE_URL_PROVIDER": "openai-compatible",
        "SECMIND_OPENAI_API_KEY": "openai-secret",
        "SECMIND_QWEN_BASE_URL": "https://gateway.example/v1",
        "SECMIND_TRUSTED_MODEL_BASE_URLS": "https://gateway.example/v1",
        "SECMIND_PLANNER_MODEL": "gpt-5.6-luna",
        "SECMIND_WORKER_MODEL": "gpt-5.6-luna",
        "SECMIND_FALLBACK_MODEL": "gpt-5.6-luna",
    }

    mode, key = platform.resolve_model_mode("live", base)
    environment = platform.build_service_environment(
        base,
        mode=mode,
        api_key=key,
        task={"budget": {"model_token_cap": 10_000}},
    )

    assert (mode, key) == ("live", "openai-secret")
    assert environment["SECMIND_MODEL_BASE_URL_PROVIDER"] == "openai-compatible"
    assert environment["SECMIND_QWEN_BASE_URL"] == "https://gateway.example/v1"
    assert environment["SECMIND_PLANNER_MODEL"] == "gpt-5.6-luna"
    assert environment["SECMIND_OPENAI_API_KEY"] == "openai-secret"
    assert environment["SECMIND_QWEN_API_KEY"] == ""
