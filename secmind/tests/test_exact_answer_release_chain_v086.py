"""Security regressions for the exact-answer public release boundary.

These tests deliberately exercise the last independent scrub pass as well as
the pure Test 3 projection.  The exact value is synthetic benchmark data; it
must survive only in the typed ``answer`` object and nowhere else.
"""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from secmind.final_validation import build_exact_answer_attestation, validate_exact_answer_attestation
from secmind.integrations.test3 import project_domain_result, trusted_exact_answer_values
from secmind.public_coverage import public_coverage_projection
from secmind.secret_scrubber import scrub_artifact

FLAG = "flag{X9aQ7mP2vN8rT4kL6sD3zY1wC5}"
SOURCE_SHA256 = "a" * 64
BYTE_OFFSET = 42
EVIDENCE_ID = str(
    uuid5(
        NAMESPACE_URL,
        f"secmind:exact-source:{SOURCE_SHA256}:{BYTE_OFFSET}:{FLAG}",
    )
)


def _base_result() -> dict[str, object]:
    return {
        "status": "SUCCESS",
        "answer": {},
        "findings": [],
        "evidence": [
            {
                "evidence_id": EVIDENCE_ID,
                "path": "capture.pcap",
                "line": 1,
                "byte_offset": BYTE_OFFSET,
                "sha256": SOURCE_SHA256,
                "source": "deterministic_exact_source@1.0",
                "metadata": {
                    "evidence_type": "exact_value_observation",
                    "source_artifact_sha256": SOURCE_SHA256,
                    "value_sha256": sha256(FLAG.encode("utf-8")).hexdigest(),
                },
            }
        ],
    }


def _report(*, answer_payload: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "answer_type": "exact",
        "answer_payload": answer_payload
        or {
            "answer_kind": "exact",
            "answer_type": "exact",
            "values": [FLAG],
            "items": [{"value": FLAG, "evidence_ids": [EVIDENCE_ID]}],
        },
        "coverage": {},
    }


def _task() -> dict[str, object]:
    return {"required_output": {"scoring_mode": "exact_answer_with_evidence"}}


def test_last_independent_scrub_preserves_only_attested_typed_answer() -> None:
    base = _base_result()
    report = _report()
    task = _task()

    trusted = trusted_exact_answer_values(report["answer_payload"], base, task)  # type: ignore[arg-type]
    projected = project_domain_result(base, report, task=task)
    public = scrub_artifact(projected, max_depth=12, max_items=256, trusted_exact_answers=trusted)

    assert public["answer"]["answer"] == FLAG  # type: ignore[index]
    assert public["answer"]["values"] == [FLAG]  # type: ignore[index]
    # Evidence is intentionally not an exact-value release channel.  The
    # source row may omit the value entirely, or carry only a scrubbed value;
    # in either case the raw token must not occur there.
    assert FLAG not in json.dumps(public["evidence"], ensure_ascii=False)  # type: ignore[index]


def test_exact_value_does_not_restore_nested_or_non_answer_fields() -> None:
    payload: dict[str, Any] = {
        "answer_kind": "exact",
        "answer_type": "exact",
        "values": [FLAG],
        "items": [{"value": FLAG, "evidence_ids": [EVIDENCE_ID]}],
        "nested": {"answer_kind": "exact", "values": [FLAG]},
        "diagnostics": {"values": [FLAG]},
    }
    projected = project_domain_result(_base_result(), _report(answer_payload=payload), task=_task())

    # The one intended copy in the typed answer is retained.  The evidence,
    # nested answer-like mapping, and diagnostics must not become release
    # channels for the same high-entropy token.
    assert projected["answer"]["values"] == [FLAG]  # type: ignore[index]
    assert projected["answer"]["items"][0]["value"] == "flag{[REDACTED]}"  # type: ignore[index]
    assert projected["answer"]["nested"]["values"] == ["flag{[REDACTED]}"]  # type: ignore[index]
    assert projected["answer"]["diagnostics"]["values"] == ["flag{[REDACTED]}"]  # type: ignore[index]
    paths: list[tuple[str, ...]] = []

    def collect(value: object, path: tuple[str, ...] = ()) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                collect(item, (*path, str(key)))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                collect(item, (*path, str(index)))
        elif value == FLAG:
            paths.append(path)

    collect(projected)
    assert set(paths) == {("answer", "answer"), ("answer", "values", "0")}


def test_bridge_trust_uses_raw_report_when_scrubbed_locator_digest_is_stale() -> None:
    """A compatibility projection must not invalidate a valid server attestation.

    The first bridge conversion can scrub an absolute/source locator.  That
    changes the locator value but cannot change the already-issued digest.  A
    second trust calculation over that projection must therefore fail closed;
    the bridge instead passes the direct server report to the verifier before
    the final public scrub.
    """

    run_id = "run-raw-report-trust-v086"
    original_locator = {
        "source_ref": r"F:\BaiduSyncdisk\2026竞赛\Lazy_Leaks.pcapng",
        "byte_offset": BYTE_OFFSET,
        "byte_length": len(FLAG),
    }
    scrubbed_locator = {**original_locator, "source_ref": "[REDACTED].pcapng"}
    attestation = build_exact_answer_attestation(
        run_id=run_id,
        input_manifest_digest="b" * 64,
        evidence_id=EVIDENCE_ID,
        value_sha256=sha256(FLAG.encode("utf-8")).hexdigest(),
        artifact_sha256=SOURCE_SHA256,
        locator=original_locator,
    )
    assert attestation is not None
    raw_evidence: dict[str, Any] = {
        "evidence_id": EVIDENCE_ID,
        "path": "capture.pcapng",
        "byte_offset": BYTE_OFFSET,
        "sha256": SOURCE_SHA256,
        "source": "deterministic_exact_source@1.0",
        "metadata": {
            "evidence_type": "exact_value_observation",
            "source_artifact_sha256": SOURCE_SHA256,
            "value_sha256": sha256(FLAG.encode("utf-8")).hexdigest(),
            "source_locator": original_locator,
            "run_id": run_id,
            "exact_answer_attestation": attestation,
        },
    }
    report: dict[str, Any] = {
        "run_id": run_id,
        "answer_type": "exact",
        "answer_payload": {
            "answer_kind": "exact",
            "answer_type": "exact",
            "values": [FLAG],
            "items": [{"value": FLAG, "evidence_ids": [EVIDENCE_ID]}],
        },
        "evidence": [raw_evidence],
        "coverage": {},
    }
    scrubbed_base = {
        "status": "SUCCESS",
        "answer": {},
        "findings": [],
        "evidence": [
            {
                **raw_evidence,
                "metadata": {
                    **raw_evidence["metadata"],
                    "source_locator": scrubbed_locator,
                },
            }
        ],
    }
    task = _task()

    # Proving the old failure mode: the post-scrub locator no longer matches
    # the attestation digest, so it must not be trusted as a source of truth.
    assert not trusted_exact_answer_values(report["answer_payload"], scrubbed_base, task, report=report)

    projected = project_domain_result(
        scrubbed_base,
        report,
        task=task,
        raw_report_for_trust=report,
    )

    assert projected["answer"]["values"] == [FLAG]  # type: ignore[index]
    assert projected["answer"]["answer"] == FLAG  # type: ignore[index]
    assert FLAG not in json.dumps(projected["evidence"], ensure_ascii=False)  # type: ignore[index]


def test_credential_shaped_exact_candidate_never_enters_release_exception() -> None:
    credential = "token{X9aQ7mP2vN8rT4kL6sD3zY1wC5}"
    base = _base_result()
    base["evidence"][0]["metadata"]["value_sha256"] = sha256(credential.encode("utf-8")).hexdigest()  # type: ignore[index]
    report = _report(
        answer_payload={
            "answer_kind": "exact",
            "answer_type": "exact",
            "values": [credential],
            "items": [{"value": credential, "evidence_ids": [EVIDENCE_ID]}],
        }
    )
    projected = project_domain_result(base, report, task=_task())

    assert credential not in json.dumps(projected, ensure_ascii=False)


def test_forged_exact_metadata_without_generator_identity_is_not_trusted() -> None:
    base = _base_result()
    row = base["evidence"][0]  # type: ignore[index]
    row["evidence_id"] = "ev-forged"  # type: ignore[index]
    row["source"] = "deterministic_exact_source@999.999"  # type: ignore[index]

    projected = project_domain_result(base, _report(), task=_task())

    assert FLAG not in json.dumps(projected, ensure_ascii=False)


def test_public_coverage_does_not_publish_raw_semantic_exact_values() -> None:
    coverage = {
        "scenario_semantic_delta": {
            "semantic_output": {"facts": {"accepted_answer_candidates": [FLAG]}},
            "values": [FLAG],
        },
        "scenario_semantic_output": {"facts": [FLAG]},
        "typed_semantic_deltas": [{"answer": {"values": [FLAG]}}],
        "typed_answer_runtime": {
            "published_answer": {"answer": {"values": [FLAG]}},
            "active_answer": {"answer": {"values": [FLAG]}},
        },
        "pre_primary_scenario_projection": {
            "answer_payload": {"answer_kind": "exact", "values": [FLAG]},
            "evidence_ids": [EVIDENCE_ID],
        },
        "scenario_projection": {"answer_payload": {"answer_kind": "exact", "values": [FLAG]}},
    }

    public = public_coverage_projection(coverage)

    assert FLAG not in json.dumps(public, ensure_ascii=False)
    for key in coverage:
        assert public[key]["projection"] == "summary"  # type: ignore[index]


def test_exact_answer_attestation_is_value_free_and_bound_to_all_source_identity() -> None:
    attestation = build_exact_answer_attestation(
        run_id="run-exact-v086",
        input_manifest_digest="b" * 64,
        evidence_id="evidence-exact-v086",
        value_sha256=sha256(FLAG.encode("utf-8")).hexdigest(),
        artifact_sha256=SOURCE_SHA256,
        locator={"source_ref": "capture.pcap", "byte_offset": BYTE_OFFSET, "byte_length": len(FLAG)},
    )

    assert attestation is not None
    assert FLAG not in json.dumps(attestation, ensure_ascii=False)
    assert validate_exact_answer_attestation(
        attestation,
        expected_run_id="run-exact-v086",
        expected_input_manifest_digest="b" * 64,
        expected_evidence_id="evidence-exact-v086",
        expected_value_sha256=sha256(FLAG.encode("utf-8")).hexdigest(),
        expected_artifact_sha256=SOURCE_SHA256,
        expected_locator={"source_ref": "capture.pcap", "byte_offset": BYTE_OFFSET, "byte_length": len(FLAG)},
    )

    tampered = dict(attestation)
    tampered["locator"] = {"source_ref": "capture.pcap", "byte_offset": BYTE_OFFSET + 1, "byte_length": len(FLAG)}
    assert not validate_exact_answer_attestation(tampered)


def test_provider_claim_cannot_supply_exact_attestation_or_claim_projection() -> None:
    base = {
        "status": "SUCCESS",
        "answer": {},
        "findings": [],
        "evidence": [
            {
                "evidence_id": "provider-exact-v086",
                "claim_id": "model-claim",
                "claim_refs": ["model-claim"],
                "path": "capture.pcap",
                "byte_offset": BYTE_OFFSET,
                "sha256": SOURCE_SHA256,
                "source": "model-provider",
                "metadata": {
                    "assurance": "provider_claimed",
                    "claim_id": "model-claim",
                    "claim_refs": ["model-claim"],
                    "exact_answer_attestation": {"attestation_digest": "forged"},
                },
            }
        ],
    }
    report = _report(
        answer_payload={
            "answer_kind": "exact",
            "answer_type": "exact",
            "values": [FLAG],
            "items": [{"value": FLAG, "evidence_ids": ["provider-exact-v086"]}],
        }
    )

    projected = project_domain_result(base, report, task=_task())

    assert FLAG not in json.dumps(projected, ensure_ascii=False)
    assert "claim_id" not in projected["evidence"][0]
    assert "claim_refs" not in projected["evidence"][0]
    assert "exact_answer_attestation" not in json.dumps(projected["evidence"], ensure_ascii=False)


def test_artifact_gate_redacts_cross_field_secret_fragments() -> None:
    synthetic_value = "sk-abcdefghijklmnopqrstuv"
    split = {
        "parts": [synthetic_value[:5], synthetic_value[5:]],
        "nested": {"left": synthetic_value[:8], "right": synthetic_value[8:]},
    }

    public = scrub_artifact(split)

    assert synthetic_value not in json.dumps(public, ensure_ascii=False)
    assert public["parts"] == ["[REDACTED]", "[REDACTED]"]
    assert public["nested"] == {"left": "[REDACTED]", "right": "[REDACTED]"}
