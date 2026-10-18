from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts.evaluate_tool_calibration import _fixture_path
from secmind_dev.tool_calibration import (
    CalibrationAssuranceLineage,
    CalibrationManifest,
    CalibrationObservations,
    ToolCalibrationError,
    ToolCalibrationPolicy,
    evaluate_tool_calibration,
    validate_calibration_report,
)


def _documents(*, false_positive: bool = False) -> tuple[CalibrationManifest, CalibrationObservations]:
    manifest_cases: list[dict[str, object]] = []
    observation_cases: list[dict[str, object]] = []
    for tool_name in ("semgrep_sast", "gitleaks_secret_scan"):
        for index in range(10):
            positive = index < 5
            expected = ("RULE-1",) if positive else ()
            found = expected
            if false_positive and tool_name == "semgrep_sast" and index >= 5:
                found = ("RULE-NOISE",)
            digest = f"{index + (0 if tool_name == 'semgrep_sast' else 20):064x}"
            case_id = f"{tool_name}-{index}"
            manifest_cases.append(
                {
                    "case_id": case_id,
                    "tool_name": tool_name,
                    "input_sha256": digest,
                    "expected_rule_ids": expected,
                }
            )
            observation_cases.append(
                {
                    "case_id": case_id,
                    "tool_name": tool_name,
                    "tool_version": "1.0.0",
                    "input_sha256": digest,
                    "found_rule_ids": found,
                    "parse_complete": True,
                    "evidence_complete": True,
                }
            )
    manifest = CalibrationManifest.model_validate(
        {
            "schema_version": "tool-calibration-manifest-1.0",
            "dataset_id": "heldout-tools-v1",
            "split": "heldout",
            "cases": manifest_cases,
        }
    )
    observations = CalibrationObservations.model_validate(
        {
            "schema_version": "tool-calibration-observations-1.0",
            "dataset_id": "heldout-tools-v1",
            "cases": observation_cases,
        }
    )
    return manifest, observations


def _policy() -> ToolCalibrationPolicy:
    return ToolCalibrationPolicy(
        required_tools=("semgrep_sast", "gitleaks_secret_scan"),
        minimum_cases_per_tool=10,
        minimum_positive_cases_per_tool=3,
        minimum_negative_cases_per_tool=3,
    )


def test_complete_heldout_calibration_is_digest_bound_and_release_eligible() -> None:
    manifest, observations = _documents()

    report = evaluate_tool_calibration(manifest, observations, _policy())

    assert report["release_eligible"] is True
    assert report["blockers"] == []
    assert report["tools"]["semgrep_sast"]["precision"] == 1.0
    assert report["tools"]["gitleaks_secret_scan"]["recall"] == 1.0
    validate_calibration_report(report)


def test_qualification_split_cannot_pass_untouched_release_gate() -> None:
    manifest, observations = _documents()
    qualification_manifest = manifest.model_copy(update={"qualification_only": True})
    policy = _policy().model_copy(update={"require_untouched_holdout": True})

    report = evaluate_tool_calibration(qualification_manifest, observations, policy)

    assert report["release_eligible"] is False
    assert "qualification_only_manifest" in report["blockers"]


def test_calibration_rejects_missing_or_wrong_input_observations() -> None:
    manifest, observations = _documents()
    missing = observations.model_copy(update={"cases": observations.cases[:-1]})
    with pytest.raises(ToolCalibrationError, match="coverage mismatch"):
        evaluate_tool_calibration(manifest, missing, _policy())

    rows = list(observations.cases)
    rows[0] = rows[0].model_copy(update={"input_sha256": "f" * 64})
    mismatched = observations.model_copy(update={"cases": tuple(rows)})
    with pytest.raises(ToolCalibrationError, match="input digest mismatch"):
        evaluate_tool_calibration(manifest, mismatched, _policy())


def test_false_positive_rate_blocks_calibrated_claim_and_report_tampering() -> None:
    manifest, observations = _documents(false_positive=True)

    report = evaluate_tool_calibration(manifest, observations, _policy())

    assert report["release_eligible"] is False
    assert "semgrep_sast:precision_below_threshold" in report["blockers"]
    with pytest.raises(ToolCalibrationError, match="not release eligible"):
        validate_calibration_report(report)

    valid = evaluate_tool_calibration(*_documents(), _policy())
    tampered = deepcopy(valid)
    tampered["tools"]["semgrep_sast"]["precision"] = 0.5
    with pytest.raises(ToolCalibrationError, match="digest mismatch"):
        validate_calibration_report(tampered)


def _strict_lineage(*, source_id: str = "scanner", report_id: str = "report-1") -> CalibrationAssuranceLineage:
    return CalibrationAssuranceLineage(
        source_id=source_id,
        report_id=report_id,
        assurance_level="calibrated_security_claim",
        signer_id="ed25519-test-signer",
        signature_algorithm="Ed25519",
        signature_valid=True,
        trusted_signer=True,
        calibration_version="heldout-test-v1",
        calibration_manifest_digest="a" * 64,
        calibration_report_digest="b" * 64,
        contract_digest="c" * 64,
    )


def test_frozen_fixture_manifest_is_license_and_digest_bound() -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "evaluation" / "tool-calibration" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["split"] == "heldout"
    assert manifest["frozen"] is True
    assert manifest["dataset_license"] == "CC0-1.0"
    assert manifest["non_leakage_attestation"]
    assert len(manifest["cases"]) == 80
    assert all(case["source_kind"] == "original_authored" for case in manifest["cases"])
    assert all(case["license_id"] == "CC0-1.0" for case in manifest["cases"])
    # SBOM rows are component-set cases and intentionally omit rule IDs.
    assert sum(bool(case.get("expected_rule_ids")) for case in manifest["cases"]) == 35
    assert sum(bool(case.get("expected_component_ids")) for case in manifest["cases"]) == 5
    assert (
        sum(not case.get("expected_rule_ids") and not case.get("expected_component_ids") for case in manifest["cases"])
        == 40
    )
    assert sum(case.get("evaluation_kind") == "sbom" for case in manifest["cases"]) == 10


def test_v3_release_manifest_is_frozen_before_execution_and_disjoint_from_v2() -> None:
    root = Path(__file__).resolve().parents[1]
    manifest_path = root / "evaluation" / "tool-calibration" / "manifest-v3.json"
    receipt_path = root / "evaluation" / "tool-calibration" / "v3-freeze-receipt.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

    assert manifest["dataset_id"] == "secmind-heldout-tools-2026-08-v3"
    assert manifest["split"] == "heldout"
    assert manifest["frozen"] is True
    assert manifest["qualification_only"] is False
    assert len(manifest["cases"]) == 80
    assert all(case["source_kind"] == "original_authored" for case in manifest["cases"])
    assert all(case["license_id"] == "CC0-1.0" for case in manifest["cases"])
    assert all(len(case["label_commitment"]) == 64 for case in manifest["cases"])
    assert receipt["scanner_invocations_before_freeze"] == 0
    assert receipt["fixture_hash_intersection_with_v2"] == 0
    assert receipt["signature_status"] == "sealed_before_scanner_invocation"
    trust_root = root / receipt["approved_platform_trust_root"]
    assert hashlib.sha256(trust_root.read_bytes()).hexdigest() == receipt["approved_platform_trust_root_file_sha256"]
    trusted_key = serialization.load_pem_public_key(trust_root.read_bytes())
    assert isinstance(trusted_key, Ed25519PublicKey)
    raw_key = trusted_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert f"ed25519-{hashlib.sha256(raw_key).hexdigest()[:16]}" == receipt["approved_platform_trust_root_key_id"]

    fixture_hashes = {
        hashlib.sha256((root / case["fixture_path"]).read_bytes()).hexdigest() for case in manifest["cases"]
    }
    private_key_fixture = root / "evaluation" / "tool-calibration" / "fixtures-v3" / "gitleaks-positive-private.pem"
    with pytest.raises(ValueError):
        serialization.load_pem_private_key(private_key_fixture.read_bytes(), password=None)

    old_fixture_root = root / "evaluation" / "tool-calibration" / "fixtures"
    old_hashes = {
        hashlib.sha256(path.read_bytes()).hexdigest() for path in old_fixture_root.iterdir() if path.is_file()
    }
    assert fixture_hashes.isdisjoint(old_hashes)

    tree_rows = "".join(
        f"{case['fixture_path']}\0{case['input_sha256']}\n"
        for case in sorted(manifest["cases"], key=lambda item: item["fixture_path"])
    )
    assert hashlib.sha256(tree_rows.encode("utf-8")).hexdigest() == manifest["fixture_tree_digest"]
    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == receipt["manifest_file_sha256"]
    validated_manifest = CalibrationManifest.model_validate(manifest)
    canonical_manifest = json.dumps(
        validated_manifest.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    assert hashlib.sha256(canonical_manifest.encode("utf-8")).hexdigest() == receipt["manifest_model_digest"]
    signature_payload = {
        "schema_version": "tool-calibration-manifest-signature-1.0",
        "dataset_id": manifest["dataset_id"],
        "manifest_model_digest": receipt["manifest_model_digest"],
        "manifest_file_sha256": receipt["manifest_file_sha256"],
        "fixture_tree_digest": manifest["fixture_tree_digest"],
        "case_count": len(manifest["cases"]),
        "frozen": manifest["frozen"],
    }
    assert receipt["manifest_signature_payload"] == signature_payload
    signature = receipt["manifest_signature"]
    assert isinstance(signature, str) and signature
    padded = signature + "=" * (-len(signature) % 4)
    trusted_key.verify(
        base64.urlsafe_b64decode(padded.encode("ascii")),
        json.dumps(signature_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
    )


def test_secret_scanner_positive_fixtures_materialize_without_committed_token_literals() -> None:
    root = Path(__file__).resolve().parents[1]
    manifests = (
        root / "evaluation" / "tool-calibration" / "manifest.json",
        root / "evaluation" / "tool-calibration" / "manifest-v3.json",
    )
    selected = []
    for manifest_path in manifests:
        manifest = CalibrationManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
        selected.extend(case for case in manifest.cases if case.case_id.endswith("gitleaks-positive-slack"))

    assert len(selected) == 2
    for case in selected:
        assert case.fixture_path is not None
        committed = root / case.fixture_path
        committed_bytes = committed.read_bytes()
        assert committed_bytes.startswith(b"SECMIND_SYNTHETIC_FIXTURE_XOR_V1\n")
        assert b"xoxb-" not in committed_bytes

        materialized = _fixture_path(case, root)
        assert materialized != committed
        assert hashlib.sha256(materialized.read_bytes()).hexdigest() == case.input_sha256
        assert b"xoxb-" in materialized.read_bytes()


def test_strict_release_gate_rejects_unsigned_observations() -> None:
    manifest, observations = _documents()
    policy = _policy().model_copy(
        update={
            "require_trusted_signer": True,
            "require_calibrated_security_claim": True,
        }
    )

    report = evaluate_tool_calibration(manifest, observations, policy)

    assert report["release_eligible"] is False
    assert "semgrep_sast:trusted_signer_required" in report["blockers"]
    assert "gitleaks_secret_scan:calibrated_security_claim_required" in report["blockers"]


def test_v3_attempt3_is_platform_bound_and_strictly_eligible() -> None:
    root = Path(__file__).resolve().parents[1]
    calibration_root = root / "evaluation" / "tool-calibration"
    report_path = calibration_root / "report-v3-platform-attempt3.json"
    observations_path = calibration_root / "observations-v3-platform-attempt3.json"
    receipt = json.loads((calibration_root / "v3-platform-run-receipt.json").read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    observations = json.loads(observations_path.read_text(encoding="utf-8"))
    binding = json.loads((calibration_root / "v3-report-binding.json").read_text(encoding="utf-8"))
    snapshot_path = calibration_root / "v3-tool-manifest-snapshot.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))

    assert snapshot["signature_status"] == "sealed_v3_platform_tool_result_signer"
    assert hashlib.sha256(snapshot_path.read_bytes()).hexdigest() == binding["tool_manifest_snapshot_sha256"]
    unsigned_binding = {key: value for key, value in binding.items() if key != "binding_digest"}
    assert (
        hashlib.sha256(
            json.dumps(unsigned_binding, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        == binding["binding_digest"]
    )
    assert report["release_eligible"] is True
    assert report["blockers"] == []
    assert report["manifest_digest"] == receipt["manifest_model_digest"]
    assert report["observations_digest"] == receipt["observations_digest"]
    assert report["report_digest"] == receipt["report_digest"]
    assert len(observations["cases"]) == 80
    assert report["release_gate"]["same_source_double_report"]["independent_source_count"] == 1
    assert report["release_gate"]["same_source_double_report"]["same_source_double_report"] is True
    assert report["release_gate"]["high_assurance_single_source"]["admitted"] is True
    for metric in report["tools"].values():
        assert metric["eligible"] is True
        assert metric["assurance_lineage"]["all_trusted_signer"] is True
        assert len(metric["assurance_lineage"]["source_ids"]) == 1
        for record in metric["assurance_lineage"]["records"]:
            contract = record["assurance_contract"]
            assert record["source_id"] == "heldout-rootless-signed-runner"
            assert record["signer_id"] == "ed25519-3bb6ac5c8bb43e3d"
            assert record["signature_valid"] is True
            assert contract["signature_algorithm"] == "Ed25519"
            assert contract["calibration_manifest_digest"] in {None, receipt["manifest_model_digest"]}
            assert contract["calibration_report_digest"] in {None, binding["binding_digest"]}


def test_same_source_double_report_counts_as_one_independent_source() -> None:
    manifest = CalibrationManifest.model_validate(
        {
            "schema_version": "tool-calibration-manifest-1.0",
            "dataset_id": "same-source-v1",
            "split": "heldout",
            "cases": [
                {
                    "case_id": "positive",
                    "tool_name": "scanner",
                    "input_sha256": "1" * 64,
                    "expected_rule_ids": ["RULE-1"],
                },
                {
                    "case_id": "negative",
                    "tool_name": "scanner",
                    "input_sha256": "2" * 64,
                    "expected_rule_ids": [],
                },
            ],
        }
    )
    observations = CalibrationObservations.model_validate(
        {
            "schema_version": "tool-calibration-observations-1.0",
            "dataset_id": "same-source-v1",
            "cases": [
                {
                    "case_id": "positive",
                    "tool_name": "scanner",
                    "tool_version": "1",
                    "input_sha256": "1" * 64,
                    "found_rule_ids": ["RULE-1"],
                    "parse_complete": True,
                    "evidence_complete": True,
                    "assurance_lineage": _strict_lineage(report_id="report-a"),
                },
                {
                    "case_id": "negative",
                    "tool_name": "scanner",
                    "tool_version": "1",
                    "input_sha256": "2" * 64,
                    "found_rule_ids": [],
                    "parse_complete": True,
                    "evidence_complete": True,
                    "assurance_lineage": _strict_lineage(report_id="report-b"),
                },
            ],
        }
    )
    policy = ToolCalibrationPolicy(
        required_tools=("scanner",),
        minimum_cases_per_tool=2,
        minimum_positive_cases_per_tool=1,
        minimum_negative_cases_per_tool=1,
        expected_independent_source_count=1,
        require_same_source_double_report=True,
        require_trusted_signer=True,
        require_calibrated_security_claim=True,
    )

    report = evaluate_tool_calibration(manifest, observations, policy)

    gate = report["release_gate"]["same_source_double_report"]
    assert gate["report_count"] == 2
    assert gate["independent_source_count"] == 1
    assert gate["same_source_double_report"] is True
    assert report["release_gate"]["high_assurance_single_source"]["admitted"] is True
    assert report["release_eligible"] is True


def test_unavailable_external_observation_is_explicit_and_blocks_required_tool() -> None:
    manifest = CalibrationManifest.model_validate(
        {
            "schema_version": "tool-calibration-manifest-1.0",
            "dataset_id": "external-unavailable-v1",
            "split": "heldout",
            "cases": [
                {
                    "case_id": "positive",
                    "tool_name": "semgrep_sast",
                    "input_sha256": "1" * 64,
                    "expected_rule_ids": ["CWE-78"],
                },
                {
                    "case_id": "negative",
                    "tool_name": "semgrep_sast",
                    "input_sha256": "2" * 64,
                    "expected_rule_ids": [],
                },
            ],
        }
    )
    observations = CalibrationObservations.model_validate(
        {
            "schema_version": "tool-calibration-observations-1.0",
            "dataset_id": "external-unavailable-v1",
            "cases": [
                {
                    "case_id": "positive",
                    "tool_name": "semgrep_sast",
                    "tool_version": "unavailable",
                    "input_sha256": "1" * 64,
                    "parse_complete": False,
                    "evidence_complete": False,
                    "status": "unavailable",
                    "execution_source": "external_image",
                },
                {
                    "case_id": "negative",
                    "tool_name": "semgrep_sast",
                    "tool_version": "unavailable",
                    "input_sha256": "2" * 64,
                    "parse_complete": False,
                    "evidence_complete": False,
                    "status": "unavailable",
                    "execution_source": "external_image",
                },
            ],
        }
    )
    policy = ToolCalibrationPolicy(
        required_tools=("semgrep_sast",),
        minimum_cases_per_tool=2,
        minimum_positive_cases_per_tool=1,
        minimum_negative_cases_per_tool=1,
    )

    report = evaluate_tool_calibration(
        manifest,
        observations,
        policy,
        unavailable_tools={"semgrep_sast": "immutable image unavailable"},
    )

    assert report["release_eligible"] is False
    assert report["unavailable_tools"]["semgrep_sast"] == "immutable image unavailable"
    assert report["toolchain_complete"] is False
    assert "semgrep_sast:unavailable_observations" in report["blockers"]

    inferred_report = evaluate_tool_calibration(manifest, observations, policy)
    assert inferred_report["toolchain_complete"] is False
    assert inferred_report["unavailable_tools"]["semgrep_sast"]

    complete_policy = policy.model_copy(update={"require_toolchain_complete": True})
    complete_report = evaluate_tool_calibration(
        manifest,
        observations,
        complete_policy,
        unavailable_tools={"semgrep_sast": "immutable image unavailable"},
    )
    assert "external_toolchain_incomplete" in complete_report["blockers"]


def test_syft_uses_component_completeness_and_accuracy_gate() -> None:
    manifest = CalibrationManifest.model_validate(
        {
            "schema_version": "tool-calibration-manifest-1.0",
            "dataset_id": "syft-component-v1",
            "split": "heldout",
            "cases": [
                {
                    "case_id": "positive",
                    "tool_name": "syft_sbom",
                    "input_sha256": "1" * 64,
                    "evaluation_kind": "sbom",
                    "expected_component_ids": ["pkg:pypi/requests@2.31.0"],
                },
                {
                    "case_id": "negative",
                    "tool_name": "syft_sbom",
                    "input_sha256": "2" * 64,
                    "evaluation_kind": "sbom",
                    "expected_component_ids": [],
                },
            ],
        }
    )
    observations = CalibrationObservations.model_validate(
        {
            "schema_version": "tool-calibration-observations-1.0",
            "dataset_id": "syft-component-v1",
            "cases": [
                {
                    "case_id": "positive",
                    "tool_name": "syft_sbom",
                    "tool_version": "1",
                    "input_sha256": "1" * 64,
                    "evaluation_kind": "sbom",
                    "observed_component_ids": ["pkg:pypi/requests@2.31.0"],
                    "parse_complete": True,
                    "evidence_complete": True,
                },
                {
                    "case_id": "negative",
                    "tool_name": "syft_sbom",
                    "tool_version": "1",
                    "input_sha256": "2" * 64,
                    "evaluation_kind": "sbom",
                    "observed_component_ids": [],
                    "parse_complete": True,
                    "evidence_complete": True,
                },
            ],
        }
    )
    policy = ToolCalibrationPolicy(
        required_tools=("syft_sbom",),
        minimum_cases_per_tool=2,
        minimum_positive_cases_per_tool=1,
        minimum_negative_cases_per_tool=1,
        minimum_component_completeness=1.0,
        minimum_component_accuracy=1.0,
    )

    report = evaluate_tool_calibration(manifest, observations, policy)

    metric = report["tools"]["syft_sbom"]
    assert metric["evaluation_kind"] == "sbom"
    assert metric["component_completeness"] == 1.0
    assert metric["component_accuracy"] == 1.0
    assert report["release_eligible"] is True
