from __future__ import annotations

import json

import pytest

from scripts.secmind_test3_v083_bridge import (
    _canonical_digest,
    _verify_bridge_pin,
    build_bridge_manifest,
)
from secmind.integrations.test3 import (
    MAX_PUBLIC_EVIDENCE,
    ProjectionCursorError,
    project_domain_result,
    read_projection_page,
)
from secmind.secret_scrubber import REDACTED, scrub_artifact, scrub_text, scrub_text_chunks


def _release_manifest(bridge) -> dict[str, object]:
    manifest = build_bridge_manifest(bridge)
    manifest["agent_git_sha"] = "a" * 40
    manifest["agent_snapshot_digest"] = "b" * 64
    manifest.pop("manifest_digest", None)
    manifest["manifest_digest"] = _canonical_digest(manifest)
    return manifest


@pytest.mark.parametrize(
    "field",
    ["signingSecret", "encryptionKey", "webhookUrl", "smtpPassword", "awsSecretAccessKey", "dbPassword"],
)
def test_secret_family_and_high_entropy_layers_are_fail_closed(field: str) -> None:
    assert scrub_text(f"{field}=s3cr3t-random-value-123456") == f"{field}={REDACTED}"
    assert scrub_text("opaque=AbC123xYz987__-qwertyuiop") == f"opaque={REDACTED}"


def test_artifact_gate_and_chunk_overlap_do_not_retain_credentials() -> None:
    safe = scrub_artifact({"api_key": "sk-abcdefghijklmnopqrstuv", "nested": {"password": "tiny"}})
    assert safe["api_key"] == REDACTED
    chunks = scrub_text_chunks(["authoriz", "ation=Bearer sk-abcdefghijklmnopqrstuv"])
    assert "sk-abcdefghijklmnopqrstuv" not in "".join(chunks)


def test_bridge_pin_default_requires_manifest_or_environment_pin(tmp_path) -> None:
    bridge = tmp_path / "bridge.py"
    bridge.write_text("BRIDGE_VERSION = 'test'\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="pin is required"):
        _verify_bridge_pin(bridge)

    source = """BRIDGE_VERSION = 'test'
MAX_RESPONSE_BYTES = 1024
def build_task_payload(*args, **kwargs): return {}
def convert_result(*args, **kwargs): return {}
class SecMindClient: pass
def main(args): return 0
"""
    bridge.write_text(source, encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(_release_manifest(bridge)), encoding="utf-8")
    result = _verify_bridge_pin(bridge, manifest, require_manifest=True, check_golden=True)
    assert result["bridge_pin_status"] == "VERIFIED"
    assert result["golden_preflight"]["schema_version"]


def test_bridge_golden_preflight_accepts_only_bounded_static_integer_arithmetic(tmp_path) -> None:
    source = """BRIDGE_VERSION = 'test'
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
def build_task_payload(*args, **kwargs): return {}
def convert_result(*args, **kwargs): return {}
class SecMindClient: pass
def main(args): return 0
"""
    bridge = tmp_path / "bridge.py"
    bridge.write_text(source, encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(_release_manifest(bridge)), encoding="utf-8")
    result = _verify_bridge_pin(bridge, manifest, require_manifest=True, check_golden=True)
    assert result["golden_preflight"]["max_response_bytes"] == 8 * 1024 * 1024

    bridge.write_text(source.replace("8 * 1024 * 1024", "dangerous()"), encoding="utf-8")
    with pytest.raises(RuntimeError, match="positive MAX_RESPONSE_BYTES"):
        build_bridge_manifest(bridge)


def test_projection_cursor_is_integrity_bound_and_reports_all_dropped_ids() -> None:
    source = [{"evidence_id": f"ev-{index}"} for index in range(MAX_PUBLIC_EVIDENCE + 2)]
    first = read_projection_page(source, collection="evidence", page_size=32)
    assert first["truncated_count"] == len(source) - 32
    assert len(first["dropped_ids"]) == first["truncated_count"]
    with pytest.raises(ProjectionCursorError):
        read_projection_page(
            source + [{"evidence_id": "mutated"}],
            collection="evidence",
            cursor=first["next_cursor"],
            page_size=32,
        )


def test_projection_metadata_keeps_authenticated_continuation_cursor() -> None:
    result = project_domain_result(
        {"status": "PARTIAL", "answer": {}, "evidence": [{"evidence_id": f"ev-{index}"} for index in range(300)]},
        {"answer_payload": {}},
    )
    cursor = result["run_proof"]["projection"]["collections"]["evidence"]["next_cursor"]
    assert isinstance(cursor, str) and cursor not in {"", REDACTED}


def test_required_reference_overflow_is_explicit_and_closes_fail_closed() -> None:
    evidence = [{"evidence_id": f"ev-{index:03d}"} for index in range(MAX_PUBLIC_EVIDENCE + 5)]
    required = [item["evidence_id"] for item in evidence]
    result = project_domain_result(
        {"status": "PARTIAL", "answer": {}, "findings": [], "evidence": evidence},
        {"answer_payload": {}},
        task={"required_output": {"required_evidence_ids": required}},
    )
    projection = result["run_proof"]["projection"]
    assert projection["collections"]["evidence"]["truncated_count"] == 5
    assert projection["reference_closure"]["closed"] is False
    assert projection["reference_closure"]["required_overflow_ids"]
