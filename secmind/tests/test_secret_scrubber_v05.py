from __future__ import annotations

import pytest

from secmind.secret_scrubber import (
    REDACTED,
    TRUNCATED,
    is_sensitive_key,
    redact,
    scrub_artifact,
    scrub_metadata,
    scrub_text,
    scrub_value,
)


def test_scrubs_nested_sensitive_keys_without_mutating_source() -> None:
    source = {
        "authorization": "Bearer short-token",
        "nested": {
            "client-secret": "tiny",
            "safe": ["visible", {"x_api_key": "also-tiny"}],
        },
        "secretary": "not a sensitive key",
    }

    result = scrub_metadata(source)

    assert result == {
        "authorization": REDACTED,
        "nested": {
            "client-secret": REDACTED,
            "safe": ["visible", {"x_api_key": REDACTED}],
        },
        "secretary": "not a sensitive key",
    }
    assert source["nested"]["client-secret"] == "tiny"


def test_exact_release_is_limited_to_the_top_level_typed_answer_path() -> None:
    flag = "flag{X9aQ7mP2vN8rT4kL6sD3zY1wC5}"

    result = scrub_artifact(
        {
            "diagnostics": {
                "answer_kind": "exact",
                "answer_type": "exact",
                "values": [flag],
            }
        },
        trusted_exact_answers={flag},
    )

    assert result["diagnostics"]["values"] == ["flag{[REDACTED]}"]


def test_scrubs_bearer_assignments_headers_and_common_tokens() -> None:
    raw = "\n".join(
        [
            "Authorization: Bearer tiny",
            'password="1234"',
            "pwd=qwerty",
            "github=ghp_abcdefghijklmnopqrstuvwxyz123456",
            "openai=sk-abcdefghijklmnopqrstuv",
            "aws=AKIAABCDEFGHIJKLMNOP",
            "jwt=eyJabcdefghijk.eyJabcdefghijk.abcdefghijk",
        ]
    )

    scrubbed = scrub_text(raw)

    assert scrubbed.count(REDACTED) == 7
    for original in ("tiny", "1234", "qwerty", "ghp_", "sk-", "AKIA", "eyJabcdefghijk"):
        assert original not in scrubbed


def test_scrubs_bearer_value_after_assignment_without_leaving_suffix() -> None:
    secret = "super-secret-value"  # noqa: S105 - synthetic redaction fixture

    scrubbed = scrub_text(f"authorization=Bearer {secret}")

    assert secret not in scrubbed
    assert REDACTED in scrubbed


def test_redacted_assignment_with_closing_markup_passes_artifact_gate() -> None:
    description = "Source uses `api_key=[REDACTED]`), in the sample."

    assert scrub_artifact({"description": description}) == {"description": description}
    assert scrub_artifact({"description": "api_key=[REDACTED]extra"}) == {
        "description": "api_key=[REDACTED]"
    }


def test_scrubs_private_key_blocks_without_retaining_key_material() -> None:
    value = "before\n-----BEGIN PRIVATE KEY-----\nABC123\n-----END PRIVATE KEY-----\nafter"

    assert scrub_text(value) == f"before\n{REDACTED}\nafter"


def test_scrubs_unlabelled_mixed_punctuation_secret() -> None:
    secret = "p5Wv!9Jz@4Rm#8Qx$2Nk&7Ty"  # noqa: S105 - synthetic redaction fixture

    assert scrub_artifact({"opaque_value": secret}) == {"opaque_value": REDACTED}
    assert secret not in scrub_text(f'payload="{secret}"')


def test_mixed_entropy_guard_preserves_normal_urls_and_source_expressions() -> None:
    values = [
        "https://example.com/releases/v0.8.6/artifact.json",
        "repository.resolve_reference(path, digest)",
    ]

    assert [scrub_text(value) for value in values] == values


def test_binary_values_become_non_reversible_safe_metadata() -> None:
    raw = b"password=short"

    scrubbed = redact({"payload": raw, "parts": [bytearray(raw), memoryview(raw)]})

    expected = {"type": "bytes", "size_bytes": len(raw), "redacted": True}
    assert scrubbed == {"payload": expected, "parts": [expected, expected]}
    rendered = repr(scrubbed)
    assert "password" not in rendered
    assert "sha" not in rendered.lower()


def test_scrubbing_is_deterministic_and_sorts_unordered_collections() -> None:
    value = {"items": {"z", "a", "ghp_abcdefghijklmnopqrstuvwxyz123456"}}

    first = redact(value)
    second = redact(value)

    assert first == second
    assert first == {"items": [REDACTED, "a", "z"]}


def test_cycles_depth_and_unsupported_objects_never_call_user_stringification() -> None:
    class UnsafeString:
        def __str__(self) -> str:
            raise AssertionError("unsafe __str__ must not be called")

    cyclic: list[object] = []
    cyclic.append(cyclic)

    result = redact({"cycle": cyclic, "object": UnsafeString()})

    assert result["cycle"] == [TRUNCATED]
    assert result["object"] == {"type": f"{UnsafeString.__module__}.{UnsafeString.__qualname__}", "redacted": True}


def test_sensitive_key_matching_has_component_boundaries() -> None:
    assert is_sensitive_key("metadata.api-key")
    assert is_sensitive_key("proxy_authorization")
    assert is_sensitive_key("session-token")
    assert not is_sensitive_key("tokenizer")
    assert not is_sensitive_key("secretary")


def test_metadata_none_and_limits_are_safe() -> None:
    assert scrub_metadata(None) == {}
    assert redact({"password": "x"}) == {"password": REDACTED}
    assert scrub_metadata({"items": {"a", "b"}}, max_items=1) == {"items": [TRUNCATED]}


def test_input_relative_path_is_preserved_as_public_provenance() -> None:
    value = {
        "path": "fixtures/api_key_handling.py",
        "source_path": "550e8400-e29b-41d4-a716-446655440000/events.json",
        "file_sha256": "a" * 64,
    }

    assert scrub_artifact(value) == value


def test_uuid_prefixed_upload_path_is_preserved_without_weakening_secret_detection() -> None:
    upload_id = "7ec65389-e32b-413e-a0e5-44a574c9dd84"
    safe_path = f"{upload_id}-vulnerable_app.py"
    secret_path = f"{upload_id}-sk-abcdefghijklmnopqrstuvwxyz123456.py"

    assert scrub_artifact({"path": safe_path}) == {"path": safe_path}
    assert scrub_artifact({"path": secret_path}) == {"path": REDACTED}


def test_server_owned_evidence_namespaces_remain_distinct_in_public_projections() -> None:
    value = {
        "evidence_ids": [
            "coverage-65e6dd7152f2a67fff590b66",
            "audit-717f388b5a65e9fbf17d0169",
            "primary-evidence-730e9ffacf9d30b2b445e88c",
            "critic-evidence-35b1892133bd84e1af4268c3",
        ]
    }

    assert scrub_artifact(value) == value


def test_nested_upload_paths_survive_tool_and_report_scrubbing() -> None:
    path = (
        "aa676984-300e-41b2-b1bd-58602fd5294a-workspace/"
        "1de3c834-77dc-453b-b458-036e9f0058b6-release-synthetic-20261012/synthetic_audit.py"
    )
    value = {
        "findings": [{"path": path, "raw": {"file_sha256": "a" * 64}}],
        "evidence": [{"metadata": {"path": path, "file_sha256": "a" * 64}}],
    }
    assert scrub_artifact(scrub_value(value)) == value


@pytest.mark.parametrize("basename", [
    "sk-abcdefghijklmnopqrstuvwxyz123456.py",
    "AbC123xYz987__-qwertyuiop.py",
    "eyJabcdefghijk.abcdefghijk.abcdefghijk.py",
])
def test_nested_upload_paths_still_redact_credential_filenames(basename: str) -> None:
    path = f"aa676984-300e-41b2-b1bd-58602fd5294a-workspace/src/{basename}"
    assert scrub_artifact({"path": path}) == {"path": REDACTED}


@pytest.mark.parametrize("path", [
    "AbC123xYz987/qWr456tUi890/sample.py",
    "aa676984-300e-41b2-b1bd-58602fd5294a-workspace/AbC123xYz987/qWr456tUi890/sample.py",
    "src/aB3!cD4@eF5#gH6$iJ7%kL8.py",
])
def test_path_separators_do_not_hide_fragmented_credentials(path: str) -> None:
    assert scrub_artifact(scrub_value({"path": path})) == {"path": REDACTED}


@pytest.mark.parametrize("path", ["C:/private/subject.py", "../subject.py", "/etc/passwd"])
def test_unsafe_paths_fail_closed_instead_of_becoming_plausible_scrubbed_paths(path: str) -> None:
    assert scrub_artifact({"path": path}) == {"path": REDACTED}
