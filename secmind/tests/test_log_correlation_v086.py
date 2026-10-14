from __future__ import annotations

import json
from dataclasses import asdict

from secmind.log_analysis import LogAnalysisLimits, analyze_offline_logs


def _analyze(records: object, *, limits: LogAnalysisLimits | None = None):
    content = json.dumps(records, ensure_ascii=False, indent=2).encode()
    return analyze_offline_logs(
        content,
        source_ref="events.json",
        artifact_ref="artifact-log-correlation",
        artifact_sha256="b" * 64,
        limits=limits,
    )


def _winrm_chain() -> list[dict[str, object]]:
    return [
        {
            "timestamp": "2020-05-24T01:13:47Z",
            "event_type": "windows_event:1",
            "Image": r"C:\Tools\RogueWinRM.exe",
            "CommandLine": r"RogueWinRM.exe -p C:\Windows\System32\cmd.exe",
            "ProcessGuid": "{winrm-guid}",
            "ProcessId": "3960",
            "User": r"NT AUTHORITY\LOCAL SERVICE",
        },
        {
            "timestamp": "2020-05-24T01:13:50Z",
            "event_type": "windows_event:3",
            "Image": r"C:\Tools\RogueWinRM.exe",
            "ProcessGuid": "{winrm-guid}",
            "DestinationIp": "127.0.0.1",
            "DestinationPort": "5985",
            "SourceIp": "127.0.0.1",
        },
        {
            "timestamp": "2020-05-24T01:13:51Z",
            "event_type": "windows_event:1",
            "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": r"C:\Windows\System32\cmd.exe",
            "ParentImage": r"C:\Tools\RogueWinRM.exe",
            "ParentProcessGuid": "{winrm-guid}",
            "ProcessGuid": "{cmd-guid}",
            "User": r"NT AUTHORITY\SYSTEM",
        },
        {
            "timestamp": "2020-05-24T01:13:54Z",
            "event_type": "windows_event:1",
            "Image": r"C:\Windows\System32\whoami.exe",
            "CommandLine": "whoami",
            "ParentImage": r"C:\Windows\System32\cmd.exe",
            "ParentProcessGuid": "{cmd-guid}",
            "User": r"NT AUTHORITY\SYSTEM",
        },
    ]


def test_winrm_cmd_whoami_chain_produces_bounded_evidence_bound_context() -> None:
    first = _analyze(_winrm_chain())
    second = _analyze(_winrm_chain())

    assert asdict(first) == asdict(second)
    by_technique = {item.technique_id: item for item in first.attack_mappings}
    assert set(by_technique) == {"T1021.006", "T1059.003", "T1033"}
    assert "T1068" not in by_technique
    assert all(item.event_ids for item in by_technique.values())
    assert all(item.rule_ids == ("SECMIND-CORR-WINRM-CMD-WHOAMI-001",) for item in by_technique.values())
    assert first.coverage["correlation_candidate_count"] == 3
    assert first.coverage["correlation_correlated_count"] == 3
    assert first.coverage["correlation_verified_count"] == 3
    assert first.coverage["correlation_rejected_count"] == 0

    traces = [item for item in first.evidence if item.metadata["evidence_type"] == "correlation_trace"]
    assert len(traces) == 3
    assert all(item.metadata["source_bindings"] for item in traces)
    assert all(
        binding["source_locator"]["source_ref"] == "events.json"
        for item in traces
        for binding in item.metadata["source_bindings"]
    )


def test_incomplete_winrm_activity_does_not_invent_attack_techniques() -> None:
    result = _analyze(_winrm_chain()[:3])

    assert result.attack_mappings == ()
    assert result.coverage["correlation_candidate_count"] == 3
    assert result.coverage["correlation_correlated_count"] == 0
    assert result.coverage["correlation_rejected_count"] == 3


def test_rdpcorets_104_is_low_confidence_context_not_malice_or_session_proof() -> None:
    result = _analyze(
        [
            {
                "timestamp": "2020-05-24T01:13:47Z",
                "event_type": "windows_event:104",
                "Provider": "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS",
                "Channel": "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
                "Computer": "MSEDGEWIN10",
            }
        ]
    )

    assert len(result.attack_mappings) == 1
    mapping = result.attack_mappings[0]
    assert mapping.technique_id == "T1021.001"
    assert mapping.confidence <= 0.5
    assert "not_proof_of_malicious_activity_or_successful_session" in mapping.interpretation
    trace = next(item for item in result.evidence if item.metadata["evidence_type"] == "correlation_trace")
    assert "does not prove malicious activity or a successful remote session" in trace.summary


def test_rdpcorets_mapping_requires_native_event_104_and_caps_event_references() -> None:
    wrong_id = _analyze(
        [{"event_type": "windows_event:105", "Provider": "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS"}]
    )
    assert wrong_id.attack_mappings == ()

    records = [
        {
            "timestamp": f"2020-05-24T01:{index // 60:02d}:{index % 60:02d}Z",
            "event_type": "windows_event:104",
            "Provider": "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS",
            "record": index,
        }
        for index in range(70)
    ]
    bounded = _analyze(records)
    assert len(bounded.attack_mappings[0].event_ids) == 64
    assert bounded.coverage["correlation_event_limit_reached"] is True
    assert any(item.code == "analysis.correlation_event_limit" for item in bounded.diagnostics)


def test_source_embedded_attack_annotations_survive_scrubbing_as_context() -> None:
    result = _analyze(
        [
            {
                "timestamp": "2019-05-16T14:17:15.753Z",
                "event_type": "windows_event:1",
                "RuleName": "technique_id=T1112,technique_name=Modify Registry",
                "Image": r"C:\Windows\System32\reg.exe",
            },
            {
                "timestamp": "2019-05-16T14:17:15.758Z",
                "event_type": "windows_event:12",
                "EVENT_DATA": {
                    "RuleName": "technique_id=T1088,technique_name=Bypass User Account Control",
                    "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system",
                },
            },
            {
                "timestamp": "2019-05-16T14:17:15.759Z",
                "event_type": "windows_event:13",
                "RuleName": "technique_id=not-an-id,technique_name=Ignored",
            },
        ]
    )

    mappings = {item.technique_id: item for item in result.attack_mappings}
    assert set(mappings) == {"T1088", "T1112"}
    assert all(item.confidence == 0.75 for item in mappings.values())
    assert all(
        item.interpretation == "source_embedded_attack_annotation_not_independent_fact" for item in mappings.values()
    )
    assert all(item.rule_ids == ("SECMIND-SOURCE-ATTACK-ANNOTATION-001",) for item in mappings.values())
    assert result.coverage["source_attack_annotation_count"] == 2
    assert result.events[0].attributes["secmind.attack.technique_ids"] == ["T1112"]
    traces = [item for item in result.evidence if item.metadata["evidence_type"] == "correlation_trace"]
    assert {item.metadata["technique_id"] for item in traces} == {"T1088", "T1112"}


def test_entity_aliases_are_case_insensitive_and_file_names_are_not_domains() -> None:
    result = _analyze(
        [
            {
                "timestamp": "2026-08-18T00:00:00Z",
                "EVENT_DATA": {
                    "Image": r"C:\Windows\System32\cmd.exe",
                    "User": r"NT AUTHORITY\SYSTEM",
                    "SourceIp": "192.0.2.10",
                    "DestinationIp": "198.51.100.20",
                    "Message": "RogueWinRM.exe cmd.exe helper.dll evil.example legitimate.example.com",
                },
                "message": "RogueWinRM.exe cmd.exe helper.dll evil.example legitimate.example.com",
            }
        ]
    )

    entities = {(item.kind, item.value) for item in result.events[0].entities}
    # Host-absolute paths stay scrubbed; the typed normalizer retains only a
    # validated executable basename for correlation and entity projection.
    assert ("process", "cmd.exe") in entities
    assert ("user", r"NT AUTHORITY\SYSTEM") in entities
    assert ("source_ip", "192.0.2.10") in entities
    assert ("destination_ip", "198.51.100.20") in entities
    domains = {item.normalized_value for item in result.iocs if item.ioc_type == "domain"}
    assert "evil.example" in domains
    assert "legitimate.example.com" in domains
    assert not {"roguewinrm.exe", "cmd.exe", "helper.dll"} & domains


def test_pretty_json_array_and_document_are_normalized_without_jsonl_diagnostic_fanout() -> None:
    array_result = _analyze(
        [
            {"timestamp": "2026-08-18T00:00:00Z", "message": "first"},
            {"timestamp": "2026-08-18T00:00:01Z", "message": "second"},
        ]
    )
    document_result = _analyze({"timestamp": "2026-08-18T00:00:00Z", "message": "single"})

    assert len(array_result.events) == 2
    assert array_result.diagnostics == ()
    assert array_result.coverage["records_seen"] == 2
    assert len(document_result.events) == 1
    assert document_result.diagnostics == ()

    jsonl = analyze_offline_logs(
        b'{"timestamp":"2026-08-18T00:00:00Z","message":"line"}',
        source_ref="events.jsonl",
        artifact_ref="artifact-log-correlation",
        artifact_sha256="b" * 64,
    )
    assert jsonl.events[0].locator.line_number == 1
    assert jsonl.events[0].locator.segment_id == "line-1"


def test_json_array_elements_are_individually_bounded_and_isolated() -> None:
    result = _analyze(
        [
            {"message": "valid"},
            {"a": {"b": {"c": "too deep"}}},
            "not an object",
            {"message": "not reached"},
        ],
        limits=LogAnalysisLimits(max_json_depth=3, max_records=3),
    )

    assert [item.message for item in result.events] == ["valid"]
    assert [item.code for item in result.diagnostics].count("record.invalid_json") == 2
    assert any(item.code == "record.limit" for item in result.diagnostics)
    assert result.coverage["records_seen"] == 4

    deeply_nested = (b"[" * 1_100) + b"{}" + (b"]" * 1_100)
    recursion_safe = analyze_offline_logs(
        deeply_nested,
        source_ref="deep.json",
        artifact_ref="artifact-log-correlation",
        artifact_sha256="b" * 64,
    )
    assert recursion_safe.status == "failed"
    assert any(item.code == "record.invalid_json" for item in recursion_safe.diagnostics)
