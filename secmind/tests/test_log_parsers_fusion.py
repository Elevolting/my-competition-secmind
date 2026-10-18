from __future__ import annotations

import hashlib
import io
import socket
import zipfile

import pytest

from secmind.log_analysis import LogAnalysisLimits, LogFormatError, analyze_offline_logs
from secmind.log_parsers import ArchiveSafetyError, BinaryParseLimits, detect_binary_format, extract_safe_zip
from secmind.runtime import build_runtime


def _zip(entries: list[tuple[str, bytes]], *, compression: int = zipfile.ZIP_STORED) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return output.getvalue()


def test_binary_format_detection_is_magic_first() -> None:
    assert detect_binary_format(b"ElfFile\x00" + b"\x00" * 32) == "evtx"
    assert detect_binary_format(b"\x0a\x0d\x0d\x0a" + b"\x00" * 32) == "pcapng"
    assert detect_binary_format(b"\xd4\xc3\xb2\xa1" + b"\x00" * 32) == "pcap"
    assert detect_binary_format(_zip([("events.jsonl", b"{}\n")])) == "zip"


def test_enabling_binary_parsers_requires_every_optional_dependency(monkeypatch, settings) -> None:
    settings.binary_log_parsers_enabled = True
    monkeypatch.setattr(
        "secmind.runtime.binary_parser_dependency_status",
        lambda: {"defusedxml": True, "dpkt": False, "python_evtx": True},
    )

    with pytest.raises(RuntimeError, match="dpkt"):
        build_runtime(settings)


@pytest.mark.parametrize("name", ["../escape.log", "/absolute.log", "safe/../escape.log", "C:/absolute.log"])
def test_safe_zip_rejects_path_escape(name: str) -> None:
    with pytest.raises(ArchiveSafetyError):
        extract_safe_zip(_zip([(name, b"event")]), limits=BinaryParseLimits())


def test_safe_zip_rejects_casefold_duplicate_and_nested_archive() -> None:
    with pytest.raises(ArchiveSafetyError, match="duplicate"):
        extract_safe_zip(
            _zip([("Logs/A.log", b"one"), ("logs/a.log", b"two")]),
            limits=BinaryParseLimits(),
        )
    with pytest.raises(ArchiveSafetyError, match="nested"):
        extract_safe_zip(_zip([("nested.zip", b"PK\x03\x04")]), limits=BinaryParseLimits())
    with pytest.raises(ArchiveSafetyError, match="nested"):
        extract_safe_zip(_zip([("disguised.log", b"PK\x03\x04not-a-log")]), limits=BinaryParseLimits())


def test_safe_zip_enforces_cumulative_and_ratio_limits() -> None:
    payload = _zip([("events.log", b"A" * 20_000)], compression=zipfile.ZIP_DEFLATED)
    with pytest.raises(ArchiveSafetyError, match="compression-ratio"):
        extract_safe_zip(payload, limits=BinaryParseLimits(max_archive_ratio=2))
    with pytest.raises(ArchiveSafetyError, match="cumulative"):
        extract_safe_zip(
            _zip([("one.log", b"1" * 10), ("two.log", b"2" * 10)]),
            limits=BinaryParseLimits(max_archive_total_bytes=15),
        )


def test_zip_log_analysis_is_feature_gated_and_preserves_member_path() -> None:
    member_content = b'{"timestamp":"2026-08-07T10:00:00Z","message":"login failed","src_ip":"192.0.2.3"}\n'
    payload = _zip(
        [
            (
                "logs/events.jsonl",
                member_content,
            )
        ]
    )
    digest = __import__("hashlib").sha256(payload).hexdigest()
    with pytest.raises(LogFormatError, match="disabled"):
        analyze_offline_logs(payload, source_ref="bundle.zip", artifact_ref=digest)
    result = analyze_offline_logs(
        payload,
        source_ref="bundle.zip",
        artifact_ref=digest,
        artifact_sha256=digest,
        allow_binary=True,
    )
    assert result.source_format == "zip"
    assert len(result.events) == 1
    assert result.events[0].locator.source_ref == "bundle.zip!logs/events.jsonl"
    member_digest = hashlib.sha256(member_content).hexdigest()
    member_evidence = next(
        item
        for item in result.evidence
        if item.metadata.get("source_locator", {}).get("source_ref") == "bundle.zip!logs/events.jsonl"
    )
    assert member_evidence.artifact_ref == member_digest
    assert member_evidence.sha256 == member_digest


def test_zip_record_limit_is_global_across_members() -> None:
    payload = _zip(
        [
            ("one.jsonl", b'{"message":"first"}\n'),
            ("two.jsonl", b'{"message":"second"}\n'),
        ]
    )
    digest = __import__("hashlib").sha256(payload).hexdigest()

    result = analyze_offline_logs(
        payload,
        source_ref="bundle.zip",
        artifact_ref=digest,
        artifact_sha256=digest,
        limits=LogAnalysisLimits(max_records=1),
        allow_binary=True,
    )

    assert len(result.events) == 1
    assert result.coverage["records_seen"] == 1
    assert any(item.code == "archive.record_limit" for item in result.diagnostics)


def test_zip_reports_unsupported_members_instead_of_claiming_complete_coverage() -> None:
    payload = _zip(
        [
            ("events.jsonl", b'{"message":"event"}\n'),
            ("notes.bin", b"not a supported log"),
        ]
    )
    digest = __import__("hashlib").sha256(payload).hexdigest()

    result = analyze_offline_logs(
        payload,
        source_ref="mixed.zip",
        artifact_ref=digest,
        artifact_sha256=digest,
        allow_binary=True,
    )

    assert result.status == "partial"
    assert any(item.code == "archive.members_skipped" for item in result.diagnostics)


def test_pcap_parser_normalizes_ipv4_and_ipv6_when_optional_dependency_is_present() -> None:
    dpkt = pytest.importorskip("dpkt")
    output = io.BytesIO()
    writer = dpkt.pcap.Writer(output)
    ipv4 = dpkt.ip.IP(
        src=socket.inet_pton(socket.AF_INET, "192.0.2.1"),
        dst=socket.inet_pton(socket.AF_INET, "198.51.100.2"),
        p=dpkt.ip.IP_PROTO_UDP,
        data=dpkt.udp.UDP(sport=1234, dport=53, data=b""),
    )
    ipv4.len = len(ipv4)
    writer.writepkt(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x01" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ipv4))
    ipv6 = dpkt.ip6.IP6(
        src=socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
        dst=socket.inet_pton(socket.AF_INET6, "2001:db8::2"),
        nxt=dpkt.ip.IP_PROTO_TCP,
        data=dpkt.tcp.TCP(sport=443, dport=4444),
    )
    writer.writepkt(
        dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\x03" * 6, type=dpkt.ethernet.ETH_TYPE_IP6, data=ipv6)
    )
    payload = output.getvalue()
    writer.close()
    digest = __import__("hashlib").sha256(payload).hexdigest()
    result = analyze_offline_logs(
        payload,
        source_ref="capture.pcap",
        artifact_ref=digest,
        artifact_sha256=digest,
        limits=LogAnalysisLimits(max_records=10),
        allow_binary=True,
    )
    assert result.coverage["records_seen"] == 2
    assert {event.attributes["src"] for event in result.events} == {"192.0.2.1", "2001:db8::1"}
    assert all(event.locator.segment_id == "pcap:whole-file" for event in result.events)
    assert all(event.locator.byte_offset == 0 for event in result.events)
    assert all(event.locator.byte_length == len(payload) for event in result.events)


def test_pcapng_parser_uses_magic_and_preserves_packet_identity() -> None:
    dpkt = pytest.importorskip("dpkt")
    output = io.BytesIO()
    writer = dpkt.pcapng.Writer(output)
    packet = dpkt.ip.IP(
        src=socket.inet_pton(socket.AF_INET, "203.0.113.1"),
        dst=socket.inet_pton(socket.AF_INET, "203.0.113.2"),
        p=dpkt.ip.IP_PROTO_UDP,
        data=dpkt.udp.UDP(sport=5353, dport=53, data=b""),
    )
    packet.len = len(packet)
    frame = dpkt.ethernet.Ethernet(
        src=b"\x04" * 6,
        dst=b"\x05" * 6,
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=packet,
    )
    writer.writepkt(bytes(frame))
    payload = output.getvalue()
    writer.close()
    digest = __import__("hashlib").sha256(payload).hexdigest()

    result = analyze_offline_logs(
        payload,
        source_ref="capture.bin",
        artifact_ref=digest,
        artifact_sha256=digest,
        allow_binary=True,
    )

    assert result.source_format == "pcapng"
    assert len(result.events) == 1
    assert result.events[0].attributes["dst"] == "203.0.113.2"


def test_pcap_unsupported_frames_are_reported_as_partial_coverage() -> None:
    dpkt = pytest.importorskip("dpkt")
    output = io.BytesIO()
    writer = dpkt.pcap.Writer(output)
    writer.writepkt(b"\x00" * 12 + b"\x08\x06" + b"\x00" * 28)
    payload = output.getvalue()
    writer.close()
    digest = __import__("hashlib").sha256(payload).hexdigest()

    result = analyze_offline_logs(
        payload,
        source_ref="arp.pcap",
        artifact_ref=digest,
        artifact_sha256=digest,
        allow_binary=True,
    )

    assert result.coverage["records_seen"] == 1
    assert result.coverage["records_emitted"] == 0
    assert any(item.code == "pcap.unsupported_frames" for item in result.diagnostics)
