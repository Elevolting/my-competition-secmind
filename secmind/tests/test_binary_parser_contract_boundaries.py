from __future__ import annotations

import builtins
import io
import socket
import sys
from types import ModuleType

import pytest

from secmind.log_parsers.binary import (
    EVTX_MAGIC,
    _bounded,
    _evtx_event,
    _iso_timestamp,
    _packet_event,
    parse_binary_log,
)
from secmind.log_parsers.contracts import BinaryParseLimits


def test_binary_parser_rejects_unknown_zip_and_oversized_input_with_typed_diagnostics() -> None:
    unknown = parse_binary_log(b"plain text", source_ref="input.bin")
    assert unknown.format_detected == "unknown"
    assert unknown.diagnostics[0].code == "binary.signature"

    archive = parse_binary_log(b"PK\x03\x04payload", source_ref="archive.zip")
    assert archive.format_detected == "zip"
    assert archive.diagnostics[0].code == "binary.signature"

    oversized = parse_binary_log(
        b"\xd4\xc3\xb2\xa1" + b"x" * 64,
        source_ref="capture.pcap",
        limits=BinaryParseLimits(max_input_bytes=32),
    )
    assert oversized.diagnostics[0].code == "binary.input_limit"


def test_evtx_parser_reports_missing_optional_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    original_import = builtins.__import__

    def guarded_import(name: str, *args, **kwargs):  # type: ignore[no-untyped-def]
        if name.startswith("Evtx"):
            raise ImportError("optional dependency absent")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    result = parse_binary_log(EVTX_MAGIC + b"fixture", source_ref="events.evtx")
    assert result.records_seen == 0
    assert result.diagnostics[0].code == "evtx.dependency_unavailable"


def test_evtx_event_normalization_is_bounded_namespace_safe_and_utc_normalized() -> None:
    from defusedxml import ElementTree as safe_etree

    xml = """
    <Event xmlns="urn:test"><System><Provider Name="Security"/><EventID>4625</EventID>
    <TimeCreated SystemTime="2026-08-17T10:00:00Z"/></System><EventData>
    <Data Name="Account">alice</Data><Data>fallback</Data></EventData></Event>
    """
    event = _evtx_event(xml, 7, safe_etree, BinaryParseLimits(max_string_chars=32, max_event_fields=16))
    assert event.event_id == "evtx-4625-7"
    assert event.timestamp_utc == "2026-08-17T10:00:00+00:00"
    assert event.event_type == "windows_event:4625"
    assert event.attributes == {"Account": "alice", "data_1": "fallback", "provider": "Security"}
    assert event.record_number == 7

    with pytest.raises(ValueError, match="bounded representation"):
        _evtx_event(
            "<Event>" + "x" * 500 + "</Event>", 1, safe_etree, BinaryParseLimits(max_string_chars=8, max_event_fields=2)
        )


def test_evtx_parser_salvages_valid_records_reports_invalid_and_record_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid_xml = '<Event><EventID>1</EventID><Provider Name="Fixture"/></Event>'

    class Record:
        def __init__(self, value: str) -> None:
            self.value = value

        def xml(self) -> str:
            return self.value

    class FakeEvtx:
        def __init__(self, _path: str) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def records(self):
            return iter((Record(valid_xml), Record("<broken"), Record(valid_xml)))

    package = ModuleType("Evtx")
    implementation = ModuleType("Evtx.Evtx")
    implementation.Evtx = FakeEvtx  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "Evtx", package)
    monkeypatch.setitem(sys.modules, "Evtx.Evtx", implementation)

    result = parse_binary_log(
        EVTX_MAGIC + b"fixture",
        source_ref="events.evtx",
        limits=BinaryParseLimits(max_records=2),
    )
    assert result.records_seen == 2
    assert result.records_emitted == 1
    assert result.truncated
    assert {item.code for item in result.diagnostics} == {"evtx.record_invalid", "evtx.record_limit"}


def test_corrupt_pcap_is_a_typed_partial_result_not_an_exception() -> None:
    result = parse_binary_log(b"\xd4\xc3\xb2\xa1" + b"\x00" * 8, source_ref="corrupt.pcap")
    assert result.records_emitted == 0
    assert result.diagnostics[0].code == "pcap.parse_error"


def test_pcap_invalid_frame_is_contained_as_a_capture_error() -> None:
    dpkt = pytest.importorskip("dpkt")
    output = io.BytesIO()
    writer = dpkt.pcap.Writer(output)
    writer.writepkt(b"bad")
    packet = dpkt.ip.IP(
        src=socket.inet_pton(socket.AF_INET, "192.0.2.1"),
        dst=socket.inet_pton(socket.AF_INET, "198.51.100.1"),
        p=dpkt.ip.IP_PROTO_TCP,
        data=dpkt.tcp.TCP(sport=123, dport=443),
    )
    packet.len = len(packet)
    writer.writepkt(
        dpkt.ethernet.Ethernet(
            src=b"\x00" * 6,
            dst=b"\x01" * 6,
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=packet,
        )
    )
    payload = output.getvalue()
    writer.close()

    result = parse_binary_log(payload, source_ref="mixed.pcap", limits=BinaryParseLimits(max_records=2))
    assert result.records_seen == 1
    assert result.records_emitted == 0
    assert not result.truncated
    assert result.diagnostics[0].code == "pcap.parse_error"


def test_pcap_record_limit_stops_before_normalizing_an_extra_frame() -> None:
    dpkt = pytest.importorskip("dpkt")
    output = io.BytesIO()
    writer = dpkt.pcap.Writer(output)
    packet = dpkt.ip.IP(
        src=socket.inet_pton(socket.AF_INET, "192.0.2.1"),
        dst=socket.inet_pton(socket.AF_INET, "198.51.100.1"),
        p=dpkt.ip.IP_PROTO_TCP,
        data=dpkt.tcp.TCP(sport=123, dport=443),
    )
    packet.len = len(packet)
    frame = bytes(
        dpkt.ethernet.Ethernet(
            src=b"\x00" * 6,
            dst=b"\x01" * 6,
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=packet,
        )
    )
    for _ in range(3):
        writer.writepkt(frame)
    payload = output.getvalue()
    writer.close()

    result = parse_binary_log(payload, source_ref="bounded.pcap", limits=BinaryParseLimits(max_records=2))
    assert result.records_seen == 2
    assert result.records_emitted == 2
    assert result.truncated
    assert [item.code for item in result.diagnostics] == ["pcap.record_limit"]


def test_packet_event_extracts_dns_and_tolerates_malformed_dns_payload() -> None:
    dpkt = pytest.importorskip("dpkt")

    def frame(payload: bytes) -> bytes:
        udp = dpkt.udp.UDP(sport=12345, dport=53, data=payload)
        udp.ulen = len(udp)
        ip = dpkt.ip.IP(
            src=socket.inet_pton(socket.AF_INET, "203.0.113.1"),
            dst=socket.inet_pton(socket.AF_INET, "203.0.113.53"),
            p=dpkt.ip.IP_PROTO_UDP,
            data=udp,
        )
        ip.len = len(ip)
        return bytes(
            dpkt.ethernet.Ethernet(
                src=b"\x00" * 6,
                dst=b"\x01" * 6,
                type=dpkt.ethernet.ETH_TYPE_IP,
                data=ip,
            )
        )

    query = bytes(dpkt.dns.DNS(id=1, qd=[dpkt.dns.DNS.Q(name="example.test")]))
    event = _packet_event(dpkt, frame(query), 1.0, 1, BinaryParseLimits())
    assert event is not None
    assert event.attributes["dns_qname"] == "example.test"
    assert event.event_type == "network:udp"

    malformed = _packet_event(dpkt, frame(b"\x00"), 2.0, 2, BinaryParseLimits())
    assert malformed is not None
    assert "dns_qname" not in malformed.attributes


def test_timestamp_and_string_helpers_fail_closed_and_remove_nul() -> None:
    assert _iso_timestamp(None) is None
    assert _iso_timestamp("not-a-time") is None
    assert _bounded(None, 4) == ""
    assert _bounded("a\x00bcdef", 4) == "abcd"
