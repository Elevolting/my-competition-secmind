"""Optional, offline EVTX and PCAP/PCAPNG parsers with strict resource caps."""

from __future__ import annotations

import hashlib
import io
import ipaddress
import os
import tempfile
from datetime import UTC, datetime
from typing import Any

from secmind.log_parsers.contracts import (
    BinaryDiagnostic,
    BinaryEvent,
    BinaryParseLimits,
    BinaryParseResult,
)

EVTX_MAGIC = b"ElfFile\x00"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
}
ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
MAX_DIAGNOSTICS = 256


def detect_binary_format(content: bytes) -> str | None:
    if content.startswith(EVTX_MAGIC):
        return "evtx"
    if content.startswith(PCAPNG_MAGIC):
        return "pcapng"
    if content[:4] in PCAP_MAGICS:
        return "pcap"
    if content.startswith(ZIP_MAGICS):
        return "zip"
    return None


def parse_binary_log(
    content: bytes,
    *,
    source_ref: str,
    limits: BinaryParseLimits | None = None,
) -> BinaryParseResult:
    active = limits or BinaryParseLimits()
    detected = detect_binary_format(content)
    if detected not in {"evtx", "pcap", "pcapng"}:
        return _failure(source_ref, detected or "unknown", "binary.signature", "unsupported binary log signature")
    if len(content) > active.max_input_bytes:
        return _failure(source_ref, detected, "binary.input_limit", "binary input exceeds the byte limit")
    if detected == "evtx":
        return _parse_evtx(content, source_ref=source_ref, limits=active)
    return _parse_capture(content, source_ref=source_ref, detected=detected, limits=active)


def _parse_evtx(content: bytes, *, source_ref: str, limits: BinaryParseLimits) -> BinaryParseResult:
    try:
        from defusedxml import ElementTree as safe_etree  # type: ignore[import-untyped]
        from Evtx.Evtx import Evtx  # type: ignore[import-not-found,import-untyped]
    except ImportError:
        return _failure(source_ref, "evtx", "evtx.dependency_unavailable", "EVTX parser dependency is unavailable")

    events: list[BinaryEvent] = []
    diagnostics: list[BinaryDiagnostic] = []
    records_seen = 0
    invalid_records = 0
    truncated = False
    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as handle:
            handle.write(content)
            tmp_path = handle.name
        with Evtx(tmp_path) as log:
            for index, record in enumerate(log.records(), 1):
                if index > limits.max_records:
                    truncated = True
                    diagnostics.append(BinaryDiagnostic("evtx.record_limit", "EVTX record limit reached", "warning"))
                    break
                records_seen += 1
                try:
                    events.append(_evtx_event(record.xml(), index, safe_etree, limits))
                except Exception as exc:
                    invalid_records += 1
                    if len(diagnostics) < MAX_DIAGNOSTICS - 1:
                        diagnostics.append(
                            BinaryDiagnostic(
                                "evtx.record_invalid",
                                f"EVTX record {index} is invalid: {type(exc).__name__}",
                                "warning",
                                index,
                            )
                        )
    except Exception as exc:
        diagnostics.append(BinaryDiagnostic("evtx.parse_error", f"EVTX parsing failed: {type(exc).__name__}", "error"))
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    if invalid_records > sum(item.code == "evtx.record_invalid" for item in diagnostics):
        diagnostics.append(
            BinaryDiagnostic(
                "evtx.diagnostic_limit",
                f"{invalid_records} invalid EVTX records were observed; diagnostics were truncated",
                "warning",
            )
        )
    if not events and not diagnostics:
        diagnostics.append(BinaryDiagnostic("evtx.empty", "EVTX contains no decodable records", "warning"))
    return BinaryParseResult(
        source_ref,
        "evtx",
        records_seen,
        len(events),
        truncated,
        tuple(events),
        tuple(diagnostics),
    )


def _evtx_event(xml_text: str, index: int, safe_etree: Any, limits: BinaryParseLimits) -> BinaryEvent:
    if len(xml_text) > limits.max_string_chars * limits.max_event_fields:
        raise ValueError("record XML exceeds the bounded representation")
    root = safe_etree.fromstring(xml_text)
    attributes: dict[str, Any] = {}
    event_id: str | None = None
    timestamp: str | None = None
    provider: str | None = None
    for element in root.iter():
        local = str(element.tag).rsplit("}", 1)[-1]
        if local == "EventID" and element.text:
            event_id = _bounded(element.text, limits.max_string_chars)
        elif local == "TimeCreated":
            timestamp = _bounded(element.attrib.get("SystemTime"), limits.max_string_chars)
        elif local == "Provider":
            provider = _bounded(element.attrib.get("Name"), limits.max_string_chars)
        elif local == "Data" and element.text is not None and len(attributes) < limits.max_event_fields:
            key = _bounded(element.attrib.get("Name"), 128) or f"data_{len(attributes)}"
            attributes[key] = _bounded(element.text, limits.max_string_chars)
    if provider:
        attributes["provider"] = provider
    message = f"Windows event {event_id or index}" + (f" from {provider}" if provider else "")
    return BinaryEvent(
        event_id=f"evtx-{event_id or index}-{index}",
        timestamp_utc=_iso_timestamp(timestamp),
        event_type=f"windows_event:{event_id or 'unknown'}",
        message=message,
        attributes=attributes,
        record_number=index,
    )


def _parse_capture(
    content: bytes,
    *,
    source_ref: str,
    detected: str,
    limits: BinaryParseLimits,
) -> BinaryParseResult:
    try:
        import dpkt  # type: ignore[import-not-found,import-untyped]
    except ImportError:
        return _failure(source_ref, detected, "pcap.dependency_unavailable", "PCAP parser dependency is unavailable")

    events: list[BinaryEvent] = []
    diagnostics: list[BinaryDiagnostic] = []
    records_seen = 0
    invalid_frames = 0
    unsupported_frames = 0
    truncated = False
    try:
        reader = (
            dpkt.pcapng.Reader(io.BytesIO(content)) if detected == "pcapng" else dpkt.pcap.Reader(io.BytesIO(content))
        )
        for index, (timestamp, frame) in enumerate(reader, 1):
            if index > limits.max_records:
                truncated = True
                diagnostics.append(BinaryDiagnostic("pcap.record_limit", "packet record limit reached", "warning"))
                break
            records_seen += 1
            try:
                event = _packet_event(dpkt, frame, timestamp, index, limits)
            except (AttributeError, IndexError, OSError, OverflowError, TypeError, ValueError):
                invalid_frames += 1
                if len(diagnostics) < MAX_DIAGNOSTICS - 2:
                    diagnostics.append(
                        BinaryDiagnostic(
                            "pcap.packet_invalid",
                            f"packet {index} could not be normalized",
                            "warning",
                            index,
                        )
                    )
                continue
            if event is not None:
                events.append(event)
            else:
                unsupported_frames += 1
    except (OSError, ValueError, dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as exc:
        diagnostics.append(
            BinaryDiagnostic("pcap.parse_error", f"packet capture parsing failed: {type(exc).__name__}", "error")
        )
    if unsupported_frames:
        diagnostics.append(
            BinaryDiagnostic(
                "pcap.unsupported_frames",
                f"{unsupported_frames} packet frame(s) used an unsupported network-layer representation",
                "warning",
            )
        )
    if invalid_frames > sum(item.code == "pcap.packet_invalid" for item in diagnostics):
        diagnostics.append(
            BinaryDiagnostic(
                "pcap.diagnostic_limit",
                f"{invalid_frames} invalid packet frame(s) were observed; diagnostics were truncated",
                "warning",
            )
        )
    return BinaryParseResult(
        source_ref,
        detected,
        records_seen,
        len(events),
        truncated,
        tuple(events),
        tuple(diagnostics),
    )


def _packet_event(
    dpkt: Any,
    frame: bytes,
    timestamp: float,
    index: int,
    limits: BinaryParseLimits,
) -> BinaryEvent | None:
    ethernet = dpkt.ethernet.Ethernet(frame)
    packet = ethernet.data
    if isinstance(packet, dpkt.ip.IP):
        source = str(ipaddress.ip_address(packet.src))
        destination = str(ipaddress.ip_address(packet.dst))
        protocol = int(packet.p)
    elif isinstance(packet, dpkt.ip6.IP6):
        source = str(ipaddress.ip_address(packet.src))
        destination = str(ipaddress.ip_address(packet.dst))
        protocol = int(packet.nxt)
    else:
        return None
    transport = packet.data
    attributes: dict[str, Any] = {"src": source, "dst": destination, "protocol": protocol}
    protocol_name = "ip"
    if isinstance(transport, dpkt.tcp.TCP):
        protocol_name = "tcp"
        attributes.update({"src_port": int(transport.sport), "dst_port": int(transport.dport)})
    elif isinstance(transport, dpkt.udp.UDP):
        protocol_name = "udp"
        attributes.update({"src_port": int(transport.sport), "dst_port": int(transport.dport)})
        if transport.sport == 53 or transport.dport == 53:
            try:
                dns = dpkt.dns.DNS(bytes(transport.data))
                if dns.qd:
                    attributes["dns_qname"] = _bounded(dns.qd[0].name, limits.max_string_chars)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, UnicodeError):
                pass
    attributes["frame_sha256"] = hashlib.sha256(frame).hexdigest()
    attributes = dict(list(attributes.items())[: limits.max_event_fields])
    return BinaryEvent(
        event_id=f"{protocol_name}-{index}-{attributes['frame_sha256'][:12]}",
        timestamp_utc=datetime.fromtimestamp(float(timestamp), tz=UTC).isoformat(),
        event_type=f"network:{protocol_name}",
        message=(
            f"{protocol_name.upper()} {source}:{attributes.get('src_port', 0)} -> "
            f"{destination}:{attributes.get('dst_port', 0)}"
        ),
        attributes=attributes,
        record_number=index,
        byte_length=min(len(frame), limits.max_input_bytes),
    )


def _iso_timestamp(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC).isoformat()
    except ValueError:
        return None


def _bounded(value: Any, maximum: int) -> str:
    return "" if value is None else str(value).replace("\x00", "")[:maximum]


def _failure(source_ref: str, detected: str, code: str, message: str) -> BinaryParseResult:
    return BinaryParseResult(
        source_ref,
        detected,
        0,
        0,
        False,
        (),
        (BinaryDiagnostic(code, message, "error"),),
    )


__all__ = ["EVTX_MAGIC", "PCAPNG_MAGIC", "PCAP_MAGICS", "detect_binary_format", "parse_binary_log"]
