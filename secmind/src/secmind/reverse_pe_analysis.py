from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ASCII_RE = re.compile(rb"[ -~]{6,}")
DOMAIN_RE = re.compile(r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}")
URL_RE = re.compile(r"https?://[^\s'\"<>]+")
TOKEN_RE = re.compile(r"[A-Z0-9]{4,}(?:-[A-Z0-9]{2,})+")

_MACHINE_NAMES = {
    0x014C: "I386",
    0x0162: "R3000",
    0x01C0: "ARM",
    0x01C2: "ARMNT",
    0x01C4: "ARMV7",
    0x01F0: "POWERPC",
    0x01F2: "POWERPCFP",
    0x0200: "IA64",
    0x8664: "AMD64",
    0xAA64: "ARM64",
}

_SUBSYSTEM_NAMES = {
    0: "UNKNOWN",
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    5: "OS2_CUI",
    7: "POSIX_CUI",
    8: "NATIVE_WINDOWS",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER",
    13: "EFI_ROM",
    14: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
}

_DLL_CHARACTERISTICS = {
    0x0020: "HIGH_ENTROPY_VA",
    0x0040: "DYNAMIC_BASE",
    0x0080: "FORCE_INTEGRITY",
    0x0100: "NX_COMPAT",
    0x0200: "NO_ISOLATION",
    0x0400: "NO_SEH",
    0x0800: "NO_BIND",
    0x1000: "APPCONTAINER",
    0x2000: "WDM_DRIVER",
    0x4000: "GUARD_CF",
    0x8000: "TERMINAL_SERVER_AWARE",
}

_SECTION_FLAGS = (
    (0x00000020, "CNT_CODE"),
    (0x00000040, "CNT_INITIALIZED_DATA"),
    (0x00000080, "CNT_UNINITIALIZED_DATA"),
    (0x02000000, "MEM_DISCARDABLE"),
    (0x20000000, "MEM_EXECUTE"),
    (0x40000000, "MEM_READ"),
    (0x80000000, "MEM_WRITE"),
)


@dataclass(frozen=True)
class CandidateString:
    value: str
    section: str
    xor_key: int | None
    source: str
    score: int


@dataclass(frozen=True)
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    offset: int
    entropy: float
    characteristics: list[str]
    content: bytes


@dataclass(frozen=True)
class ParsedPE:
    file_info: dict[str, Any]
    pe_info: dict[str, Any]
    sections: list[SectionInfo]
    imports: list[dict[str, Any]]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_enum(value: Any) -> str:
    text = str(value)
    if "." in text:
        return text.split(".", 1)[1]
    return text


def extract_ascii_strings(data: bytes, min_len: int = 6) -> list[str]:
    pattern = re.compile(rb"[ -~]{%d,}" % min_len)
    return [match.group().decode("ascii", "ignore") for match in pattern.finditer(data)]


def dedupe_keep_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            output.append(item)
    return output


def score_candidate(value: str, source: str) -> int:
    score = len(value)
    if URL_RE.fullmatch(value):
        score += 80
    if DOMAIN_RE.fullmatch(value):
        score += 60
    if TOKEN_RE.fullmatch(value):
        score += 50
    if "." in value:
        score += 10
    if "-" in value:
        score += 8
    if "/" in value:
        score += 4
    if source == "xor":
        score += 6
    return score


def _candidate_confidence(value: str) -> str:
    if value.endswith((".invalid", ".example", ".test", ".localhost")):
        return "high"
    if TOKEN_RE.fullmatch(value):
        return "high"
    if DOMAIN_RE.fullmatch(value) or URL_RE.fullmatch(value):
        return "medium"
    return "low"


def _visible_segments(value: str) -> list[str]:
    """Split decoded padding runs before applying semantic extractors.

    Zero-filled PE padding becomes a long run of the XOR key byte.  Treating
    that run as text causes a real token/domain to absorb hundreds of padding
    characters and outrank the true value.
    """

    return [segment for segment in re.split(r"(.)\1{3,}", value)[::2] if len(segment) >= 6]


def is_useful_candidate(value: str) -> bool:
    if len(value) < 6:
        return False
    if not any(ch.isalpha() for ch in value):
        return False
    if len(set(value)) == 1:
        return False
    return True


def parse_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def parse_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def parse_u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def read_c_string(data: bytes, offset: int, limit: int = 256) -> str:
    end = data.find(b"\x00", offset, min(len(data), offset + limit))
    if end < 0:
        end = min(len(data), offset + limit)
    return data[offset:end].decode("ascii", "ignore")


def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    size = len(data)
    entropy = 0.0
    for count in counts:
        if not count:
            continue
        p = count / size
        entropy -= p * (p.bit_length() if False else 0)
    # Use a stable direct implementation to avoid importing math.log2 repeatedly.
    import math

    entropy = 0.0
    for count in counts:
        if not count:
            continue
        p = count / size
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def machine_name(machine: int) -> str:
    return _MACHINE_NAMES.get(machine, f"0x{machine:04x}")


def subsystem_name(subsystem: int) -> str:
    return _SUBSYSTEM_NAMES.get(subsystem, f"0x{subsystem:04x}")


def dll_characteristics(mask: int) -> list[str]:
    return [name for bit, name in _DLL_CHARACTERISTICS.items() if mask & bit]


def section_characteristics(mask: int) -> list[str]:
    return [name for bit, name in _SECTION_FLAGS if mask & bit]


def rva_to_offset(rva: int, sections: list[SectionInfo], size_of_headers: int) -> int:
    for section in sections:
        raw_span = max(section.virtual_size, section.raw_size)
        if section.raw_size and section.virtual_address <= rva < section.virtual_address + raw_span:
            return section.offset + (rva - section.virtual_address)
    if rva < size_of_headers:
        return rva
    raise ValueError(f"RVA 0x{rva:x} does not map to a file offset")


def parse_pe(raw: bytes) -> ParsedPE:
    if len(raw) < 0x40 or raw[:2] != b"MZ":
        raise RuntimeError("input is not a PE file")

    e_lfanew = parse_u32(raw, 0x3C)
    if e_lfanew + 24 > len(raw) or raw[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise RuntimeError("PE signature not found")

    machine = parse_u16(raw, e_lfanew + 4)
    number_of_sections = parse_u16(raw, e_lfanew + 6)
    size_of_optional_header = parse_u16(raw, e_lfanew + 20)
    optional_start = e_lfanew + 24
    optional_end = optional_start + size_of_optional_header
    if optional_end > len(raw):
        raise RuntimeError("optional header exceeds file size")

    magic = parse_u16(raw, optional_start)
    if magic == 0x20B:
        is_pe32_plus = True
        entrypoint_rva = parse_u32(raw, optional_start + 16)
        imagebase = parse_u64(raw, optional_start + 24)
        section_alignment = parse_u32(raw, optional_start + 32)
        file_alignment = parse_u32(raw, optional_start + 36)
        size_of_image = parse_u32(raw, optional_start + 56)
        size_of_headers = parse_u32(raw, optional_start + 60)
        subsystem = parse_u16(raw, optional_start + 68)
        dll_chars = parse_u16(raw, optional_start + 70)
        num_rva_and_sizes = parse_u32(raw, optional_start + 108)
        data_dir_start = optional_start + 112
    elif magic == 0x10B:
        is_pe32_plus = False
        entrypoint_rva = parse_u32(raw, optional_start + 16)
        imagebase = parse_u32(raw, optional_start + 28)
        section_alignment = parse_u32(raw, optional_start + 32)
        file_alignment = parse_u32(raw, optional_start + 36)
        size_of_image = parse_u32(raw, optional_start + 56)
        size_of_headers = parse_u32(raw, optional_start + 60)
        subsystem = parse_u16(raw, optional_start + 68)
        dll_chars = parse_u16(raw, optional_start + 70)
        num_rva_and_sizes = parse_u32(raw, optional_start + 92)
        data_dir_start = optional_start + 96
    else:
        raise RuntimeError(f"unsupported PE optional header magic: 0x{magic:04x}")

    sections: list[SectionInfo] = []
    section_table_start = optional_end
    for index in range(number_of_sections):
        start = section_table_start + index * 40
        end = start + 40
        if end > len(raw):
            break
        header = raw[start:end]
        name = header[:8].split(b"\x00", 1)[0].decode("ascii", "ignore")
        virtual_size = parse_u32(header, 8)
        virtual_address = parse_u32(header, 12)
        raw_size = parse_u32(header, 16)
        raw_offset = parse_u32(header, 20)
        characteristics_mask = parse_u32(header, 36)
        content = raw[raw_offset : min(len(raw), raw_offset + raw_size)] if raw_size else b""
        sections.append(
            SectionInfo(
                name=name,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                raw_size=raw_size,
                offset=raw_offset,
                entropy=compute_entropy(content),
                characteristics=section_characteristics(characteristics_mask),
                content=content,
            )
        )

    data_directories: list[tuple[int, int]] = []
    for index in range(min(num_rva_and_sizes, 16)):
        offset = data_dir_start + index * 8
        if offset + 8 > len(raw):
            break
        data_directories.append((parse_u32(raw, offset), parse_u32(raw, offset + 4)))
    while len(data_directories) < 16:
        data_directories.append((0, 0))

    import_rva, import_size = data_directories[1]

    imports: list[dict[str, Any]] = []
    if import_rva and import_size:
        try:
            desc_offset = rva_to_offset(import_rva, sections, size_of_headers)
            thunk_size = 8 if is_pe32_plus else 4
            ordinal_flag = 0x8000000000000000 if is_pe32_plus else 0x80000000
            while desc_offset + 20 <= len(raw):
                original_first_thunk = parse_u32(raw, desc_offset)
                name_rva = parse_u32(raw, desc_offset + 12)
                first_thunk = parse_u32(raw, desc_offset + 16)
                if not any(raw[desc_offset : desc_offset + 20]):
                    break
                library_name = read_c_string(raw, rva_to_offset(name_rva, sections, size_of_headers))
                thunk_rva = original_first_thunk or first_thunk
                entries: list[dict[str, Any]] = []
                if thunk_rva:
                    thunk_offset = rva_to_offset(thunk_rva, sections, size_of_headers)
                    slot_index = 0
                    while thunk_offset + thunk_size <= len(raw):
                        thunk_value = parse_u64(raw, thunk_offset) if is_pe32_plus else parse_u32(raw, thunk_offset)
                        if thunk_value == 0:
                            break
                        iat_address = thunk_rva + slot_index * thunk_size
                        if thunk_value & ordinal_flag:
                            entries.append(
                                {
                                    "iat_address": f"0x{iat_address:x}",
                                    "is_ordinal": True,
                                    "ordinal": thunk_value & 0xFFFF,
                                }
                            )
                        else:
                            by_name_offset = rva_to_offset(thunk_value, sections, size_of_headers)
                            entries.append(
                                {
                                    "iat_address": f"0x{iat_address:x}",
                                    "is_ordinal": False,
                                    "name": read_c_string(raw, by_name_offset + 2),
                                    "hint": parse_u16(raw, by_name_offset),
                                }
                            )
                        slot_index += 1
                        thunk_offset += thunk_size
                imports.append({"library": library_name, "count": len(entries), "entries": entries})
                desc_offset += 20
        except Exception:
            imports = []

    file_info = {
        "format": "PE",
        "machine": machine_name(machine),
        "architecture": {
            "AMD64": "x86-64",
            "I386": "x86",
            "ARM64": "ARM64",
            "ARMNT": "ARM",
            "ARM": "ARM",
        }.get(machine_name(machine), machine_name(machine)),
        "subsystem": subsystem_name(subsystem),
        "imagebase": f"0x{imagebase:x}",
        "section_alignment": section_alignment,
        "file_alignment": file_alignment,
        "size_of_image": size_of_image,
    }

    pe_info = {
        "imagebase": f"0x{imagebase:x}",
        "entrypoint_rva": f"0x{entrypoint_rva:x}",
        "entrypoint_va": f"0x{imagebase + entrypoint_rva:x}",
        "entrypoint_offset": rva_to_offset(entrypoint_rva, sections, size_of_headers),
        "entrypoint_bytes_hex": raw[
            rva_to_offset(entrypoint_rva, sections, size_of_headers) : rva_to_offset(
                entrypoint_rva, sections, size_of_headers
            )
            + 64
        ].hex(" "),
        "dll_characteristics": dll_characteristics(dll_chars),
        "file_alignment": file_alignment,
        "section_count": len(sections),
        "import_library_count": len(imports),
        "export_count": 0,
    }

    return ParsedPE(file_info=file_info, pe_info=pe_info, sections=sections, imports=imports)


def classify_import_hints(imports: list[dict[str, Any]]) -> list[dict[str, str]]:
    hints: list[tuple[str, str]] = [
        ("fopen", "file open / file I/O"),
        ("fprintf", "formatted file output"),
        ("fclose", "file close"),
        ("fwrite", "binary or file output"),
        ("fputc", "character output"),
        ("puts", "console output"),
        ("strcmp", "string comparison"),
        ("strncmp", "bounded string comparison"),
        ("strlen", "string length"),
        ("memcpy", "memory copy"),
        ("memset", "memory initialization"),
        ("VirtualProtect", "memory protection change"),
        ("VirtualQuery", "memory query"),
        ("Sleep", "delay / pacing"),
        ("GetLastError", "error handling"),
        ("SetUnhandledExceptionFilter", "exception handling"),
    ]
    found: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in imports:
        for entry in item["entries"]:
            name = entry.get("name")
            if not name:
                continue
            for needle, label in hints:
                if name == needle and name not in seen:
                    seen.add(name)
                    found.append({"api": name, "hint": label, "observation": "static_presence"})
    return found


def extract_xor_candidates(sections: list[SectionInfo]) -> list[CandidateString]:
    candidates: dict[tuple[str, str], CandidateString] = {}
    for section in sections:
        if not section.content or "MEM_EXECUTE" in section.characteristics:
            continue
        raw = section.content
        for key in range(1, 256):
            decoded = bytes(byte ^ key for byte in raw)
            visible = [match.group().decode("ascii", "ignore") for match in ASCII_RE.finditer(decoded)]
            for value in visible:
                if len(value) > 4096:
                    value = value[:4096]
                extracted_items: list[str] = []
                for segment in _visible_segments(value):
                    extracted_items.extend(DOMAIN_RE.findall(segment))
                    extracted_items.extend(URL_RE.findall(segment))
                    extracted_items.extend(TOKEN_RE.findall(segment))
                for extracted in extracted_items:
                    if len(extracted) < 6 or not any(ch.isalpha() for ch in extracted):
                        continue
                    if DOMAIN_RE.fullmatch(extracted) and extracted != extracted.lower():
                        continue
                    if TOKEN_RE.fullmatch(extracted) and extracted != extracted.upper():
                        continue
                    score = score_candidate(extracted, "xor")
                    current_key = (section.name, extracted)
                    best = candidates.get(current_key)
                    if best is None or score > best.score:
                        candidates[current_key] = CandidateString(
                            value=extracted,
                            section=section.name,
                            xor_key=key,
                            source="xor",
                            score=score,
                        )
    ranked = sorted(
        candidates.values(),
        key=lambda item: (
            {"high": 0, "medium": 1, "low": 2}[_candidate_confidence(item.value)],
            -item.score,
            item.section,
            item.value,
        ),
    )
    return ranked[:20]


def build_report(input_path: Path) -> dict[str, Any]:
    raw = input_path.read_bytes()
    parsed = parse_pe(raw)
    raw_strings = dedupe_keep_order([s for s in extract_ascii_strings(raw, min_len=6) if any(ch.isalpha() for ch in s)])
    decoded_candidates = extract_xor_candidates(parsed.sections)
    sections = [
        {
            "name": section.name,
            "virtual_address": f"0x{section.virtual_address:x}",
            "virtual_size": section.virtual_size,
            "raw_size": section.raw_size,
            "offset": section.offset,
            "entropy": section.entropy,
            "characteristics": section.characteristics,
            "sample_hex": section.content[:32].hex(" "),
        }
        for section in parsed.sections
    ]
    decoded_compact = [
        {
            "value": item.value,
            "section": item.section,
            "xor_key": f"0x{item.xor_key:02x}" if item.xor_key is not None else None,
            "source": item.source,
            "confidence": _candidate_confidence(item.value),
        }
        for item in decoded_candidates
    ]
    return {
        "schema_version": "1.0",
        "title": "Enhanced static reverse analysis",
        "status": "completed",
        "file": {
            "name": input_path.name,
            "path": str(input_path),
            "size_bytes": len(raw),
            "sha256": sha256_hex(raw),
            **parsed.file_info,
        },
        "pe": parsed.pe_info,
        "sections": sections,
        "imports": parsed.imports,
        "import_hints": classify_import_hints(parsed.imports),
        "import_semantics": "static_presence",
        "runtime_calls_observed": False,
        "raw_strings": raw_strings[:200],
        "xor_decode_candidates": decoded_compact,
        "limitations": [
            "No dynamic execution was performed.",
            "No full disassembly engine is bundled in this helper.",
            "XOR decoding is heuristic and may include false positives.",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    file_info = report["file"]
    pe = report["pe"]
    lines = [
        f"# Enhanced reverse analysis: {file_info['name']}",
        "",
        f"- Status: `{report['status']}`",
        f"- SHA256: `{file_info['sha256']}`",
        f"- Format: `{file_info['format']}`",
        f"- Architecture: `{file_info['architecture']}`",
        f"- Machine: `{file_info['machine']}`",
        f"- Subsystem: `{file_info['subsystem']}`",
        f"- Image base: `{pe['imagebase']}`",
        f"- Entrypoint RVA: `{pe['entrypoint_rva']}`",
        f"- Entrypoint VA: `{pe['entrypoint_va']}`",
        "",
        "## What improved",
        "",
        "- PE header parsing: architecture, subsystem, image base, entry point.",
        "- Section inspection: names, sizes, entropy, and flags.",
        "- Import table parsing: real API names are collected instead of only raw strings.",
        "- Heuristic string recovery: XOR-based scan surfaces hidden candidates such as tokens and domains.",
        "",
        "## Likely behavior from imports",
    ]
    if report["import_hints"]:
        for item in report["import_hints"]:
            lines.append(f"- `{item['api']}` -> {item['hint']}")
    else:
        lines.append("- No import-based behavior hints found.")

    lines.extend(["", "## Recovered strings", ""])
    if report["xor_decode_candidates"]:
        for item in report["xor_decode_candidates"]:
            lines.append(f"- `{item['value']}` from `{item['section']}` with XOR `{item['xor_key']}`")
    else:
        lines.append("- No high-confidence decoded strings found.")

    lines.extend(["", "## Limitations", ""])
    for item in report["limitations"]:
        lines.append(f"- {item}")

    return "\n".join(lines) + "\n"
