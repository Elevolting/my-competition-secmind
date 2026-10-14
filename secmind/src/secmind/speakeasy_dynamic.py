"""Safe Speakeasy profile selection, report normalization, and compatibility hooks."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from secmind.reverse_analysis_observation import ReverseAnalysisObservation

_PROFILE_ARGV = {
    "wrong_token": ("NOT-THE-TOKEN",),
    "correct_token": ("SECMIND-REVERSE-OK",),
}
SAFE_DEMO_SHA256 = "efb6050e10a8d548ae454034120a233283b33d5d679e6fc06147549441f82c38"


def approved_safe_fixture_sha256(value: str) -> bool:
    """Return whether a digest identifies the sole approved emulation fixture."""

    return value.casefold() == SAFE_DEMO_SHA256


def profile_argv(profile_id: str) -> list[str]:
    """Return a copy of a fixed safe command-line profile."""

    try:
        return list(_PROFILE_ARGV[profile_id])
    except KeyError as exc:
        raise ValueError(f"unsupported Speakeasy profile: {profile_id}") from exc


def resolve_safe_target(target: str, workspace: Path) -> Path:
    """Resolve a file target without permitting workspace escape."""

    root = workspace.resolve()
    candidate = (root / target).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("Speakeasy target must remain inside the workspace") from exc
    if not candidate.is_file():
        raise ValueError("Speakeasy target must be an existing file")
    return candidate


def mingw_iob_func_hook(state: dict[str, int]) -> Callable[..., int]:
    """Provide the legacy MinGW three-entry FILE table expected by `__iob_func`.

    The hook only allocates inert emulated memory.  It neither fabricates a
    business API result nor touches the host filesystem.
    """

    def hook(emu: Any, _api_name: str, _original: Any, _params: list[Any]) -> int:
        address = state.get("address")
        if address is None:
            address = int(emu.mem_map(3 * 48, tag="secmind.mingw.iob"))
            emu.mem_write(address, b"\x00" * (3 * 48))
            state["address"] = address
        return address

    return hook


def initialize_mingw_acmdln(emu: Any, command_line: str) -> bool:
    """Initialize Speakeasy's inert `_acmdln` import slot in emulated memory."""

    slot = next(
        (item for item in emu.get_mem_maps() if "api.msvcrt._acmdln" in str(getattr(item, "tag", "")).casefold()),
        None,
    )
    if slot is None:
        return False
    encoded = command_line.encode("utf-8") + b"\x00"
    value_address = int(emu.mem_map(len(encoded), tag="secmind.mingw.acmdln"))
    emu.mem_write(value_address, encoded)
    emu.mem_write(int(slot.base), value_address.to_bytes(int(emu.get_ptr_size()), "little"))
    return True


def initialize_safe_fixture_argv(
    emu: Any,
    module_base: int,
    sample_sha256: str,
    argv: list[str],
) -> bool:
    """Apply the MinGW argv shim only to the repository-authored safe fixture.

    Speakeasy's empty `_initterm` handler does not dispatch MinGW's initializer
    that populates these globals.  The RVAs are therefore deliberately bound to
    the immutable fixture digest and must never be applied to an arbitrary PE.
    """

    if not approved_safe_fixture_sha256(sample_sha256) or len(argv) != 1:
        return False
    values = [b"reverse_demo.exe\x00", argv[0].encode("utf-8") + b"\x00"]
    pointer_size = int(emu.get_ptr_size())
    table_size = pointer_size * 3
    block = int(emu.mem_map(table_size + sum(map(len, values)), tag="secmind.safe_fixture.argv"))
    string_address = block + table_size
    for index, value in enumerate(values):
        emu.mem_write(block + index * pointer_size, string_address.to_bytes(pointer_size, "little"))
        emu.mem_write(string_address, value)
        string_address += len(value)
    emu.mem_write(block + 2 * pointer_size, b"\x00" * pointer_size)
    emu.mem_write(module_base + 0xC038, (2).to_bytes(4, "little"))
    emu.mem_write(module_base + 0xC030, block.to_bytes(pointer_size, "little"))
    return True


def _safe_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "event": str(event.get("event", ""))[:40],
        "api_name": str(event.get("api_name", ""))[:160],
        "args": [str(value)[:500] for value in list(event.get("args", []))[:16]],
        "ret_val": str(event.get("ret_val", ""))[:80] or None,
    }


def _parse_ret_val(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def normalize_speakeasy_report(
    report: dict[str, Any],
    *,
    profile_id: str,
    event_limit: int = 500,
) -> ReverseAnalysisObservation:
    """Project the large native report into a stable, bounded observation."""

    if profile_id not in _PROFILE_ARGV:
        raise ValueError(f"unsupported Speakeasy profile: {profile_id}")
    retained: list[dict[str, Any]] = []
    file_open_attempts: set[str] = set()
    open_handles: dict[str, str] = {}
    written_files: set[str] = set()
    total = 0
    exit_code: int | None = None
    errors: list[str] = []
    for entry in report.get("entry_points", []):
        if not isinstance(entry, dict):
            continue
        if entry.get("ep_type") == "module_entry":
            exit_code = _parse_ret_val(entry.get("ret_val"))
        if entry.get("error"):
            errors.append(str(entry["error"])[:1000])
        for event in entry.get("events", []):
            if not isinstance(event, dict):
                continue
            total += 1
            safe = _safe_event(event)
            if len(retained) < max(1, min(event_limit, 500)):
                retained.append(safe)
            api_name = safe["api_name"].casefold()
            if api_name.endswith((".fopen", ".fopen_s")) and len(safe["args"]) >= 2:
                filename = Path(safe["args"][0].replace("\\", "/")).name
                file_open_attempts.add(filename)
                mode = safe["args"][1]
                handle_value = _parse_ret_val(safe["ret_val"])
                if any(flag in mode for flag in ("w", "a", "+")) and handle_value not in (None, 0, -1):
                    assert handle_value is not None
                    open_handles[hex(handle_value)] = filename
            if api_name.endswith((".fputc", ".fputs", ".fwrite", ".fprintf")):
                argument_handles = {_parse_ret_val(value) for value in safe["args"][1:]}
                for handle_key, filename in open_handles.items():
                    if int(handle_key, 0) in argument_handles:
                        written_files.add(filename)
    error = {"code": "SPEAKEASY_RUNTIME_ERROR", "messages": errors} if errors else None
    return ReverseAnalysisObservation(
        source="speakeasy",
        status="partial" if errors else "completed",
        sample_sha256=str(report.get("sha256", "")).casefold(),
        tool_identity={
            "name": "speakeasy",
            "version": "2.0.0b6",
            "commit": "b364d53ce9364e1f8aa898b9ed53597be39b23cb",
        },
        profile_id=profile_id,
        coverage={
            "architecture": report.get("arch"),
            "runtime_calls_observed": total > 0,
            "events_total": total,
            "events_retained": len(retained),
            "truncated": total > len(retained),
            "real_network_requests": 0,
            "host_pe_executions": 0,
        },
        events=retained,
        artifacts={
            "exit_code": exit_code,
            "file_open_attempts": sorted(file_open_attempts),
            "created_files": sorted(written_files),
        },
        error=error,
    )


def format_speakeasy_runner_output(
    native_report: dict[str, Any],
    observation: ReverseAnalysisObservation,
    *,
    output_format: str,
) -> dict[str, Any]:
    """Format runner output without changing the bounded tool's default contract."""

    normalized = observation.model_dump(mode="json")
    if output_format == "normalized":
        return normalized
    if output_format == "bundle":
        return {"native": native_report, "normalized": normalized}
    raise ValueError(f"unsupported Speakeasy output format: {output_format}")
