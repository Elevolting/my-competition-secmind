"""Fail-closed extraction for bounded ZIP log bundles."""

from __future__ import annotations

import io
import re
import stat
import zipfile
from pathlib import PurePosixPath

from secmind.log_parsers.contracts import BinaryParseLimits, SafeArchiveMember, SafeArchiveResult

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_NESTED_ARCHIVE_SUFFIXES = {".7z", ".bz2", ".gz", ".rar", ".tar", ".tgz", ".xz", ".zip"}
_ARCHIVE_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c")
_SUPPORTED_MEMBER_SUFFIXES = {
    ".csv",
    ".evtx",
    ".json",
    ".jsonl",
    ".log",
    ".ndjson",
    ".pcap",
    ".pcapng",
    ".syslog",
    ".tsv",
}


class ArchiveSafetyError(ValueError):
    """The ZIP cannot be expanded without violating a declared bound."""


def extract_safe_zip(content: bytes, *, limits: BinaryParseLimits) -> SafeArchiveResult:
    if len(content) > limits.max_input_bytes:
        raise ArchiveSafetyError("archive exceeds the input byte limit")
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as exc:
        raise ArchiveSafetyError("invalid ZIP archive") from exc

    members: list[SafeArchiveMember] = []
    skipped: list[str] = []
    collision_keys: set[str] = set()
    total_bytes = 0
    total_compressed = 0
    with archive:
        infos = archive.infolist()
        if len(infos) > limits.max_archive_members:
            raise ArchiveSafetyError("archive member limit exceeded")
        for info in infos:
            if info.is_dir():
                continue
            normalized = info.filename.replace("\\", "/")
            path = PurePosixPath(normalized)
            if (
                not normalized
                or path.is_absolute()
                or _WINDOWS_DRIVE.match(normalized)
                or any(part in {"", ".", ".."} for part in path.parts)
                or _CONTROL.search(normalized)
            ):
                raise ArchiveSafetyError("archive contains an unsafe member path")
            collision_key = path.as_posix().casefold()
            if collision_key in collision_keys:
                raise ArchiveSafetyError("archive contains a duplicate normalized member path")
            collision_keys.add(collision_key)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ArchiveSafetyError("archive contains a symbolic link")
            if info.flag_bits & 0x1:
                raise ArchiveSafetyError("encrypted archive members are not allowed")
            suffix = path.suffix.casefold()
            if suffix in _NESTED_ARCHIVE_SUFFIXES:
                raise ArchiveSafetyError("nested archives are not allowed")
            if info.file_size > limits.max_archive_member_bytes:
                raise ArchiveSafetyError("archive member exceeds its byte limit")
            total_bytes += info.file_size
            if total_bytes > limits.max_archive_total_bytes:
                raise ArchiveSafetyError("archive cumulative output limit exceeded")
            compressed = max(1, info.compress_size)
            total_compressed += compressed
            if info.file_size > compressed * limits.max_archive_ratio:
                raise ArchiveSafetyError("archive member exceeds the compression-ratio limit")
            if total_bytes > max(1, total_compressed) * limits.max_archive_ratio:
                raise ArchiveSafetyError("archive exceeds the cumulative compression-ratio limit")
            try:
                with archive.open(info, "r") as stream:
                    payload = (
                        stream.read(info.file_size + 1) if suffix in _SUPPORTED_MEMBER_SUFFIXES else stream.read(8)
                    )
            except (NotImplementedError, OSError, RuntimeError, zipfile.BadZipFile) as exc:
                raise ArchiveSafetyError("archive member could not be decoded safely") from exc
            if suffix not in _SUPPORTED_MEMBER_SUFFIXES:
                if payload.startswith(_ARCHIVE_MAGICS):
                    raise ArchiveSafetyError("nested archives are not allowed")
                skipped.append(path.as_posix())
                continue
            if len(payload) != info.file_size or len(payload) > limits.max_archive_member_bytes:
                raise ArchiveSafetyError("archive member size changed while reading")
            if payload.startswith(_ARCHIVE_MAGICS):
                raise ArchiveSafetyError("nested archives are not allowed")
            members.append(SafeArchiveMember(path=path.as_posix(), content=payload))
    return SafeArchiveResult(tuple(members), tuple(skipped))


__all__ = ["ArchiveSafetyError", "extract_safe_zip"]
