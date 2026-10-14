from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from secmind.artifact_store import ArtifactStoreError, ContentAddressedArtifactStore
from secmind.ledger import canonical_json

SEGMENTED_ARTIFACT_FORMAT = "secmind-segmented-artifact-v1"
SEGMENT_MANIFEST_MEDIA_TYPE = "application/vnd.secmind.segment-manifest+json"
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_MEDIA_TYPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$")


class SegmentedArtifactError(ArtifactStoreError):
    pass


@dataclass(frozen=True)
class SegmentReference:
    sequence: int
    offset: int
    size_bytes: int
    sha256: str
    artifact_id: str


@dataclass(frozen=True)
class SegmentedArtifactManifest:
    manifest_artifact_id: str
    media_type: str
    total_size: int
    stream_sha256: str
    segments: tuple[SegmentReference, ...]


@dataclass(frozen=True)
class SegmentCursor:
    sequence: int = 0
    byte_offset: int = 0

    def __post_init__(self) -> None:
        if self.sequence < 0 or self.byte_offset < 0:
            raise SegmentedArtifactError("segment cursor cannot be negative")


class SegmentedArtifactStore:
    """Bounded streaming facade over the immutable content-addressed store.

    Segment objects are committed first and the canonical manifest is committed
    last. Therefore an interrupted write can leave only unreferenced immutable
    objects; it can never expose a partially valid stream manifest.

    This facade does not claim to add encryption or access control. Production
    RAW_RESTRICTED streams still require an encrypted, authenticated backend.
    """

    def __init__(
        self,
        artifact_store: ContentAddressedArtifactStore,
        *,
        segment_bytes: int = 4 * 1024 * 1024,
        max_total_bytes: int = 512 * 1024 * 1024,
        max_segments: int = 4_096,
        max_manifest_bytes: int = 2 * 1024 * 1024,
    ) -> None:
        if segment_bytes < 1 or segment_bytes > artifact_store.max_artifact_bytes:
            raise ValueError("segment size must fit one content-addressed artifact")
        if max_total_bytes < segment_bytes or max_segments < 1 or max_manifest_bytes < 1:
            raise ValueError("invalid segmented artifact limits")
        self.artifact_store = artifact_store
        self.segment_bytes = segment_bytes
        self.max_total_bytes = max_total_bytes
        self.max_segments = max_segments
        self.max_manifest_bytes = max_manifest_bytes

    def put_stream(
        self,
        chunks: Iterable[bytes | bytearray | memoryview],
        *,
        media_type: str = "application/octet-stream",
        expected_sha256: str | None = None,
    ) -> SegmentedArtifactManifest:
        self._validate_media_type(media_type)
        if expected_sha256 is not None and not _DIGEST.fullmatch(expected_sha256.lower()):
            raise SegmentedArtifactError("expected stream digest is invalid")
        total_size = 0
        stream_hasher = hashlib.sha256()
        buffer = bytearray()
        segments: list[SegmentReference] = []
        for chunk in chunks:
            if not isinstance(chunk, (bytes, bytearray, memoryview)):
                raise SegmentedArtifactError("stream yielded a non-bytes chunk")
            view = memoryview(chunk)
            total_size += view.nbytes
            if total_size > self.max_total_bytes:
                raise SegmentedArtifactError("segmented artifact exceeds the configured total size")
            stream_hasher.update(view)
            cursor = 0
            while cursor < view.nbytes:
                take = min(self.segment_bytes - len(buffer), view.nbytes - cursor)
                buffer.extend(view[cursor : cursor + take])
                cursor += take
                if len(buffer) == self.segment_bytes:
                    self._store_segment(bytes(buffer), segments)
                    buffer.clear()
        if buffer:
            self._store_segment(bytes(buffer), segments)
        digest = stream_hasher.hexdigest()
        if expected_sha256 is not None and not hmac.compare_digest(digest, expected_sha256.lower()):
            raise SegmentedArtifactError("segmented artifact stream digest mismatch")
        manifest_payload = self._manifest_payload(media_type, total_size, digest, tuple(segments))
        manifest_bytes = canonical_json(manifest_payload).encode("utf-8")
        if len(manifest_bytes) > self.max_manifest_bytes:
            raise SegmentedArtifactError("segmented artifact manifest exceeds its size limit")
        manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
        stored = self.artifact_store.put(
            manifest_bytes,
            expected_sha256=manifest_digest,
            media_type=SEGMENT_MANIFEST_MEDIA_TYPE,
        )
        return SegmentedArtifactManifest(
            manifest_artifact_id=stored.artifact_id,
            media_type=media_type,
            total_size=total_size,
            stream_sha256=digest,
            segments=tuple(segments),
        )

    def verify(
        self,
        manifest_artifact_id: str,
        *,
        expected_stream_sha256: str | None = None,
    ) -> SegmentedArtifactManifest:
        manifest = self.load_manifest(manifest_artifact_id)
        hasher = hashlib.sha256()
        observed_size = 0
        for segment in manifest.segments:
            content = self._read_segment(segment)
            observed_size += len(content)
            hasher.update(content)
        observed_digest = hasher.hexdigest()
        if observed_size != manifest.total_size:
            raise SegmentedArtifactError("segmented artifact total size verification failed")
        if not hmac.compare_digest(observed_digest, manifest.stream_sha256):
            raise SegmentedArtifactError("segmented artifact stream digest verification failed")
        if expected_stream_sha256 is not None and not hmac.compare_digest(
            observed_digest, expected_stream_sha256.lower()
        ):
            raise SegmentedArtifactError("segmented artifact does not match the expected stream digest")
        return manifest

    def load_manifest(self, manifest_artifact_id: str) -> SegmentedArtifactManifest:
        try:
            content = self.artifact_store.read(manifest_artifact_id)
        except (ArtifactStoreError, OSError) as exc:
            raise SegmentedArtifactError("segmented artifact manifest is absent or corrupt") from exc
        if len(content) > self.max_manifest_bytes:
            raise SegmentedArtifactError("segmented artifact manifest exceeds its size limit")
        try:
            raw = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SegmentedArtifactError("segmented artifact manifest is invalid JSON") from exc
        if not isinstance(raw, dict) or canonical_json(raw).encode("utf-8") != content:
            raise SegmentedArtifactError("segmented artifact manifest must use canonical JSON")
        return self._parse_manifest(manifest_artifact_id.lower(), raw)

    def iter_chunks(
        self,
        manifest_artifact_id: str,
        *,
        cursor: SegmentCursor | None = None,
    ) -> Iterator[bytes]:
        """Yield independently verified segments from a bounded cursor.

        Consumers that need whole-stream assurance must call ``verify`` before
        accepting a final result. A parser may retain already parsed records and
        report a typed partial result if a later segment is corrupt.
        """

        manifest = self.load_manifest(manifest_artifact_id)
        selected = cursor or SegmentCursor()
        if selected.sequence > len(manifest.segments):
            raise SegmentedArtifactError("segment cursor is beyond the manifest")
        if selected.sequence == len(manifest.segments):
            if selected.byte_offset:
                raise SegmentedArtifactError("terminal segment cursor must have offset zero")
            return
        for segment in manifest.segments[selected.sequence :]:
            content = self._read_segment(segment)
            if segment.sequence == selected.sequence:
                if selected.byte_offset > len(content):
                    raise SegmentedArtifactError("segment cursor byte offset is beyond the segment")
                content = content[selected.byte_offset :]
            yield content

    def _store_segment(self, content: bytes, segments: list[SegmentReference]) -> None:
        if len(segments) >= self.max_segments:
            raise SegmentedArtifactError("segmented artifact exceeds the configured segment count")
        stored = self.artifact_store.put(content, media_type="application/octet-stream")
        offset = segments[-1].offset + segments[-1].size_bytes if segments else 0
        segments.append(
            SegmentReference(
                sequence=len(segments),
                offset=offset,
                size_bytes=stored.size_bytes,
                sha256=stored.sha256,
                artifact_id=stored.artifact_id,
            )
        )

    def _read_segment(self, segment: SegmentReference) -> bytes:
        if not hmac.compare_digest(segment.artifact_id, segment.sha256):
            raise SegmentedArtifactError(f"segment {segment.sequence} digest verification failed")
        try:
            content = self.artifact_store.read(segment.artifact_id)
        except (ArtifactStoreError, OSError) as exc:
            raise SegmentedArtifactError(f"segment {segment.sequence} is absent or corrupt") from exc
        if len(content) != segment.size_bytes:
            raise SegmentedArtifactError(f"segment {segment.sequence} size verification failed")
        return content

    def _parse_manifest(self, artifact_id: str, raw: dict[str, Any]) -> SegmentedArtifactManifest:
        if set(raw) != {"format", "media_type", "segments", "stream_sha256", "total_size"}:
            raise SegmentedArtifactError("segmented artifact manifest fields are invalid")
        if raw.get("format") != SEGMENTED_ARTIFACT_FORMAT:
            raise SegmentedArtifactError("unsupported segmented artifact manifest format")
        media_type = raw.get("media_type")
        total_size = raw.get("total_size")
        stream_sha256 = raw.get("stream_sha256")
        raw_segments = raw.get("segments")
        if not isinstance(media_type, str):
            raise SegmentedArtifactError("segmented artifact media type is invalid")
        self._validate_media_type(media_type)
        if not isinstance(total_size, int) or isinstance(total_size, bool) or total_size < 0:
            raise SegmentedArtifactError("segmented artifact total size is invalid")
        if total_size > self.max_total_bytes:
            raise SegmentedArtifactError("segmented artifact exceeds the configured total size")
        if not isinstance(stream_sha256, str) or not _DIGEST.fullmatch(stream_sha256):
            raise SegmentedArtifactError("segmented artifact stream digest is invalid")
        if not isinstance(raw_segments, list) or len(raw_segments) > self.max_segments:
            raise SegmentedArtifactError("segmented artifact segment list is invalid")
        segments: list[SegmentReference] = []
        expected_offset = 0
        for sequence, item in enumerate(raw_segments):
            if not isinstance(item, dict) or set(item) != {
                "artifact_id",
                "offset",
                "sequence",
                "sha256",
                "size_bytes",
            }:
                raise SegmentedArtifactError("segmented artifact segment fields are invalid")
            artifact = item.get("artifact_id")
            digest = item.get("sha256")
            offset = item.get("offset")
            size = item.get("size_bytes")
            if item.get("sequence") != sequence or offset != expected_offset:
                raise SegmentedArtifactError("segmented artifact segment order or offset is invalid")
            if not isinstance(size, int) or isinstance(size, bool) or size < 1 or size > self.segment_bytes:
                raise SegmentedArtifactError("segmented artifact segment size is invalid")
            if not isinstance(artifact, str) or not isinstance(digest, str):
                raise SegmentedArtifactError("segmented artifact segment digest is invalid")
            if not _DIGEST.fullmatch(artifact) or not _DIGEST.fullmatch(digest) or artifact != digest:
                raise SegmentedArtifactError("segmented artifact segment is not content addressed")
            segments.append(SegmentReference(sequence, offset, size, digest, artifact))
            expected_offset += size
        if expected_offset != total_size or (total_size == 0) != (len(segments) == 0):
            raise SegmentedArtifactError("segmented artifact manifest size does not match its segments")
        payload = self._manifest_payload(media_type, total_size, stream_sha256, tuple(segments))
        if hashlib.sha256(canonical_json(payload).encode()).hexdigest() != artifact_id:
            raise SegmentedArtifactError("segmented artifact manifest digest mismatch")
        return SegmentedArtifactManifest(artifact_id, media_type, total_size, stream_sha256, tuple(segments))

    @staticmethod
    def _manifest_payload(
        media_type: str,
        total_size: int,
        stream_sha256: str,
        segments: tuple[SegmentReference, ...],
    ) -> dict[str, Any]:
        return {
            "format": SEGMENTED_ARTIFACT_FORMAT,
            "media_type": media_type,
            "segments": [
                {
                    "artifact_id": segment.artifact_id,
                    "offset": segment.offset,
                    "sequence": segment.sequence,
                    "sha256": segment.sha256,
                    "size_bytes": segment.size_bytes,
                }
                for segment in segments
            ],
            "stream_sha256": stream_sha256,
            "total_size": total_size,
        }

    @staticmethod
    def _validate_media_type(media_type: str) -> None:
        if not _MEDIA_TYPE.fullmatch(media_type):
            raise SegmentedArtifactError("segmented artifact media type is invalid")


__all__ = [
    "SEGMENTED_ARTIFACT_FORMAT",
    "SEGMENT_MANIFEST_MEDIA_TYPE",
    "SegmentCursor",
    "SegmentReference",
    "SegmentedArtifactError",
    "SegmentedArtifactManifest",
    "SegmentedArtifactStore",
]
