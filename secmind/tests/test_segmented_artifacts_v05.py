from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.ledger import canonical_json
from secmind.segmented_artifacts import (
    SegmentCursor,
    SegmentedArtifactError,
    SegmentedArtifactStore,
    SegmentReference,
)


def _store(tmp_path: Path, *, segment_bytes: int = 4, max_total_bytes: int = 64) -> SegmentedArtifactStore:
    backend = ContentAddressedArtifactStore(tmp_path / "artifacts", max_artifact_bytes=1024 * 1024)
    return SegmentedArtifactStore(
        backend,
        segment_bytes=segment_bytes,
        max_total_bytes=max_total_bytes,
        max_segments=16,
    )


def test_stream_is_split_independently_of_input_chunk_boundaries_and_verified(tmp_path: Path) -> None:
    content = b"abcdefghij"
    store = _store(tmp_path)

    manifest = store.put_stream(
        [content[:1], bytearray(content[1:8]), memoryview(content[8:])],
        media_type="text/plain",
        expected_sha256=hashlib.sha256(content).hexdigest(),
    )

    assert [item.sequence for item in manifest.segments] == [0, 1, 2]
    assert [item.offset for item in manifest.segments] == [0, 4, 8]
    assert [item.size_bytes for item in manifest.segments] == [4, 4, 2]
    assert b"".join(store.iter_chunks(manifest.manifest_artifact_id)) == content
    assert store.verify(manifest.manifest_artifact_id) == manifest


def test_manifest_and_segments_are_deterministic_content_addressed_objects(tmp_path: Path) -> None:
    store = _store(tmp_path)
    content = b"same-stream-content"

    first = store.put_stream([content], media_type="application/x-ndjson")
    second = store.put_stream([content[:3], content[3:]], media_type="application/x-ndjson")

    assert second == first
    assert (
        first.manifest_artifact_id == hashlib.sha256(store.artifact_store.read(first.manifest_artifact_id)).hexdigest()
    )
    assert all(segment.artifact_id == segment.sha256 for segment in first.segments)


def test_manifest_contains_no_raw_log_or_secret_material(tmp_path: Path) -> None:
    store = _store(tmp_path, segment_bytes=32, max_total_bytes=128)
    secret = b"authorization=Bearer competition-secret"  # noqa: S105 - raw restricted fixture

    manifest = store.put_stream([secret], media_type="application/x-ndjson")
    manifest_bytes = store.artifact_store.read(manifest.manifest_artifact_id)

    assert secret not in manifest_bytes
    assert b"competition-secret" not in manifest_bytes
    assert manifest.stream_sha256.encode() in manifest_bytes


def test_cursor_resumes_at_segment_and_byte_offset_without_materializing_whole_stream(tmp_path: Path) -> None:
    store = _store(tmp_path)
    manifest = store.put_stream([b"abcdefghijkl"], media_type="text/plain")

    resumed = b"".join(
        store.iter_chunks(
            manifest.manifest_artifact_id,
            cursor=SegmentCursor(sequence=1, byte_offset=2),
        )
    )

    assert resumed == b"ghijkl"
    with pytest.raises(SegmentedArtifactError, match="beyond"):
        list(store.iter_chunks(manifest.manifest_artifact_id, cursor=SegmentCursor(sequence=1, byte_offset=99)))
    with pytest.raises(SegmentedArtifactError, match="negative"):
        SegmentCursor(sequence=-1)
    with pytest.raises(SegmentedArtifactError, match="terminal"):
        list(
            store.iter_chunks(
                manifest.manifest_artifact_id,
                cursor=SegmentCursor(sequence=len(manifest.segments), byte_offset=1),
            )
        )


def test_empty_stream_has_a_valid_canonical_manifest(tmp_path: Path) -> None:
    store = _store(tmp_path)

    manifest = store.put_stream([], media_type="application/octet-stream")

    assert manifest.total_size == 0
    assert manifest.segments == ()
    assert manifest.stream_sha256 == hashlib.sha256(b"").hexdigest()
    assert list(store.iter_chunks(manifest.manifest_artifact_id)) == []
    assert store.verify(manifest.manifest_artifact_id) == manifest


def test_size_count_digest_chunk_and_media_limits_fail_closed(tmp_path: Path) -> None:
    store = _store(tmp_path, segment_bytes=4, max_total_bytes=8)

    with pytest.raises(SegmentedArtifactError, match="total size"):
        store.put_stream([b"12345678", b"9"])
    with pytest.raises(SegmentedArtifactError, match="stream digest mismatch"):
        store.put_stream([b"ok"], expected_sha256="0" * 64)
    with pytest.raises(SegmentedArtifactError, match="expected stream digest"):
        store.put_stream([b"ok"], expected_sha256="bad")
    with pytest.raises(SegmentedArtifactError, match="non-bytes"):
        store.put_stream(["not-bytes"])  # type: ignore[list-item]
    with pytest.raises(SegmentedArtifactError, match="media type"):
        store.put_stream([b"ok"], media_type="text/plain; password=secret")

    limited = SegmentedArtifactStore(
        store.artifact_store,
        segment_bytes=2,
        max_total_bytes=16,
        max_segments=1,
    )
    with pytest.raises(SegmentedArtifactError, match="segment count"):
        limited.put_stream([b"123"])
    with pytest.raises(ValueError, match="segment size"):
        SegmentedArtifactStore(store.artifact_store, segment_bytes=0)
    with pytest.raises(ValueError, match="limits"):
        SegmentedArtifactStore(store.artifact_store, segment_bytes=4, max_total_bytes=3)

    tiny_manifest = SegmentedArtifactStore(
        store.artifact_store,
        segment_bytes=4,
        max_total_bytes=8,
        max_manifest_bytes=1,
    )
    with pytest.raises(SegmentedArtifactError, match="manifest exceeds"):
        tiny_manifest.put_stream([b"ok"])


def test_corrupt_segment_or_manifest_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    manifest = store.put_stream([b"integrity"], media_type="text/plain")
    segment_path = store.artifact_store.path_for(manifest.segments[0].artifact_id)
    segment_path.write_bytes(b"tampered")

    with pytest.raises(SegmentedArtifactError, match="segment 0"):
        store.verify(manifest.manifest_artifact_id)

    clean = _store(tmp_path / "manifest")
    clean_manifest = clean.put_stream([b"manifest"], media_type="text/plain")
    clean.artifact_store.path_for(clean_manifest.manifest_artifact_id).write_bytes(b"{}")
    with pytest.raises(SegmentedArtifactError, match="manifest"):
        clean.load_manifest(clean_manifest.manifest_artifact_id)


def test_cursor_preserves_verified_prefix_before_later_bad_segment(tmp_path: Path) -> None:
    store = _store(tmp_path)
    manifest = store.put_stream([b"abcdefgh"], media_type="text/plain")
    store.artifact_store.path_for(manifest.segments[1].artifact_id).write_bytes(b"tampered")

    stream = store.iter_chunks(manifest.manifest_artifact_id)
    assert next(stream) == b"abcd"
    with pytest.raises(SegmentedArtifactError, match="segment 1"):
        next(stream)


def test_manifest_parser_rejects_noncanonical_invalid_json_and_missing_objects(tmp_path: Path) -> None:
    store = _store(tmp_path)
    invalid_json = store.artifact_store.put(b"not-json")
    noncanonical = store.artifact_store.put(b'{ "format": "wrong" }')

    with pytest.raises(SegmentedArtifactError, match="invalid JSON"):
        store.load_manifest(invalid_json.artifact_id)
    with pytest.raises(SegmentedArtifactError, match="canonical JSON"):
        store.load_manifest(noncanonical.artifact_id)
    with pytest.raises(SegmentedArtifactError, match="absent or corrupt"):
        store.load_manifest("f" * 64)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"extra": True}), "fields"),
        (lambda value: value.update({"format": "future"}), "unsupported"),
        (lambda value: value.update({"media_type": 7}), "media type"),
        (lambda value: value.update({"total_size": True}), "total size"),
        (lambda value: value.update({"stream_sha256": "bad"}), "stream digest"),
        (lambda value: value.update({"segments": {}}), "segment list"),
        (lambda value: value["segments"][0].update({"sequence": 9}), "order or offset"),
        (lambda value: value["segments"][0].update({"size_bytes": 0}), "segment size"),
        (lambda value: value["segments"][0].update({"sha256": "0" * 64}), "content addressed"),
        (lambda value: value.update({"total_size": value["total_size"] + 1}), "size does not match"),
    ],
)
def test_manifest_structure_is_strictly_validated(tmp_path: Path, mutation, message: str) -> None:  # type: ignore[no-untyped-def]
    store = _store(tmp_path)
    manifest = store.put_stream([b"data"], media_type="text/plain")
    payload = json.loads(store.artifact_store.read(manifest.manifest_artifact_id))
    mutation(payload)
    corrupted = store.artifact_store.put(canonical_json(payload).encode())

    with pytest.raises(SegmentedArtifactError, match=message):
        store.load_manifest(corrupted.artifact_id)


def test_verify_rejects_wrong_expected_digest_and_wrong_declared_stream_digest(tmp_path: Path) -> None:
    store = _store(tmp_path)
    manifest = store.put_stream([b"data"], media_type="text/plain")
    with pytest.raises(SegmentedArtifactError, match="expected stream digest"):
        store.verify(manifest.manifest_artifact_id, expected_stream_sha256="0" * 64)

    payload = json.loads(store.artifact_store.read(manifest.manifest_artifact_id))
    payload["stream_sha256"] = "0" * 64
    wrong = store.artifact_store.put(canonical_json(payload).encode())
    with pytest.raises(SegmentedArtifactError, match="stream digest verification"):
        store.verify(wrong.artifact_id)


def test_segment_offset_uses_only_the_previous_reference(tmp_path: Path) -> None:
    store = _store(tmp_path)
    segments: list[SegmentReference] = []
    store._store_segment(b"abcd", segments)

    class NonIterableSegments(list[SegmentReference]):
        def __iter__(self):  # type: ignore[no-untyped-def]
            raise AssertionError("offset calculation must not traverse prior segments")

    guarded = NonIterableSegments(segments)
    store._store_segment(b"ef", guarded)

    assert guarded[-1].offset == 4


def test_segment_reference_digest_is_checked_before_store_read(tmp_path: Path, monkeypatch) -> None:
    store = _store(tmp_path)
    manifest = store.put_stream([b"data"], media_type="text/plain")
    original = manifest.segments[0]
    invalid = SegmentReference(
        sequence=original.sequence,
        offset=original.offset,
        size_bytes=original.size_bytes,
        sha256="0" * 64,
        artifact_id=original.artifact_id,
    )
    reads = 0

    def unexpected_read(_artifact_id: str) -> bytes:
        nonlocal reads
        reads += 1
        return b"data"

    monkeypatch.setattr(store.artifact_store, "read", unexpected_read)
    with pytest.raises(SegmentedArtifactError, match="digest verification"):
        store._read_segment(invalid)
    assert reads == 0
