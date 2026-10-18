from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from secmind.api import create_app
from secmind.artifact_store import ArtifactStoreError, ContentAddressedArtifactStore
from secmind.schemas import AgentState, DataView, InputArtifact, LogLayer, StepRuntime, TaskRequest
from secmind.unit_of_work import DataAccessEventRow


def _marker_directory(store: ContentAddressedArtifactStore, artifact_id: str) -> Path:
    return store.root / "metadata" / "sha256" / artifact_id[:2] / artifact_id


def _replace_markers(
    store: ContentAddressedArtifactStore,
    artifact_id: str,
    serialized: bytes,
    *,
    filename: str | None = None,
) -> Path:
    directory = _marker_directory(store, artifact_id)
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True)
    marker = directory / f"{filename or hashlib.sha256(serialized).hexdigest()}.json"
    marker.write_bytes(serialized)
    return marker


def _valid_marker_payload(store: ContentAddressedArtifactStore, artifact_id: str) -> dict[str, Any]:
    marker = next(_marker_directory(store, artifact_id).glob("*.json"))
    payload = json.loads(marker.read_text(encoding="ascii"))
    assert isinstance(payload, dict)
    return payload


def test_artifact_classification_is_monotonic_and_run_bound(tmp_path) -> None:
    store = ContentAddressedArtifactStore(tmp_path / "artifacts")
    content = b'{"message":"raw security log"}\n'
    stored = store.put(
        content,
        media_type="application/x-ndjson",
        run_id="run-a",
        data_view=DataView.RAW_RESTRICTED,
        log_layer=LogLayer.RAW_SECURITY,
    )

    metadata = store.metadata_for(stored.artifact_id)
    assert metadata.data_view == DataView.RAW_RESTRICTED
    assert metadata.log_layer == LogLayer.RAW_SECURITY
    assert metadata.run_ids == ("run-a",)
    assert metadata.globally_bound is False

    # A later generic/observable alias cannot downgrade the same CAS bytes or
    # make their raw view globally accessible.
    store.put(content, media_type="application/octet-stream")
    metadata = store.metadata_for(stored.artifact_id)
    assert metadata.data_view == DataView.RAW_RESTRICTED
    assert metadata.run_ids == ("run-a",)
    assert metadata.globally_bound is False

    store.classify(
        stored.artifact_id,
        run_id="run-b",
        data_view=DataView.RAW_RESTRICTED,
        log_layer=LogLayer.RAW_SECURITY,
        media_type="application/x-ndjson",
    )
    assert store.metadata_for(stored.artifact_id).run_ids == ("run-a", "run-b")

    marker = next((store.root / "metadata" / "sha256" / stored.artifact_id[:2] / stored.artifact_id).glob("*.json"))
    marker.write_bytes(marker.read_bytes() + b" ")
    with pytest.raises(ValueError, match="classification metadata"):
        store.metadata_for(stored.artifact_id)


def test_artifact_put_recovers_when_an_identical_writer_wins_replace_race(tmp_path, monkeypatch) -> None:
    store = ContentAddressedArtifactStore(tmp_path / "race")
    content = b"concurrent immutable artifact"
    digest = hashlib.sha256(content).hexdigest()
    original_replace = Path.replace

    def replace_after_winner(path: Path, target: Path) -> Path:
        destination = Path(target)
        if destination.name == digest:
            destination.write_bytes(path.read_bytes())
            raise FileExistsError(destination)
        return original_replace(path, destination)

    monkeypatch.setattr(Path, "replace", replace_after_winner)
    stored = store.put(content)
    assert stored.artifact_id == digest
    assert store.read(digest) == content


@pytest.mark.parametrize("field,value", [("data_view", "invalid"), ("log_layer", "invalid")])
def test_classify_rejects_unknown_view_or_layer(tmp_path, field: str, value: str) -> None:
    store = ContentAddressedArtifactStore(tmp_path / field)
    stored = store.put(b"classification")
    values: dict[str, Any] = {"data_view": DataView.OBSERVABLE, "log_layer": None}
    values[field] = value
    with pytest.raises(ArtifactStoreError, match="invalid artifact access classification"):
        store.classify(stored.artifact_id, run_id="run", media_type="text/plain", **values)


@pytest.mark.parametrize("run_id", ["", "   ", "r" * 101, "run\x00id"])
def test_classify_rejects_invalid_run_binding(tmp_path, run_id: str) -> None:
    store = ContentAddressedArtifactStore(tmp_path / hashlib.sha256(run_id.encode()).hexdigest())
    stored = store.put(b"run binding")
    with pytest.raises(ArtifactStoreError, match="invalid artifact run binding"):
        store.classify(stored.artifact_id, run_id=run_id, data_view=DataView.OBSERVABLE)


@pytest.mark.parametrize("media_type", ["", "a" * 201, "text/plain\x00"])
def test_classify_rejects_invalid_media_type(tmp_path, media_type: str) -> None:
    store = ContentAddressedArtifactStore(tmp_path / hashlib.sha256(media_type.encode()).hexdigest())
    stored = store.put(b"media binding")
    with pytest.raises(ArtifactStoreError, match="invalid artifact media type"):
        store.classify(
            stored.artifact_id,
            run_id="run",
            data_view=DataView.OBSERVABLE,
            media_type=media_type,
        )


def test_raw_classification_defaults_layer_and_rejects_observable_raw_layer(tmp_path) -> None:
    store = ContentAddressedArtifactStore(tmp_path / "raw-default")
    stored = store.put(b"raw default")
    metadata = store.classify(
        stored.artifact_id,
        run_id="run",
        data_view=DataView.RAW_RESTRICTED,
        media_type="text/plain",
    )
    assert metadata.log_layer == LogLayer.RAW_SECURITY
    with pytest.raises(ArtifactStoreError, match="view and log layer"):
        store.classify(
            stored.artifact_id,
            run_id="run",
            data_view=DataView.OBSERVABLE,
            log_layer=LogLayer.RAW_SECURITY,
        )


def test_classify_reuses_identical_marker_and_detects_existing_collision_or_non_file(tmp_path) -> None:
    store = ContentAddressedArtifactStore(tmp_path / "existing-marker")
    stored = store.put(b"existing marker", media_type="text/plain")
    first = store.classify(
        stored.artifact_id,
        run_id=None,
        data_view=DataView.OBSERVABLE,
        media_type="text/plain",
    )
    assert first.classified
    marker = next(_marker_directory(store, stored.artifact_id).glob("*.json"))
    original = marker.read_bytes()

    marker.write_bytes(b"different marker")
    with pytest.raises(ArtifactStoreError, match="marker collision|metadata is invalid"):
        store.classify(
            stored.artifact_id,
            run_id=None,
            data_view=DataView.OBSERVABLE,
            media_type="text/plain",
        )

    marker.unlink()
    marker.mkdir()
    with pytest.raises(ArtifactStoreError, match="metadata is invalid"):
        store.classify(
            stored.artifact_id,
            run_id=None,
            data_view=DataView.OBSERVABLE,
            media_type="text/plain",
        )
    marker.rmdir()
    marker.write_bytes(original)


@pytest.mark.parametrize("winner_matches", [True, False])
def test_classify_handles_replace_race_and_rejects_late_collision(tmp_path, monkeypatch, winner_matches: bool) -> None:
    store = ContentAddressedArtifactStore(tmp_path / f"marker-race-{winner_matches}")
    stored = store.put(b"classification race", data_view=DataView.OBSERVABLE)
    original_replace = Path.replace

    def replace_after_winner(path: Path, target: Path) -> Path:
        destination = Path(target)
        if destination.suffix == ".json" and not destination.exists():
            destination.write_bytes(path.read_bytes() if winner_matches else b"different winner")
            raise FileExistsError(destination)
        return original_replace(path, destination)

    monkeypatch.setattr(Path, "replace", replace_after_winner)
    if winner_matches:
        metadata = store.classify(
            stored.artifact_id,
            run_id="concurrent-run",
            data_view=DataView.OBSERVABLE,
        )
        assert metadata.run_ids == ("concurrent-run",)
    else:
        with pytest.raises(ArtifactStoreError, match="marker collision"):
            store.classify(
                stored.artifact_id,
                run_id="concurrent-run",
                data_view=DataView.OBSERVABLE,
            )


def test_metadata_for_quarantines_legacy_artifact_without_markers(tmp_path) -> None:
    store = ContentAddressedArtifactStore(tmp_path / "legacy")
    stored = store.put(b"legacy artifact")
    shutil.rmtree(_marker_directory(store, stored.artifact_id))
    with pytest.raises(ArtifactStoreError, match="classification metadata is missing; access is quarantined"):
        store.metadata_for(stored.artifact_id)


@pytest.mark.parametrize("too_many", [False, True])
def test_metadata_for_rejects_empty_or_excessive_marker_set(tmp_path, too_many: bool) -> None:
    store = ContentAddressedArtifactStore(tmp_path / f"marker-count-{too_many}")
    stored = store.put(b"marker count")
    directory = _marker_directory(store, stored.artifact_id)
    shutil.rmtree(directory)
    directory.mkdir(parents=True)
    if too_many:
        for index in range(4097):
            (directory / f"{index:064x}.json").touch()
    with pytest.raises(ArtifactStoreError, match="metadata is invalid"):
        store.metadata_for(stored.artifact_id)


@pytest.mark.parametrize("kind", ["oversized", "directory", "symlink"])
def test_metadata_for_rejects_unsafe_marker_file(tmp_path, kind: str) -> None:
    store = ContentAddressedArtifactStore(tmp_path / kind)
    stored = store.put(b"unsafe marker file")
    directory = _marker_directory(store, stored.artifact_id)
    shutil.rmtree(directory)
    directory.mkdir(parents=True)
    marker = directory / f"{'a' * 64}.json"
    if kind == "oversized":
        marker.write_bytes(b"x" * 4097)
    elif kind == "directory":
        marker.mkdir()
    else:
        target = directory / "target"
        target.write_text("not a marker", encoding="ascii")
        try:
            marker.symlink_to(target)
        except OSError as exc:
            pytest.skip(f"symlinks unavailable: {exc}")
    with pytest.raises(ArtifactStoreError, match="metadata is invalid"):
        store.metadata_for(stored.artifact_id)


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("artifact_id", "f" * 64),
        ("schema_version", "2.0"),
        ("data_view", "unknown"),
        ("log_layer", "L99"),
        ("delete:data_view", None),
        ("delete:media_type", None),
        ("run_id", 7),
        ("run_id", ""),
        ("run_id", "r" * 101),
        ("run_id", "run\x00id"),
        ("media_type", 7),
        ("media_type", ""),
        ("media_type", "m" * 201),
        ("media_type", "text/plain\x00"),
        ("raw_without_layer", None),
        ("observable_raw_layer", None),
    ],
)
def test_metadata_for_rejects_structurally_invalid_signed_marker(tmp_path, mutation: str, value: Any) -> None:
    store = ContentAddressedArtifactStore(tmp_path / hashlib.sha256(repr((mutation, value)).encode()).hexdigest())
    stored = store.put(b"structured marker")
    payload = _valid_marker_payload(store, stored.artifact_id)
    if mutation.startswith("delete:"):
        del payload[mutation.partition(":")[2]]
    elif mutation == "raw_without_layer":
        payload.update(data_view=DataView.RAW_RESTRICTED.value, log_layer=None)
    elif mutation == "observable_raw_layer":
        payload.update(data_view=DataView.OBSERVABLE.value, log_layer=LogLayer.RAW_SECURITY.value)
    else:
        payload[mutation] = value
    serialized = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    _replace_markers(store, stored.artifact_id, serialized)
    with pytest.raises(ArtifactStoreError, match="metadata is invalid"):
        store.metadata_for(stored.artifact_id)


@pytest.mark.parametrize(
    ("serialized", "filename"),
    [
        (b"not-json", None),
        (b"\xff", None),
        (b"{}", "short-name"),
        (b"{}", "0" * 64),
    ],
)
def test_metadata_for_rejects_invalid_encoding_json_or_marker_digest(
    tmp_path, serialized: bytes, filename: str | None
) -> None:
    store = ContentAddressedArtifactStore(tmp_path / hashlib.sha256(serialized + str(filename).encode()).hexdigest())
    stored = store.put(b"invalid marker serialization")
    _replace_markers(store, stored.artifact_id, serialized, filename=filename)
    with pytest.raises(ArtifactStoreError, match="metadata is invalid"):
        store.metadata_for(stored.artifact_id)


def test_artifact_and_metadata_paths_reject_resolved_escape(tmp_path, monkeypatch) -> None:
    store = ContentAddressedArtifactStore(tmp_path / "escape")
    stored = store.put(b"path escape")
    original_resolve = Path.resolve
    outside = tmp_path / "outside"

    def escape_content(path: Path, *args: Any, **kwargs: Any) -> Path:
        if path.name == stored.artifact_id and "metadata" not in path.parts:
            return outside
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", escape_content)
    with pytest.raises(ArtifactStoreError, match="invalid artifact path"):
        store.path_for(stored.artifact_id)

    def escape_metadata(path: Path, *args: Any, **kwargs: Any) -> Path:
        if "metadata" in path.parts:
            return outside
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", escape_metadata)
    with pytest.raises(ArtifactStoreError, match="invalid artifact metadata path"):
        store._metadata_directory(stored.artifact_id)


def test_raw_cas_download_requires_data_view_purpose_run_binding_and_audit(settings) -> None:
    app = create_app(settings)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        service = app.state.runtime.service
        assert service.unit_of_work is not None
        raw = service.artifact_store.put(
            b'{"authorization":"Bearer synthetic-secret-token","event":"login"}\n',
            media_type="application/x-ndjson",
            run_id="run-raw-owner",
            data_view=DataView.RAW_RESTRICTED,
            log_layer=LogLayer.RAW_SECURITY,
        )
        owner_state = AgentState(
            run_id="run-raw-owner",
            task=TaskRequest(objective="analyze raw security log"),
            input_artifacts=[
                InputArtifact(
                    artifact_id=raw.artifact_id,
                    original_name="auth.jsonl",
                    relative_path="auth.jsonl",
                    sha256=raw.sha256,
                    size_bytes=raw.size_bytes,
                    media_type=raw.media_type,
                )
            ],
            step_runtime={"timeline": StepRuntime(step_id="timeline", artifact_ids=[raw.artifact_id])},
        )
        other_state = AgentState(
            run_id="run-other",
            task=TaskRequest(objective="analyze another run"),
            step_runtime={"timeline": StepRuntime(step_id="timeline", artifact_ids=[raw.artifact_id])},
        )
        assert service.unit_of_work.submit_run(owner_state)
        assert service.unit_of_work.submit_run(other_state)

        base = f"/api/v1/runs/{owner_state.run_id}/artifacts/{raw.artifact_id}"
        assert client.get(base).status_code == 403
        assert client.get(base, params={"view": "observable"}).status_code == 403
        assert client.get(base, params={"view": "raw_restricted"}).status_code == 403

        synthetic_secret = "ghp_abcdefghijklmnopqrstuvwxyz123456"  # noqa: S105
        downloaded = client.get(
            base,
            params={"view": "raw_restricted"},
            headers={"X-SecMind-Access-Purpose": f"incident review {synthetic_secret}"},
        )
        assert downloaded.status_code == 200
        assert downloaded.content.startswith(b'{"authorization"')
        assert downloaded.headers["cache-control"] == "private, no-store"
        assert downloaded.headers["x-secmind-data-view"] == "raw_restricted"
        assert downloaded.headers["x-secmind-access-id"]
        assert "etag" not in downloaded.headers

        cross_run = client.get(
            f"/api/v1/runs/{other_state.run_id}/artifacts/{raw.artifact_id}",
            params={"view": "raw_restricted"},
            headers={"X-SecMind-Access-Purpose": "unrelated review"},
        )
        assert cross_run.status_code == 403

        with Session(service.unit_of_work.engine) as session:
            events = session.scalars(
                select(DataAccessEventRow).order_by(DataAccessEventRow.created_at, DataAccessEventRow.access_id)
            ).all()
        assert len(events) == 5
        assert sum("decision=allowed" in item.purpose for item in events) == 1
        assert any("EXPLICIT_RAW_VIEW_REQUIRED" in item.purpose for item in events)
        assert any("RAW_ACCESS_PURPOSE_REQUIRED" in item.purpose for item in events)
        assert any("CROSS_RUN_ACCESS_DENIED" in item.purpose for item in events)
        assert synthetic_secret not in "\n".join(item.purpose for item in events)


def test_input_digest_is_restricted_during_sidecar_rolling_upgrade(settings) -> None:
    app = create_app(settings)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        service = app.state.runtime.service
        assert service.unit_of_work is not None
        legacy = service.artifact_store.put(b"legacy raw log", media_type="text/plain")
        state = AgentState(
            run_id="run-legacy-raw",
            task=TaskRequest(objective="analyze legacy log"),
            input_artifacts=[
                InputArtifact(
                    original_name="legacy.log",
                    relative_path="legacy.log",
                    sha256=legacy.sha256,
                    size_bytes=legacy.size_bytes,
                    media_type=legacy.media_type,
                )
            ],
            step_runtime={"timeline": StepRuntime(step_id="timeline", artifact_ids=[legacy.artifact_id])},
        )
        assert service.unit_of_work.submit_run(state)

        endpoint = f"/api/v1/runs/{state.run_id}/artifacts/{legacy.artifact_id}"
        assert client.get(endpoint).status_code == 403
        allowed = client.get(
            endpoint,
            params={"view": "raw_restricted"},
            headers={"X-SecMind-Access-Purpose": "rolling upgrade evidence review"},
        )
        assert allowed.status_code == 200
        assert allowed.headers["x-secmind-data-view"] == "raw_restricted"


def test_ingested_input_uuid_is_downloadable_by_its_immutable_digest(settings) -> None:
    app = create_app(settings)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        service = app.state.runtime.service
        content = b"print('immutable input')\n"
        upload = client.post("/api/v1/uploads", files={"file": ("app.py", content)})
        assert upload.status_code == 201
        submitted = client.post(
            "/api/v1/tasks",
            json={
                "objective": "audit immutable input",
                "attachments": [{"ref": upload.json()["ref"]}],
            },
        )
        assert submitted.status_code == 202
        run_id = submitted.json()["run_id"]
        for _ in range(150):
            state = service.state(run_id)
            if state.status.value in {"completed", "partial", "failed", "denied", "recovery_required"}:
                break
            time.sleep(0.02)
        input_artifact = state.input_artifacts[0]
        assert input_artifact.artifact_id != input_artifact.sha256

        endpoint = f"/api/v1/runs/{run_id}/artifacts/{input_artifact.sha256}"
        response = client.get(
            endpoint,
            params={"view": "raw_restricted"},
            headers={"X-SecMind-Access-Purpose": "authorized source review"},
        )
        assert response.status_code == 200
        assert response.content == content
        assert response.headers["x-secmind-data-view"] == "raw_restricted"


def test_artifact_read_uses_one_bounded_streaming_pass(tmp_path: Path, monkeypatch) -> None:
    store = ContentAddressedArtifactStore(tmp_path / "streaming", max_artifact_bytes=2 * 1024 * 1024)
    content = b"bounded-read" * 100_000
    artifact = store.put(content)
    artifact_path = store.path_for(artifact.artifact_id)
    original_read_bytes = Path.read_bytes
    whole_file_reads: list[Path] = []

    def tracked_read_bytes(path: Path) -> bytes:
        if path == artifact_path:
            whole_file_reads.append(path)
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", tracked_read_bytes)

    assert store.read(artifact.artifact_id) == content
    assert whole_file_reads == []


def test_artifact_read_rejects_stored_object_over_configured_limit(tmp_path: Path) -> None:
    store = ContentAddressedArtifactStore(tmp_path / "bounded", max_artifact_bytes=32)
    artifact = store.put(b"small")
    store.path_for(artifact.artifact_id).write_bytes(b"x" * 33)

    with pytest.raises(ArtifactStoreError, match="configured size limit"):
        store.read(artifact.artifact_id)
