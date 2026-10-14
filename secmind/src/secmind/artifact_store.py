from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from secmind.schemas import DataView, LogLayer

_FILE_CHUNK_BYTES = 1024 * 1024


class ArtifactStoreError(ValueError):
    pass


@dataclass(frozen=True)
class StoredArtifact:
    artifact_id: str
    storage_ref: str
    sha256: str
    size_bytes: int
    media_type: str


@dataclass(frozen=True)
class ArtifactAccessMetadata:
    """Server-owned access classification for immutable artifact bytes.

    A digest may be referenced by several runs.  The effective view is always
    the most restrictive marker ever attached to those bytes, preventing a
    second, less restrictive alias from downgrading raw evidence.
    """

    artifact_id: str
    data_view: DataView
    log_layer: LogLayer | None
    run_ids: tuple[str, ...]
    globally_bound: bool
    media_type: str
    classified: bool


class ContentAddressedArtifactStore:
    """Immutable local artifact store keyed by the complete SHA-256 digest."""

    def __init__(self, root: Path, *, max_artifact_bytes: int = 16 * 1024 * 1024) -> None:
        self.root = root.resolve()
        self.max_artifact_bytes = max_artifact_bytes
        self.root.mkdir(parents=True, exist_ok=True)

    def put(
        self,
        content: bytes,
        *,
        expected_sha256: str | None = None,
        media_type: str = "application/octet-stream",
        run_id: str | None = None,
        data_view: DataView | str = DataView.RAW_RESTRICTED,
        log_layer: LogLayer | str | None = None,
    ) -> StoredArtifact:
        if len(content) > self.max_artifact_bytes:
            raise ArtifactStoreError("artifact exceeds the configured size limit")
        digest = hashlib.sha256(content).hexdigest()
        if expected_sha256 is not None and not hmac.compare_digest(digest, expected_sha256.lower()):
            raise ArtifactStoreError("artifact digest does not match runner metadata")
        relative = Path("sha256") / digest[:2] / digest
        destination = self.root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            self._verify_file(destination, digest, len(content))
        else:
            fd, temporary = tempfile.mkstemp(prefix=".artifact-", dir=destination.parent)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                temporary_path = Path(temporary)
                self._verify_file(temporary_path, digest, len(content))
                try:
                    temporary_path.replace(destination)
                except FileExistsError:
                    temporary_path.unlink(missing_ok=True)
                    self._verify_file(destination, digest, len(content))
            finally:
                Path(temporary).unlink(missing_ok=True)
        stored = StoredArtifact(
            artifact_id=digest,
            storage_ref=relative.as_posix(),
            sha256=digest,
            size_bytes=len(content),
            media_type=media_type,
        )
        # Ownerless bytes default to RAW_RESTRICTED.  A digest proves byte
        # identity, not disclosure safety, so the store must never invent a
        # global OBSERVABLE owner.
        self.classify(
            digest,
            run_id=run_id,
            data_view=data_view,
            log_layer=log_layer,
            media_type=media_type,
        )
        return stored

    def classify(
        self,
        artifact_id: str,
        *,
        run_id: str | None,
        data_view: DataView | str,
        log_layer: LogLayer | str | None = None,
        media_type: str = "application/octet-stream",
    ) -> ArtifactAccessMetadata:
        """Add an immutable classification marker and return effective policy.

        Markers are independent files rather than one mutable sidecar.  This
        avoids a lost-update race when separate API/worker processes classify
        the same content at the same time.  Reclassification can only make the
        effective view more restrictive; an existing raw marker is never
        overwritten by a later observable marker.
        """

        digest = artifact_id.lower()
        self.path_for(digest)
        try:
            view = data_view if isinstance(data_view, DataView) else DataView(data_view)
            layer = log_layer if isinstance(log_layer, LogLayer) else LogLayer(log_layer) if log_layer else None
        except ValueError as exc:
            raise ArtifactStoreError("invalid artifact access classification") from exc
        if run_id is not None and (
            not run_id.strip() or len(run_id) > 100 or any(ord(character) < 32 for character in run_id)
        ):
            raise ArtifactStoreError("invalid artifact run binding")
        if not media_type or len(media_type) > 200 or any(ord(character) < 32 for character in media_type):
            raise ArtifactStoreError("invalid artifact media type")
        if view == DataView.RAW_RESTRICTED and layer is None:
            layer = LogLayer.RAW_SECURITY
        if (view == DataView.RAW_RESTRICTED) != (layer == LogLayer.RAW_SECURITY):
            raise ArtifactStoreError("raw artifact view and log layer must be classified together")

        payload = {
            "artifact_id": digest,
            "data_view": view.value,
            "log_layer": None if layer is None else layer.value,
            "media_type": media_type,
            "run_id": run_id,
            "schema_version": "1.0",
        }
        serialized = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
        marker_digest = hashlib.sha256(serialized).hexdigest()
        marker_directory = self._metadata_directory(digest)
        marker_directory.mkdir(parents=True, exist_ok=True)
        destination = marker_directory / f"{marker_digest}.json"
        if destination.exists():
            if destination.is_symlink() or not destination.is_file():
                raise ArtifactStoreError("artifact classification metadata is invalid")
            if not hmac.compare_digest(destination.read_bytes(), serialized):
                raise ArtifactStoreError("artifact classification marker collision")
        else:
            fd, temporary = tempfile.mkstemp(prefix=".classification-", dir=marker_directory)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(serialized)
                    handle.flush()
                    os.fsync(handle.fileno())
                temporary_path = Path(temporary)
                try:
                    temporary_path.replace(destination)
                except FileExistsError:
                    temporary_path.unlink(missing_ok=True)
                    if not hmac.compare_digest(destination.read_bytes(), serialized):
                        raise ArtifactStoreError("artifact classification marker collision") from None
            finally:
                Path(temporary).unlink(missing_ok=True)
        return self.metadata_for(digest)

    def metadata_for(self, artifact_id: str) -> ArtifactAccessMetadata:
        """Return the fail-closed effective classification for an artifact."""

        digest = artifact_id.lower()
        self.path_for(digest)
        marker_directory = self._metadata_directory(digest)
        if not marker_directory.exists():
            raise ArtifactStoreError("artifact classification metadata is missing; access is quarantined")
        marker_paths = sorted(marker_directory.glob("*.json"))
        if not marker_paths or len(marker_paths) > 4096:
            raise ArtifactStoreError("artifact classification metadata is invalid")
        markers: list[tuple[DataView, LogLayer | None, str | None, str]] = []
        for marker_path in marker_paths:
            if marker_path.is_symlink() or not marker_path.is_file() or marker_path.stat().st_size > 4096:
                raise ArtifactStoreError("artifact classification metadata is invalid")
            try:
                serialized = marker_path.read_bytes()
                if len(marker_path.stem) != 64 or not hmac.compare_digest(
                    hashlib.sha256(serialized).hexdigest(), marker_path.stem
                ):
                    raise ValueError
                payload = json.loads(serialized.decode("ascii"))
                if payload.get("artifact_id") != digest or payload.get("schema_version") != "1.0":
                    raise ValueError
                view = DataView(payload["data_view"])
                layer = LogLayer(payload["log_layer"]) if payload.get("log_layer") else None
                run_id = payload.get("run_id")
                media_type = payload["media_type"]
                if run_id is not None and (
                    not isinstance(run_id, str)
                    or not run_id
                    or len(run_id) > 100
                    or any(ord(character) < 32 for character in run_id)
                ):
                    raise ValueError
                if (
                    not isinstance(media_type, str)
                    or not media_type
                    or len(media_type) > 200
                    or any(ord(character) < 32 for character in media_type)
                ):
                    raise ValueError
                if (view == DataView.RAW_RESTRICTED) != (layer == LogLayer.RAW_SECURITY):
                    raise ValueError
            except (KeyError, TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise ArtifactStoreError("artifact classification metadata is invalid") from exc
            markers.append((view, layer, run_id, media_type))

        restrictiveness = {
            DataView.PUBLIC_REPORT: 0,
            DataView.OBSERVABLE: 1,
            DataView.RAW_RESTRICTED: 2,
        }
        effective_view = max((item[0] for item in markers), key=restrictiveness.__getitem__)
        effective_markers = [item for item in markers if item[0] == effective_view]
        run_ids = tuple(sorted({item[2] for item in effective_markers if item[2] is not None}))
        # An ownerless raw marker means "quarantined until explicitly bound",
        # not "downloadable by every run".  Global binding is meaningful only
        # for a deliberately observable/public projection.
        globally_bound = effective_view != DataView.RAW_RESTRICTED and any(
            item[2] is None for item in effective_markers
        )
        layer = next((item[1] for item in effective_markers if item[1] is not None), None)
        media_type = sorted(item[3] for item in effective_markers)[0]
        return ArtifactAccessMetadata(
            artifact_id=digest,
            data_view=effective_view,
            log_layer=layer,
            run_ids=run_ids,
            globally_bound=globally_bound,
            media_type=media_type,
            classified=True,
        )

    def read(self, artifact_id: str) -> bytes:
        path = self.path_for(artifact_id)
        size = path.stat().st_size
        if size > self.max_artifact_bytes:
            raise ArtifactStoreError("stored artifact exceeds the configured size limit")
        content = self._read_verified_file(path, artifact_id.lower(), size, collect=True)
        if content is None:  # pragma: no cover - collect=True guarantees bytes
            raise ArtifactStoreError("stored artifact could not be read")
        return content

    def path_for(self, artifact_id: str) -> Path:
        digest = artifact_id.lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ArtifactStoreError("invalid artifact id")
        path = (self.root / "sha256" / digest[:2] / digest).resolve()
        if not path.is_relative_to(self.root):
            raise ArtifactStoreError("invalid artifact path")
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(artifact_id)
        return path

    def _metadata_directory(self, artifact_id: str) -> Path:
        directory = (self.root / "metadata" / "sha256" / artifact_id[:2] / artifact_id).resolve()
        if not directory.is_relative_to(self.root):
            raise ArtifactStoreError("invalid artifact metadata path")
        return directory

    @staticmethod
    def _verify_file(path: Path, expected_sha256: str, expected_size: int) -> None:
        stat = path.stat()
        if stat.st_size != expected_size:
            raise ArtifactStoreError("stored artifact size verification failed")
        ContentAddressedArtifactStore._read_verified_file(
            path,
            expected_sha256,
            expected_size,
            collect=False,
        )

    @staticmethod
    def _read_verified_file(
        path: Path,
        expected_sha256: str,
        expected_size: int,
        *,
        collect: bool,
    ) -> bytes | None:
        hasher = hashlib.sha256()
        observed_size = 0
        content = bytearray() if collect else None
        with path.open("rb") as handle:
            while True:
                remaining = expected_size - observed_size
                chunk = handle.read(min(_FILE_CHUNK_BYTES, remaining + 1))
                if not chunk:
                    break
                observed_size += len(chunk)
                if observed_size > expected_size:
                    raise ArtifactStoreError("stored artifact size verification failed")
                hasher.update(chunk)
                if content is not None:
                    content.extend(chunk)
        if observed_size != expected_size:
            raise ArtifactStoreError("stored artifact size verification failed")
        digest = hasher.hexdigest()
        if not hmac.compare_digest(digest, expected_sha256):
            raise ArtifactStoreError("stored artifact digest verification failed")
        return bytes(content) if content is not None else None
