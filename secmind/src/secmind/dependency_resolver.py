from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable
from typing import Protocol

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from secmind.artifact_store import ArtifactStoreError, ContentAddressedArtifactStore
from secmind.coordinator import ArtifactOwnerRow
from secmind.schemas import ArtifactRef, DependencyBinding


class DependencyResolutionError(ValueError):
    """A dependency artifact failed ownership, integrity, or contract checks."""


class ArtifactOwnershipRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    producer_step_id: str
    output_name: str
    artifact_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size_bytes: int = Field(ge=0)
    media_type: str


class ResolvedDependency(BaseModel):
    """A verified broker handle; it deliberately contains no host path or bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    upstream_step_id: str
    output_name: str
    artifact: ArtifactRef
    mount_mode: str
    input_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class ArtifactOwnershipStore(Protocol):
    def get(self, run_id: str, artifact_id: str) -> ArtifactOwnershipRecord | None: ...


class InMemoryArtifactOwnershipStore:
    """Test/embedded adapter; PostgreSQL ownership remains the production authority."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], ArtifactOwnershipRecord] = {}

    def register(self, record: ArtifactOwnershipRecord) -> None:
        key = (record.run_id, record.artifact_id)
        existing = self._records.get(key)
        if existing is not None and existing != record:
            raise DependencyResolutionError("artifact ownership key was reused with different metadata")
        self._records[key] = record

    def get(self, run_id: str, artifact_id: str) -> ArtifactOwnershipRecord | None:
        return self._records.get((run_id, artifact_id))


class SqlArtifactOwnershipStore:
    """PostgreSQL/SQLite adapter for broker-committed artifact ownership."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def get(self, run_id: str, artifact_id: str) -> ArtifactOwnershipRecord | None:
        with Session(self.engine) as session:
            row = session.scalars(
                select(ArtifactOwnerRow).where(
                    ArtifactOwnerRow.run_id == run_id,
                    ArtifactOwnerRow.artifact_id == artifact_id,
                )
            ).first()
            if row is None:
                return None
            return ArtifactOwnershipRecord(
                run_id=row.run_id,
                producer_step_id=row.producer_step_id,
                output_name=row.output_name,
                artifact_id=row.artifact_id,
                sha256=row.sha256,
                size_bytes=row.size_bytes,
                media_type=row.media_type,
            )


class DependencyResolver:
    def __init__(
        self,
        artifact_store: ContentAddressedArtifactStore,
        ownership_store: ArtifactOwnershipStore,
    ) -> None:
        self.artifact_store = artifact_store
        self.ownership_store = ownership_store

    def resolve(self, run_id: str, binding: DependencyBinding) -> ResolvedDependency:
        artifact_id = (binding.artifact_id or "").lower()
        if len(artifact_id) != 64 or any(char not in "0123456789abcdef" for char in artifact_id):
            raise DependencyResolutionError("dependency binding has no valid immutable artifact id")
        record = self.ownership_store.get(run_id, artifact_id)
        if record is None:
            raise DependencyResolutionError("dependency artifact is not owned by this run")
        if record.producer_step_id != binding.upstream_step_id:
            raise DependencyResolutionError("dependency producer step does not match the binding")
        if record.output_name != binding.output_name:
            raise DependencyResolutionError("dependency output name does not match the binding")
        if not hmac.compare_digest(record.artifact_id, artifact_id) or not hmac.compare_digest(
            record.sha256, artifact_id
        ):
            raise DependencyResolutionError("dependency metadata is not content-addressed")
        if _normalize_media_type(record.media_type) != _normalize_media_type(binding.expected_media_type):
            raise DependencyResolutionError("dependency media type does not match the binding")
        try:
            content = self.artifact_store.read(artifact_id)
        except (ArtifactStoreError, OSError) as exc:
            raise DependencyResolutionError("dependency artifact cannot be read or verified") from exc
        digest = hashlib.sha256(content).hexdigest()
        if not hmac.compare_digest(digest, record.sha256) or len(content) != record.size_bytes:
            raise DependencyResolutionError("dependency artifact integrity check failed")
        self._validate_schema(content, record.media_type, binding.expected_schema)
        artifact = ArtifactRef(
            artifact_id=artifact_id,
            ref=artifact_id,
            sha256=digest,
            size_bytes=len(content),
            media_type=record.media_type,
        )
        input_digest = hashlib.sha256(
            _canonical_json(
                {
                    "run_id": run_id,
                    "upstream_step_id": binding.upstream_step_id,
                    "output_name": binding.output_name,
                    "artifact_id": artifact_id,
                    "sha256": digest,
                    "media_type": record.media_type,
                    "mount_mode": binding.mount_mode,
                    "expected_schema": binding.expected_schema,
                }
            ).encode("utf-8")
        ).hexdigest()
        return ResolvedDependency(
            upstream_step_id=binding.upstream_step_id,
            output_name=binding.output_name,
            artifact=artifact,
            mount_mode=binding.mount_mode,
            input_digest=input_digest,
        )

    def resolve_many(
        self,
        run_id: str,
        bindings: Iterable[DependencyBinding],
    ) -> list[ResolvedDependency]:
        resolved: list[ResolvedDependency] = []
        names: set[str] = set()
        for binding in sorted(bindings, key=lambda item: (item.upstream_step_id, item.output_name)):
            if binding.output_name in names:
                raise DependencyResolutionError("dependency output names must be unique for a consumer step")
            names.add(binding.output_name)
            resolved.append(self.resolve(run_id, binding))
        return resolved

    @staticmethod
    def _validate_schema(content: bytes, media_type: str, schema: dict[str, object]) -> None:
        if not schema:
            return
        normalized = _normalize_media_type(media_type)
        if normalized != "application/json" and not normalized.endswith("+json"):
            raise DependencyResolutionError("dependency schema requires a JSON media type")
        try:
            Draft202012Validator.check_schema(schema)
            payload = json.loads(content)
            Draft202012Validator(schema).validate(payload)
        except SchemaError as exc:
            raise DependencyResolutionError("dependency binding contains an invalid JSON Schema") from exc
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
            raise DependencyResolutionError("dependency artifact does not satisfy its JSON Schema") from exc


def ownership_record(
    *,
    run_id: str,
    producer_step_id: str,
    output_name: str,
    artifact: ArtifactRef,
) -> ArtifactOwnershipRecord:
    if artifact.artifact_id.lower() != artifact.sha256.lower():
        raise DependencyResolutionError("artifact reference is not content-addressed")
    return ArtifactOwnershipRecord(
        run_id=run_id,
        producer_step_id=producer_step_id,
        output_name=output_name,
        artifact_id=artifact.artifact_id.lower(),
        sha256=artifact.sha256.lower(),
        size_bytes=artifact.size_bytes,
        media_type=artifact.media_type,
    )


def _normalize_media_type(value: str) -> str:
    return value.split(";", 1)[0].strip().casefold()


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
