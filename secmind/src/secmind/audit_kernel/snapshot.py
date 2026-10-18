from __future__ import annotations

from typing import Self

from pydantic import Field, field_validator, model_validator

from secmind.audit_kernel.contracts import (
    SHA256_PATTERN,
    AuditContract,
    canonical_path,
    content_digest,
)
from secmind.live_source_review import SourceUnit


class SnapshotFile(AuditContract):
    path: str = Field(min_length=1, max_length=1024)
    sha256: str = Field(pattern=SHA256_PATTERN)
    size: int = Field(ge=0)
    language: str = Field(min_length=1, max_length=64)

    @field_validator("path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        return canonical_path(value)


class WorkspaceSnapshot(AuditContract):
    snapshot_id: str = Field(pattern=r"^snapshot-[a-f0-9]{64}$")
    input_manifest_digest: str = Field(pattern=SHA256_PATTERN)
    authorized_scope: tuple[str, ...] = Field(min_length=1)
    files: tuple[SnapshotFile, ...] = Field(min_length=1)
    snapshot_digest: str = Field(pattern=SHA256_PATTERN)

    @field_validator("authorized_scope")
    @classmethod
    def normalize_scope(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(values)))
        if not normalized:
            raise ValueError("authorized_scope cannot be empty")
        return normalized

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        payload = self.model_dump(mode="json", exclude={"snapshot_id", "snapshot_digest"})
        digest = content_digest(payload)
        if self.snapshot_id != f"snapshot-{digest}" or self.snapshot_digest != digest:
            raise ValueError("workspace snapshot digest is invalid")
        return self

    @classmethod
    def build(
        cls,
        sources: list[SourceUnit],
        *,
        authorized_scope: tuple[str, ...] = (".",),
    ) -> Self:
        if not sources:
            raise ValueError("workspace snapshot requires at least one source")
        files = tuple(
            SnapshotFile(
                path=source.path,
                sha256=source.sha256,
                size=len(source.content.encode("utf-8")),
                language="java" if source.path.lower().endswith(".java") else "text",
            )
            for source in sorted(sources, key=lambda item: (item.path, item.sha256))
        )
        manifest_digest = content_digest(
            {"files": [{"path": item.path, "sha256": item.sha256, "size": item.size} for item in files]}
        )
        payload = {
            "input_manifest_digest": manifest_digest,
            "authorized_scope": list(authorized_scope),
            "files": [item.model_dump(mode="json") for item in files],
        }
        digest = content_digest(payload)
        return cls(
            snapshot_id=f"snapshot-{digest}",
            input_manifest_digest=manifest_digest,
            authorized_scope=authorized_scope,
            files=files,
            snapshot_digest=digest,
        )


__all__ = ["SnapshotFile", "WorkspaceSnapshot"]
