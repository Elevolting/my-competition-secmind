from __future__ import annotations

from collections.abc import Iterable
from importlib.resources import files
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from secmind.prompting.contracts import PromptRole, PromptSeed, PromptSeedStatus, canonical_digest


class PromptCatalogError(ValueError):
    """The reviewed prompt catalog is missing, ambiguous, or tampered with."""


class _CatalogDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(pattern=r"^1\.0$")
    catalog_version: str = Field(min_length=1, max_length=80)
    status: str = Field(min_length=1, max_length=30)
    total_templates: int = Field(ge=1, le=500)
    entries: list[PromptSeed]

    @model_validator(mode="after")
    def total_matches(self) -> _CatalogDocument:
        if len(self.entries) != self.total_templates:
            raise ValueError("catalog total_templates does not match entries")
        return self


class PromptCatalog:
    """Immutable prompt metadata and reviewed strategy assets."""

    def __init__(self, *, catalog_version: str, status: str, seeds: Iterable[PromptSeed]) -> None:
        catalog: dict[tuple[str, str], PromptSeed] = {}
        for seed in seeds:
            key = (seed.template_id, seed.version)
            if key in catalog:
                raise PromptCatalogError(f"duplicate prompt seed: {seed.template_id}@{seed.version}")
            catalog[key] = seed
        if not catalog:
            raise PromptCatalogError("prompt catalog cannot be empty")
        self.catalog_version = catalog_version
        self.status = status
        self._seeds = MappingProxyType(catalog)

    @classmethod
    def load(cls, path: Path) -> PromptCatalog:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise PromptCatalogError("prompt catalog cannot be read") from exc
        if len(raw) > 2_000_000:
            raise PromptCatalogError("prompt catalog exceeds the reviewed size limit")
        return cls._load_document(raw, lambda ref: cls._read_local_strategy(path.parent, ref))

    @classmethod
    def builtin(cls) -> PromptCatalog:
        root = files("secmind").joinpath("prompt_assets", "v0.7")
        try:
            raw = root.joinpath("catalog.yaml").read_bytes()
        except OSError as exc:
            raise PromptCatalogError("built-in prompt catalog cannot be read") from exc
        return cls._load_document(raw, lambda ref: root.joinpath(*PurePosixPath(ref).parts).read_bytes())

    @classmethod
    def _load_document(cls, raw: bytes, strategy_reader: Any) -> PromptCatalog:
        try:
            payload = yaml.safe_load(raw.decode("utf-8"))
            if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
                raise ValueError("prompt catalog root is invalid")
            for entry in payload["entries"]:
                if not isinstance(entry, dict):
                    continue
                ref = cls._safe_strategy_ref(str(entry.get("strategy_ref", "")))
                if (entry.get("strategy_body") or "").strip():
                    continue
                if entry.get("status") not in {"reviewed", "shadow", "approved"}:
                    # Draft metadata may intentionally precede its strategy asset.
                    # Once reviewed, content becomes mandatory and load failures
                    # must fail closed rather than silently downgrading the seed.
                    continue
                strategy_raw = strategy_reader(ref)
                if len(strategy_raw) > 32_000:
                    raise ValueError("prompt strategy exceeds the reviewed size limit")
                body = strategy_raw.decode("utf-8").strip()
                if not body:
                    raise ValueError("prompt strategy cannot be empty")
                entry["strategy_body"] = body
            document = _CatalogDocument.model_validate(payload)
        except (OSError, UnicodeDecodeError, yaml.YAMLError, ValueError, TypeError) as exc:
            raise PromptCatalogError("prompt catalog failed schema validation") from exc
        return cls(
            catalog_version=document.catalog_version,
            status=document.status,
            seeds=document.entries,
        )

    @staticmethod
    def _safe_strategy_ref(value: str) -> str:
        normalized = value.replace("\\", "/")
        path = PurePosixPath(normalized)
        if (
            path.is_absolute()
            or not normalized.startswith("strategies/")
            or path.suffix.casefold() != ".md"
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("prompt strategy reference is not a safe relative Markdown path")
        return path.as_posix()

    @staticmethod
    def _read_local_strategy(root: Path, ref: str) -> bytes:
        base = root.resolve()
        target = (base / Path(*PurePosixPath(ref).parts)).resolve()
        if not target.is_relative_to(base) or not target.is_file():
            raise OSError("prompt strategy is outside the catalog or missing")
        return target.read_bytes()

    @property
    def digest(self) -> str:
        return canonical_digest(
            {
                "catalog_version": self.catalog_version,
                "status": self.status,
                "seeds": [seed.model_dump(mode="json") for seed in self.seeds()],
            }
        )

    def seeds(self, *, role: PromptRole | None = None) -> tuple[PromptSeed, ...]:
        values = tuple(self._seeds.values())
        if role is not None:
            values = tuple(seed for seed in values if seed.role == role)
        return tuple(sorted(values, key=lambda seed: (seed.template_id, seed.version)))

    def get(self, template_id: str, version: str) -> PromptSeed:
        try:
            return self._seeds[(template_id, version)]
        except KeyError as exc:
            raise PromptCatalogError(f"unknown prompt seed: {template_id}@{version}") from exc

    def manifest(self, *, include_strategy_body: bool = False) -> list[dict[str, Any]]:
        manifest: list[dict[str, Any]] = []
        for seed in self.seeds():
            item = seed.model_dump(mode="json", exclude_none=True)
            if not include_strategy_body:
                item.pop("strategy_body", None)
            item["digest"] = seed.seed_digest
            item["content_ready"] = seed.has_strategy_content
            manifest.append(item)
        return manifest

    def readiness(self) -> dict[str, int | str]:
        counts = {status.value: 0 for status in PromptSeedStatus}
        content_ready = 0
        for seed in self.seeds():
            counts[seed.status.value] += 1
            content_ready += int(seed.has_strategy_content)
        return {
            "catalog_version": self.catalog_version,
            "catalog_digest": self.digest,
            "total": len(self._seeds),
            "content_ready": content_ready,
            **counts,
        }

    def verify_digest(self, expected: str) -> bool:
        return bool(expected) and self.digest == expected


__all__ = ["PromptCatalog", "PromptCatalogError"]
