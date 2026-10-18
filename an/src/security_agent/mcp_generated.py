"""Persisted, declarative MCP tool proposals.

The model may propose a small parser when an input format is not covered.  A
proposal is data (never executable Python): only the operations implemented by
the local adapter are accepted.  This keeps reuse useful without allowing a
model response to become arbitrary code execution.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class GeneratedToolProposal(BaseModel):
    tool_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{2,63}$")
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(min_length=3, max_length=1000)
    file_extensions: list[str] = Field(min_length=1, max_length=20)
    operation: Literal["text_regex", "binary_strings", "json_keys"]
    patterns: list[str] = Field(default_factory=list, max_length=20)
    rationale: str = Field(min_length=1, max_length=2000)

    @field_validator("file_extensions")
    @classmethod
    def normalize_extensions(cls, value: list[str]) -> list[str]:
        normalized = []
        for item in value:
            item = item.strip().casefold()
            if not item or len(item) > 16 or (item != "*" and not item.startswith(".")):
                raise ValueError("file_extensions must contain suffixes such as .dat or *")
            normalized.append(item)
        return list(dict.fromkeys(normalized))

    @field_validator("patterns")
    @classmethod
    def validate_patterns(cls, value: list[str]) -> list[str]:
        cleaned = []
        for pattern in value:
            pattern = pattern.strip()
            if len(pattern) > 300:
                raise ValueError("generated regex is too long")
            re.compile(pattern)
            cleaned.append(pattern)
        return cleaned


class GeneratedMCPStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, proposal: GeneratedToolProposal, *, source_run_id: str) -> Path:
        payload = {
            "schema_version": "1.0",
            "kind": "declarative_generated_tool",
            "source_run_id": source_run_id,
            "proposal": proposal.model_dump(mode="json"),
        }
        path = self.root / f"{proposal.tool_id}.mcp.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(path)
        return path

    def list(self) -> list[dict[str, Any]]:
        result = []
        for path in sorted(self.root.glob("*.mcp.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                proposal = GeneratedToolProposal.model_validate(payload.get("proposal", {}))
            except (OSError, ValueError, TypeError):
                continue
            result.append({"path": str(path), "source_run_id": payload.get("source_run_id"), **proposal.model_dump(mode="json")})
        return result

    def proposals(self) -> list[GeneratedToolProposal]:
        return [GeneratedToolProposal.model_validate(item) for item in self.list()]
