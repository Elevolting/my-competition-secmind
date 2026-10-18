"""Built-in project inventory adapter."""

# ruff: noqa: F401,F403,F405
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from secmind.language_registry import LANGUAGE_REGISTRY_VERSION, LANGUAGE_SUFFIXES
from secmind.schemas import *
from secmind.tooling.builtin_python import BanditTool
from secmind.tooling.core import DEPENDENCY_FILES, BaseTool, ToolError, public_evidence_id


class ProjectInventoryTool(BaseTool):
    manifest = ToolManifest(
        name="project_inventory",
        version="1",
        description="Inventory source languages and dependency manifests without executing project code.",
        scenarios=[Scenario.CODE_AUDIT],
        input_schema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
        risk_level=RiskLevel.R0,
        permissions=["workspace:read"],
        timeout_seconds=30,
        capability_tags=["inventory"],
        # Inventory is deliberately language-agnostic.  Declaring every known
        # language here made unknown/config-only repositories look
        # incompatible and could remove the prerequisite step entirely.
        supported_languages=[],
        evidence_types=["project_inventory"],
        concurrency_key="inventory",
    )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        started = time.monotonic()
        try:
            target = BanditTool._resolve_target(str(args.get("target", ".")), context)
        except ToolError as exc:
            return ToolResult(status=ToolStatus.DENIED, error_code="TOOL_SCOPE_VIOLATION", error_message=str(exc))
        paths = [target] if target.is_file() else sorted(path for path in target.rglob("*") if path.is_file())
        language_counts: dict[str, int] = {}
        dependencies: list[str] = []
        total_bytes = 0
        for path in paths:
            language = LANGUAGE_SUFFIXES.get(path.suffix.lower())
            if language:
                language_counts[language] = language_counts.get(language, 0) + 1
            if path.name.lower() in DEPENDENCY_FILES:
                dependencies.append(path.relative_to(target if target.is_dir() else target.parent).as_posix())
            total_bytes += path.stat().st_size
        payload = {
            "languages": dict(sorted(language_counts.items())),
            "dependency_files": sorted(dependencies),
            "file_count": len(paths),
            "total_bytes": total_bytes,
            "language_registry_version": LANGUAGE_REGISTRY_VERSION,
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        evidence = Evidence(
            evidence_id=public_evidence_id(digest),
            source="project_inventory:1",
            summary=f"Inventoried {len(paths)} file(s) across {len(language_counts)} language(s).",
            sha256=digest,
            metadata=payload,
        )
        evidence.metadata.update(
            {
                "evidence_type": "project_inventory",
                "tool_name": self.manifest.name,
                "tool_version": self.manifest.version,
            }
        )
        return ToolResult(
            status=ToolStatus.SUCCESS,
            data=payload,
            summary=evidence.summary,
            evidence=[evidence],
            duration_ms=int((time.monotonic() - started) * 1000),
        )
