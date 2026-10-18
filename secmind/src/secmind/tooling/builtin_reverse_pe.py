"""Built-in static reverse analysis for Windows PE binaries."""

from __future__ import annotations

import asyncio
import hashlib
import time
from pathlib import Path
from typing import Any

from secmind.reverse_pe_analysis import build_report
from secmind.schemas import Evidence, RiskLevel, Scenario, ToolContext, ToolManifest, ToolResult, ToolStatus
from secmind.tooling.builtin_python import BanditTool
from secmind.tooling.core import BaseTool, ToolError, public_evidence_id


class ReversePeAnalysisTool(BaseTool):
    """Analyze uploaded Windows PE samples without executing them."""

    manifest = ToolManifest(
        name="pe_reverse_analysis",
        version="1",
        description=(
            "Static Windows PE reverse analysis for uploaded executables; reads headers, sections, imports, "
            "and heuristic string candidates without execution."
        ),
        scenarios=[Scenario.REVERSE_TRIAGE],
        input_schema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
        risk_level=RiskLevel.R1,
        permissions=["workspace:read"],
        timeout_seconds=60,
        idempotent=True,
        requires_network=False,
        capability_tags=["reverse_analysis", "pe_analysis"],
        supported_languages=[],
        evidence_types=["reverse_analysis"],
        concurrency_key="reverse_analysis",
        max_parallelism=2,
    )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        started = time.monotonic()
        try:
            target = BanditTool._resolve_target(str(args.get("target", ".")), context)
        except ToolError as exc:
            return ToolResult(status=ToolStatus.DENIED, error_code="TOOL_SCOPE_VIOLATION", error_message=str(exc))

        path = target if target.is_file() else self._find_sample(target)
        if path is None:
            return ToolResult(
                status=ToolStatus.ERROR,
                error_code="PE_SAMPLE_NOT_FOUND",
                error_message="No PE sample was found at the requested target.",
            )

        try:
            report = build_report(path)
        except Exception as exc:  # noqa: BLE001 - report generation should fail closed
            return ToolResult(
                status=ToolStatus.ERROR,
                error_code="PE_REVERSE_ANALYSIS_FAILED",
                error_message=str(exc),
            )

        raw = await asyncio.to_thread(Path(path).read_bytes)
        digest = hashlib.sha256(raw).hexdigest()
        evidence_summary = (
            f"Static PE analysis completed for {path.name}: "
            f"{report['file']['architecture']}, {report['pe']['section_count']} section(s), "
            f"{report['pe']['import_library_count']} import library/libraries."
        )
        evidence_payload = {
            "tool": self.manifest.name,
            "version": self.manifest.version,
            "sample_name": path.name,
            "sample_sha256": digest,
            "architecture": report["file"]["architecture"],
            "section_count": report["pe"]["section_count"],
            "import_libraries": report["pe"]["import_library_count"],
            "entrypoint_rva": report["pe"]["entrypoint_rva"],
        }
        evidence_digest = hashlib.sha256(repr(sorted(evidence_payload.items())).encode()).hexdigest()
        evidence = Evidence(
            evidence_id=public_evidence_id(evidence_digest),
            source=f"{self.manifest.name}:{self.manifest.version}",
            summary=evidence_summary,
            artifact_ref=digest,
            sha256=digest,
            metadata=evidence_payload,
        )
        evidence.metadata.update(
            {
                "evidence_type": "reverse_analysis",
                "tool_name": self.manifest.name,
                "tool_version": self.manifest.version,
                "analysis_digest": evidence_digest,
            }
        )
        return ToolResult(
            invocation_id=context.invocation_id,
            status=ToolStatus.SUCCESS,
            data=report,
            summary=evidence.summary,
            evidence=[evidence],
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    @staticmethod
    def _find_sample(target: Path) -> Path | None:
        candidates = [
            path
            for path in sorted(target.rglob("*"))
            if path.is_file() and path.suffix.casefold() in {".exe", ".dll", ".sys", ".bin"}
        ]
        return candidates[0] if candidates else None


__all__ = ["ReversePeAnalysisTool"]
