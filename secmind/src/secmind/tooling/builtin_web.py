"""Built-in deterministic web-workflow static analysis."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

from secmind.language_registry import LANGUAGE_REGISTRY_VERSION
from secmind.ledger import canonical_json
from secmind.schemas import Evidence, Finding, RiskLevel, Scenario, ToolContext, ToolManifest, ToolResult, ToolStatus
from secmind.tooling.builtin_python import BanditTool
from secmind.tooling.core import (
    BaseTool,
    ToolError,
    _provenance_metadata,
    compute_input_manifest_digest,
    public_evidence_id,
    workspace_input_manifest,
)
from secmind.web_static_audit import (
    RULE_BUNDLE_DIGEST,
    TOOL_NAME,
    TOOL_VERSION,
    analyze_web_source,
)

_MAX_FILES = 512
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_TOTAL_BYTES = 8 * 1024 * 1024


class WebWorkflowAuditTool(BaseTool):
    """Prove narrow server-side workflow bypasses without executing input."""

    manifest = ToolManifest(
        name=TOOL_NAME,
        version=TOOL_VERSION,
        description=(
            "Deterministic PHP source-to-sink workflow SAST for client-controlled stage transitions "
            "and locally proven password-change authentication or storage weaknesses."
        ),
        scenarios=[Scenario.CODE_AUDIT],
        input_schema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "properties": {"findings": {"type": "array"}}},
        risk_level=RiskLevel.R1,
        permissions=["workspace:read"],
        timeout_seconds=30,
        idempotent=True,
        requires_network=False,
        capability_tags=["sast"],
        supported_languages=["php"],
        rule_bundle_digest=RULE_BUNDLE_DIGEST,
        evidence_types=["sast_flow"],
        concurrency_key="sast",
        max_parallelism=2,
    )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        started = time.monotonic()
        try:
            target = BanditTool._resolve_target(str(args.get("target", ".")), context)
        except ToolError as exc:
            return ToolResult(
                invocation_id=context.invocation_id,
                status=ToolStatus.DENIED,
                error_code="TOOL_SCOPE_VIOLATION",
                error_message=str(exc),
            )

        workspace = Path(context.workspace).resolve()  # noqa: ASYNC240 - bounded local static analysis
        candidates = [target] if target.is_file() else sorted(target.rglob("*.php"))
        manifest_rows = workspace_input_manifest(workspace, target)
        input_manifest_digest = compute_input_manifest_digest(manifest_rows)
        evidence: list[Evidence] = []
        findings: list[dict[str, Any]] = []
        files_scanned = 0
        parse_failures = 0
        total_bytes = 0

        for path in candidates[:_MAX_FILES]:
            if path.suffix.casefold() != ".php" or path.is_symlink():
                continue
            try:
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(workspace):
                    parse_failures += 1
                    continue
                size = resolved.stat().st_size
                if size > _MAX_FILE_BYTES or total_bytes + size > _MAX_TOTAL_BYTES:
                    parse_failures += 1
                    continue
                payload = resolved.read_bytes()
                source = payload.decode("utf-8")
            except (OSError, UnicodeDecodeError):
                parse_failures += 1
                continue

            files_scanned += 1
            total_bytes += len(payload)
            relative = resolved.relative_to(workspace).as_posix()
            file_sha256 = hashlib.sha256(payload).hexdigest()
            lines = source.splitlines()
            for flow in analyze_web_source(source):
                excerpt = "\n".join(
                    f"{line}: {lines[line - 1].strip()[:400]}" for line in flow.evidence_lines if 0 < line <= len(lines)
                )[:2_000]
                material = {
                    "tool": self.manifest.name,
                    "version": self.manifest.version,
                    "native_rule_id": flow.native_rule_id,
                    "normalized_rule_id": flow.rule_id,
                    "path": relative,
                    "line": flow.line,
                    "sink_line": flow.sink_line,
                    "data_flow": flow.data_flow,
                    "file_sha256": file_sha256,
                    "excerpt": excerpt,
                }
                record_digest = hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
                evidence_id = public_evidence_id(record_digest)
                finding_id = f"finding-{record_digest[:32]}"
                metadata = {
                    "evidence_type": "sast_flow",
                    "assurance_level": "semantically_corroborated",
                    "semantic_corroboration": True,
                    "tool_name": self.manifest.name,
                    "tool_version": self.manifest.version,
                    "native_rule_id": flow.native_rule_id,
                    "normalized_rule_id": flow.rule_id,
                    "weakness_ids": list(flow.weakness_ids),
                    "data_flow": list(flow.data_flow),
                    "source_step": flow.source_step,
                    "target_step": flow.target_step,
                    "sink_line": flow.sink_line,
                    "excerpt": excerpt,
                    "record_digest": record_digest,
                    **_provenance_metadata(
                        path=relative,
                        line=flow.line,
                        file_sha256=file_sha256,
                        input_manifest_digest=input_manifest_digest,
                        rule_bundle_digest=RULE_BUNDLE_DIGEST,
                        finding_id=finding_id,
                    ),
                }
                evidence.append(
                    Evidence(
                        evidence_id=evidence_id,
                        source=f"{self.manifest.name}:{self.manifest.version}",
                        summary=f"{flow.rule_id} proven web security flow at {relative}:{flow.line}",
                        sha256=record_digest,
                        metadata=metadata,
                    )
                )
                findings.append(
                    Finding(
                        finding_id=finding_id,
                        rule_id=flow.rule_id,
                        severity="HIGH",
                        confidence="HIGH",
                        path=relative,
                        line=flow.line,
                        title=flow.title,
                        description=flow.description,
                        remediation=flow.remediation,
                        evidence_ids=[evidence_id],
                        raw={
                            "native_rule_id": flow.native_rule_id,
                            "normalized_rule_id": flow.rule_id,
                            "weakness_ids": list(flow.weakness_ids),
                            "data_flow": list(flow.data_flow),
                            "evidence_excerpt": excerpt,
                            "root_cause": flow.description,
                            "impact": flow.impact,
                            "preconditions": list(flow.preconditions),
                            "semantic_corroboration": True,
                            "tool_name": self.manifest.name,
                            "file_sha256": file_sha256,
                            "input_manifest_digest": input_manifest_digest,
                            "rule_bundle_digest": RULE_BUNDLE_DIGEST,
                        },
                    ).model_dump(mode="json")
                )

        return ToolResult(
            invocation_id=context.invocation_id,
            status=ToolStatus.SUCCESS,
            data={
                "findings": findings,
                "files_scanned": files_scanned,
                "parse_failures": parse_failures,
                "truncated": len(candidates) > _MAX_FILES or total_bytes >= _MAX_TOTAL_BYTES,
                "coverage": {
                    "complete": (
                        len(candidates) <= _MAX_FILES and parse_failures == 0 and total_bytes < _MAX_TOTAL_BYTES
                    ),
                    "language": "php",
                    "rule_count": 3,
                },
                "input_manifest": manifest_rows,
                "input_manifest_digest": input_manifest_digest,
                "rule_bundle_digest": RULE_BUNDLE_DIGEST,
                "language_registry_version": LANGUAGE_REGISTRY_VERSION,
            },
            summary=f"Web workflow audit completed with {len(findings)} proven flow(s).",
            evidence=evidence,
            duration_ms=int((time.monotonic() - started) * 1_000),
        )


__all__ = ["WebWorkflowAuditTool"]
