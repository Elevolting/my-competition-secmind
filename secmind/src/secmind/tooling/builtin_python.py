"""Built-in Python static-analysis adapters."""

# ruff: noqa: F401,F403,F405
import ast
import asyncio
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

from secmind.language_registry import LANGUAGE_REGISTRY_VERSION
from secmind.ledger import canonical_json
from secmind.python_dataflow import analyze_python_source
from secmind.schemas import *
from secmind.tooling.core import (
    BANDIT_RULE_BUNDLE_DIGEST,
    PYTHON_DATAFLOW_RULE_BUNDLE_DIGEST,
    BaseTool,
    ToolError,
    _provenance_metadata,
    compute_input_manifest_digest,
    normalize_bandit_findings,
    public_evidence_id,
    sanitized_tool_environment,
    workspace_input_manifest,
)


class BanditTool(BaseTool):
    manifest = ToolManifest(
        name="bandit_python_audit",
        version="1",
        description="Run Bandit static security analysis over Python source in the controlled workspace.",
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
        timeout_seconds=120,
        idempotent=True,
        requires_network=False,
        capability_tags=["sast"],
        supported_languages=["python"],
        rule_bundle_digest=BANDIT_RULE_BUNDLE_DIGEST,
        evidence_types=["sast_finding"],
        concurrency_key="sast",
        max_parallelism=2,
    )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        started = time.monotonic()
        try:
            target = self._resolve_target(str(args.get("target", ".")), context)
        except ToolError as exc:
            return ToolResult(
                status=ToolStatus.DENIED,
                error_code="TOOL_SCOPE_VIOLATION",
                error_message=str(exc),
            )
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-I",
            "-m",
            "bandit",
            "-r",
            str(target),
            "-f",
            "json",
            "-q",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=context.workspace,
            env=sanitized_tool_environment(),
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.manifest.timeout_seconds)
        except TimeoutError:
            process.kill()
            await process.communicate()
            return ToolResult(
                status=ToolStatus.TIMEOUT,
                duration_ms=int((time.monotonic() - started) * 1000),
                error_code="TOOL_TIMEOUT",
                error_message="Bandit exceeded its execution deadline.",
            )
        if process.returncode not in {0, 1}:
            return ToolResult(
                status=ToolStatus.ERROR,
                duration_ms=int((time.monotonic() - started) * 1000),
                error_code="BANDIT_FAILED",
                error_message=stderr.decode(errors="replace")[-2000:],
            )
        try:
            body = json.loads(stdout.decode(errors="replace") or "{}")
        except json.JSONDecodeError as exc:
            return ToolResult(
                status=ToolStatus.ERROR,
                duration_ms=int((time.monotonic() - started) * 1000),
                error_code="BANDIT_INVALID_JSON",
                error_message=str(exc),
            )
        workspace = Path(context.workspace).resolve()  # noqa: ASYNC240 - bounded local metadata operation
        manifest_rows = workspace_input_manifest(workspace, target)
        input_manifest_digest = compute_input_manifest_digest(manifest_rows)
        evidence, findings = normalize_bandit_findings(
            body.get("results", []),
            self.manifest.version,
            workspace,
            input_manifest_digest=input_manifest_digest,
            rule_bundle_digest=BANDIT_RULE_BUNDLE_DIGEST,
        )
        return ToolResult(
            status=ToolStatus.SUCCESS,
            data={
                "findings": findings,
                "metrics": body.get("metrics", {}),
                "input_manifest": manifest_rows,
                "input_manifest_digest": input_manifest_digest,
                "rule_bundle_digest": BANDIT_RULE_BUNDLE_DIGEST,
                "language_registry_version": LANGUAGE_REGISTRY_VERSION,
            },
            summary=f"Bandit completed with {len(findings)} finding(s).",
            evidence=evidence,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    @staticmethod
    def _resolve_target(value: str, context: ToolContext) -> Path:
        workspace = Path(context.workspace).resolve()  # noqa: ASYNC240 - bounded local metadata operation
        candidate = (workspace / value).resolve() if not Path(value).is_absolute() else Path(value).resolve()
        allowed = [Path(path).resolve() for path in context.allowed_paths]
        if not any(candidate == root or root in candidate.parents for root in allowed):
            raise ToolError("Tool target is outside the allowed workspace")
        if not candidate.exists():
            raise ToolError("Tool target does not exist")
        return candidate


class PythonDataflowTool(BaseTool):
    """Prove narrow Python source-to-sink flows without executing input code."""

    manifest = ToolManifest(
        name="python_taint_audit",
        version="1",
        description="Deterministic intra-procedural Python source-to-sink analysis for high-value security sinks.",
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
        timeout_seconds=60,
        idempotent=True,
        requires_network=False,
        capability_tags=["sast"],
        supported_languages=["python"],
        rule_bundle_digest=PYTHON_DATAFLOW_RULE_BUNDLE_DIGEST,
        evidence_types=["sast_flow"],
        concurrency_key="sast",
        max_parallelism=2,
    )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        started = time.monotonic()
        try:
            target = BanditTool._resolve_target(str(args.get("target", ".")), context)
        except ToolError as exc:
            return ToolResult(status=ToolStatus.DENIED, error_code="TOOL_SCOPE_VIOLATION", error_message=str(exc))
        workspace = Path(context.workspace).resolve()  # noqa: ASYNC240 - bounded local static-analysis adapter
        paths = [target] if target.is_file() else sorted(target.rglob("*.py"))
        manifest_rows = workspace_input_manifest(workspace, target)
        input_manifest_digest = compute_input_manifest_digest(manifest_rows)
        evidence: list[Evidence] = []
        findings: list[dict[str, Any]] = []
        parse_failures = 0
        for path in paths:
            if path.suffix.casefold() != ".py" or path.stat().st_size > 2 * 1024 * 1024:
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                parse_failures += 1
                continue
            flows = analyze_python_source(source)
            if not flows and source.strip():
                try:
                    ast.parse(source, filename=str(path))
                except (SyntaxError, ValueError):
                    parse_failures += 1
            relative = path.relative_to(workspace).as_posix()
            lines = source.splitlines()
            file_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
            for flow in flows:
                excerpt = lines[flow.line - 1].strip()[:500] if flow.line <= len(lines) else ""
                trace = [*flow.source_names, f"sink:{flow.sink}"]
                material = {
                    "tool": self.manifest.name,
                    "version": self.manifest.version,
                    "rule_id": flow.rule_id,
                    "native_rule_id": flow.native_rule_id,
                    "path": relative,
                    "line": flow.line,
                    "trace": trace,
                    "file_sha256": file_sha256,
                    "excerpt": excerpt,
                }
                digest = hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
                evidence_id = public_evidence_id(digest)
                finding_id = f"finding-{digest[:32]}"
                evidence.append(
                    Evidence(
                        evidence_id=evidence_id,
                        source=f"{self.manifest.name}:{self.manifest.version}",
                        summary=f"{flow.rule_id} proven flow at {relative}:{flow.line}",
                        sha256=digest,
                        metadata={
                            "evidence_type": "sast_flow",
                            "assurance_level": "semantically_corroborated",
                            "semantic_corroboration": True,
                            "tool_name": self.manifest.name,
                            "tool_version": self.manifest.version,
                            "native_rule_id": flow.native_rule_id,
                            "normalized_rule_id": flow.rule_id,
                            "path": relative,
                            "line": flow.line,
                            "file_sha256": file_sha256,
                            "data_flow": trace,
                            "excerpt": excerpt,
                            **_provenance_metadata(
                                path=relative,
                                line=flow.line,
                                file_sha256=file_sha256,
                                input_manifest_digest=input_manifest_digest,
                                rule_bundle_digest=PYTHON_DATAFLOW_RULE_BUNDLE_DIGEST,
                                finding_id=finding_id,
                            ),
                        },
                    )
                )
                findings.append(
                    Finding(
                        finding_id=finding_id,
                        rule_id=flow.rule_id,
                        severity=flow.severity,
                        confidence=flow.confidence,
                        path=relative,
                        line=flow.line,
                        title=flow.title,
                        description=flow.description,
                        remediation=flow.remediation,
                        evidence_ids=[evidence_id],
                        raw={
                            "native_rule_id": flow.native_rule_id,
                            "data_flow": trace,
                            "evidence_excerpt": excerpt,
                            "root_cause": flow.description,
                            "impact": flow.impact,
                            "semantic_corroboration": True,
                            "tool_name": self.manifest.name,
                            "file_sha256": file_sha256,
                            "input_manifest_digest": input_manifest_digest,
                            "rule_bundle_digest": PYTHON_DATAFLOW_RULE_BUNDLE_DIGEST,
                        },
                    ).model_dump(mode="json")
                )
        return ToolResult(
            status=ToolStatus.SUCCESS,
            data={
                "findings": findings,
                "files_scanned": len(paths),
                "parse_failures": parse_failures,
                "input_manifest": manifest_rows,
                "input_manifest_digest": input_manifest_digest,
                "rule_bundle_digest": PYTHON_DATAFLOW_RULE_BUNDLE_DIGEST,
                "language_registry_version": LANGUAGE_REGISTRY_VERSION,
            },
            summary=f"Python data-flow audit completed with {len(findings)} proven flow(s).",
            evidence=evidence,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
