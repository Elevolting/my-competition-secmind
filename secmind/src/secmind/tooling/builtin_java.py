"""Built-in Java semantic SAST adapter."""

# ruff: noqa: F401,F403,F405
import hashlib
import time
from pathlib import Path
from typing import Any

from secmind.java_semantic_sast import (
    RULE_BUNDLE_DIGEST as JAVA_SEMANTIC_RULE_BUNDLE_DIGEST,
)
from secmind.java_semantic_sast import (
    TOOL_NAME as JAVA_SEMANTIC_TOOL_NAME,
)
from secmind.java_semantic_sast import (
    TOOL_VERSION as JAVA_SEMANTIC_TOOL_VERSION,
)
from secmind.java_semantic_sast import (
    JavaSource,
    analyze_java_sources,
)
from secmind.language_registry import LANGUAGE_REGISTRY_VERSION
from secmind.schemas import *
from secmind.tooling.builtin_python import BanditTool
from secmind.tooling.core import BaseTool, ToolError, compute_input_manifest_digest


class JavaSemanticSastTool(BaseTool):
    """Prove bounded high-specificity Java flows without executing code."""

    manifest = ToolManifest(
        name=JAVA_SEMANTIC_TOOL_NAME,
        version=JAVA_SEMANTIC_TOOL_VERSION,
        description=(
            "Deterministic Java semantic SAST for LDAP-filter injection, sensitive-value logging, "
            "and security-sensitive weak MessageDigest use; unproven lexical matches are excluded."
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
        capability_tags=["sast", "java_semantic"],
        supported_languages=["java"],
        rule_bundle_digest=JAVA_SEMANTIC_RULE_BUNDLE_DIGEST,
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
        workspace = Path(context.workspace).resolve()  # noqa: ASYNC240 - bounded read-only analysis
        paths = [target] if target.is_file() else sorted(target.rglob("*.java"))
        sources: list[JavaSource] = []
        parse_failures = 0
        total_bytes = 0
        for path in paths[:512]:
            if path.suffix.casefold() != ".java" or path.is_symlink():
                continue
            try:
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(workspace):
                    parse_failures += 1
                    continue
                size = resolved.stat().st_size
                if size > 2 * 1024 * 1024 or total_bytes + size > 8 * 1024 * 1024:
                    parse_failures += 1
                    continue
                payload = resolved.read_bytes()
                source = payload.decode("utf-8")
            except (OSError, UnicodeDecodeError):
                parse_failures += 1
                continue
            total_bytes += len(payload)
            sources.append(
                JavaSource(
                    path=resolved.relative_to(workspace).as_posix(),
                    source=source,
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
        evidence, findings = analyze_java_sources(run_id=context.run_id, sources=tuple(sources))
        manifest_rows = [
            {"path": item.path, "sha256": item.sha256, "size_bytes": len(item.source.encode("utf-8"))}
            for item in sources
        ]
        input_manifest_digest = compute_input_manifest_digest(manifest_rows)
        return ToolResult(
            invocation_id=context.invocation_id,
            status=ToolStatus.SUCCESS,
            data={
                "findings": findings,
                "files_scanned": len(sources),
                "parse_failures": parse_failures,
                "finding_limit": 9,
                "input_manifest": manifest_rows,
                "input_manifest_digest": input_manifest_digest,
                "rule_bundle_digest": JAVA_SEMANTIC_RULE_BUNDLE_DIGEST,
                "language_registry_version": LANGUAGE_REGISTRY_VERSION,
            },
            summary=f"Java semantic SAST completed with {len(findings)} bounded finding(s).",
            evidence=evidence,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
