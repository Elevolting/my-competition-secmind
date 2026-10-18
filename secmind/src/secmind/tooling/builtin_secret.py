"""Built-in redacted secret-pattern adapter."""

# ruff: noqa: F401,F403,F405
import hashlib
import time
from pathlib import Path
from typing import Any

from secmind.language_registry import LANGUAGE_REGISTRY_VERSION
from secmind.schemas import *
from secmind.tooling.builtin_python import BanditTool
from secmind.tooling.core import (
    SECRET_ASSIGNMENT,
    SECRET_PATTERN_RULE_BUNDLE_DIGEST,
    BaseTool,
    ToolError,
    _provenance_metadata,
    compute_input_manifest_digest,
    public_evidence_id,
    workspace_input_manifest,
)


class SecretPatternTool(BaseTool):
    """Offline, fully redacted secret detector used until the Gitleaks image is enabled."""

    manifest = ToolManifest(
        name="secret_pattern_scan",
        version="1",
        description="Detect likely hard-coded credentials while never persisting the matched value.",
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
        capability_tags=["secret_scan"],
        rule_bundle_digest=SECRET_PATTERN_RULE_BUNDLE_DIGEST,
        evidence_types=["redacted_secret_finding"],
        concurrency_key="secret_scan",
        max_parallelism=2,
    )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        started = time.monotonic()
        try:
            target = BanditTool._resolve_target(str(args.get("target", ".")), context)
        except ToolError as exc:
            return ToolResult(status=ToolStatus.DENIED, error_code="TOOL_SCOPE_VIOLATION", error_message=str(exc))
        workspace = Path(context.workspace).resolve()  # noqa: ASYNC240 - bounded local metadata operation
        paths = [target] if target.is_file() else sorted(path for path in target.rglob("*") if path.is_file())
        manifest_rows = workspace_input_manifest(workspace, target)
        input_manifest_digest = compute_input_manifest_digest(manifest_rows)
        evidence: list[Evidence] = []
        findings: list[dict[str, Any]] = []
        for path in paths:
            if path.stat().st_size > 2 * 1024 * 1024:
                continue
            try:
                payload = path.read_bytes()
                text = payload.decode("utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            relative = path.relative_to(workspace).as_posix()
            file_sha256 = hashlib.sha256(payload).hexdigest()
            for line_number, line in enumerate(text.splitlines(), start=1):
                if line.lstrip().startswith("#"):
                    continue
                for match in SECRET_ASSIGNMENT.finditer(line):
                    value = match.group(2).strip()
                    if value.startswith(("${", "<", "[")):
                        continue
                    secret_type = match.group(1).lower().replace("-", "_")
                    fingerprint = hashlib.sha256(f"{relative}:{line_number}:{secret_type}".encode()).hexdigest()
                    evidence_id = public_evidence_id(fingerprint)
                    finding_id = f"finding-{fingerprint[:32]}"
                    evidence.append(
                        Evidence(
                            evidence_id=evidence_id,
                            source="secret_pattern_scan:1",
                            summary=f"Redacted {secret_type} candidate at {relative}:{line_number}",
                            sha256=fingerprint,
                            metadata={
                                "evidence_type": "redacted_secret_finding",
                                "tool_name": self.manifest.name,
                                "tool_version": self.manifest.version,
                                "rule_id": "CWE-798",
                                "native_rule_id": "SECMIND-SECRET-001",
                                "normalized_rule_id": "CWE-798",
                                "weakness_ids": ["CWE-798"],
                                "secret_type": secret_type,
                                "redacted": True,
                                "path": relative,
                                "file_sha256": file_sha256,
                                **_provenance_metadata(
                                    path=relative,
                                    line=line_number,
                                    file_sha256=file_sha256,
                                    input_manifest_digest=input_manifest_digest,
                                    rule_bundle_digest=SECRET_PATTERN_RULE_BUNDLE_DIGEST,
                                    finding_id=finding_id,
                                ),
                            },
                        )
                    )
                    findings.append(
                        Finding(
                            finding_id=finding_id,
                            rule_id="CWE-798",
                            severity="HIGH",
                            confidence="MEDIUM",
                            path=relative,
                            line=line_number,
                            title="Possible hard-coded credential",
                            description=f"A value assigned to {secret_type} appears to be hard-coded; value redacted.",
                            remediation="Move the credential to a secret store and rotate any exposed value.",
                            evidence_ids=[evidence_id],
                            raw={
                                "native_rule_id": "SECMIND-SECRET-001",
                                "normalized_rule_id": "CWE-798",
                                "weakness_ids": ["CWE-798"],
                                "tool_name": self.manifest.name,
                                "tool_version": self.manifest.version,
                                "file_sha256": file_sha256,
                                "input_manifest_digest": input_manifest_digest,
                                "rule_bundle_digest": SECRET_PATTERN_RULE_BUNDLE_DIGEST,
                            },
                        ).model_dump(mode="json")
                    )
        return ToolResult(
            status=ToolStatus.SUCCESS,
            data={
                "findings": findings,
                "input_manifest": manifest_rows,
                "input_manifest_digest": input_manifest_digest,
                "rule_bundle_digest": SECRET_PATTERN_RULE_BUNDLE_DIGEST,
                "language_registry_version": LANGUAGE_REGISTRY_VERSION,
            },
            summary=f"Secret scan completed with {len(findings)} redacted finding(s).",
            evidence=evidence,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
