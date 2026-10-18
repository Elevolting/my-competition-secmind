"""External sandbox scanner adapters and immutable output normalization."""

# ruff: noqa: F401,F403,F405
import base64
import hashlib
import hmac
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.language_registry import LANGUAGE_REGISTRY_VERSION
from secmind.sandbox import *
from secmind.schemas import *
from secmind.secret_scrubber import scrub_text
from secmind.tool_assurance import build_tool_assurance
from secmind.tooling.builtin_python import BanditTool
from secmind.tooling.core import (
    BaseTool,
    ToolError,
    ToolValidationError,
    _provenance_metadata,
    compute_input_manifest_digest,
    public_evidence_id,
)
from secmind.tooling.external_manifests import (
    _EXTERNAL_DEFAULT_WEAKNESS,
    EXTERNAL_TOOL_NAMES,
    SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST,
)


@dataclass(frozen=True, slots=True)
class _SandboxInputBinding:
    sha256: str
    size_bytes: int
    line_count: int


class SandboxJsonTool(BaseTool):
    """Generic client for allowlisted external scanners returning normalized JSON.

    Images and entrypoints are server-owned ``SandboxToolSpec`` values. The caller
    can only choose a target inside ``ToolContext.allowed_paths`` and can never
    supply a command, image, network policy, or Docker option.
    """

    def __init__(
        self,
        manifest: ToolManifest,
        runner_url: str,
        service_token: str | None = None,
        client: httpx.AsyncClient | None = None,
        *,
        capability_ticket_provider: Callable[[SandboxInvocation], str] | None = None,
        artifact_store: ContentAddressedArtifactStore | None = None,
    ) -> None:
        if manifest.name not in EXTERNAL_TOOL_NAMES:
            raise ValueError("SandboxJsonTool only accepts approved external audit tools")
        if manifest.health_status != ToolHealth.HEALTHY or not manifest.execution.image_digest:
            raise ValueError("external sandbox tool requires an approved immutable image")
        if manifest.name == "semgrep_sast" and manifest.rule_bundle_digest != SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST:
            raise ValueError("Semgrep requires the approved immutable rule bundle")
        if not runner_url or not (service_token or capability_ticket_provider):
            raise ValueError("Sandbox runner URL and capability credentials are required")
        self.manifest = manifest.model_copy(deep=True)
        self.runner_url = runner_url.rstrip("/")
        self.service_token = service_token or ""
        self.capability_ticket_provider = capability_ticket_provider
        self.artifact_store = artifact_store
        self._client = client

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        try:
            target = BanditTool._resolve_target(str(args.get("target", ".")), context)
            files = collect_sandbox_input_files(target)
            dependency_artifact = args.get("cyclonedx_sbom")
            if dependency_artifact is not None:
                if self.manifest.name != "osv_dependency_audit" or self.artifact_store is None:
                    raise ToolError("dependency artifact input is unavailable")
                content = self.artifact_store.read(str(dependency_artifact))
                files.append(
                    SandboxInputFile(
                        path=".secmind/dependencies/cyclonedx.json",
                        content_base64=base64.b64encode(content).decode(),
                    )
                )
        except (OSError, ToolError, ValueError) as exc:
            return ToolResult(
                invocation_id=context.invocation_id,
                status=ToolStatus.DENIED,
                error_code="SANDBOX_INPUT_INVALID",
                error_message=str(exc),
            )
        invocation = SandboxInvocation(
            run_id=context.run_id,
            invocation_id=context.invocation_id,
            tool_name=self.manifest.name,
            lease_fence=context.lease_fence,
            files=files,
        )
        manifest_rows = [
            {"path": item.path, "sha256": hashlib.sha256(item.decoded()).hexdigest(), "size_bytes": len(item.decoded())}
            for item in files
        ]
        input_manifest_digest = compute_input_manifest_digest(manifest_rows)
        credential = (
            self.capability_ticket_provider(invocation) if self.capability_ticket_provider else self.service_token
        )
        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=self.manifest.timeout_seconds + 15)
        try:
            response = await client.post(
                f"{self.runner_url}/internal/v1/invocations",
                headers={"Authorization": f"Bearer {credential}"},
                json=invocation.model_dump(mode="json"),
                timeout=self.manifest.timeout_seconds + 15,
            )
            if response.status_code != 200:
                return self._error(context, "SANDBOX_RUNNER_REJECTED")
            result = SandboxResult.model_validate(response.json())
        except (httpx.HTTPError, ValueError):
            return self._error(context, "SANDBOX_RUNNER_UNAVAILABLE")
        finally:
            if owns_client:
                await client.aclose()
        if result.invocation_id != context.invocation_id:
            return self._error(context, "SANDBOX_INVOCATION_MISMATCH")
        status = {
            "success": ToolStatus.SUCCESS,
            "timeout": ToolStatus.TIMEOUT,
            "denied": ToolStatus.DENIED,
            "error": ToolStatus.ERROR,
        }.get(result.status, ToolStatus.ERROR)
        try:
            findings, evidence, rejected_findings = self._normalize_findings(
                result.data.get("findings", []),
                input_bindings=self._input_bindings(files),
                input_manifest_digest=input_manifest_digest,
            )
        except ToolValidationError:
            return self._error(context, "SANDBOX_OUTPUT_INVALID")
        if rejected_findings and not findings and status == ToolStatus.SUCCESS:
            return ToolResult(
                invocation_id=context.invocation_id,
                status=ToolStatus.ERROR,
                data={
                    "accepted_findings": len(findings),
                    "rejected_findings": rejected_findings,
                    "rejected_unbound_findings": len(rejected_findings),
                    "coverage": {
                        "accepted_count": 0,
                        "rejected_count": len(rejected_findings),
                        "complete": False,
                    },
                },
                summary="External scanner output was incomplete because findings failed immutable input binding.",
                duration_ms=result.duration_ms,
                error_code="SANDBOX_OUTPUT_INCOMPLETE",
                error_message="External scanner findings failed immutable input binding.",
            )
        # Gitleaks reports can contain the matched credential. Until a trusted
        # wrapper proves artifact-level redaction, do not expose its artifacts.
        artifacts = (
            []
            if self.manifest.name == "gitleaks_secret_scan"
            else [
                ArtifactRef(
                    artifact_id=item.artifact_id,
                    ref=item.artifact_id,
                    sha256=item.sha256,
                    size_bytes=item.size_bytes,
                    media_type=item.media_type,
                )
                for item in result.artifacts
            ]
        )
        safe_data: dict[str, Any] = {"findings": findings}
        if rejected_findings:
            safe_data["rejected_findings"] = rejected_findings
            safe_data["rejected_unbound_findings"] = len(rejected_findings)
        safe_data["coverage"] = {
            "accepted_count": len(findings),
            "rejected_count": len(rejected_findings),
            "complete": not rejected_findings,
        }
        for key in ("components_count", "database_version", "files_scanned", "rules_run"):
            value = result.data.get(key)
            if isinstance(value, (str, int, float, bool)) and not isinstance(value, bytes):
                safe_data[key] = value
        if self.manifest.name != "gitleaks_secret_scan":
            safe_data.update(
                {
                    "input_manifest": manifest_rows,
                    "input_manifest_digest": input_manifest_digest,
                    "rule_bundle_digest": self.manifest.rule_bundle_digest,
                    "language_registry_version": LANGUAGE_REGISTRY_VERSION,
                }
            )
        summary = (
            f"Gitleaks completed with {len(findings)} fully redacted finding(s)."
            if self.manifest.name == "gitleaks_secret_scan"
            else f"{self.manifest.name} completed with {len(findings)} finding(s)."
        )
        if rejected_findings and findings:
            summary += (
                f" {len(rejected_findings)} invalid record(s) were quarantined without discarding valid findings."
            )
        return ToolResult(
            invocation_id=context.invocation_id,
            status=status,
            data=safe_data,
            summary=summary,
            artifacts=artifacts,
            evidence=evidence,
            duration_ms=result.duration_ms,
            error_code=self._safe_error_code(result.error_code),
            error_message=("External scanner failed." if result.error_code else None),
        )

    def _normalize_findings(
        self,
        raw_findings: Any,
        *,
        input_bindings: Mapping[str, _SandboxInputBinding],
        input_manifest_digest: str | None = None,
    ) -> tuple[list[dict[str, Any]], list[Evidence], list[dict[str, str]]]:
        if not isinstance(raw_findings, list):
            raise ToolValidationError("sandbox findings must be an array")
        findings: list[dict[str, Any]] = []
        evidence: list[Evidence] = []
        rejected: list[dict[str, str]] = []
        is_secret_scan = self.manifest.name == "gitleaks_secret_scan"

        def reject(index: int, raw_value: Any, reason: str) -> None:
            try:
                encoded = json.dumps(
                    raw_value,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                )
            except (TypeError, ValueError):
                encoded = type(raw_value).__name__
            raw_digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            rejected.append(
                {
                    "rejected_id": f"rejected-{index}-{raw_digest[:24]}",
                    "reason_code": reason,
                    "raw_digest": raw_digest,
                }
            )

        for index, raw in enumerate(raw_findings):
            if not isinstance(raw, dict):
                reject(index, raw, "RECORD_NOT_OBJECT")
                continue
            declared_rule_id = self._safe_text(raw.get("rule_id"), "UNKNOWN", 160)
            path = self._normalize_scanner_path(raw.get("path"))
            if path is None or (binding := input_bindings.get(path)) is None:
                reject(index, raw, "PATH_NOT_MANIFEST_BOUND")
                continue
            line_value = raw.get("line")
            if line_value is None:
                line = None
            elif (
                not isinstance(line_value, int)
                or isinstance(line_value, bool)
                or line_value < 1
                or line_value > binding.line_count
            ):
                reject(index, raw, "LINE_OUT_OF_BOUNDS")
                continue
            else:
                line = line_value
            reported_sha256 = raw.get("file_sha256")
            if (
                not isinstance(reported_sha256, str)
                or not re.fullmatch(r"[a-fA-F0-9]{64}", reported_sha256)
                or not hmac.compare_digest(reported_sha256.lower(), binding.sha256)
            ):
                reject(index, raw, "FILE_DIGEST_MISMATCH")
                continue
            severity = str(raw.get("severity", "UNKNOWN")).upper()
            if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}:
                severity = "UNKNOWN"
            confidence = str(raw.get("confidence", "UNKNOWN")).upper()
            if confidence not in {"LOW", "MEDIUM", "HIGH", "UNKNOWN"}:
                confidence = "UNKNOWN"
            remediation: str | None
            if is_secret_scan:
                if not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,160}", declared_rule_id):
                    declared_rule_id = "UNKNOWN-SECRET"
                title = "Potential hard-coded secret (value redacted)"
                description = "A credential-like value was detected; its value and match content were removed."
                remediation = "Rotate the credential and move it to an approved secret store."
            else:
                title = self._safe_text(raw.get("title"), declared_rule_id, 300)
                description = self._safe_text(raw.get("description"), "Scanner finding.", 2_000)
                remediation = self._optional_text(raw.get("remediation"), 2_000)
            native_rule_id = self._safe_text(raw.get("native_rule_id"), declared_rule_id, 160)
            normalized_hint = self._safe_text(raw.get("normalized_rule_id"), declared_rule_id, 160)
            weakness_ids = self._weakness_ids(raw.get("weakness_ids"), normalized_hint)
            if not weakness_ids:
                default_weakness = _EXTERNAL_DEFAULT_WEAKNESS.get(self.manifest.name)
                if default_weakness is None:
                    reject(index, raw, "WEAKNESS_ID_REQUIRED")
                    continue
                weakness_ids = [default_weakness]
            rule_id = weakness_ids[0]
            normalized_rule_id = rule_id
            sink = "" if is_secret_scan else self._safe_text(raw.get("sink"), "", 512)
            data_flow = "" if is_secret_scan else self._safe_text(raw.get("data_flow"), "", 2_000)
            fingerprint_body = {
                "tool": self.manifest.name,
                "version": self.manifest.version,
                "rule_id": rule_id,
                "path": path,
                "line": line,
                "severity": severity,
            }
            digest = hashlib.sha256(
                json.dumps(fingerprint_body, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            evidence_id = public_evidence_id(digest)
            finding_id = f"finding-{digest[:32]}"
            assurance = build_tool_assurance(
                tool_name=self.manifest.name,
                tool_version=self.manifest.version,
                input_manifest_digest=input_manifest_digest or "0" * 64,
                finding_fingerprint=digest,
                rule_bundle_digest=self.manifest.rule_bundle_digest,
            )
            evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    source=f"{self.manifest.name}:{self.manifest.version}",
                    summary=f"{rule_id} at {path}:{line or 0}",
                    artifact_ref=binding.sha256,
                    sha256=binding.sha256,
                    metadata={
                        "redacted": is_secret_scan,
                        "evidence_type": self.manifest.evidence_types[0] if self.manifest.evidence_types else "finding",
                        "tool_name": self.manifest.name,
                        "rule_bundle_digest": self.manifest.rule_bundle_digest,
                        "rule_id": rule_id,
                        "tool_version": self.manifest.version,
                        "path": path,
                        "line": line,
                        "file_sha256": binding.sha256,
                        "native_rule_id": native_rule_id,
                        "normalized_rule_id": normalized_rule_id,
                        "weakness_ids": weakness_ids,
                        "record_fingerprint": digest,
                        "sink": sink,
                        "data_flow": data_flow,
                        "tool_assurance": assurance.model_dump(mode="json"),
                        **_provenance_metadata(
                            path=path,
                            line=line,
                            file_sha256=binding.sha256,
                            input_manifest_digest=input_manifest_digest or "0" * 64,
                            rule_bundle_digest=self.manifest.rule_bundle_digest,
                            finding_id=finding_id,
                        ),
                    },
                )
            )
            findings.append(
                Finding.model_validate(
                    {
                        "finding_id": finding_id,
                        "rule_id": rule_id,
                        "severity": severity,
                        "confidence": confidence,
                        "path": path,
                        "line": line,
                        "title": title,
                        "description": description,
                        "remediation": remediation,
                        "evidence_ids": [evidence_id],
                        "raw": {
                            "file_sha256": binding.sha256,
                            "native_rule_id": native_rule_id,
                            "normalized_rule_id": normalized_rule_id,
                            "tool_name": self.manifest.name,
                            "tool_version": self.manifest.version,
                            "weakness_ids": weakness_ids,
                            "input_manifest_digest": input_manifest_digest or "0" * 64,
                            "rule_bundle_digest": self.manifest.rule_bundle_digest,
                            "tool_assurance": assurance.model_dump(mode="json"),
                            "sink": sink,
                            "data_flow": data_flow,
                        },
                    }
                ).model_dump(mode="json")
            )
        return findings, evidence, rejected

    @staticmethod
    def _input_bindings(files: list[SandboxInputFile]) -> dict[str, _SandboxInputBinding]:
        bindings: dict[str, _SandboxInputBinding] = {}
        for item in files:
            content = item.decoded()
            bindings[item.path] = _SandboxInputBinding(
                sha256=hashlib.sha256(content).hexdigest(),
                size_bytes=len(content),
                line_count=len(content.splitlines()) if content else 0,
            )
        return bindings

    @classmethod
    def _normalize_scanner_path(cls, value: Any) -> str | None:
        path = cls._safe_text(value, "", 1024)
        for prefix in ("/input/", "./"):
            if path.startswith(prefix):
                path = path[len(prefix) :]
                break
        try:
            return validate_relative_path(path, description="scanner finding path")
        except ValueError:
            return None

    @staticmethod
    def _weakness_ids(value: Any, normalized_rule_id: str) -> list[str]:
        candidates = value if isinstance(value, list) else [normalized_rule_id]
        return sorted(
            {
                str(candidate).upper()
                for candidate in candidates
                if re.fullmatch(r"CWE-[1-9][0-9]*", str(candidate), flags=re.IGNORECASE)
            }
        )[:16]

    _collect_files = staticmethod(collect_sandbox_input_files)

    @staticmethod
    def _safe_text(value: Any, default: str, limit: int) -> str:
        return str(value if value is not None else default).replace("\x00", "")[:limit]

    @classmethod
    def _optional_text(cls, value: Any, limit: int) -> str | None:
        return cls._safe_text(value, "", limit) or None

    @staticmethod
    def _error(context: ToolContext, code: str) -> ToolResult:
        unavailable = code in {"SANDBOX_RUNNER_UNAVAILABLE", "SANDBOX_RUNNER_REJECTED"}
        return ToolResult(
            invocation_id=context.invocation_id,
            status=ToolStatus.ERROR,
            data={"availability": "unavailable"} if unavailable else {},
            summary="External scanner is unavailable." if unavailable else "External scanner failed.",
            error_code=code,
            error_message="External scanner runner is unavailable or rejected the request.",
        )

    @staticmethod
    def _safe_error_code(value: str | None) -> str | None:
        if value is None:
            return None
        return value if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value) else "EXTERNAL_TOOL_FAILED"


class UnavailableTool(BaseTool):
    """Placeholder adapter used when an immutable external runner is absent."""

    def __init__(self, manifest: ToolManifest) -> None:
        self.manifest = manifest

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        return ToolResult(
            invocation_id=context.invocation_id,
            status=ToolStatus.ERROR,
            data={"availability": "unavailable"},
            summary="The configured external scanner is unavailable.",
            error_code="TOOL_UNAVAILABLE",
            error_message=f"Tool {self.manifest.name} has no configured immutable image.",
        )
