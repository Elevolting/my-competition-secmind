from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

import httpx

from secmind.sandbox import (
    SandboxInputFile,
    SandboxInvocation,
    SandboxResult,
    collect_sandbox_input_files,
    validate_relative_path,
)
from secmind.schemas import ArtifactRef, ToolContext, ToolResult, ToolStatus
from secmind.tools import (
    BANDIT_RULE_BUNDLE_DIGEST,
    BanditTool,
    BaseTool,
    ToolError,
    compute_input_manifest_digest,
    normalize_bandit_findings,
)


@dataclass(frozen=True, slots=True)
class _SandboxInputBinding:
    file_sha256: str
    line_count: int
    size_bytes: int


class SandboxBanditTool(BaseTool):
    """Bandit adapter that sends immutable file content to the isolated runner."""

    manifest = BanditTool.manifest.model_copy(deep=True)
    manifest.version = "sandbox-1"

    def __init__(
        self,
        runner_url: str,
        service_token: str | None = None,
        client: httpx.AsyncClient | None = None,
        *,
        capability_ticket_provider: Callable[[SandboxInvocation], str] | None = None,
    ) -> None:
        if not runner_url or not (service_token or capability_ticket_provider):
            raise ValueError("Sandbox runner URL and capability credentials are required")
        self.runner_url = runner_url.rstrip("/")
        self.service_token = service_token or ""
        self.capability_ticket_provider = capability_ticket_provider
        self._client = client

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        try:
            target = BanditTool._resolve_target(str(args.get("target", ".")), context)
            files = collect_sandbox_input_files(target)
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
            lease_fence=int(getattr(context, "lease_fence", 0)),
            files=files,
        )
        credential = (
            self.capability_ticket_provider(invocation) if self.capability_ticket_provider else self.service_token
        )
        # Snapshot the exact request body after capability derivation. Both the
        # output allowlist and file digests must come from these sent bytes, not
        # from a later read of the mutable workspace.
        request_payload = invocation.model_dump(mode="json")
        sent_files = [SandboxInputFile.model_validate(item) for item in request_payload["files"]]
        input_bindings = self._input_bindings(sent_files)
        input_manifest = [
            {
                "path": path,
                "sha256": binding.file_sha256,
                "size_bytes": binding.size_bytes,
            }
            for path, binding in sorted(input_bindings.items())
        ]
        input_manifest_digest = compute_input_manifest_digest(input_manifest)
        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=self.manifest.timeout_seconds + 15)
        try:
            response = await client.post(
                f"{self.runner_url}/internal/v1/invocations",
                headers={"Authorization": f"Bearer {credential}"},
                json=request_payload,
                timeout=self.manifest.timeout_seconds + 15,
            )
            if response.status_code != 200:
                return ToolResult(
                    invocation_id=context.invocation_id,
                    status=ToolStatus.ERROR,
                    error_code="SANDBOX_RUNNER_REJECTED",
                    error_message=f"Sandbox runner returned HTTP {response.status_code}",
                )
            sandbox_result = SandboxResult.model_validate(response.json())
        except (httpx.HTTPError, ValueError) as exc:
            return ToolResult(
                invocation_id=context.invocation_id,
                status=ToolStatus.ERROR,
                error_code="SANDBOX_RUNNER_UNAVAILABLE",
                error_message=type(exc).__name__,
            )
        finally:
            if owns_client:
                await client.aclose()

        if sandbox_result.invocation_id != context.invocation_id:
            return ToolResult(
                invocation_id=context.invocation_id,
                status=ToolStatus.ERROR,
                error_code="SANDBOX_INVOCATION_MISMATCH",
                error_message="Sandbox runner response belongs to a different invocation.",
            )

        status_map = {
            "success": ToolStatus.SUCCESS,
            "timeout": ToolStatus.TIMEOUT,
            "denied": ToolStatus.DENIED,
            "error": ToolStatus.ERROR,
        }
        status = status_map.get(sandbox_result.status, ToolStatus.ERROR)
        try:
            raw_findings, rejected_findings = self._bind_runner_findings(
                sandbox_result.data.get("findings", []), input_bindings=input_bindings
            )
            evidence, findings = normalize_bandit_findings(
                raw_findings,
                self.manifest.version,
                input_manifest_digest=input_manifest_digest,
            )
        except ValueError:
            return ToolResult(
                invocation_id=context.invocation_id,
                status=ToolStatus.ERROR,
                error_code="SANDBOX_OUTPUT_INVALID",
                error_message="Sandbox runner returned invalid Bandit findings",
            )
        for evidence_item in evidence:
            binding = input_bindings[str(evidence_item.metadata["path"])]
            evidence_item.metadata["file_sha256"] = binding.file_sha256
        for finding in findings:
            binding = input_bindings[str(finding["path"])]
            finding["raw"]["file_sha256"] = binding.file_sha256
        if rejected_findings and status == ToolStatus.SUCCESS and not findings:
            return ToolResult(
                invocation_id=context.invocation_id,
                status=ToolStatus.ERROR,
                data={
                    "accepted_findings": 0,
                    "rejected_unbound_findings": rejected_findings,
                },
                summary=(
                    "Bandit output was incomplete because one or more findings "
                    "could not be bound to the input snapshot."
                ),
                duration_ms=sandbox_result.duration_ms,
                error_code="SANDBOX_OUTPUT_UNBOUND",
                error_message="No sandbox finding could be bound to the immutable input snapshot.",
            )
        artifacts = [
            ArtifactRef(
                artifact_id=item.artifact_id,
                ref=item.artifact_id,
                sha256=item.sha256,
                size_bytes=item.size_bytes,
                media_type=item.media_type,
            )
            for item in sandbox_result.artifacts
        ]
        data = {
            **sandbox_result.data,
            "findings": findings,
            "input_manifest": input_manifest,
            "input_manifest_digest": input_manifest_digest,
            "rule_bundle_digest": BANDIT_RULE_BUNDLE_DIGEST,
            "coverage": {
                "status": "partial" if rejected_findings else "complete",
                "accepted_findings": len(findings),
                "rejected_unbound_findings": rejected_findings,
                "complete": not rejected_findings,
            },
        }
        if rejected_findings:
            data["rejected_unbound_findings"] = rejected_findings
        return ToolResult(
            invocation_id=context.invocation_id,
            status=status,
            data=data,
            summary=(
                f"{sandbox_result.summary} Preserved {len(findings)} bound finding(s) and quarantined "
                f"{rejected_findings} unbound finding(s)."
                if rejected_findings and findings
                else sandbox_result.summary
            ),
            artifacts=artifacts,
            evidence=evidence,
            duration_ms=sandbox_result.duration_ms,
            error_code=sandbox_result.error_code,
            error_message=sandbox_result.error_message,
        )

    @staticmethod
    def _bind_runner_findings(
        items: Any,
        *,
        input_bindings: dict[str, _SandboxInputBinding],
    ) -> tuple[list[dict[str, Any]], int]:
        if not isinstance(items, list):
            raise ValueError("Bandit findings must be an array")
        normalized: list[dict[str, Any]] = []
        rejected = 0
        input_root = PurePosixPath("/input")
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("Bandit finding must be an object")
            copied = dict(item)
            raw_filename = copied.get("filename")
            if not isinstance(raw_filename, str) or "\\" in raw_filename:
                rejected += 1
                continue
            raw_path = raw_filename
            candidate = PurePosixPath(raw_path)
            if candidate.is_absolute():
                try:
                    candidate = candidate.relative_to(input_root)
                except ValueError:
                    rejected += 1
                    continue
            try:
                relative = validate_relative_path(candidate.as_posix(), description="Bandit finding path")
            except ValueError:
                rejected += 1
                continue
            binding = input_bindings.get(relative)
            line = copied.get("line_number")
            if (
                binding is None
                or not isinstance(line, int)
                or isinstance(line, bool)
                or line < 1
                or line > binding.line_count
            ):
                rejected += 1
                continue
            copied["filename"] = relative
            # Overwrite any runner-supplied digest before the normalizer hashes
            # the evidence payload, so its identity commits to the sent bytes.
            copied["file_sha256"] = binding.file_sha256
            normalized.append(copied)
        return normalized, rejected

    @staticmethod
    def _input_bindings(files: list[SandboxInputFile]) -> dict[str, _SandboxInputBinding]:
        bindings: dict[str, _SandboxInputBinding] = {}
        for item in files:
            content = item.decoded()
            bindings[item.path] = _SandboxInputBinding(
                file_sha256=hashlib.sha256(content).hexdigest(),
                line_count=len(content.splitlines()),
                size_bytes=len(content),
            )
        return bindings

    _collect_files = staticmethod(collect_sandbox_input_files)
