"""Reviewed local Semgrep adapter."""

# ruff: noqa: F401,F403,F405
import asyncio
import hashlib
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from secmind.language_registry import LANGUAGE_REGISTRY_VERSION
from secmind.sandbox import *
from secmind.schemas import *
from secmind.tooling.builtin_python import BanditTool
from secmind.tooling.core import (
    BaseTool,
    ToolError,
    _provenance_metadata,
    compute_input_manifest_digest,
    sanitized_tool_environment,
    workspace_input_manifest,
)
from secmind.tooling.external_manifests import (
    EXTERNAL_TOOL_NAMES,
    SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST,
    SEMGREP_REVIEWED_RULE_LANGUAGES,
)


class DevelopmentSemgrepTool(BaseTool):
    """Run the reviewed offline Semgrep bundle through the Broker in local evaluation.

    Production continues to require the isolated sandbox runner.  This adapter is
    constructed only when ``unsafe_development_tools`` and the reviewed candidate
    flag are both explicit. It uses an installed Semgrep CLI when available and a
    bounded implementation of only the repository-owned reviewed rules otherwise;
    the result records which engine ran.
    """

    _MAX_RESULT_BYTES = 16 * 1024 * 1024
    _MAX_FINDINGS = 2_000
    _MAX_FALLBACK_SOURCE_BYTES = 512_000
    _SEVERITY: dict[str, Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]] = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }

    def __init__(self, rules_path: Path) -> None:
        resolved = rules_path.resolve(strict=True)
        if not resolved.is_dir():
            raise ValueError("Semgrep reviewed rule bundle must be a directory")
        self.rules_path = resolved
        self.manifest = ToolManifest(
            name="semgrep_sast",
            version="development-adapter-2",
            description="Reviewed offline SAST rules in an explicit local test profile.",
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
            timeout_seconds=180,
            idempotent=True,
            requires_network=False,
            capability_tags=["sast"],
            supported_languages=list(SEMGREP_REVIEWED_RULE_LANGUAGES),
            rule_bundle_digest=SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST,
            evidence_types=["sast_finding"],
            concurrency_key="sast",
            max_parallelism=2,
            health_status=ToolHealth.HEALTHY,
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
        workspace = Path(context.workspace).resolve()  # noqa: ASYNC240 - bounded local metadata operation
        manifest_rows = workspace_input_manifest(workspace, target)
        input_manifest_digest = compute_input_manifest_digest(manifest_rows)
        with tempfile.TemporaryDirectory(prefix="secmind-semgrep-") as temporary:
            output = Path(temporary) / "result.json"
            environment = sanitized_tool_environment(
                {
                    "SEMGREP_SEND_METRICS": "off",
                    "SEMGREP_ENABLE_VERSION_CHECK": "0",
                    "SEMGREP_SETTINGS_FILE": str(Path(temporary) / "settings.yml"),
                }
            )
            semgrep_executable = shutil.which("semgrep")
            semgrep_args = (
                "--config",
                str(self.rules_path),
                "--json-output",
                str(output),
                "--metrics",
                "off",
                "--disable-version-check",
                "--no-rewrite-rule-ids",
                "--no-git-ignore",
                "--quiet",
                str(target),
            )
            command: tuple[str, ...]
            if os.name == "nt" and importlib.util.find_spec("semgrep") is not None:
                # uv-generated Windows entrypoints can retain a stale absolute
                # interpreter path after a virtualenv is moved.  Invoke the
                # installed legacy CLI through the current interpreter so the
                # reviewed local adapter remains testable without trusting the
                # broken launcher shim.
                command = (sys.executable, "-I", "-c", "from semgrep.cli import cli; cli()", *semgrep_args)
            elif semgrep_executable is None:
                body = self._reviewed_fallback_body(workspace, manifest_rows)
                findings, evidence, rejected = self._normalize(
                    body,
                    workspace,
                    input_manifest_digest=input_manifest_digest,
                )
                return self._result(
                    context=context,
                    started=started,
                    findings=findings,
                    evidence=evidence,
                    rejected=rejected,
                    manifest_rows=manifest_rows,
                    input_manifest_digest=input_manifest_digest,
                    engine="bounded-reviewed-fallback",
                )
            else:
                command = (semgrep_executable, *semgrep_args)
            try:
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    cwd=context.workspace,
                    env=environment,
                )
                await asyncio.wait_for(process.wait(), timeout=self.manifest.timeout_seconds)
            except TimeoutError:
                process.kill()
                await process.wait()
                return ToolResult(
                    invocation_id=context.invocation_id,
                    status=ToolStatus.TIMEOUT,
                    duration_ms=int((time.monotonic() - started) * 1000),
                    error_code="TOOL_TIMEOUT",
                    error_message="Semgrep exceeded its execution deadline.",
                )
            except OSError as exc:
                return ToolResult(
                    invocation_id=context.invocation_id,
                    status=ToolStatus.ERROR,
                    duration_ms=int((time.monotonic() - started) * 1000),
                    error_code="SEMGREP_UNAVAILABLE",
                    error_message=type(exc).__name__,
                )
            if process.returncode not in {0, 1} or not output.is_file():
                return ToolResult(
                    invocation_id=context.invocation_id,
                    status=ToolStatus.ERROR,
                    duration_ms=int((time.monotonic() - started) * 1000),
                    error_code="SEMGREP_FAILED",
                    error_message="Semgrep did not produce a valid result artifact.",
                )
            try:
                if output.stat().st_size > self._MAX_RESULT_BYTES:
                    raise ValueError("Semgrep result exceeded the bounded output size")
                body = json.loads(output.read_text(encoding="utf-8"))
                findings, evidence, rejected = self._normalize(
                    body,
                    workspace,
                    input_manifest_digest=input_manifest_digest,
                )
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                return ToolResult(
                    invocation_id=context.invocation_id,
                    status=ToolStatus.ERROR,
                    duration_ms=int((time.monotonic() - started) * 1000),
                    error_code="SEMGREP_OUTPUT_INVALID",
                    error_message=str(exc)[:500],
                )
        return self._result(
            context=context,
            started=started,
            findings=findings,
            evidence=evidence,
            rejected=rejected,
            manifest_rows=manifest_rows,
            input_manifest_digest=input_manifest_digest,
            engine="semgrep-cli",
        )

    def _result(
        self,
        *,
        context: ToolContext,
        started: float,
        findings: list[dict[str, Any]],
        evidence: list[Evidence],
        rejected: int,
        manifest_rows: list[dict[str, Any]],
        input_manifest_digest: str,
        engine: str,
    ) -> ToolResult:
        if rejected:
            return ToolResult(
                invocation_id=context.invocation_id,
                status=ToolStatus.ERROR,
                data={"findings": findings, "rejected_findings": rejected},
                evidence=evidence,
                duration_ms=int((time.monotonic() - started) * 1000),
                error_code="SEMGREP_INCOMPLETE_RESULTS",
                error_message="One or more Semgrep findings failed input binding validation.",
            )
        return ToolResult(
            invocation_id=context.invocation_id,
            status=ToolStatus.SUCCESS,
            data={
                "findings": findings,
                "rejected_findings": 0,
                "input_manifest": manifest_rows,
                "input_manifest_digest": input_manifest_digest,
                "rule_bundle_digest": SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST,
                "language_registry_version": LANGUAGE_REGISTRY_VERSION,
                "engine": engine,
            },
            summary=f"Semgrep completed with {len(findings)} reviewed finding(s).",
            evidence=evidence,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    def _reviewed_fallback_body(self, workspace: Path, manifest_rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        """Evaluate the tiny reviewed bundle when a local Semgrep CLI is absent.

        This deterministic development-only path is intentionally limited to
        the three repository-owned source-to-sink rules. Production continues
        to execute the same YAML bundle in the isolated Semgrep container.
        """

        results: list[dict[str, Any]] = []
        for row in manifest_rows:
            relative = str(row["path"])
            path = (workspace / relative).resolve()
            if path.suffix.casefold() not in {".cjs", ".java", ".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}:
                continue
            if int(row["size_bytes"]) > self._MAX_FALLBACK_SOURCE_BYTES:
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            suffix = path.suffix.casefold()
            if suffix == ".py":
                has_flask_source = re.search(r"\bflask\.request\.(?:args|form|values)\.get\s*\(", source) is not None
                sink_pattern = re.compile(
                    r"\bsubprocess\.(?:run|call|Popen)\s*\([^\n]*\bshell\s*=\s*True\b",
                    re.IGNORECASE,
                )
                for match in sink_pattern.finditer(source) if has_flask_source else ():
                    results.append(
                        self._fallback_result(
                            path=relative,
                            line=source.count("\n", 0, match.start()) + 1,
                            native_rule_id="secmind.python.flask-shell-command-injection",
                            weakness_id="CWE-78",
                            message="User-controlled Flask request data reaches a subprocess shell command.",
                            remediation=(
                                "Pass a fixed executable and validated arguments as a list with shell disabled."
                            ),
                        )
                    )
            elif suffix in {".cjs", ".js", ".jsx", ".mjs", ".ts", ".tsx"}:
                has_request_source = re.search(r"\b(?:req|request)\.(?:params|query|body)\b", source) is not None
                if not has_request_source:
                    continue
                rules = (
                    (
                        re.compile(r"\b(?:fs\.)?(?:readFile|readFileSync|createReadStream)\s*\("),
                        "secmind.javascript.express-path-traversal",
                        "CWE-22",
                        "User-controlled request data reaches a filesystem path sink.",
                        "Resolve paths below an approved root and reject traversal segments.",
                    ),
                    (
                        re.compile(r"\b(?:child_process\.)?(?:exec|spawn)\s*\("),
                        "secmind.javascript.express-command-injection",
                        "CWE-78",
                        "User-controlled request data reaches a child-process command sink.",
                        "Use a fixed executable and validated argument vector without shell interpolation.",
                    ),
                )
                for pattern, native_rule_id, weakness_id, message, remediation in rules:
                    for match in pattern.finditer(source):
                        results.append(
                            self._fallback_result(
                                path=relative,
                                line=source.count("\n", 0, match.start()) + 1,
                                native_rule_id=native_rule_id,
                                weakness_id=weakness_id,
                                message=message,
                                remediation=remediation,
                            )
                        )
            elif re.search(r"\b(?:request|req)\.(?:getParameter|getHeader)\s*\(", source):
                for match in re.finditer(r"\b(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(", source):
                    results.append(
                        self._fallback_result(
                            path=relative,
                            line=source.count("\n", 0, match.start()) + 1,
                            native_rule_id="secmind.java.request-runtime-command-injection",
                            weakness_id="CWE-78",
                            message="User-controlled request data reaches a Java process execution sink.",
                            remediation="Use a fixed command and validated argument list.",
                        )
                    )
            if len(results) >= self._MAX_FINDINGS:
                break
        return {"results": results[: self._MAX_FINDINGS], "errors": []}

    @staticmethod
    def _fallback_result(
        *,
        path: str,
        line: int,
        native_rule_id: str,
        weakness_id: str,
        message: str,
        remediation: str,
    ) -> dict[str, Any]:
        return {
            "check_id": native_rule_id,
            "path": path,
            "start": {"line": line},
            "extra": {
                "severity": "ERROR",
                "message": message,
                "metadata": {"cwe": weakness_id, "remediation": remediation},
            },
        }

    def _normalize(
        self,
        body: object,
        workspace: Path,
        *,
        input_manifest_digest: str = "0" * 64,
    ) -> tuple[list[dict[str, Any]], list[Evidence], int]:
        if not isinstance(body, dict) or not isinstance(body.get("results", []), list):
            raise ValueError("Semgrep result must contain a results array")
        errors = body.get("errors", [])
        if not isinstance(errors, list) or errors:
            raise ValueError("Semgrep reported an incomplete scan")
        findings: list[dict[str, Any]] = []
        evidence: list[Evidence] = []
        rejected = max(0, len(body["results"]) - self._MAX_FINDINGS)
        for item in body["results"][: self._MAX_FINDINGS]:
            normalized = self._normalize_one(item, workspace, input_manifest_digest=input_manifest_digest)
            if normalized is None:
                rejected += 1
                continue
            finding, item_evidence = normalized
            findings.append(finding.model_dump(mode="json"))
            evidence.append(item_evidence)
        pairs = sorted(
            zip(findings, evidence, strict=True),
            key=lambda pair: (
                pair[0]["path"],
                pair[0]["line"],
                pair[0]["raw"]["native_rule_id"],
            ),
        )
        return [pair[0] for pair in pairs], [pair[1] for pair in pairs], rejected

    def _normalize_one(
        self,
        item: object,
        workspace: Path,
        *,
        input_manifest_digest: str = "0" * 64,
    ) -> tuple[Finding, Evidence] | None:
        if not isinstance(item, dict):
            return None
        raw_path = str(item.get("path") or "")
        candidate = Path(raw_path)
        resolved = candidate.resolve() if candidate.is_absolute() else (workspace / candidate).resolve()
        try:
            relative = resolved.relative_to(workspace).as_posix()
        except ValueError:
            return None
        if not resolved.is_file() or resolved.is_symlink():
            return None
        try:
            line = int((item.get("start") or {}).get("line", 0))
        except (AttributeError, TypeError, ValueError):
            return None
        payload = resolved.read_bytes()
        line_count = len(payload.splitlines())
        if line < 1 or line > line_count:
            return None
        raw_extra = item.get("extra")
        extra: dict[str, Any] = raw_extra if isinstance(raw_extra, dict) else {}
        raw_metadata = extra.get("metadata")
        metadata: dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
        native_rule_id = str(item.get("check_id") or "semgrep.unknown")[:160]
        raw_cwe = metadata.get("cwe")
        cwe_values = raw_cwe if isinstance(raw_cwe, list) else [raw_cwe]
        weakness_ids = sorted(
            {
                f"CWE-{match.group(1)}"
                for value in cwe_values
                if (match := re.search(r"(?:CWE-)?([1-9][0-9]*)", str(value or ""), re.IGNORECASE))
            }
        )[:16]
        rule_id = weakness_ids[0] if weakness_ids else native_rule_id
        message = str(extra.get("message") or native_rule_id).replace("\x00", "")[:2_000]
        severity = self._SEVERITY.get(str(extra.get("severity") or "").upper(), "UNKNOWN")
        file_sha256 = hashlib.sha256(payload).hexdigest()
        evidence_id = hashlib.sha256(f"semgrep:{native_rule_id}:{relative}:{line}:{file_sha256}".encode()).hexdigest()[
            :32
        ]
        finding_id = f"finding-{evidence_id}"
        item_evidence = Evidence(
            evidence_id=evidence_id,
            source=f"semgrep_sast:{self.manifest.version}",
            summary=f"{native_rule_id} matched at {relative}:{line}",
            sha256=file_sha256,
            metadata={
                "evidence_type": "sast_finding",
                "tool_name": self.manifest.name,
                "tool_version": self.manifest.version,
                "path": relative,
                "line": line,
                "file_sha256": file_sha256,
                "native_rule_id": native_rule_id,
                "normalized_rule_id": rule_id,
                "weakness_ids": weakness_ids,
                "rule_bundle_digest": SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST,
                "assurance_level": "integrity_verified",
                **_provenance_metadata(
                    path=relative,
                    line=line,
                    file_sha256=file_sha256,
                    input_manifest_digest=input_manifest_digest,
                    rule_bundle_digest=SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST,
                    finding_id=finding_id,
                ),
            },
        )
        return (
            Finding(
                finding_id=finding_id,
                rule_id=rule_id,
                severity=severity,
                confidence="HIGH" if severity == "HIGH" else "MEDIUM",
                path=relative,
                line=line,
                title=message.splitlines()[0][:300],
                description=message,
                remediation=(str(metadata.get("remediation"))[:2_000] if metadata.get("remediation") else None),
                evidence_ids=[evidence_id],
                raw={
                    "native_rule_id": native_rule_id,
                    "normalized_rule_id": rule_id,
                    "weakness_ids": weakness_ids,
                    "tool_name": self.manifest.name,
                    "tool_version": self.manifest.version,
                    "file_sha256": file_sha256,
                    "input_manifest_digest": input_manifest_digest,
                    "rule_bundle_digest": SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST,
                },
            ),
            item_evidence,
        )
