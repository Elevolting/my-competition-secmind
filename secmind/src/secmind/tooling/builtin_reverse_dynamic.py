"""Bounded Speakeasy API-emulation tool for approved safe PE fixtures."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from secmind.reverse_analysis_observation import ReverseAnalysisObservation
from secmind.schemas import Evidence, RiskLevel, Scenario, ToolContext, ToolManifest, ToolResult, ToolStatus
from secmind.speakeasy_dynamic import approved_safe_fixture_sha256, resolve_safe_target
from secmind.tooling.core import BaseTool, public_evidence_id


class SpeakeasyDynamicAnalysisTool(BaseTool):
    """Invoke a fixed local runner; task input cannot select a command or URL."""

    manifest = ToolManifest(
        name="speakeasy_dynamic_analysis",
        version="1",
        description="Emulate one approved PE with a fixed safe command-line profile and no host PE execution.",
        scenarios=[Scenario.REVERSE_TRIAGE],
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 500},
                "profile_id": {"type": "string", "enum": ["wrong_token", "correct_token"]},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 30},
                "max_instructions": {"type": "integer", "minimum": 1000, "maximum": 5000000},
                "max_api_count": {"type": "integer", "minimum": 100, "maximum": 10000},
            },
            "required": ["target", "profile_id"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
        risk_level=RiskLevel.R1,
        permissions=["workspace:read"],
        timeout_seconds=40,
        idempotent=True,
        requires_network=False,
        capability_tags=["reverse_analysis", "api_emulation", "pe_analysis"],
        evidence_types=["reverse_dynamic_analysis"],
        concurrency_key="reverse_dynamic_analysis",
        max_parallelism=1,
    )

    def __init__(
        self,
        *,
        python_executable: Path | None = None,
        runner_script: Path | None = None,
        sandbox_enabled: bool | None = None,
    ) -> None:
        configured_python = os.getenv("SECMIND_SPEAKEASY_PYTHON", "")
        self.python_executable = python_executable or (Path(configured_python) if configured_python else None)
        repo_root = Path(__file__).resolve().parents[3]
        self.runner_script = runner_script or repo_root / "reverse_evaluation" / "tools" / "run_speakeasy.py"
        self.sandbox_enabled = (sys.platform == "darwin") if sandbox_enabled is None else sandbox_enabled
        self._sandbox_was_explicit = sandbox_enabled is not None

    @staticmethod
    def _sandbox_profile(target: Path, python: Path, runner: Path) -> str:
        readable = {
            target,
            target.parent,
            runner,
            runner.parent,
            python.parent.parent,
            python.resolve().parent.parent,
            runner.parents[2] / "src",
            Path("/System"),
            Path("/usr/lib"),
            Path("/Library"),
        }
        clauses = " ".join(f'(subpath "{path}")' for path in sorted(readable, key=str) if path.is_dir())
        literals = " ".join(f'(literal "{path}")' for path in (target, runner, python, python.resolve()))
        return (
            "(version 1) (deny default) (allow process*) (allow sysctl-read) (allow mach-lookup) "
            f'(allow file-read* (literal "/") {clauses} {literals}) '
            '(allow file-read* (subpath "/dev")) (allow file-write* (literal "/dev/null"))'
        )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        started = time.monotonic()
        try:
            target = resolve_safe_target(str(args.get("target", "")), Path(context.workspace))
        except ValueError as exc:
            return ToolResult(status=ToolStatus.DENIED, error_code="TOOL_SCOPE_VIOLATION", error_message=str(exc))
        python = self.python_executable
        if python is None or not python.is_file() or not self.runner_script.is_file():
            return ToolResult(
                status=ToolStatus.ERROR,
                error_code="SPEAKEASY_UNAVAILABLE",
                error_message="The pinned Speakeasy tool environment is not installed.",
            )
        if not self.sandbox_enabled and not self._sandbox_was_explicit:
            return ToolResult(
                status=ToolStatus.ERROR,
                error_code="SPEAKEASY_SANDBOX_UNAVAILABLE",
                error_message="No reviewed operating-system sandbox backend is available on this platform.",
            )
        sample_bytes = await asyncio.to_thread(target.read_bytes)
        sample_sha256 = hashlib.sha256(sample_bytes).hexdigest()
        if not approved_safe_fixture_sha256(sample_sha256):
            return ToolResult(
                status=ToolStatus.DENIED,
                error_code="SPEAKEASY_SAMPLE_NOT_APPROVED",
                error_message="Only the repository-authored safe fixture is approved for emulation.",
            )
        timeout = int(args.get("timeout_seconds", 15))
        skip_inner_sandbox = os.getenv("SECMIND_SKIP_INNER_SANDBOX") == "1"
        with tempfile.TemporaryDirectory(prefix="secmind-speakeasy-") as temporary:
            temporary_root = await asyncio.to_thread(Path(temporary).resolve)
            execution_target = temporary_root / f"{sample_sha256}.exe"
            await asyncio.to_thread(execution_target.write_bytes, sample_bytes)
            await asyncio.to_thread(execution_target.chmod, 0o400)
            launch_python = python.resolve() if self.sandbox_enabled else python
            command = [
                str(launch_python),
                str(self.runner_script),
                "--target",
                str(execution_target),
                "--profile",
                str(args.get("profile_id", "")),
                "--timeout",
                str(timeout),
                "--max-instructions",
                str(int(args.get("max_instructions", 1_000_000))),
                "--max-api-count",
                str(int(args.get("max_api_count", 2_000))),
            ]
            if self.sandbox_enabled and not skip_inner_sandbox:
                command = [
                    "/usr/bin/sandbox-exec",
                    "-p",
                    self._sandbox_profile(execution_target, python, self.runner_script),
                    *command,
                ]
            env = {"PATH": str(python.parent), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}
            if self.sandbox_enabled:
                env["__PYVENV_LAUNCHER__"] = str(python)
            try:
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout + 8)
            except TimeoutError:
                if "process" in locals() and process.returncode is None:
                    process.kill()
                    await process.wait()
                return ToolResult(
                    status=ToolStatus.ERROR, error_code="SPEAKEASY_TIMEOUT", error_message="Emulation timed out."
                )
        if len(stdout) > 512 * 1024:
            return ToolResult(
                status=ToolStatus.ERROR,
                error_code="SPEAKEASY_OUTPUT_LIMIT",
                error_message="Normalized emulation output exceeded 512 KiB.",
            )
        if process.returncode != 0:
            diagnostic = stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or ["no diagnostic"]
            safe_diagnostic = diagnostic[0].replace(str(target), "<target>")[:240]
            return ToolResult(
                status=ToolStatus.ERROR,
                error_code="SPEAKEASY_RUNNER_FAILED",
                error_message=f"Pinned runner exited with code {process.returncode}: {safe_diagnostic}",
            )
        try:
            payload = json.loads(stdout.decode("utf-8"))
            observation = ReverseAnalysisObservation.model_validate(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
            return ToolResult(
                status=ToolStatus.ERROR,
                error_code="SPEAKEASY_REPORT_INVALID",
                error_message=type(exc).__name__,
            )
        target_bytes_after = await asyncio.to_thread(target.read_bytes)
        target_sha256_after = hashlib.sha256(target_bytes_after).hexdigest()
        if observation.sample_sha256 != sample_sha256 or target_sha256_after != sample_sha256:
            return ToolResult(
                status=ToolStatus.ERROR,
                error_code="SPEAKEASY_SAMPLE_HASH_MISMATCH",
                error_message="The emulated observation was not bound to the admitted sample bytes.",
            )
        serialized = observation.model_dump(mode="json")
        serialized["coverage"]["sandbox_enforced"] = self.sandbox_enabled and not skip_inner_sandbox
        serialized["coverage"]["sandbox_scope"] = (
            "delegated_unverified" if skip_inner_sandbox else "tool_inner"
        )
        serialized["coverage"]["content_addressed_copy"] = True
        digest = hashlib.sha256(json.dumps(serialized, sort_keys=True).encode()).hexdigest()
        evidence = Evidence(
            evidence_id=public_evidence_id(digest),
            source="speakeasy_dynamic_analysis:1",
            summary=f"Speakeasy {observation.profile_id} profile retained {len(observation.events)} runtime event(s).",
            sha256=digest,
            metadata={
                "evidence_type": "reverse_dynamic_analysis",
                "tool_name": self.manifest.name,
                "tool_version": self.manifest.version,
                "sample_sha256": observation.sample_sha256,
                "profile_id": observation.profile_id,
            },
        )
        serialized["evidence_refs"] = [evidence.evidence_id]
        return ToolResult(
            invocation_id=context.invocation_id,
            status=ToolStatus.SUCCESS,
            data=serialized,
            summary=evidence.summary,
            evidence=[evidence],
            duration_ms=int((time.monotonic() - started) * 1000),
        )
