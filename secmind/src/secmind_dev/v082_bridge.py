"""Fail-closed process Bridge for the v0.8.2 evaluation CLI.

The Bridge is responsible for process I/O and typed execution telemetry.  It
does not score findings and it never writes provider response bodies into a
public result.  stdout/stderr are drained, hashed and optionally retained in
CAS so a temporary service directory can be removed without losing failure
diagnostics.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess  # nosec B404
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .v082_cas import CASStore
from .v082_contracts import (
    BRIDGE_SCHEMA_VERSION,
    AttemptRecord,
    FailureCapsule,
    QuarantineRecord,
    canonical_digest,
    canonical_json,
    normalize_sha256,
    sha256_bytes,
)


class BridgeError(RuntimeError):
    """Raised for invalid Bridge configuration, not an agent finding."""


@dataclass(frozen=True, slots=True)
class BridgeConfig:
    timeout_seconds: float = 1_200.0
    max_stdout_bytes: int = 1_048_576
    max_stderr_bytes: int = 1_048_576
    max_attempts: int = 2
    kill_grace_seconds: float = 2.0
    inherit_environment: bool = False
    pass_environment: tuple[str, ...] = ()
    fixed_environment: Mapping[str, str] = field(default_factory=dict)
    working_directory: Path | None = None

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0 or self.timeout_seconds > 7_200:
            raise BridgeError("Bridge timeout_seconds must be in (0, 7200]")
        for name in ("max_stdout_bytes", "max_stderr_bytes", "max_attempts"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise BridgeError(f"Bridge {name} must be a positive integer")
        if self.max_attempts > 2:
            raise BridgeError("v0.8.2 Bridge permits at most one primary and one fallback attempt")
        if self.kill_grace_seconds < 0 or self.kill_grace_seconds > 60:
            raise BridgeError("kill_grace_seconds is outside the safe range")
        if any(not isinstance(item, str) or not item.isidentifier() for item in self.pass_environment):
            raise BridgeError("pass_environment contains an invalid environment name")
        if any(_secret_like(key) for key in self.fixed_environment):
            raise BridgeError("fixed_environment cannot contain secret-like keys")

    @property
    def digest(self) -> str:
        return canonical_digest(
            {
                "timeout_seconds": self.timeout_seconds,
                "max_stdout_bytes": self.max_stdout_bytes,
                "max_stderr_bytes": self.max_stderr_bytes,
                "max_attempts": self.max_attempts,
                "kill_grace_seconds": self.kill_grace_seconds,
                "inherit_environment": self.inherit_environment,
                "pass_environment": list(self.pass_environment),
                "fixed_environment": dict(sorted(self.fixed_environment.items())),
                "working_directory": str(self.working_directory) if self.working_directory else None,
            }
        )


@dataclass(frozen=True, slots=True)
class BridgeInvocation:
    command: tuple[str, ...]
    request: Mapping[str, Any]
    attempt_type: str = "primary"
    model_profile: str = "UNKNOWN"
    request_digest: str = ""

    def __post_init__(self) -> None:
        if not self.command or any(not isinstance(item, str) or not item for item in self.command):
            raise BridgeError("Bridge command must be a non-empty argument array")
        if not isinstance(self.request, Mapping):
            raise BridgeError("Bridge request must be a JSON object")
        if not self.attempt_type or len(self.attempt_type) > 64:
            raise BridgeError("Bridge attempt_type is invalid")
        computed = canonical_digest(self.request)
        if self.request_digest:
            object.__setattr__(
                self, "request_digest", normalize_sha256(self.request_digest, field_name="request_digest")
            )
            if self.request_digest != computed:
                raise BridgeError("request_digest does not match the request payload")
        else:
            object.__setattr__(self, "request_digest", computed)


@dataclass(frozen=True, slots=True)
class StreamCapture:
    stream: str
    sha256: str
    total_bytes: int
    retained_bytes: int
    truncated: bool
    cas_digest: str | None
    text: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "stream": self.stream,
            "sha256": self.sha256,
            "total_bytes": self.total_bytes,
            "retained_bytes": self.retained_bytes,
            "truncated": self.truncated,
            "cas_digest": self.cas_digest,
            "text": self.text,
        }


@dataclass(frozen=True, slots=True)
class BridgeExecution:
    status: str
    exit_code: int | None
    duration_ms: int
    timed_out: bool
    stdout: StreamCapture
    stderr: StreamCapture
    result: Mapping[str, Any] | None
    attempt: AttemptRecord
    failure_capsule: FailureCapsule | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": BRIDGE_SCHEMA_VERSION,
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
            "stdout": self.stdout.to_dict(),
            "stderr": self.stderr.to_dict(),
            "result": dict(self.result) if self.result is not None else None,
            "attempt": self.attempt.to_dict(),
            "failure_capsule": self.failure_capsule.to_dict() if self.failure_capsule else None,
        }


@dataclass(frozen=True, slots=True)
class BridgeRun:
    executions: tuple[BridgeExecution, ...]
    selected_result: Mapping[str, Any] | None
    failure_capsule: FailureCapsule | None

    @property
    def attempts(self) -> tuple[AttemptRecord, ...]:
        return tuple(item.attempt for item in self.executions)

    @property
    def status(self) -> str:
        if self.selected_result is not None:
            return "SUCCESS" if self.executions and self.executions[-1].status == "SUCCESS" else "PARTIAL"
        return self.executions[-1].status if self.executions else "FAILED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": BRIDGE_SCHEMA_VERSION,
            "status": self.status,
            "executions": [item.to_dict() for item in self.executions],
            "selected_result": dict(self.selected_result) if self.selected_result is not None else None,
            "failure_capsule": self.failure_capsule.to_dict() if self.failure_capsule else None,
        }


class _CaptureBuffer:
    def __init__(self, stream: str, limit: int, cas: CASStore | None) -> None:
        self.stream = stream
        self.limit = limit
        self.cas = cas
        self._digest = hashlib.sha256()
        self._retained = bytearray()
        self.total_bytes = 0

    def add(self, chunk: bytes) -> None:
        self._digest.update(chunk)
        self.total_bytes += len(chunk)
        if len(self._retained) < self.limit:
            self._retained.extend(chunk[: self.limit - len(self._retained)])

    def finish(self) -> StreamCapture:
        digest = self._digest.hexdigest()
        payload = bytes(self._retained)
        cas_digest = self.cas.put_bytes(payload, kind=f"bridge-{self.stream}") if self.cas is not None else None
        return StreamCapture(
            stream=self.stream,
            sha256=digest,
            total_bytes=self.total_bytes,
            retained_bytes=len(payload),
            truncated=self.total_bytes > len(payload),
            cas_digest=cas_digest,
            text=payload.decode("utf-8", errors="replace"),
        )


class ProcessBridge:
    """Run an adapter command while preserving typed, bounded telemetry."""

    def __init__(self, config: BridgeConfig, *, cas: CASStore | None = None) -> None:
        self.config = config
        self.cas = cas

    def run(self, invocation: BridgeInvocation, *, attempt_ordinal: int = 1) -> BridgeExecution:
        started = time.monotonic()
        stdout_capture = _CaptureBuffer("stdout", self.config.max_stdout_bytes, self.cas)
        stderr_capture = _CaptureBuffer("stderr", self.config.max_stderr_bytes, self.cas)
        process: subprocess.Popen[bytes] | None = None
        timed_out = False
        exit_code: int | None = None
        stage = "spawn"
        error_type: str | None = None
        retryable = False
        try:
            stage = "process"
            process = subprocess.Popen(  # noqa: S603  # nosec B603
                list(invocation.command),
                cwd=str(self.config.working_directory) if self.config.working_directory else None,
                env=self._environment(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
                start_new_session=(os.name != "nt"),
            )
            if process.stdout is None or process.stderr is None:
                raise BridgeError("Bridge subprocess pipes were not created")
            stdin = process.stdin
            if stdin is not None:
                request_errors: list[BaseException] = []

                def write_request() -> None:
                    try:
                        stdin.write(canonical_json(invocation.request) + b"\n")
                        stdin.close()
                    except (BrokenPipeError, OSError) as exc:
                        request_errors.append(exc)

                request_thread = threading.Thread(target=write_request, daemon=True)
                request_thread.start()
                request_thread.join(timeout=min(5.0, self.config.timeout_seconds))
                if request_thread.is_alive() or request_errors:
                    stage = "request_write"
                    error_type = "transport"
                    retryable = request_thread.is_alive()
            threads = [
                threading.Thread(target=self._drain, args=(process.stdout, stdout_capture), daemon=True),
                threading.Thread(target=self._drain, args=(process.stderr, stderr_capture), daemon=True),
            ]
            for thread in threads:
                thread.start()
            try:
                exit_code = process.wait(timeout=self.config.timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                stage = "timeout"
                error_type = "timeout"
                retryable = True
                self._terminate(process)
                exit_code = process.poll()
            for thread in threads:
                thread.join(timeout=max(1.0, self.config.kill_grace_seconds + 1.0))
        except FileNotFoundError:
            error_type = "transport"
            stage = "spawn"
            retryable = False
        except (OSError, ValueError):
            error_type = "transport"
            stage = "spawn"
            retryable = False
        finally:
            stdout = stdout_capture.finish()
            stderr = stderr_capture.finish()
        duration_ms = int((time.monotonic() - started) * 1000)
        if error_type is None and exit_code not in (0, None):
            error_type = "crash"
            retryable = False
        if error_type is None and exit_code is None:
            error_type = "transport"
            retryable = False
        if error_type is None:
            status = "SUCCESS"
        elif timed_out:
            status = "TIMEOUT"
        elif exit_code not in (None, 0):
            status = "CRASH"
        else:
            status = "FAILED"
        result = self._parse_result(stdout.text) if status == "SUCCESS" else None
        if status == "SUCCESS" and result is None:
            status = "PARTIAL"
            error_type = "parse"
            # A malformed response may use a distinct fallback request; the
            # Bridge still rejects an identical request digest.
            retryable = True
            stage = "parse"
        attempt = AttemptRecord(
            attempt_ordinal=attempt_ordinal,
            attempt_type=invocation.attempt_type,
            status=status,
            duration_ms=duration_ms,
            stage=stage,
            retryable=retryable,
            request_digest=invocation.request_digest,
            provider_payload_digest=invocation.request_digest,
            response_digest=sha256_bytes(canonical_json(result)) if result is not None else None,
            error_type=error_type,
            model_profile=invocation.model_profile,
            stdout_sha256=stdout.sha256,
            stderr_sha256=stderr.sha256,
        )
        capsule = None
        if error_type is not None:
            capsule = FailureCapsule(
                task_id=str(invocation.request.get("task_id", "task-unknown")),
                status=status,
                final_error_type=error_type,
                stage=stage,
                retryable=retryable,
                request_digest=invocation.request_digest,
                attempt_ordinals=(attempt_ordinal,),
                stdout_sha256=stdout.sha256,
                stderr_sha256=stderr.sha256,
                message=_safe_failure_message(stderr.text or stdout.text),
            )
        return BridgeExecution(
            status=status,
            exit_code=exit_code,
            duration_ms=duration_ms,
            timed_out=timed_out,
            stdout=stdout,
            stderr=stderr,
            result=result,
            attempt=attempt,
            failure_capsule=capsule,
        )

    def run_with_fallback(self, invocations: Sequence[BridgeInvocation]) -> BridgeRun:
        values = tuple(invocations)
        if not values:
            raise BridgeError("at least one Bridge invocation is required")
        if len(values) > self.config.max_attempts:
            raise BridgeError("invocation count exceeds Bridge max_attempts")
        if len(values) > 1 and values[1].request_digest == values[0].request_digest:
            raise BridgeError("fallback must not repeat the identical request digest")
        executions: list[BridgeExecution] = []
        for ordinal, invocation in enumerate(values, 1):
            execution = self.run(invocation, attempt_ordinal=ordinal)
            executions.append(execution)
            if execution.result is not None and execution.status == "SUCCESS":
                return BridgeRun(tuple(executions), execution.result, None)
            if not execution.attempt.retryable:
                break
        last = executions[-1] if executions else None
        capsule = self._combine_capsules(executions) if last is not None else None
        return BridgeRun(tuple(executions), None, capsule)

    def quarantine(self, record: QuarantineRecord) -> str:
        if self.cas is None:
            raise BridgeError("quarantine persistence requires a CAS store")
        return self.cas.put_json(record.to_dict(), kind="quarantine-record")

    def _environment(self) -> dict[str, str]:
        if self.config.inherit_environment:
            environment = dict(os.environ)
        else:
            keep = {"PATH", "PATHEXT", "SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP", "USERPROFILE"}
            environment = {key: value for key, value in os.environ.items() if key in keep}
        for key in self.config.pass_environment:
            if key in os.environ:
                environment[key] = os.environ[key]
        environment.update({key: str(value) for key, value in self.config.fixed_environment.items()})
        environment.update({"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"})
        return environment

    @staticmethod
    def _drain(stream: Any, capture: _CaptureBuffer) -> None:
        try:
            while True:
                chunk = stream.read(16_384)
                if not chunk:
                    return
                capture.add(chunk)
        except OSError:
            return

    def _terminate(self, process: subprocess.Popen[bytes]) -> None:
        try:
            if os.name == "nt":
                # ``CTRL_BREAK_EVENT`` exists only on Windows, so resolve it
                # dynamically to keep cross-platform type checking valid.
                process.send_signal(getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM))
            else:
                killpg = getattr(os, "killpg", None)
                if killpg is not None:
                    killpg(process.pid, signal.SIGTERM)
                else:
                    process.terminate()
        except (OSError, ProcessLookupError):
            try:
                process.terminate()
            except OSError:
                pass
        try:
            process.wait(timeout=self.config.kill_grace_seconds)
        except subprocess.TimeoutExpired:
            try:
                if os.name != "nt":
                    killpg = getattr(os, "killpg", None)
                    if killpg is not None:
                        killpg(process.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
                    else:
                        process.kill()
                else:
                    process.kill()
            except (OSError, ProcessLookupError):
                pass

    @staticmethod
    def _parse_result(text: str) -> dict[str, Any] | None:
        candidate = text.strip()
        if not candidate:
            return None
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            start = candidate.find("{")
            if start < 0:
                return None
            try:
                value, _ = json.JSONDecoder().raw_decode(candidate[start:])
            except json.JSONDecodeError:
                return None
        return dict(value) if isinstance(value, Mapping) else None

    @staticmethod
    def _combine_capsules(executions: Sequence[BridgeExecution]) -> FailureCapsule:
        last = executions[-1]
        if last.failure_capsule is None:
            raise BridgeError("cannot combine successful executions into a failure capsule")
        return FailureCapsule(
            task_id=last.failure_capsule.task_id,
            status=last.status,
            final_error_type=last.failure_capsule.final_error_type,
            stage=last.failure_capsule.stage,
            retryable=last.failure_capsule.retryable,
            request_digest=last.attempt.request_digest,
            attempt_ordinals=tuple(item.attempt.attempt_ordinal for item in executions),
            stdout_sha256=last.stdout.sha256,
            stderr_sha256=last.stderr.sha256,
            message=last.failure_capsule.message,
        )


def _secret_like(key: str) -> bool:
    folded = key.casefold()
    return any(token in folded for token in ("api_key", "token", "password", "secret", "private_key", "authorization"))


def _safe_failure_message(value: str) -> str:
    text = value[-1_000:]
    for marker in ("sk-", "Bearer ", "-----BEGIN"):
        if marker in text:
            text = text.replace(marker, "[REDACTED]")
    return " ".join(text.split())[:1_000]


__all__ = [
    "BridgeConfig",
    "BridgeError",
    "BridgeExecution",
    "BridgeInvocation",
    "BridgeRun",
    "ProcessBridge",
    "StreamCapture",
]
