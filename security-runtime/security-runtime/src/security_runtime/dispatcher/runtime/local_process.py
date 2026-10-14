from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
import threading
from contextlib import suppress
from pathlib import Path

from security_runtime.dispatcher.runtime.process import ProcessResult

LOG = logging.getLogger(__name__)

STREAM_JOIN_TIMEOUT_SECONDS = 5.0
FORCE_KILL_REAP_TIMEOUT_SECONDS = 2.0


def prepare_local_command(command: list[str], *, windows: bool | None = None) -> list[str]:
    """Resolve local CLI shims so Windows ``CreateProcess`` can execute them."""
    if windows is None:
        windows = os.name == "nt"
    if not windows or not command:
        return list(command)
    executable = command[0]
    resolved = executable if os.path.isabs(executable) else shutil.which(executable)
    if not resolved:
        return list(command)
    if Path(resolved).suffix.lower() in {".cmd", ".bat"}:
        # ``call`` preserves a quoted batch-file path when it contains spaces;
        # without it cmd.exe treats the leading quote as its /c wrapper.
        command_line = "call " + subprocess.list2cmdline([resolved, *command[1:]])
        comspec = os.environ.get("ComSpec") or os.environ.get("COMSPEC") or "cmd.exe"
        return [comspec, "/d", "/s", "/c", command_line]
    return [resolved, *command[1:]]


def command_for_popen(command: list[str], *, windows: bool | None = None) -> list[str] | str:
    """Build the exact Popen form, including a raw cmd.exe command line."""
    if windows is None:
        windows = os.name == "nt"
    prepared = prepare_local_command(command, windows=windows)
    if windows and len(prepared) == 5 and prepared[1:4] == ["/d", "/s", "/c"]:
        # Passing the /c payload as a list item makes Python quote it once
        # more. A single command line lets cmd.exe receive the intended quotes
        # around npm's path-with-spaces shim.
        return f"{subprocess.list2cmdline(prepared[:4])} {prepared[4]}"
    return prepared


class LocalProcess:
    """Runs a worker command as a host subprocess.

    Mirrors the container ManagedProcess surface (start/communicate/kill/cancel) but
    executes on the dispatcher host: its own process group so children are killed as a
    group, a Python-enforced timeout instead of the ``timeout`` coreutil, and a
    SIGTERM -> grace -> SIGKILL shutdown so the CLI can flush its session before dying.
    """

    def __init__(
        self,
        command: list[str],
        cwd: str,
        env: dict[str, str],
        timeout_seconds: int | None = None,
        term_grace_seconds: int = 5,
    ):
        self.command = command
        self.env = env
        self._cwd = cwd
        self._timeout_seconds = timeout_seconds
        self._term_grace = max(1.0, float(term_grace_seconds))
        self._process: subprocess.Popen[str] | None = None
        self._stdout_chunks: list[str] = []
        self._stderr_chunks: list[str] = []
        self._stdout_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._timed_out = False
        self._cancel_reason: str | None = None
        self._kill_lock = threading.Lock()

    def start(self) -> None:
        command = command_for_popen(self.command)
        self._process = subprocess.Popen(
            command,
            cwd=self._cwd,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=True,
        )
        self._stdout_thread = threading.Thread(
            target=self._drain, args=(self._process.stdout, self._stdout_chunks), daemon=True
        )
        self._stderr_thread = threading.Thread(
            target=self._drain, args=(self._process.stderr, self._stderr_chunks), daemon=True
        )
        self._stdout_thread.start()
        self._stderr_thread.start()

    def communicate(self, timeout: float | None) -> ProcessResult:
        assert self._process is not None
        wait_for = float(self._timeout_seconds) if self._timeout_seconds is not None else timeout
        try:
            self._process.wait(timeout=wait_for)
        except subprocess.TimeoutExpired:
            self._timed_out = True
            self._terminate()
        with suppress(subprocess.TimeoutExpired):
            self._process.wait(timeout=FORCE_KILL_REAP_TIMEOUT_SECONDS)
        if self._stdout_thread is not None:
            self._stdout_thread.join(timeout=STREAM_JOIN_TIMEOUT_SECONDS)
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=STREAM_JOIN_TIMEOUT_SECONDS)
        returncode = self._process.returncode
        if returncode is None:
            returncode = 137 if self._timed_out else 1
        return ProcessResult(
            returncode=returncode,
            stdout="".join(self._stdout_chunks),
            stderr="".join(self._stderr_chunks),
            timed_out=self._timed_out,
            cancelled=self._cancel_reason is not None,
            cancel_reason=self._cancel_reason,
        )

    def kill(self) -> None:
        self._terminate()

    def cancel(self, reason: str) -> None:
        if self._cancel_reason is None:
            self._cancel_reason = reason
        self._terminate()

    def _terminate(self) -> None:
        with self._kill_lock:
            process = self._process
            if process is None or process.poll() is not None:
                return
            if os.name == "nt":
                # Kill the tree while its root still exists. Terminating the
                # root first orphans CLI children and makes taskkill /T unable
                # to find them (a cancelled scan would continue running).
                self._signal_group(process, 9)
                with suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=self._term_grace)
                if process.poll() is None:
                    with suppress(ProcessLookupError, PermissionError):
                        process.kill()
                return
            self._signal_group(process, signal.SIGTERM)
            try:
                process.wait(timeout=self._term_grace)
                return
            except subprocess.TimeoutExpired:
                pass
            self._signal_group(process, signal.SIGKILL)

    @staticmethod
    def _signal_group(process: subprocess.Popen[str], sig: int) -> None:
        # ``os.killpg`` is POSIX-only.  On Windows use ``taskkill /T`` for the
        # forceful path so shell-launched children are terminated as well.
        if os.name == "nt":
            if sig == 9:
                with suppress(FileNotFoundError, OSError, subprocess.TimeoutExpired):
                    subprocess.run(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                        timeout=5,
                    )
            else:
                with suppress(ProcessLookupError, PermissionError):
                    process.terminate()
            return
        try:
            os.killpg(os.getpgid(process.pid), sig)
        except (ProcessLookupError, PermissionError):
            with suppress(ProcessLookupError, PermissionError, ValueError):
                process.send_signal(sig)

    @staticmethod
    def _drain(pipe, sink: list[str]) -> None:
        try:
            # Pi emits one JSON event per line.  TextIOWrapper.read(size) may
            # wait for a full 64 KiB (or EOF); an inherited pipe handle can
            # outlive the CLI and hide its final message from communicate().
            # Read complete events as they arrive instead.
            for line in pipe:
                sink.append(line)
        except (ValueError, OSError):
            pass
        finally:
            with suppress(Exception):
                pipe.close()
