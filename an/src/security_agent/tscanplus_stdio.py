"""Keep TscanPlus diagnostics off its MCP JSON-RPC stdout stream."""
from __future__ import annotations

import os
import re
import subprocess
import sys
import threading

_DIAGNOSTIC = re.compile(rb"^\[[0-9]{2}:[0-9]{2}:[0-9]{2}\] \[(?:DEBUG|INFO|WARNING|ERROR)\]")
_ANSI = re.compile(rb"\x1b\[[0-9;]*m")


def _is_diagnostic(line: bytes) -> bool:
    return bool(_DIAGNOSTIC.match(_ANSI.sub(b"", line)))


def _copy(source, destination) -> None:
    for chunk in iter(lambda: source.read(8192), b""):
        destination.write(chunk)
        destination.flush()


def _copy_stdin(destination) -> None:
    while chunk := os.read(sys.stdin.fileno(), 8192):
        destination.write(chunk)
        destination.flush()


def _relay_stdout(source) -> None:
    for line in iter(source.readline, b""):
        destination = sys.stderr.buffer if _is_diagnostic(line) else sys.stdout.buffer
        destination.write(line)
        destination.flush()


def main() -> int:
    if len(sys.argv) < 2:
        return 2
    process = subprocess.Popen(  # noqa: S603 - the caller has verified the signed executable
        sys.argv[1:], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=0,
    )
    assert process.stdin and process.stdout and process.stderr
    stdout = threading.Thread(target=_relay_stdout, args=(process.stdout,), daemon=True)
    stderr = threading.Thread(target=_copy, args=(process.stderr, sys.stderr.buffer), daemon=True)
    stdout.start()
    stderr.start()
    try:
        _copy_stdin(process.stdin)
    except (BrokenPipeError, OSError):
        pass
    finally:
        process.stdin.close()
        try:
            code = process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                code = process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                code = process.wait()
        stdout.join(timeout=3)
        stderr.join(timeout=3)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
