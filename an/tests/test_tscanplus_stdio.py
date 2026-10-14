import subprocess
import sys

from security_agent.tscanplus_stdio import _is_diagnostic


def test_only_timestamped_diagnostics_are_redirected():
    assert _is_diagnostic(b"[11:51:41] [WARNING] Free mode\n")
    assert _is_diagnostic(b"[\x1b[36m11:51:41\x1b[0m] [WARNING] Free mode\n")
    assert not _is_diagnostic(b'{"jsonrpc":"2.0","id":1,"result":{}}\n')
    assert not _is_diagnostic(b"unexpected output\n")


def test_wrapper_preserves_protocol_and_surfaces_unexpected_output():
    child = ("import sys; "
             "sys.stdout.write('[11:51:41] [WARNING] Free mode\\n'); "
             "sys.stdout.write('{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\\n'); "
             "sys.stdout.write('unexpected output\\n'); sys.stdout.flush()")
    result = subprocess.run(  # noqa: S603 - fixed interpreter and local test code
        [sys.executable, '-m', 'security_agent.tscanplus_stdio', sys.executable, '-c', child],
        input=b'', capture_output=True, timeout=10, check=True,
    )
    assert result.stdout.replace(b'\r\n', b'\n') == (
        b'{"jsonrpc":"2.0","id":1,"result":{}}\n' + b'unexpected output\n')
    assert b'[11:51:41] [WARNING] Free mode' in result.stderr


def test_wrapper_forwards_request_before_input_closes():
    child = ("import sys; line = sys.stdin.readline(); "
             "sys.stdout.write(line); sys.stdout.flush()")
    request = b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
    result = subprocess.run(  # noqa: S603 - fixed interpreter and local test code
        [sys.executable, '-m', 'security_agent.tscanplus_stdio', sys.executable, '-c', child],
        input=request, capture_output=True, timeout=10, check=True,
    )
    assert result.stdout.replace(b'\r\n', b'\n') == request
