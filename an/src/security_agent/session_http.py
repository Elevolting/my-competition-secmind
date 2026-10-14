"""Session-aware HTTP authorization for an authorized penetration target.

The task's ``target_scope`` remains the authorization boundary.  This policy
extends ``bounded_http`` with the one capability an authenticated business
workflow needs: reusing a session the target itself just handed out.  A solver
that recovered an account (for example from a disclosed credential) must be
able to carry the resulting session cookie into the next request, otherwise
role-based endpoints such as ``/api/admin/`` stay unreachable and the task can
never produce a flag.

Everything is still scoped to the operator-approved URL: no redirect following
and no verbs beyond GET/HEAD/POST.  Headers are limited to a small allowlist so
this stays a session capability rather than an arbitrary request-forgery one:
``Host``, ``Authorization``, ``Content-Type``, ``Accept``, ``Origin``,
``Referer``, ``X-Requested-With`` and the ``Cookie`` header.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

POLICY = "session_http"
CONSTRAINT = (
    "仅允许对授权 URL 发起 GET/HEAD/POST 请求；请求体不超过 4 KB，"
    "可携带会话 Cookie 与受限请求头，不跟随跳转"
)
REQUEST_ID = "session-http-request"

MAX_BODY_BYTES = 4096
METHODS = frozenset({"GET", "HEAD", "POST"})
BODY_METHODS = frozenset({"GET", "POST"})
ALLOWED_HEADERS = frozenset({
    "host", "authorization", "content-type", "accept", "accept-language",
    "origin", "referer", "x-requested-with", "cookie", "user-agent", "x-auth-token",
})
_HEADER_SEPARATOR = re.compile(r";(?=\s*[A-Za-z][A-Za-z0-9-]*\s*:)")
# The blackboard bridge bounds work with runtime/lease timeouts rather than a
# fixed number of tool calls: blackboard_max_mcp_calls_per_run and
# blackboard_max_mcp_calls_per_intent default to None (unlimited).  Reusing a
# target-issued session is an ordinary part of an authenticated workflow, so
# this policy follows that global budget instead of re-introducing a call cap
# that can strand a run one request short of the flag.  The scope, verb,
# body-size and header-allowlist checks above remain the enforced boundaries.
MAX_CALLS_PER_RUN = None
MAX_CALLS_PER_INTENT = None


class UnsafeSessionHeaderError(ValueError):
    pass


def _header_lines(value: object) -> list[tuple[str, str]]:
    if value is None or value == "":
        return []
    if not isinstance(value, str):
        raise ValueError("请求头必须是字符串")
    if len(value.encode("utf-8")) > 4096:
        raise ValueError("请求头超过 4 KB 上限")
    if any((ord(char) < 32 and char not in "\r\n") or ord(char) == 127 for char in value):
        raise UnsafeSessionHeaderError("请求头包含控制字符")
    lines: list[tuple[str, str]] = []
    for raw_line in _HEADER_SEPARATOR.sub("\n", value).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if ":" not in line:
            raise ValueError("请求头必须使用 Name: Value 格式")
        name, header_value = (part.strip() for part in line.split(":", 1))
        name = name.casefold()
        if not name:
            raise ValueError("请求头名称不能为空")
        if any(ord(char) < 32 or ord(char) == 127 for char in header_value):
            raise UnsafeSessionHeaderError("请求头值包含控制字符")
        lines.append((name, header_value))
    return lines


def validate_headers(headers: object, cookie: object, url: object = None) -> None:
    lines = _header_lines(headers)
    names = [name for name, _ in lines]
    if isinstance(cookie, str):
        if any(ord(char) < 32 or ord(char) == 127 for char in cookie):
            raise UnsafeSessionHeaderError("Cookie 包含控制字符")
        if cookie.strip():
            names.append("cookie")
    elif cookie is not None and not isinstance(cookie, str):
        raise ValueError("Cookie 必须是字符串")
    if isinstance(cookie, str) and len(cookie.encode("utf-8")) > 4096:
        raise ValueError("Cookie 超过 4 KB 上限")
    unexpected = sorted({name for name in names if name not in ALLOWED_HEADERS})
    if unexpected:
        raise ValueError("请求头不在会话策略允许范围内：" + ", ".join(unexpected))
    host_values = [value for name, value in lines if name == "host"]
    if host_values:
        if len(host_values) != 1 or not isinstance(url, str):
            raise ValueError("Host 请求头与目标 URL 不一致")
        try:
            target = urlsplit(url)
            header = urlsplit("//" + host_values[0])
            default_port = 443 if target.scheme == "https" else 80
            target_port = target.port if target.port is not None else default_port
            header_port = header.port if header.port is not None else default_port
        except ValueError as exc:
            raise ValueError("Host 请求头无效") from exc
        if (target.scheme not in {"http", "https"} or not target.hostname
                or not header.hostname or header.username or header.password
                or header.path or header.query or header.fragment
                or header.hostname.casefold().rstrip(".") != target.hostname.casefold().rstrip(".")
                or header_port != target_port):
            raise ValueError("Host 请求头与目标 URL 不一致")


def validate_request(arguments: dict) -> None:
    """Raise ValueError when a request exceeds the session HTTP authorization."""
    method = arguments.get("method", "GET")
    if not isinstance(method, str) or method.strip().upper() not in METHODS:
        raise ValueError("请求方法仅允许 GET/HEAD/POST")
    if arguments.get("follow_redirect", False) is not False:
        raise ValueError("不允许跟随跳转")
    validate_headers(arguments.get("headers"), arguments.get("cookie"), arguments.get("url"))
    body = arguments.get("body")
    if body is None or body == "":
        return
    if not isinstance(body, str):
        raise ValueError("请求体必须是字符串")
    if method.strip().upper() not in BODY_METHODS:
        raise ValueError("HEAD 请求不允许请求体")
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise ValueError(f"请求体超过 {MAX_BODY_BYTES} 字节上限")
