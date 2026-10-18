"""Bounded HTTP request authorization for an authorized penetration target.

The task's ``target_scope`` stays the authorization boundary; this policy only
adds the minimum capability an RFI / file-inclusion / upload challenge needs,
namely one request with a bounded body to the URL the operator already
authorized.  Everything else stays closed: no redirect following, no custom
headers or cookies, and no verbs beyond GET/HEAD/POST.  Arbitrary ``data:``
style payloads are the point of the policy, so the body is size-bounded rather
than content-filtered.
"""
from __future__ import annotations

POLICY = "bounded_http"
CONSTRAINT = (
    "仅允许对授权 URL 发起 GET/HEAD/POST 请求；请求体不超过 4 KB，"
    "不自定义请求头或 Cookie，不跟随跳转"
)
REQUEST_ID = "bounded-http-request"

MAX_BODY_BYTES = 4096
METHODS = frozenset({"GET", "HEAD", "POST"})
BODY_METHODS = frozenset({"GET", "POST"})
# A body-carrying request changes target state, so this policy keeps a
# generous but finite ceiling even when the operator removed the global
# blackboard call budget.
MAX_CALLS_PER_RUN = 400
MAX_CALLS_PER_INTENT = 120


def validate_request(arguments: dict) -> None:
    """Raise ValueError when a request exceeds the bounded HTTP authorization."""
    method = arguments.get("method", "GET")
    if not isinstance(method, str) or method.strip().upper() not in METHODS:
        raise ValueError("请求方法仅允许 GET/HEAD/POST")
    if arguments.get("follow_redirect", False) is not False:
        raise ValueError("不允许跟随跳转")
    for key in ("headers", "cookie"):
        value = arguments.get(key)
        if value is not None and value != "":
            raise ValueError("不允许自定义请求头或 Cookie")
    body = arguments.get("body")
    if body is None or body == "":
        return
    if not isinstance(body, str):
        raise ValueError("请求体必须是字符串")
    if method.strip().upper() not in BODY_METHODS:
        raise ValueError("HEAD 请求不允许请求体")
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise ValueError(f"请求体超过 {MAX_BODY_BYTES} 字节上限")
