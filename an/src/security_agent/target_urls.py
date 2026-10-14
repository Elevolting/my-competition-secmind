"""Validate operator-supplied network targets before a run is queued."""
from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit


_EMBEDDED_URL = re.compile(r"https?://|https?%3a%2f%2f", re.IGNORECASE)
_BAD_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")


def normalize_target_url(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("授权 URL 不能为空或包含首尾空白")
    if any(ord(char) < 32 for char in value) or "\\" in value:
        raise ValueError("授权 URL 包含无效字符")
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("授权 URL 必须是完整的 HTTP(S) 地址")
    if (re.search(r"\s", parsed.netloc) or '%' in parsed.netloc
            or _BAD_ESCAPE.search(value) or '%25' in parsed.path.lower()):
        raise ValueError("授权 URL 的主机或转义字符无效")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("授权 URL 不能包含账号、密码或片段")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("授权 URL 端口无效") from exc
    if _EMBEDDED_URL.search(parsed.path):
        raise ValueError("授权 URL 路径中重复包含网址，请检查是否粘贴了两次")
    authority = parsed.hostname.lower()
    if ":" in authority:
        authority = f"[{authority}]"
    if port is not None:
        authority += f":{port}"
    return urlunsplit((parsed.scheme.lower(), authority, parsed.path or "/", parsed.query, ""))
