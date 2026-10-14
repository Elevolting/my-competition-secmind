"""Redact public execution content before indexing or returning it."""
from __future__ import annotations

import json
import re
from typing import Any

REDACTED = "[REDACTED]"
_SECRET_NAMES = {
    "apikey", "authorization", "proxyauthorization", "password", "passwd", "secret",
    "token", "accesstoken", "refreshtoken", "idtoken", "clientsecret", "cookie", "setcookie",
    "xapikey", "privatekey", "sessiontoken", "sessionid",
}
_AUTH = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
_HEADER = re.compile(r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:\s*).*$")
_PAIR = re.compile(
    r'''(?i)(["']?(?:api[_-]?key|password|passwd|client[_-]?secret|access[_-]?token|refresh[_-]?token|token|secret|session[_-]?id)["']?\s*[:=]\s*)(?:\[REDACTED\]|"[^"\r\n]*"|'[^'\r\n]*'|[^\s&,;\r\n}\]]+)'''
)
_USERINFO = re.compile(r"(?i)(https?://)[^\s/@]+:[^\s/@]+@")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.S,
)


def _secret_name(name: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", name.lower())
    return normalized in _SECRET_NAMES or normalized.endswith(
        ("password", "secret", "apikey", "accesstoken", "refreshtoken"))


def redact_trace(value: Any) -> Any:
    if isinstance(value, dict):
        named_secret = _secret_name(str(value.get("name", "")))
        return {key: REDACTED if _secret_name(str(key)) or named_secret and key == "value"
                else redact_trace(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_trace(item) for item in value]
    if isinstance(value, str):
        if value.lstrip().startswith(("{", "[")):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, (dict, list)):
                    return json.dumps(redact_trace(parsed), ensure_ascii=False)
            except (ValueError, RecursionError):
                pass
        value = _PRIVATE_KEY.sub(REDACTED, value)
        value = _HEADER.sub(lambda match: match[1] + REDACTED, value)
        value = _AUTH.sub(lambda match: match[1] + " " + REDACTED, value)
        value = _USERINFO.sub(lambda match: match[1] + REDACTED + "@", value)
        return _PAIR.sub(lambda match: match[1] + REDACTED, value)
    return value
