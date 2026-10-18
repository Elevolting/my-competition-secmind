from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx


class TSecError(RuntimeError):
    def __init__(self, status_code: int, code: str, message: str, detail: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.detail = detail if detail is not None else {}


@dataclass(frozen=True)
class TSecConfig:
    base_url: str = ""
    token: str = field(default="", repr=False)

    @property
    def configured(self) -> bool:
        return bool(self.base_url.strip() and self.token.strip())


class TSecBenchmarkClient:
    """Small async client for the TSec Challenges API.

    The token is sent only as a request header. Error payloads redact it.
    """

    def __init__(self, config: TSecConfig, timeout: float = 30.0, transport: httpx.AsyncBaseTransport | None = None):
        self.config = TSecConfig(config.base_url.strip().rstrip("/"), config.token.strip())
        self.timeout = timeout
        self.transport = transport

    def _url(self, path: str) -> str:
        return self.config.base_url.rstrip("/") + "/openapi/v1/challenges" + path

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        if not self.config.configured:
            raise TSecError(503, "not_configured", "尚未配置 BENCHMARK_BASE_URL 和 BENCHMARK_TOKEN")
        try:
            parsed = urlsplit(self.config.base_url)
            valid = (parsed.scheme in {"http", "https"} and parsed.hostname and not parsed.username
                     and not parsed.password and not parsed.query and not parsed.fragment)
            _ = parsed.port  # Access validates malformed port numbers.
        except ValueError:
            valid = False
        if not valid:
            raise TSecError(503, "invalid_config", "BENCHMARK_BASE_URL 必须是无凭证、查询参数和片段的 HTTP(S) 地址")
        headers = dict(kwargs.pop("headers", {}))
        headers["BENCHMARK_TOKEN"] = self.config.token
        headers.setdefault("Accept", "application/json")
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, transport=self.transport, follow_redirects=False
            ) as client:
                response = await client.request(method, self._url(path), headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise TSecError(503, "platform_unavailable", f"评测平台连接失败：{exc.__class__.__name__}") from exc
        if 300 <= response.status_code < 400:
            raise TSecError(502, "unexpected_redirect", "评测平台返回重定向，请检查平台地址")
        try:
            data = response.json()
        except ValueError:
            raise TSecError(502, "invalid_response", "评测平台返回了非 JSON 响应") from None
        # Even a misconfigured upstream must not echo a secret into browser errors.
        if response.is_error:
            data = self._redact(data)
            if isinstance(data, dict) and data.get("code"):
                raise TSecError(response.status_code, str(data["code"]),
                                str(data.get("message") or "评测平台请求失败"), data.get("detail", {}))
            if response.status_code == 422 and isinstance(data, dict):
                raise TSecError(422, "validation_error", "评测平台参数校验失败", data.get("detail", []))
            raise TSecError(response.status_code, "platform_error", f"评测平台返回 HTTP {response.status_code}", data)
        if path and not isinstance(data, dict):
            raise TSecError(502, "invalid_response", "评测平台响应格式无效")
        return data

    def _redact(self, value: Any) -> Any:
        if isinstance(value, str):
            return value.replace(self.config.token, "[REDACTED]")
        if isinstance(value, dict):
            return {str(self._redact(key)): self._redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        return value

    async def list_challenges(self) -> list[dict[str, Any]]:
        data = await self._request("GET", "")
        if not isinstance(data, list) or any(
            not isinstance(item, dict) or not item.get("unique_code") for item in data
        ):
            raise TSecError(502, "invalid_response", "评测平台题目列表格式无效")
        return data

    async def start(self, unique_code: str) -> dict[str, Any]:
        return await self._request("POST", "/start", params={"unique_code": unique_code})

    async def hint(self, unique_code: str) -> dict[str, Any]:
        return await self._request("GET", "/hint", params={"unique_code": unique_code})

    async def submit(self, unique_code: str, flag: str) -> dict[str, Any]:
        if not 1 <= len(flag) <= 4096:
            raise TSecError(422, "validation_error", "flag 长度必须在 1~4096 之间")
        return await self._request("POST", "/submit", json={"unique_code": unique_code, "flag": flag})

    async def close(self, unique_code: str) -> dict[str, Any]:
        return await self._request("POST", "/close", params={"unique_code": unique_code})
