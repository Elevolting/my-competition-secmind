from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, TypeVar
from uuid import uuid4

import httpx
from pydantic import BaseModel, ValidationError
from tenacity import AsyncRetrying, retry_if_exception_type, stop_after_attempt, wait_exponential_jitter

from security_agent.config import Settings
from security_agent.model_snapshots import ModelConfiguration, ModelSnapshotStore, SnapshotParent
from security_agent.model_usage import normalize_usage

T = TypeVar("T", bound=BaseModel)


class ModelGatewayError(RuntimeError):
    pass


class RetryableModelError(ModelGatewayError):
    pass


def completion_text(response: httpx.Response) -> tuple[str, dict[str, int]]:
    if 'text/event-stream' in response.headers.get('content-type', ''):
        chunks: list[str] = []
        usage: dict[str, int] = {}
        try:
            for line in response.text.splitlines():
                if not line.startswith('data:'):
                    continue
                data = line.removeprefix('data:').strip()
                if not data or data == '[DONE]':
                    continue
                event = json.loads(data)
                usage = normalize_usage(event.get('usage')) or usage
                for choice in event.get('choices') or []:
                    content = choice.get('delta', {}).get('content')
                    if isinstance(content, str):
                        chunks.append(content)
            content = ''.join(chunks)
        except (ValueError, TypeError, AttributeError) as exc:
            raise ModelGatewayError('Malformed streamed model response') from exc
    else:
        try:
            body = response.json()
            content = body['choices'][0]['message']['content']
            usage = normalize_usage(body.get('usage'))
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ModelGatewayError('Malformed model response') from exc
    if not isinstance(content, str) or not content.strip():
        raise ModelGatewayError('Model returned no text')
    return content, usage


@dataclass
class ModelCallMeta:
    model_id: str
    prompt_version: str
    response_sha256: str
    duration_ms: int
    used_fallback: bool
    usage: dict[str, int]


StreamObserver = Callable[[str, dict[str, Any]], Awaitable[None]]


class ModelGateway:

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None,
                 *, snapshot_store: ModelSnapshotStore | None = None) -> None:
        self.settings = settings
        self._client = client or httpx.AsyncClient(timeout=settings.model_timeout_seconds)
        self._owns_client = client is None
        self._failures: dict[str, int] = {}
        self._open_until: dict[str, float] = {}
        self.snapshot_store = snapshot_store

    def snapshot_configuration(self, model_id: str) -> ModelConfiguration:
        return ModelConfiguration(
            base_url=self.settings.model_base_url, provider="compatible-api", model_id=model_id,
            planner_model=self.settings.planner_model, worker_model=self.settings.worker_model,
            fallback_model=self.settings.fallback_model,
        )

    async def answer_side_question(
        self, snapshot: dict[str, Any], question: str,
    ) -> tuple[str, dict[str, int]]:
        """Ask a bounded question using the frozen request context."""

        if self.settings.demo_mode or not self.settings.model_api_key:
            raise ModelGatewayError("side-question model calls require a configured model")
        request = copy.deepcopy(snapshot.get("request"))
        if not isinstance(request, dict) or not isinstance(request.get("messages"), list):
            raise ModelGatewayError("side-question snapshot has no usable messages")
        messages = request["messages"]
        messages.append({"role": "user", "content": question})
        payload: dict[str, Any] = {
            "model": str(snapshot["model_id"]),
            "messages": messages,
            "max_tokens": self.settings.side_question_output_token_budget,
            "temperature": 0,
        }
        try:
            response = await self._client.post(
                f"{self.settings.model_base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {self.settings.model_api_key}"},
                json=payload,
                timeout=self.settings.model_timeout_seconds,
            )
            if response.status_code >= 400:
                raise ModelGatewayError(f"Model response: {response.status_code}")
            return completion_text(response)
        except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError) as exc:
            raise ModelGatewayError("Malformed side-question model response") from exc

    async def _capture_request(self, payload: dict, parent: SnapshotParent | None, provenance: dict) -> None:
        if self.snapshot_store is None or parent is None:
            return
        try:
            # Capture completes before send; observation errors do not interrupt the main task.
            await asyncio.to_thread(
                self.snapshot_store.capture, parent=parent,
                configuration=self.snapshot_configuration(payload["model"]), request=payload, provenance=provenance,
            )
        except Exception as exc:
            logging.getLogger(__name__).warning("Model snapshot capture failed (%s)", type(exc).__name__)

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def test_connection(self, base_url: str, api_key: str) -> dict[str, Any]:
        started = time.monotonic()
        try:
            response = await self._client.get(
                f"{base_url.rstrip('/')}/models",
                headers={"Authorization": f"Bearer {api_key}"},
            )
        except httpx.HTTPError as exc:
            raise ModelGatewayError(f"Unable to reach model service: {type(exc).__name__}") from exc
        if response.status_code in {401, 403}:
            raise ModelGatewayError("API key was rejected by the model service")
        if response.status_code >= 400:
            raise ModelGatewayError(f"Model service returned HTTP {response.status_code}")
        try:
            body = response.json()
            rows = body.get("data") if isinstance(body, dict) else None
            if not isinstance(rows, list):
                raise ValueError('Missing model list')
            model_ids = sorted(
                str(item["id"])
                for item in rows
                if isinstance(item, dict) and item.get("id")
            )
            model_count = len(model_ids)
        except (ValueError, TypeError):
            raise ModelGatewayError("服务未返回有效模型列表") from None
        return {
            "latency_ms": int((time.monotonic() - started) * 1000),
            "model_count": model_count,
            "model_ids": model_ids,
        }

    async def probe_model(self, base_url, api_key, model_id, observer):
        """A small real completion; discovery alone cannot verify inference access."""
        trace = str(uuid4())
        payload = {'trace_id': trace, 'model': model_id, 'stage': 'connection_test', 'provider': 'compatible-api'}
        await observer('llm.stream.started', payload)
        started = time.monotonic()
        usage = {}
        try:
            response = await self._client.post(base_url + '/chat/completions',
                headers={'Authorization': 'Bearer ' + api_key},
                json={'model': model_id, 'messages': [{'role': 'user', 'content': 'Reply with OK.'}],
                      'max_tokens': 256, 'stream': True, 'stream_options': {'include_usage': True}}, timeout=30)
            if response.status_code >= 400:
                raise ModelGatewayError(f'模型 {model_id} 调用失败：HTTP {response.status_code}')
            _, usage = completion_text(response)
            await observer('llm.stream.completed', {**payload, 'usage': usage})
            return {'model': model_id, 'ok': True, 'latency_ms': int((time.monotonic()-started)*1000), 'usage': usage}
        except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError, ModelGatewayError) as exc:
            await observer('llm.stream.failed', {**payload, 'usage': usage, 'error_type': type(exc).__name__})
            detail = str(exc) if isinstance(exc, ModelGatewayError) else type(exc).__name__
            raise ModelGatewayError(f'推理测试失败：{detail}') from exc

    async def structured(
        self,
        *,
        role: str,
        system_prompt: str,
        user_prompt: str,
        output_model: type[T],
        prompt_version: str,
        stage: str | None = None,
        stream_observer: StreamObserver | None = None,
        timeout_seconds: float | None = None,
        run_id: str | None = None,
        step_id: str | None = None,
        worker_id: str | None = None,
        call_purpose: str = "auxiliary",
    ) -> tuple[T, ModelCallMeta]:
        if self.settings.demo_mode:
            raise ModelGatewayError("Model calls are disabled in deterministic demo mode")
        if not self.settings.model_api_key:
            raise ModelGatewayError("SECURITY_AGENT_MODEL_API_KEY is not configured")
        from security_agent.runtime_prompts import RuntimePrompts

        system_prompt, prompt_receipt = RuntimePrompts(self.settings.run_root.parent).compose(
            stage or role, system_prompt,
        )
        if prompt_receipt:
            prompt_version = prompt_receipt["version"]
            if stream_observer is not None:
                await stream_observer("llm.prompt.selected", {**prompt_receipt, "stage": stage or role})
        primary = self.settings.planner_model if role == "planner" else self.settings.worker_model
        candidates = list(dict.fromkeys([primary, self.settings.fallback_model]))
        last_error: Exception | None = None
        for index, model_id in enumerate(candidates):
            if self._open_until.get(model_id, 0) > time.monotonic():
                continue
            try:
                trace_id = str(uuid4())
                raw, duration_ms, usage = await self._request_with_retry(
                    model_id,
                    system_prompt,
                    user_prompt,
                    output_model.model_json_schema(),
                    trace_id=trace_id,
                    stage=stage or role,
                    stream_observer=stream_observer,
                    timeout_seconds=timeout_seconds,
                    snapshot_parent=SnapshotParent(run_id, "workbench", step_id, worker_id)
                    if run_id and call_purpose == "primary" else None,
                    prompt_version=prompt_version,
                )
                parsed = self._parse_model(raw, output_model)
                self._failures[model_id] = 0
                return parsed, ModelCallMeta(
                    model_id=model_id,
                    prompt_version=prompt_version,
                    response_sha256=hashlib.sha256(raw.encode()).hexdigest(),
                    duration_ms=duration_ms,
                    used_fallback=index > 0,
                    usage=usage,
                )
            except (ModelGatewayError, ValidationError, json.JSONDecodeError, httpx.HTTPError) as exc:
                if stream_observer is not None:
                    await stream_observer(
                        "llm.response.rejected",
                        {
                            "trace_id": trace_id,
                            "message_id": f"{trace_id}:assistant",
                            "stage": stage or role,
                            "provider": "compatible-api",
                            "model": model_id,
                            "message": f"Model attempt failed: {type(exc).__name__}",
                            "error_type": type(exc).__name__,
                        },
                    )
                last_error = exc
                failures = self._failures.get(model_id, 0) + 1
                self._failures[model_id] = failures
                if failures >= 3:
                    self._open_until[model_id] = time.monotonic() + 60
        raise ModelGatewayError(f"All configured models failed: {last_error}")

    async def embeddings(self, texts: list[str]) -> list[list[float]]:
        if not texts or any(not text.strip() for text in texts):
            raise ValueError("Embedding input must contain non-empty text")
        if self.settings.demo_mode:
            raise ModelGatewayError("Embedding calls are disabled in deterministic demo mode")
        if not self.settings.model_api_key:
            raise ModelGatewayError("SECURITY_AGENT_MODEL_API_KEY is not configured")
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(3),
            wait=wait_exponential_jitter(initial=0.5, max=8),
            retry=retry_if_exception_type((RetryableModelError, httpx.TimeoutException)),
            reraise=True,
        ):
            with attempt:
                response = await self._client.post(
                    f"{self.settings.model_base_url.rstrip('/')}/embeddings",
                    headers={"Authorization": f"Bearer {self.settings.model_api_key}"},
                    json={"model": self.settings.embedding_model, "input": texts},
                )
                if response.status_code in {408, 409, 429} or response.status_code >= 500:
                    raise RetryableModelError(f"Retryable embedding response: {response.status_code}")
                if response.status_code >= 400:
                    raise ModelGatewayError(f"Embedding response: {response.status_code}")
                try:
                    rows = sorted(response.json()["data"], key=lambda item: item["index"])
                    vectors = [[float(value) for value in row["embedding"]] for row in rows]
                except (KeyError, TypeError, ValueError) as exc:
                    raise ModelGatewayError("Malformed embedding response") from exc
                if len(vectors) != len(texts):
                    raise ModelGatewayError("Embedding response count does not match input count")
                return vectors
        raise AssertionError("Retry loop exited unexpectedly")

    async def _request_with_retry(
        self,
        model_id: str,
        system_prompt: str,
        user_prompt: str,
        schema: dict[str, Any],
        *,
        trace_id: str,
        stage: str,
        stream_observer: StreamObserver | None,
        timeout_seconds: float | None,
        snapshot_parent: SnapshotParent | None = None,
        prompt_version: str = "",
    ) -> tuple[str, int, dict[str, int]]:
        started = time.monotonic()
        request_timeout = timeout_seconds or self.settings.model_timeout_seconds
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(3),
            wait=wait_exponential_jitter(initial=0.5, max=8),
            retry=retry_if_exception_type((RetryableModelError, httpx.TimeoutException)),
            reraise=True,
        ):
            with attempt:
                trace_id = str(uuid4())
                usage = {}
                try:
                    schema_text = json.dumps(schema, ensure_ascii=False, separators=(",", ":"))
                    request_payload = {
                            "model": model_id,
                            "messages": [
                                {
                                    "role": "system",
                                    "content": f"{system_prompt}\nRequired JSON Schema: {schema_text}",
                                },
                                {"role": "user", "content": user_prompt},
                            ],
                            "temperature": 0,
                            "response_format": {"type": "json_object"},
                        }
                    if stream_observer is None:
                        await self._capture_request(request_payload, snapshot_parent, {
                            "call_id": trace_id, "stage": stage, "prompt_version": prompt_version,
                            "attempt": attempt.retry_state.attempt_number,
                        })
                        response = await self._client.post(
                            f"{self.settings.model_base_url.rstrip('/')}/chat/completions",
                            headers={"Authorization": f"Bearer {self.settings.model_api_key}"},
                            json=request_payload,
                            timeout=request_timeout,
                        )
                        if response.status_code in {408, 409, 429} or response.status_code >= 500:
                            raise RetryableModelError(f"Retryable model response: {response.status_code}")
                        if response.status_code >= 400:
                            raise ModelGatewayError(f"Model response: {response.status_code}")
                        content, response_usage = completion_text(response)
                        return (
                            content,
                            int((time.monotonic() - started) * 1000),
                            response_usage,
                        )

                    await stream_observer(
                        "llm.stream.started",
                        {
                            "trace_id": trace_id,
                            "message_id": f"{trace_id}:assistant",
                            "stage": stage,
                            "provider": "compatible-api",
                            "model": model_id,
                        },
                    )
                    request_payload["stream"] = True
                    request_payload["stream_options"] = {"include_usage": True}
                    await self._capture_request(request_payload, snapshot_parent, {
                        "call_id": trace_id, "stage": stage, "prompt_version": prompt_version,
                        "attempt": attempt.retry_state.attempt_number,
                    })
                    chunks: list[str] = []
                    usage: dict[str, int] = {}
                    finish_reason: str | None = None
                    index = 0
                    async with self._client.stream(
                        "POST",
                        f"{self.settings.model_base_url.rstrip('/')}/chat/completions",
                        headers={"Authorization": f"Bearer {self.settings.model_api_key}"},
                        json=request_payload,
                        timeout=request_timeout,
                    ) as response:
                        if response.status_code in {408, 409, 429} or response.status_code >= 500:
                            raise RetryableModelError(f"Retryable model response: {response.status_code}")
                        if response.status_code >= 400:
                            raise ModelGatewayError(f"Model response: {response.status_code}")
                        async for line in response.aiter_lines():
                            if not line.startswith("data:"):
                                continue
                            data = line.removeprefix("data:").strip()
                            if not data or data == "[DONE]":
                                continue
                            body = json.loads(data)
                            normalized = self._normalize_usage(body.get("usage"))
                            if normalized:
                                usage = normalized
                            choices = body.get("choices") or []
                            if not choices:
                                continue
                            choice = choices[0]
                            finish_reason = choice.get("finish_reason") or finish_reason
                            delta = choice.get("delta", {}).get("content")
                            if not isinstance(delta, str) or not delta:
                                continue
                            chunks.append(delta)
                            index += 1
                            await stream_observer(
                                "llm.stream.delta",
                                {
                                    "trace_id": trace_id,
                                    "message_id": f"{trace_id}:assistant",
                                    "index": index,
                                    "delta": delta,
                                    "content_length": sum(len(item) for item in chunks),
                                    "stage": stage,
                                    "provider": "compatible-api",
                                    "model": model_id,
                                },
                            )
                    content = "".join(chunks)
                    await stream_observer(
                        "llm.stream.completed",
                        {
                            "trace_id": trace_id,
                            "message_id": f"{trace_id}:assistant",
                            "stage": stage,
                            "provider": "compatible-api",
                            "model": model_id,
                            "delta_count": index,
                            "content_length": len(content),
                            "finish_reason": finish_reason,
                            "usage": usage,
                            "content": content,
                        },
                    )
                    return content, int((time.monotonic() - started) * 1000), usage
                except (httpx.HTTPError, ModelGatewayError, ValueError, KeyError, TypeError) as exc:
                    if stream_observer is not None:
                        await stream_observer("llm.stream.failed", {
                            "trace_id": trace_id, "model": model_id, "stage": stage,
                            "provider": "compatible-api", "usage": usage,
                            "error_type": type(exc).__name__,
                        })
                    raise
        raise AssertionError("Retry loop exited unexpectedly")

    @staticmethod
    def _normalize_usage(value: Any) -> dict[str, int]:
        return normalize_usage(value)

    @staticmethod
    def _parse_model(raw: str, output_model: type[T]) -> T:
        text = raw.strip()
        if text.startswith("```"):
            text = text.removeprefix("```json").removeprefix("```")
            text = text.rsplit("```", 1)[0]
        return output_model.model_validate_json(text)


async def close_gateway_safely(gateway: ModelGateway) -> None:
    try:
        await gateway.close()
    except (httpx.HTTPError, asyncio.CancelledError):
        pass
