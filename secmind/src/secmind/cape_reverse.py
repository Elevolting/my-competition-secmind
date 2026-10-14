"""CAPE report normalization and an approval-gated HTTP contract."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from secmind.reverse_analysis_observation import ReverseAnalysisObservation


@dataclass(frozen=True, slots=True)
class CapeConfig:
    base_url: str
    token: str = field(repr=False)
    allowed_hosts: tuple[str, ...] = ()
    submit_enabled: bool = False
    timeout_seconds: float = 30.0
    approval_public_key: str = ""
    max_sample_bytes: int = 32 * 1024 * 1024

    def __post_init__(self) -> None:
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https":
            raise ValueError("CAPE base URL must use HTTPS")
        if not parsed.hostname or parsed.hostname.casefold() not in {host.casefold() for host in self.allowed_hosts}:
            raise ValueError("CAPE host is not present in the HTTPS allowlist")
        if not self.token:
            raise ValueError("CAPE token is required")
        if self.submit_enabled and not self.approval_public_key:
            raise ValueError("CAPE submission requires an approval public key")


@dataclass(frozen=True, slots=True)
class CapeApprovalReceipt:
    approval_id: str
    tier: str
    sample_sha256: str
    audience: str
    expires_at: str
    nonce: str
    signature: str = field(repr=False)


def issue_cape_approval(
    *,
    approval_id: str,
    sample_sha256: str,
    audience: str,
    expires_at: datetime,
    nonce: str,
    private_key: Ed25519PrivateKey,
) -> CapeApprovalReceipt:
    """Issue a sample-bound broker receipt; the client never holds this private key."""

    expiry = expires_at.astimezone(UTC).isoformat()
    fields = (approval_id, "R2", sample_sha256.casefold(), audience.casefold(), expiry, nonce)
    message = "\n".join(fields).encode()
    signature = base64.b64encode(private_key.sign(message)).decode()
    return CapeApprovalReceipt(
        approval_id=approval_id,
        tier="R2",
        sample_sha256=sample_sha256.casefold(),
        audience=audience.casefold(),
        expires_at=expiry,
        nonce=nonce,
        signature=signature,
    )


def cape_public_key_b64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def _approval_message(receipt: CapeApprovalReceipt) -> bytes:
    return "\n".join(
        (
            receipt.approval_id,
            receipt.tier,
            receipt.sample_sha256,
            receipt.audience,
            receipt.expires_at,
            receipt.nonce,
        )
    ).encode()


def normalize_cape_report(
    report: dict[str, Any],
    *,
    report_sha256: str,
    event_limit: int = 500,
) -> ReverseAnalysisObservation:
    target_value = report.get("target")
    target: dict[str, Any] = target_value if isinstance(target_value, dict) else {}
    file_value = target.get("file")
    file_info: dict[str, Any] = file_value if isinstance(file_value, dict) else {}
    behavior_value = report.get("behavior")
    behavior: dict[str, Any] = behavior_value if isinstance(behavior_value, dict) else {}
    processes_value = behavior.get("processes")
    processes: list[Any] = processes_value if isinstance(processes_value, list) else []
    events: list[dict[str, Any]] = []
    total_calls = 0
    for process in processes:
        if not isinstance(process, dict):
            continue
        for call in process.get("calls", []):
            if not isinstance(call, dict):
                continue
            total_calls += 1
            if len(events) < max(1, min(event_limit, 500)):
                events.append(
                    {
                        "event": "api",
                        "api_name": str(call.get("api", ""))[:160],
                        "process_name": str(process.get("process_name", ""))[:260],
                        "arguments": {
                            str(key)[:100]: str(value)[:500]
                            for key, value in list((call.get("arguments") or {}).items())[:16]
                        },
                    }
                )
    summary_value = behavior.get("summary")
    summary: dict[str, Any] = summary_value if isinstance(summary_value, dict) else {}
    files_value = summary.get("files")
    files: list[Any] = files_value if isinstance(files_value, list) else []
    created_files = sorted({PureWindowsPath(str(value)).name for value in files if str(value)})
    network_value = report.get("network")
    network: dict[str, Any] = network_value if isinstance(network_value, dict) else {}
    network_observations = 0
    for value in network.values():
        if isinstance(value, list):
            network_observations += len(value)
    info_value = report.get("info")
    info: dict[str, Any] = info_value if isinstance(info_value, dict) else {}
    return ReverseAnalysisObservation(
        source="cape",
        status="completed",
        sample_sha256=str(file_info.get("sha256", "")).casefold(),
        tool_identity={"name": "CAPEv2", "interface": "apiv2"},
        profile_id=str(info.get("id", "")) or None,
        coverage={
            "report_sha256": report_sha256,
            "events_total": total_calls,
            "events_retained": len(events),
            "truncated": total_calls > len(events),
            "external_network_observations": network_observations,
            "local_real_network_requests": 0,
            "host_pe_executions": 0,
        },
        events=events,
        artifacts={"created_files": created_files},
    )


class CapeClient:
    def __init__(self, config: CapeConfig, *, http: httpx.AsyncClient | None = None) -> None:
        self.config = config
        self._http = http or httpx.AsyncClient(timeout=config.timeout_seconds)
        self._used_approval_nonces: set[str] = set()

    @property
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.config.token}"}

    async def submit(self, sample: Path, *, approval: CapeApprovalReceipt) -> int:
        if not self.config.submit_enabled:
            raise PermissionError("CAPE file submission is disabled by default")
        raw = await asyncio.to_thread(sample.read_bytes)
        if len(raw) > self.config.max_sample_bytes:
            raise PermissionError("CAPE sample exceeds the approved size limit")
        sample_sha256 = hashlib.sha256(raw).hexdigest()
        parsed = urlparse(self.config.base_url)
        expiry = datetime.min.replace(tzinfo=UTC)
        signature_valid = False
        try:
            expiry = datetime.fromisoformat(approval.expires_at).astimezone(UTC)
            key_bytes = base64.b64decode(self.config.approval_public_key, validate=True)
            signature = base64.b64decode(approval.signature, validate=True)
            Ed25519PublicKey.from_public_bytes(key_bytes).verify(signature, _approval_message(approval))
            signature_valid = True
        except (ValueError, InvalidSignature):
            pass
        if (
            not signature_valid
            or approval.tier != "R2"
            or approval.sample_sha256 != sample_sha256
            or approval.audience != str(parsed.hostname).casefold()
            or not approval.nonce
            or approval.nonce in self._used_approval_nonces
            or expiry <= datetime.now(UTC)
        ):
            raise PermissionError("CAPE file submission requires a valid sample-bound R2 approval receipt")
        self._used_approval_nonces.add(approval.nonce)
        response = await self._http.post(
            f"{self.config.base_url.rstrip('/')}/apiv2/tasks/create/file/",
            headers=self._headers,
            files={"file": (sample.name, raw, "application/octet-stream")},
        )
        self._raise_redacted(response)
        payload = response.json()
        task_ids = ((payload.get("data") or {}).get("task_ids") or []) if isinstance(payload, dict) else []
        if not task_ids:
            raise RuntimeError("CAPE response did not contain a task id")
        return int(task_ids[0])

    async def status(self, task_id: int) -> str:
        response = await self._http.get(
            f"{self.config.base_url.rstrip('/')}/apiv2/tasks/status/{int(task_id)}/",
            headers=self._headers,
        )
        self._raise_redacted(response)
        payload = response.json()
        value = payload.get("data") if isinstance(payload, dict) else None
        if isinstance(value, dict):
            value = value.get("status")
        return str(value or "unknown")

    async def report(self, task_id: int, *, expected_sample_sha256: str) -> ReverseAnalysisObservation:
        response = await self._http.get(
            f"{self.config.base_url.rstrip('/')}/apiv2/tasks/get/report/{int(task_id)}/",
            headers=self._headers,
        )
        self._raise_redacted(response)
        raw = response.content
        payload = json.loads(raw)
        observation = normalize_cape_report(payload, report_sha256=hashlib.sha256(raw).hexdigest())
        if observation.sample_sha256 != expected_sample_sha256.casefold():
            raise ValueError("CAPE report sample hash does not match the submitted artifact")
        return observation

    @staticmethod
    def _raise_redacted(response: httpx.Response) -> None:
        if response.is_success:
            return
        raise RuntimeError(f"CAPE HTTP request failed with status {response.status_code}")
