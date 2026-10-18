from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class CapabilityError(ValueError):
    """A capability ticket is missing, invalid, expired, or already consumed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise CapabilityError("CAPABILITY_MALFORMED", "capability ticket is malformed") from exc
    if _b64url(decoded) != value:
        raise CapabilityError("CAPABILITY_MALFORMED", "capability ticket encoding is not canonical")
    return decoded


def canonical_payload(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


@dataclass(frozen=True)
class CapabilityClaims:
    ticket_id: str
    invocation_id: str
    tool_name: str
    input_sha256: str
    fence: int
    issued_at: int
    expires_at: int
    policy_sha256: str


class CapabilityReplayStore(Protocol):
    def consume(self, ticket_id: str, expires_at: int, now: int) -> bool: ...


class MemoryCapabilityReplayStore:
    def __init__(self) -> None:
        self._consumed: dict[str, int] = {}
        self._lock = threading.Lock()

    def consume(self, ticket_id: str, expires_at: int, now: int) -> bool:
        with self._lock:
            self._consumed = {key: expiry for key, expiry in self._consumed.items() if expiry >= now}
            if ticket_id in self._consumed:
                return False
            self._consumed[ticket_id] = expires_at
            return True


class SqliteCapabilityReplayStore:
    """Small durable replay cache for a runner; INSERT is the single-consumption boundary."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, timeout=5, check_same_thread=False, isolation_level=None)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS consumed_capabilities (ticket_id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)"
        )
        self._lock = threading.Lock()

    def consume(self, ticket_id: str, expires_at: int, now: int) -> bool:
        with self._lock:
            self._connection.execute("DELETE FROM consumed_capabilities WHERE expires_at < ?", (now,))
            try:
                self._connection.execute(
                    "INSERT INTO consumed_capabilities(ticket_id, expires_at) VALUES (?, ?)",
                    (ticket_id, expires_at),
                )
            except sqlite3.IntegrityError:
                return False
            return True

    def close(self) -> None:
        self._connection.close()


class CapabilityTicketIssuer:
    def __init__(self, private_key: Ed25519PrivateKey, *, ttl_seconds: int = 60) -> None:
        if not 1 <= ttl_seconds <= 300:
            raise ValueError("capability TTL must be between 1 and 300 seconds")
        self._private_key = private_key
        self._ttl_seconds = ttl_seconds

    @classmethod
    def from_pem(cls, pem: str | bytes, *, ttl_seconds: int = 60) -> CapabilityTicketIssuer:
        raw = pem.encode() if isinstance(pem, str) else pem
        key = serialization.load_pem_private_key(raw, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("capability private key must be Ed25519")
        return cls(key, ttl_seconds=ttl_seconds)

    @classmethod
    def generate(cls, *, ttl_seconds: int = 60) -> CapabilityTicketIssuer:
        return cls(Ed25519PrivateKey.generate(), ttl_seconds=ttl_seconds)

    def public_key_pem(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def issue(
        self,
        *,
        invocation_id: str,
        tool_name: str,
        input_sha256: str,
        fence: int,
        policy: dict[str, Any],
        now: int | None = None,
    ) -> str:
        timestamp = int(time.time() if now is None else now)
        if fence < 0 or len(input_sha256) != 64 or any(char not in "0123456789abcdef" for char in input_sha256.lower()):
            raise ValueError("invalid capability binding")
        payload = {
            "exp": timestamp + self._ttl_seconds,
            "fence": fence,
            "iat": timestamp,
            "input_sha256": input_sha256,
            "invocation_id": invocation_id,
            "jti": secrets.token_urlsafe(24),
            "policy_sha256": hashlib.sha256(canonical_payload(policy)).hexdigest(),
            "tool_name": tool_name,
            "v": 1,
        }
        encoded = _b64url(canonical_payload(payload))
        signature = _b64url(self._private_key.sign(encoded.encode("ascii")))
        return f"{encoded}.{signature}"


class CapabilityTicketVerifier:
    """Verifies bound Ed25519 tickets and consumes each jti at most once per runner process."""

    def __init__(
        self,
        public_key: Ed25519PublicKey,
        *,
        clock: Callable[[], float] = time.time,
        max_clock_skew_seconds: int = 5,
        replay_store: CapabilityReplayStore | None = None,
    ) -> None:
        self._public_key = public_key
        self._clock = clock
        self._max_clock_skew_seconds = max_clock_skew_seconds
        self._replay_store = replay_store or MemoryCapabilityReplayStore()

    @classmethod
    def from_pem(cls, pem: str | bytes, **kwargs: Any) -> CapabilityTicketVerifier:
        raw = pem.encode() if isinstance(pem, str) else pem
        key = serialization.load_pem_public_key(raw)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("capability public key must be Ed25519")
        return cls(key, **kwargs)

    def verify_and_consume(
        self,
        ticket: str,
        *,
        invocation_id: str,
        tool_name: str,
        input_sha256: str,
        fence: int,
        policy: dict[str, Any],
    ) -> CapabilityClaims:
        parts = ticket.split(".")
        if len(parts) != 2:
            raise CapabilityError("CAPABILITY_MALFORMED", "capability ticket is malformed")
        encoded, encoded_signature = parts
        try:
            signature = _unb64url(encoded_signature)
            self._public_key.verify(signature, encoded.encode("ascii"))
        except (CapabilityError, InvalidSignature, UnicodeEncodeError) as exc:
            raise CapabilityError("CAPABILITY_INVALID", "capability signature is invalid") from exc
        try:
            payload = json.loads(_unb64url(encoded))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CapabilityError("CAPABILITY_MALFORMED", "capability payload is malformed") from exc
        if not isinstance(payload, dict) or payload.get("v") != 1:
            raise CapabilityError("CAPABILITY_MALFORMED", "unsupported capability payload")
        required = {
            "jti",
            "invocation_id",
            "tool_name",
            "input_sha256",
            "fence",
            "iat",
            "exp",
            "policy_sha256",
        }
        if not required.issubset(payload):
            raise CapabilityError("CAPABILITY_MALFORMED", "capability payload is incomplete")
        now = int(self._clock())
        if not isinstance(payload["iat"], int) or payload["iat"] > now + self._max_clock_skew_seconds:
            raise CapabilityError("CAPABILITY_NOT_YET_VALID", "capability is not yet valid")
        if not isinstance(payload["exp"], int) or payload["exp"] <= now:
            raise CapabilityError("CAPABILITY_EXPIRED", "capability has expired")
        expected_policy = hashlib.sha256(canonical_payload(policy)).hexdigest()
        bindings = (
            payload["invocation_id"] == invocation_id,
            payload["tool_name"] == tool_name,
            payload["input_sha256"] == input_sha256,
            payload["fence"] == fence,
            secrets.compare_digest(str(payload["policy_sha256"]), expected_policy),
        )
        if not all(bindings):
            raise CapabilityError("CAPABILITY_BINDING_MISMATCH", "capability does not authorize this invocation")
        ticket_id = str(payload["jti"])
        if not self._replay_store.consume(ticket_id, int(payload["exp"]), now):
            raise CapabilityError("CAPABILITY_REPLAYED", "capability ticket was already consumed")
        return CapabilityClaims(
            ticket_id=ticket_id,
            invocation_id=invocation_id,
            tool_name=tool_name,
            input_sha256=input_sha256,
            fence=fence,
            issued_at=int(payload["iat"]),
            expires_at=int(payload["exp"]),
            policy_sha256=expected_policy,
        )

    def close(self) -> None:
        close = getattr(self._replay_store, "close", None)
        if close is not None:
            close()
