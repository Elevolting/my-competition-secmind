"""Offline, content-addressed quarantine records.

The normal finding path intentionally keeps the candidate object available to
the gain gate.  A rejected candidate must not, however, be kept as a second
mutable report lane or as an unbounded copy of scanner output.  This module is
the small durable lane for that information:

* :class:`FailureCapsule` contains only bounded, scrubbed identity metadata;
* :class:`FailureCapsuleStore` writes immutable objects addressed by their
  digest and an append-only index; and
* replay verifies every object and rejects a duplicate identity with a
  different payload.

It deliberately does not depend on the orchestrator or on a database.  A
directory copied to an offline machine is sufficient to verify and replay the
capsules.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secmind.secret_scrubber import REDACTED, TRUNCATED, redact, scrub_text

SCHEMA_VERSION = "failure-capsule-v1"
CAPSULE_STORE_VERSION = "failure-capsule-store-v1"
DEFAULT_MAX_PAYLOAD_BYTES = 16 * 1024
DEFAULT_MAX_CAPSULE_BYTES = 64 * 1024
_SHA256_LENGTH = 64
_RAW_BODY_KEYS = frozenset(
    {
        "body",
        "content",
        "description",
        "raw",
        "raw_body",
        "response",
        "response_body",
        "stderr",
        "stdout",
    }
)


class CapsuleError(ValueError):
    """Base error for malformed, tampered, or conflicting capsule data."""


class CapsuleIntegrityError(CapsuleError):
    """A stored capsule or append-only index failed verification."""


class CapsuleConflictError(CapsuleError):
    """One logical candidate was submitted with a different payload."""


# Compatibility aliases make the boundary easy to consume from older callers
# that used ``FailureCapsuleError`` as the public exception name.
FailureCapsuleError = CapsuleError


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _SHA256_LENGTH
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


def _text(value: object, *, maximum: int, default: str = "") -> str:
    if value is None:
        return default
    if not isinstance(value, str):
        value = str(value)
    value = scrub_text(value).replace("\x00", "")
    if len(value) > maximum:
        return value[: max(0, maximum - len(TRUNCATED))] + TRUNCATED
    return value


def _identity_text(value: object, *, maximum: int, namespace: str, default: str = "") -> str:
    """Preserve a safe identifier or replace sensitive bytes with a unique digest.

    Identity fields must not collapse to the shared ``[REDACTED]`` token: that
    would make unrelated candidates share an idempotency key. The opaque
    digest retains no original bytes while remaining deterministic and unique.
    """

    if value is None:
        raw = default
    elif isinstance(value, str):
        raw = value
    else:
        raw = str(value)
    raw = raw.replace("\x00", "")
    scrubbed = scrub_text(raw)
    if REDACTED in scrubbed or scrubbed != raw or len(raw) > maximum:
        return f"{namespace}-sha256-{hashlib.sha256(raw.encode('utf-8')).hexdigest()}"
    return raw


def _reference_text(value: object) -> str:
    return _identity_text(value, maximum=512, namespace="ref")


def _safe_value(value: Any, *, max_depth: int = 5, max_items: int = 128) -> Any:
    """Scrub and bound an arbitrary value without retaining a raw body."""

    scrubbed = redact(value)

    def bound(item: Any, depth: int) -> Any:
        if depth >= max_depth:
            return TRUNCATED
        if isinstance(item, str):
            return _text(item, maximum=512)
        if isinstance(item, Mapping):
            result: dict[str, Any] = {}
            for index, (key, child) in enumerate(item.items()):
                if index >= max_items:
                    result["scrubber.truncated"] = True
                    break
                safe_key = _text(key, maximum=128)
                if safe_key.casefold() in _RAW_BODY_KEYS:
                    result[safe_key] = {
                        "omitted": True,
                        "digest": _digest(_safe_value(child, max_depth=3, max_items=32)),
                    }
                else:
                    result[safe_key] = REDACTED if "[REDACTED]" == child else bound(child, depth + 1)
            return result
        if isinstance(item, (list, tuple, set, frozenset)):
            values = [bound(child, depth + 1) for child in list(item)[:max_items]]
            if len(item) > max_items:
                values.append(TRUNCATED)
            return values
        if item is None or isinstance(item, (bool, int, float)):
            return item
        return _text(repr(item), maximum=256)

    return bound(scrubbed, 0)


def _bounded_payload(value: Mapping[str, Any] | None, *, maximum: int = DEFAULT_MAX_PAYLOAD_BYTES) -> dict[str, Any]:
    safe = _safe_value(dict(value or {}))
    if not isinstance(safe, dict):
        safe = {"value": safe}
    encoded = _canonical(safe)
    if len(encoded) <= maximum:
        return safe
    # A capsule is an identity record, never a raw diagnostic envelope.  If a
    # caller supplies an unusually large safe value, retain only its digest
    # and bounded keys instead of slicing JSON in the middle of a string.
    return {
        "payload_digest": hashlib.sha256(encoded).hexdigest(),
        "payload_bytes": len(encoded),
        "payload_truncated": True,
    }


def _identity_payload(values: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: values[key]
        for key in values
        if key not in {"capsule_id", "capsule_digest", "payload_digest", "candidate_digest"}
    }


class FailureCapsule(BaseModel):
    """A bounded, immutable rejection/quarantine event.

    ``payload`` contains a short identity projection only.  The original
    Finding, Evidence, tool stdout, and scanner response are intentionally not
    fields in this contract.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = SCHEMA_VERSION
    version: str = "quarantine-v1"
    capsule_id: str = ""
    run_id: str = Field(min_length=1, max_length=128)
    candidate_id: str = Field(min_length=1, max_length=256)
    finding_id: str = Field(min_length=1, max_length=256)
    reason_code: str = Field(min_length=1, max_length=160)
    reason: str = ""
    refs: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    artifact_refs: tuple[str, ...] = ()
    delta_refs: tuple[str, ...] = ()
    payload: dict[str, Any] = Field(default_factory=dict)
    payload_digest: str = ""
    candidate_digest: str = ""
    transition: dict[str, Any] = Field(default_factory=dict)
    transition_digest: str = ""
    fence: dict[str, int] = Field(default_factory=dict)
    fence_digest: str = ""
    tool_name: str | None = None
    tool_version: str | None = None
    tool: dict[str, str | None] = Field(default_factory=dict)
    rule_id: str = "unknown"
    rule_version: str | None = None
    rule_digest: str | None = None
    rule: dict[str, str | None] = Field(default_factory=dict)
    gate_version: str = "TOOL-GAIN-GATE-V2"
    dedupe_key: str = ""
    previous_digest: str | None = None
    sequence: int = Field(default=0, ge=0)
    capsule_digest: str = ""

    _MAX_REFS: ClassVar[int] = 256

    @model_validator(mode="after")
    def _normalize_and_verify(self) -> FailureCapsule:
        if self.schema_version != SCHEMA_VERSION:
            raise CapsuleIntegrityError("unsupported failure capsule schema")
        if not self.version:
            raise CapsuleIntegrityError("failure capsule version is required")

        # Pydantic's frozen model still permits one canonicalization pass while
        # validating externally supplied JSON.  All values are bounded before
        # their digest is checked, so a secret or multi-megabyte diagnostic can
        # never become a durable capsule payload.
        object.__setattr__(self, "reason_code", _text(self.reason_code, maximum=160))
        object.__setattr__(self, "reason", _text(self.reason, maximum=512))
        object.__setattr__(self, "run_id", _identity_text(self.run_id, maximum=128, namespace="run"))
        object.__setattr__(
            self,
            "candidate_id",
            _identity_text(self.candidate_id, maximum=256, namespace="candidate"),
        )
        object.__setattr__(
            self,
            "finding_id",
            _identity_text(self.finding_id, maximum=256, namespace="finding"),
        )
        object.__setattr__(self, "rule_id", _text(self.rule_id, maximum=256, default="unknown"))
        object.__setattr__(self, "tool_name", None if self.tool_name is None else _text(self.tool_name, maximum=160))
        object.__setattr__(
            self,
            "tool_version",
            None if self.tool_version is None else _text(self.tool_version, maximum=160),
        )
        object.__setattr__(
            self,
            "rule_version",
            None if self.rule_version is None else _text(self.rule_version, maximum=160),
        )
        if self.rule_digest is not None and not _is_digest(self.rule_digest):
            raise CapsuleIntegrityError("rule_digest must be a SHA-256 digest")
        object.__setattr__(self, "rule_digest", None if self.rule_digest is None else self.rule_digest.lower())

        refs = tuple(sorted({_reference_text(item) for item in self.refs if _reference_text(item)}))
        if len(refs) > self._MAX_REFS:
            raise CapsuleIntegrityError("failure capsule has too many refs")
        object.__setattr__(self, "refs", refs)
        for field_name in ("evidence_refs", "artifact_refs", "delta_refs"):
            values = tuple(
                sorted({_reference_text(item) for item in getattr(self, field_name) if _reference_text(item)})
            )
            if len(values) > self._MAX_REFS:
                raise CapsuleIntegrityError(f"failure capsule has too many {field_name}")
            object.__setattr__(self, field_name, values)

        payload = _bounded_payload(self.payload)
        object.__setattr__(self, "payload", payload)
        expected_payload_digest = _digest(payload)
        if self.payload_digest and not hmac.compare_digest(self.payload_digest.lower(), expected_payload_digest):
            raise CapsuleIntegrityError("failure capsule payload digest mismatch")
        object.__setattr__(self, "payload_digest", expected_payload_digest)

        candidate_material = {
            "run_id": self.run_id,
            "candidate_id": self.candidate_id,
            "finding_id": self.finding_id,
            "payload_digest": self.payload_digest,
            "rule_id": self.rule_id,
            "refs": self.refs,
        }
        expected_candidate_digest = _digest(candidate_material)
        if self.candidate_digest and not hmac.compare_digest(self.candidate_digest.lower(), expected_candidate_digest):
            raise CapsuleIntegrityError("failure capsule candidate digest mismatch")
        object.__setattr__(self, "candidate_digest", expected_candidate_digest)

        transition = _safe_value(self.transition)
        if not isinstance(transition, dict):
            transition = {"value": transition}
        object.__setattr__(self, "transition", transition)
        expected_transition_digest = _digest(transition)
        if self.transition_digest and not hmac.compare_digest(
            self.transition_digest.lower(), expected_transition_digest
        ):
            raise CapsuleIntegrityError("failure capsule transition digest mismatch")
        object.__setattr__(self, "transition_digest", expected_transition_digest)

        fence: dict[str, int] = {}
        for key, value in self.fence.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise CapsuleIntegrityError("failure capsule fence values must be non-negative integers")
            fence[_text(key, maximum=64)] = value
        object.__setattr__(self, "fence", dict(sorted(fence.items())))
        expected_fence_digest = _digest(fence)
        if self.fence_digest and not hmac.compare_digest(self.fence_digest.lower(), expected_fence_digest):
            raise CapsuleIntegrityError("failure capsule fence digest mismatch")
        object.__setattr__(self, "fence_digest", expected_fence_digest)

        tool = _safe_value(self.tool)
        object.__setattr__(self, "tool", tool if isinstance(tool, dict) else {})
        rule = _safe_value(self.rule)
        object.__setattr__(self, "rule", rule if isinstance(rule, dict) else {})
        if self.previous_digest is not None and not _is_digest(self.previous_digest):
            raise CapsuleIntegrityError("previous_digest must be a SHA-256 digest")
        if self.previous_digest is not None:
            object.__setattr__(self, "previous_digest", self.previous_digest.lower())

        transition_version = self.transition.get("version", 1)
        dedupe = self.dedupe_key or _digest(
            {
                "run_id": self.run_id,
                "candidate_id": self.candidate_id,
                "finding_id": self.finding_id,
                "transition_version": transition_version,
            }
        )
        # ``dedupe_key`` is an integrity identifier, not user-controlled
        # diagnostic text.  Passing it through ``scrub_text`` collapses every
        # high-entropy digest to ``[REDACTED]`` and makes unrelated candidates
        # conflict.  Require the canonical digest shape instead; callers that
        # need to derive a key must hash their material before constructing a
        # capsule.
        if not _is_digest(dedupe):
            raise CapsuleIntegrityError("failure capsule dedupe_key must be a SHA-256 digest")
        object.__setattr__(self, "dedupe_key", dedupe.lower())
        identity = _identity_payload(self.model_dump(mode="json"))
        expected_capsule_digest = _digest(identity)
        if self.capsule_digest and not hmac.compare_digest(self.capsule_digest.lower(), expected_capsule_digest):
            raise CapsuleIntegrityError("failure capsule digest mismatch")
        object.__setattr__(self, "capsule_digest", expected_capsule_digest)
        expected_id = f"failure-capsule-{expected_capsule_digest}"
        if self.capsule_id and self.capsule_id != expected_id:
            raise CapsuleIntegrityError("failure capsule id mismatch")
        object.__setattr__(self, "capsule_id", expected_id)
        return self

    @classmethod
    def from_candidate(
        cls,
        candidate: Any,
        *,
        run_id: str,
        reason_code: str,
        reason: str | None = None,
        refs: Iterable[str] = (),
        evidence_refs: Iterable[str] = (),
        artifact_refs: Iterable[str] = (),
        delta_refs: Iterable[str] = (),
        transition: Mapping[str, Any] | None = None,
        fence: Mapping[str, int] | None = None,
        tool_name: str | None = None,
        tool_version: str | None = None,
        rule_version: str | None = None,
        rule_digest: str | None = None,
        gate_version: str = "TOOL-GAIN-GATE-V2",
        previous_digest: str | None = None,
        sequence: int = 0,
        candidate_id: str | None = None,
    ) -> FailureCapsule:
        """Create a capsule from a Finding without retaining its raw body."""

        if isinstance(candidate, BaseModel):
            values = candidate.model_dump(mode="json")
        elif isinstance(candidate, Mapping):
            values = dict(candidate)
        else:
            values = {}
        finding_id = _identity_text(
            values.get("finding_id"),
            maximum=256,
            namespace="finding",
            default="unknown-finding",
        )
        candidate_id = _identity_text(
            candidate_id or values.get("candidate_id") or finding_id,
            maximum=256,
            namespace="candidate",
        )
        rule_id = _text(values.get("rule_id"), maximum=256, default="unknown")
        evidence_ids = tuple(_reference_text(item) for item in values.get("evidence_ids", ()) if item)
        safe_description = _text(values.get("description"), maximum=2_048)
        safe_payload = {
            "finding_id": finding_id,
            "candidate_id": candidate_id,
            "rule_id": rule_id,
            "path": _text(values.get("path"), maximum=1024, default="."),
            "line": values.get("line") if isinstance(values.get("line"), int) else None,
            "severity": _text(values.get("severity"), maximum=32),
            "confidence": _text(values.get("confidence"), maximum=32),
            "title": _text(values.get("title"), maximum=512),
            # Keep only a scrubbed digest.  Even a bounded description excerpt
            # can contain source or credential material, so raw body text is
            # never copied into a capsule.
            "description_digest": _digest({"description": safe_description}),
            "description_omitted": True,
            "evidence_count": len(evidence_ids),
        }
        safe_evidence_refs = tuple(evidence_refs) or evidence_ids
        all_refs = tuple(refs) or tuple(
            [f"candidate:{candidate_id}", f"finding:{finding_id}"]
            + [f"evidence:{item}" for item in safe_evidence_refs]
            + [f"artifact:{item}" for item in artifact_refs]
            + [f"delta:{item}" for item in delta_refs]
        )
        safe_transition = dict(transition or {})
        safe_transition.setdefault("to_state", "quarantined")
        safe_transition.setdefault("reason_code", reason_code)
        safe_tool = {"name": tool_name, "version": tool_version}
        safe_rule = {"id": rule_id, "version": rule_version, "digest": rule_digest}
        return cls(
            version="quarantine-v1",
            run_id=run_id,
            candidate_id=candidate_id,
            finding_id=finding_id,
            reason_code=reason_code,
            reason=reason or reason_code,
            refs=all_refs,
            evidence_refs=safe_evidence_refs,
            artifact_refs=tuple(artifact_refs),
            delta_refs=tuple(delta_refs),
            payload=safe_payload,
            transition=safe_transition,
            fence=dict(fence or {}),
            tool_name=tool_name,
            tool_version=tool_version,
            tool=safe_tool,
            rule_id=rule_id,
            rule_version=rule_version,
            rule_digest=rule_digest,
            rule=safe_rule,
            gate_version=gate_version,
            previous_digest=previous_digest,
            sequence=sequence,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def to_json_bytes(self) -> bytes:
        return _canonical(self.to_dict())


class FailureCapsuleStore:
    """An append-only local store for :class:`FailureCapsule` objects."""

    def __init__(self, root: Path, *, max_capsule_bytes: int = DEFAULT_MAX_CAPSULE_BYTES) -> None:
        if max_capsule_bytes < 1_024:
            raise ValueError("max_capsule_bytes must be at least 1024")
        self.root = Path(root).resolve()
        self.max_capsule_bytes = max_capsule_bytes
        self.objects = self.root / "sha256"
        self.index_path = self.root / "index.jsonl"
        self.objects.mkdir(parents=True, exist_ok=True)

    def _path_for(self, digest: str) -> Path:
        if not _is_digest(digest):
            raise CapsuleIntegrityError("invalid capsule digest")
        path = (self.objects / digest[:2] / digest.lower()).resolve()
        if not path.is_relative_to(self.root):
            raise CapsuleIntegrityError("invalid capsule path")
        return path

    def _read(self, digest: str) -> FailureCapsule:
        path = self._path_for(digest)
        if not path.is_file() or path.is_symlink():
            raise CapsuleIntegrityError("capsule object is missing")
        raw = path.read_bytes()
        if len(raw) > self.max_capsule_bytes:
            raise CapsuleIntegrityError("capsule object exceeds size limit")
        try:
            capsule = FailureCapsule.model_validate(json.loads(raw.decode("utf-8")))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise CapsuleIntegrityError("capsule object is invalid") from exc
        if capsule.capsule_digest != digest.lower() or capsule.to_json_bytes() != raw:
            raise CapsuleIntegrityError("capsule object bytes or digest mismatch")
        return capsule

    def _existing(self) -> tuple[FailureCapsule, ...]:
        if not self.index_path.exists():
            return ()
        capsules: list[FailureCapsule] = []
        previous_sequence = 0
        previous_digest: str | None = None
        for line in self.index_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                digest = event["capsule_digest"]
                sequence = event["sequence"]
                if event.get("schema_version") != CAPSULE_STORE_VERSION:
                    raise CapsuleIntegrityError("capsule index schema is invalid")
                if not isinstance(sequence, int) or sequence <= previous_sequence:
                    raise CapsuleIntegrityError("capsule index sequence is not append-only")
                previous_sequence = sequence
                capsule = self._read(digest)
                if event.get("dedupe_key") != capsule.dedupe_key:
                    raise CapsuleIntegrityError("capsule index identity mismatch")
                if capsule.previous_digest is not None and capsule.previous_digest != previous_digest:
                    raise CapsuleIntegrityError("failure capsule chain predecessor mismatch")
                previous_digest = capsule.capsule_digest
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise CapsuleIntegrityError("capsule index is invalid") from exc
            capsules.append(capsule)
        return tuple(capsules)

    def append(self, capsule: FailureCapsule | Mapping[str, Any]) -> FailureCapsule:
        """Atomically append *capsule*, deduplicating only identical payloads."""

        return self.append_many((capsule,))[0]

    def append_many(
        self,
        capsules: Iterable[FailureCapsule | Mapping[str, Any]],
    ) -> tuple[FailureCapsule, ...]:
        """Append a batch after one verified index read.

        A scan can quarantine hundreds of candidates. Replaying the complete
        index for every item is quadratic and previously made a terminal
        report slower than the investigation. The batch is fully validated
        for identity and object collisions before any index row is appended;
        a crash during the final append can leave only a valid prefix, which a
        retry deterministically deduplicates.
        """

        # ``model_copy(update=...)`` intentionally skips Pydantic validation;
        # re-validate instances here so a caller cannot smuggle stale digest
        # fields into an append-only object.
        items = tuple(
            FailureCapsule.model_validate(
                capsule.model_dump(mode="json") if isinstance(capsule, FailureCapsule) else dict(capsule)
            )
            for capsule in capsules
        )
        if not items:
            return ()
        existing = list(self._existing())
        by_dedupe = {item.dedupe_key: item for item in existing}
        by_digest = {item.capsule_digest: item for item in existing}
        resolved: list[FailureCapsule] = []
        pending: list[tuple[FailureCapsule, bytes, Path]] = []
        previous_digest = existing[-1].capsule_digest if existing else None
        # Validate and stage genuinely new identities. This second loop keeps
        # duplicate items in the input batch deterministic without writing the
        # same object or index row twice.
        resolved.clear()
        for item in items:
            prior = by_dedupe.get(item.dedupe_key)
            if prior is not None:
                if prior.capsule_digest != item.capsule_digest or prior.payload_digest != item.payload_digest:
                    raise CapsuleConflictError("failure capsule payload conflict")
                resolved.append(prior)
                continue
            digest_prior = by_digest.get(item.capsule_digest)
            if digest_prior is not None and digest_prior.to_json_bytes() != item.to_json_bytes():
                raise CapsuleConflictError("content-addressed capsule collision")
            if item.previous_digest is not None and item.previous_digest != previous_digest:
                raise CapsuleIntegrityError("failure capsule chain predecessor mismatch")
            raw = item.to_json_bytes()
            if len(raw) > self.max_capsule_bytes:
                raise CapsuleIntegrityError("capsule object exceeds size limit")
            destination = self._path_for(item.capsule_digest)
            if destination.exists() and (destination.is_symlink() or destination.read_bytes() != raw):
                raise CapsuleConflictError("content-addressed capsule collision")
            pending.append((item, raw, destination))
            by_dedupe[item.dedupe_key] = item
            by_digest[item.capsule_digest] = item
            resolved.append(item)
            previous_digest = item.capsule_digest

        for _item, raw, destination in pending:
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                continue
            fd, temporary = tempfile.mkstemp(prefix=".capsule-", dir=destination.parent)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                Path(temporary).replace(destination)
            except FileExistsError:
                Path(temporary).unlink(missing_ok=True)
                if destination.is_symlink() or destination.read_bytes() != raw:
                    raise CapsuleConflictError("content-addressed capsule collision") from None
            finally:
                Path(temporary).unlink(missing_ok=True)

        if pending:
            # ``sequence`` belongs to the append-only index. Capsule objects
            # are content-addressed and keep their default sequence so the
            # same payload can be deduplicated across stores.
            with self.index_path.open("a", encoding="utf-8", newline="\n") as handle:
                for offset, (item, _raw, _destination) in enumerate(pending, start=1):
                    event = {
                        "schema_version": CAPSULE_STORE_VERSION,
                        "sequence": len(existing) + offset,
                        "capsule_digest": item.capsule_digest,
                        "dedupe_key": item.dedupe_key,
                    }
                    handle.write(_canonical(event).decode("utf-8") + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        return tuple(resolved)

    put = append
    save = append

    def get(self, digest_or_id: str) -> FailureCapsule:
        digest = digest_or_id.removeprefix("failure-capsule-")
        return self._read(digest)

    def replay(self) -> tuple[FailureCapsule, ...]:
        """Verify and return the append-only sequence in deterministic order."""

        return self._existing()

    def verify(self) -> bool:
        try:
            self._existing()
        except CapsuleError:
            return False
        return True

    def __iter__(self):
        return iter(self.replay())


def scrub_failure_payload(value: Mapping[str, Any] | None) -> dict[str, Any]:
    """Public scrubber used by gate/admission integration and tests."""

    return _bounded_payload(value)


def capture_failure_capsule(
    store: FailureCapsuleStore,
    candidate: Any,
    *,
    run_id: str,
    reason_code: str,
    reason: str | None = None,
    **kwargs: Any,
) -> FailureCapsule:
    """Build and append one capsule, returning the immutable stored value."""

    capsule = FailureCapsule.from_candidate(
        candidate,
        run_id=run_id,
        reason_code=reason_code,
        reason=reason,
        **kwargs,
    )
    return store.append(capsule)


__all__ = [
    "CAPSULE_STORE_VERSION",
    "DEFAULT_MAX_CAPSULE_BYTES",
    "DEFAULT_MAX_PAYLOAD_BYTES",
    "SCHEMA_VERSION",
    "CapsuleConflictError",
    "CapsuleError",
    "CapsuleIntegrityError",
    "FailureCapsule",
    "FailureCapsuleError",
    "FailureCapsuleStore",
    "capture_failure_capsule",
    "scrub_failure_payload",
]
