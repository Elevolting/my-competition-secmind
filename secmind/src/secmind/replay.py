from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import re
import stat
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.ledger import ZERO_HASH, canonical_json
from secmind.schemas import SCHEMA_VERSION, LedgerEvent, ReplayBundleRef
from secmind.unit_of_work import ReplayBundleRow

REPLAY_MEDIA_TYPE = "application/vnd.secmind.replay+zip"
REQUIRED_REPLAY_ENTRIES = frozenset(
    {
        "input-inventory.json",
        "effective-policy.json",
        "selected-skills.json",
        "repository-index-ref.json",
        "context-pack-manifest.jsonl",
        "plan-revisions.jsonl",
        "outcome-contracts.jsonl",
        "model-invocations.jsonl",
        "tool-invocations.jsonl",
        "approvals-and-grants.jsonl",
        "claims.jsonl",
        "evidence-graph.jsonl",
        "artifact-manifest.json",
        "ledger.jsonl",
        "report.json",
        "report.md",
        "report.sarif",
    }
)
OPTIONAL_REPLAY_ENTRIES = frozenset({"step-patches.jsonl"})
ALLOWED_REPLAY_ENTRIES = REQUIRED_REPLAY_ENTRIES | OPTIONAL_REPLAY_ENTRIES
_DIGEST = re.compile(r"^[a-fA-F0-9]{64}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class ReplayError(ValueError):
    pass


@dataclass(frozen=True)
class ReplayEntry:
    path: str
    content: bytes
    media_type: str = "application/json"


@dataclass(frozen=True)
class ReplayVerification:
    run_id: str
    artifact_id: str
    manifest_digest: str
    ledger_head_hash: str
    entry_digests: dict[str, str]
    ledger_events: tuple[LedgerEvent, ...]
    model_calls: int = 0
    tool_calls: int = 0


@dataclass(frozen=True)
class DeterministicReplayResult:
    run_id: str
    ledger_events: tuple[dict[str, Any], ...]
    step_patches: tuple[dict[str, Any], ...]
    final_sequence: int
    ledger_head_hash: str
    model_calls: int = 0
    tool_calls: int = 0


class LedgerHeadSigner:
    def __init__(self, key_id: str, private_key: Ed25519PrivateKey) -> None:
        if not _KEY_ID.fullmatch(key_id):
            raise ValueError("invalid ledger signer key id")
        self.key_id = key_id
        self._private_key = private_key

    def sign(self, run_id: str, ledger_head_hash: str) -> str:
        payload = _ledger_signature_payload(run_id, ledger_head_hash)
        signature = base64.urlsafe_b64encode(self._private_key.sign(payload)).rstrip(b"=").decode("ascii")
        return f"{self.key_id}.{signature}"

    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()


class ReplayManager:
    """Build and verify immutable replay bundles without invoking tools or models."""

    def __init__(
        self,
        artifact_store: ContentAddressedArtifactStore,
        *,
        engine: Engine | None = None,
        ledger_signer: LedgerHeadSigner | None = None,
        trusted_ledger_signers: dict[str, Ed25519PublicKey] | None = None,
        max_entry_bytes: int = 16 * 1024 * 1024,
        max_bundle_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        if max_entry_bytes < 1 or max_bundle_bytes < max_entry_bytes:
            raise ValueError("invalid replay bundle limits")
        self.artifact_store = artifact_store
        self.engine = engine
        self.ledger_signer = ledger_signer
        self.trusted_ledger_signers = dict(trusted_ledger_signers or {})
        self.max_entry_bytes = max_entry_bytes
        self.max_bundle_bytes = max_bundle_bytes

    def build(
        self,
        *,
        run_id: str,
        entries: Iterable[ReplayEntry],
        ledger_head_hash: str,
        parent_run_id: str | None = None,
    ) -> ReplayBundleRef:
        if not run_id or not _DIGEST.fullmatch(ledger_head_hash):
            raise ReplayError("run id and a valid ledger head hash are required")
        materialized: dict[str, ReplayEntry] = {}
        total = 0
        for entry in entries:
            _validate_entry_path(entry.path)
            if entry.path not in ALLOWED_REPLAY_ENTRIES:
                raise ReplayError(f"replay entry is not allowlisted: {entry.path}")
            if entry.path in materialized:
                raise ReplayError(f"duplicate replay entry: {entry.path}")
            if len(entry.content) > self.max_entry_bytes:
                raise ReplayError(f"replay entry exceeds size limit: {entry.path}")
            total += len(entry.content)
            if total > self.max_bundle_bytes:
                raise ReplayError("replay bundle exceeds size limit")
            materialized[entry.path] = entry
        missing = REQUIRED_REPLAY_ENTRIES - set(materialized)
        if missing:
            raise ReplayError(f"replay bundle is incomplete: {', '.join(sorted(missing))}")
        ledger_events = _verify_ledger_jsonl(materialized["ledger.jsonl"].content)
        if any(event.run_id != run_id for event in ledger_events):
            raise ReplayError("ledger entry belongs to a different run")
        actual_head = ledger_events[-1].hash if ledger_events else ZERO_HASH
        if actual_head != ledger_head_hash.lower():
            raise ReplayError("ledger entry does not match the declared chain head")
        ledger_signature = self.ledger_signer.sign(run_id, ledger_head_hash) if self.ledger_signer else None
        manifest_entries = [
            {
                "media_type": entry.media_type,
                "path": path,
                "sha256": hashlib.sha256(entry.content).hexdigest(),
                "size_bytes": len(entry.content),
            }
            for path, entry in sorted(materialized.items())
        ]
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "bundle_format": "secmind-replay-v1",
            "run_id": run_id,
            "parent_run_id": parent_run_id,
            "ledger_head_hash": ledger_head_hash.lower(),
            "ledger_head_signature": ledger_signature,
            "entries": manifest_entries,
        }
        manifest_bytes = canonical_json(manifest).encode("utf-8")
        manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
        archive = _build_archive(materialized, manifest_bytes)
        if len(archive) > self.max_bundle_bytes:
            raise ReplayError("replay archive exceeds size limit")
        stored = self.artifact_store.put(archive, media_type=REPLAY_MEDIA_TYPE, run_id=run_id)
        replay_ref = ReplayBundleRef(
            run_id=run_id,
            parent_run_id=parent_run_id,
            artifact_id=stored.artifact_id,
            manifest_digest=manifest_digest,
            ledger_head_hash=ledger_head_hash.lower(),
            ledger_head_signature=ledger_signature,
            mode="verify-only",
        )
        return self._persist(replay_ref)

    def verify_only(self, replay_ref: ReplayBundleRef) -> ReplayVerification:
        archive = self.artifact_store.read(replay_ref.artifact_id)
        manifest, contents = self._read_archive(archive)
        manifest_bytes = canonical_json(manifest).encode("utf-8")
        manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
        if manifest_digest != replay_ref.manifest_digest.lower():
            raise ReplayError("replay manifest digest mismatch")
        if manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("bundle_format") != "secmind-replay-v1":
            raise ReplayError("unsupported replay bundle format")
        if manifest.get("run_id") != replay_ref.run_id:
            raise ReplayError("replay bundle belongs to a different run")
        if manifest.get("parent_run_id") != replay_ref.parent_run_id:
            raise ReplayError("replay bundle parent run mismatch")
        if manifest.get("ledger_head_hash") != replay_ref.ledger_head_hash.lower():
            raise ReplayError("replay ledger head metadata mismatch")
        if manifest.get("ledger_head_signature") != replay_ref.ledger_head_signature:
            raise ReplayError("replay ledger signature metadata mismatch")
        if replay_ref.ledger_head_signature is not None:
            self._verify_ledger_signature(
                replay_ref.run_id,
                replay_ref.ledger_head_hash,
                replay_ref.ledger_head_signature,
            )
        entry_manifest = manifest.get("entries")
        if not isinstance(entry_manifest, list):
            raise ReplayError("replay entry manifest is invalid")
        expected: dict[str, dict[str, Any]] = {}
        for item in entry_manifest:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise ReplayError("replay entry manifest is invalid")
            path = item["path"]
            _validate_entry_path(path)
            if path in expected:
                raise ReplayError(f"duplicate replay manifest entry: {path}")
            expected[path] = item
        if set(expected) != set(contents) or not REQUIRED_REPLAY_ENTRIES.issubset(contents):
            raise ReplayError("replay archive and manifest entries differ")
        entry_digests: dict[str, str] = {}
        for path, content in contents.items():
            item = expected[path]
            digest = hashlib.sha256(content).hexdigest()
            if item.get("sha256") != digest or item.get("size_bytes") != len(content):
                raise ReplayError(f"replay entry integrity check failed: {path}")
            entry_digests[path] = digest
        ledger_events = _verify_ledger_jsonl(contents["ledger.jsonl"])
        if any(event.run_id != replay_ref.run_id for event in ledger_events):
            raise ReplayError("replayed ledger event belongs to a different run")
        actual_head = ledger_events[-1].hash if ledger_events else ZERO_HASH
        if actual_head != replay_ref.ledger_head_hash.lower():
            raise ReplayError("replayed ledger chain head mismatch")
        return ReplayVerification(
            run_id=replay_ref.run_id,
            artifact_id=replay_ref.artifact_id,
            manifest_digest=manifest_digest,
            ledger_head_hash=actual_head,
            entry_digests=entry_digests,
            ledger_events=tuple(ledger_events),
        )

    def deterministic_replay(self, replay_ref: ReplayBundleRef) -> DeterministicReplayResult:
        verification = self.verify_only(replay_ref)
        archive = self.artifact_store.read(replay_ref.artifact_id)
        _manifest, contents = self._read_archive(archive)
        patches = tuple(_jsonl_objects(contents.get("step-patches.jsonl", b""), "step-patches.jsonl"))
        events = tuple(event.model_dump(mode="json") for event in verification.ledger_events)
        return DeterministicReplayResult(
            run_id=replay_ref.run_id,
            ledger_events=events,
            step_patches=patches,
            final_sequence=verification.ledger_events[-1].sequence if verification.ledger_events else 0,
            ledger_head_hash=verification.ledger_head_hash,
        )

    def _read_archive(self, archive: bytes) -> tuple[dict[str, Any], dict[str, bytes]]:
        if len(archive) > self.max_bundle_bytes:
            raise ReplayError("replay archive exceeds size limit")
        try:
            handle = zipfile.ZipFile(io.BytesIO(archive), mode="r")
        except zipfile.BadZipFile as exc:
            raise ReplayError("replay artifact is not a valid archive") from exc
        with handle:
            infos = handle.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise ReplayError("replay archive contains duplicate entries")
            if "manifest.json" not in names:
                raise ReplayError("replay archive has no manifest")
            total = 0
            contents: dict[str, bytes] = {}
            manifest_bytes = b""
            for info in infos:
                _validate_archive_info(info)
                total += info.file_size
                if info.file_size > self.max_entry_bytes or total > self.max_bundle_bytes:
                    raise ReplayError("replay archive exceeds extraction limits")
                content = handle.read(info)
                if len(content) != info.file_size:
                    raise ReplayError("replay archive entry size mismatch")
                if info.filename == "manifest.json":
                    manifest_bytes = content
                else:
                    if info.filename not in ALLOWED_REPLAY_ENTRIES:
                        raise ReplayError(f"replay archive entry is not allowlisted: {info.filename}")
                    contents[info.filename] = content
            try:
                manifest = json.loads(manifest_bytes)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ReplayError("replay manifest is invalid JSON") from exc
            if not isinstance(manifest, dict) or canonical_json(manifest).encode("utf-8") != manifest_bytes:
                raise ReplayError("replay manifest must use canonical JSON")
            return manifest, contents

    def _verify_ledger_signature(self, run_id: str, ledger_head_hash: str, signature: str) -> None:
        try:
            key_id, encoded = signature.split(".", maxsplit=1)
        except ValueError as exc:
            raise ReplayError("ledger head signature is malformed") from exc
        public_key = self.trusted_ledger_signers.get(key_id)
        if public_key is None:
            raise ReplayError("ledger head signer is not trusted")
        decoded = _decode_signature(encoded)
        try:
            public_key.verify(decoded, _ledger_signature_payload(run_id, ledger_head_hash))
        except InvalidSignature as exc:
            raise ReplayError("ledger head signature is invalid") from exc

    def _persist(self, replay_ref: ReplayBundleRef) -> ReplayBundleRef:
        if self.engine is None:
            return replay_ref
        with Session(self.engine) as session:
            if self.engine.dialect.name == "postgresql":
                session.execute(
                    text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
                    {"lock_key": f"secmind:replay:{replay_ref.run_id}"},
                )
            elif self.engine.dialect.name == "sqlite":
                session.execute(text("BEGIN IMMEDIATE"))
            existing = session.scalars(
                select(ReplayBundleRow).where(
                    ReplayBundleRow.run_id == replay_ref.run_id,
                    ReplayBundleRow.manifest_digest == replay_ref.manifest_digest,
                )
            ).first()
            if existing is not None:
                if existing.artifact_id != replay_ref.artifact_id:
                    raise ReplayError("replay manifest digest is bound to a different artifact")
                return ReplayBundleRef(
                    replay_id=existing.replay_id,
                    run_id=existing.run_id,
                    parent_run_id=existing.parent_run_id,
                    artifact_id=existing.artifact_id,
                    manifest_digest=existing.manifest_digest,
                    ledger_head_hash=existing.ledger_head_hash,
                    ledger_head_signature=existing.ledger_head_signature,
                    mode=existing.mode,  # type: ignore[arg-type]
                    created_at=_aware(existing.created_at),
                )
            now = datetime.now(UTC)
            session.add(
                ReplayBundleRow(
                    replay_id=replay_ref.replay_id,
                    run_id=replay_ref.run_id,
                    parent_run_id=replay_ref.parent_run_id,
                    artifact_id=replay_ref.artifact_id,
                    manifest_digest=replay_ref.manifest_digest,
                    ledger_head_hash=replay_ref.ledger_head_hash,
                    ledger_head_signature=replay_ref.ledger_head_signature,
                    mode=replay_ref.mode,
                    created_at=now,
                )
            )
            session.commit()
            return replay_ref


def _build_archive(entries: dict[str, ReplayEntry], manifest: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_STORED, strict_timestamps=True) as archive:
        ordered = [("manifest.json", manifest), *[(key, item.content) for key, item in sorted(entries.items())]]
        for path, content in ordered:
            info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    return output.getvalue()


def _validate_archive_info(info: zipfile.ZipInfo) -> None:
    _validate_entry_path(info.filename, allow_manifest=True)
    if info.flag_bits & 0x1:
        raise ReplayError("encrypted replay entries are forbidden")
    if info.compress_type != zipfile.ZIP_STORED:
        raise ReplayError("replay entries must use deterministic stored compression")
    mode = info.external_attr >> 16
    if stat.S_IFMT(mode) == stat.S_IFLNK or info.is_dir():
        raise ReplayError("replay archive links and directories are forbidden")


def _validate_entry_path(path: str, *, allow_manifest: bool = False) -> None:
    if not path or "\\" in path or any(ord(character) < 32 or ord(character) == 127 for character in path):
        raise ReplayError("replay entry path is not canonical")
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or len(parsed.parts) != 1 or parsed.name != path or path in {".", ".."}:
        raise ReplayError("replay entry path is not canonical")
    if path == "manifest.json" and not allow_manifest:
        raise ReplayError("manifest.json is reserved by the replay format")


def _verify_ledger_jsonl(content: bytes) -> list[LedgerEvent]:
    rows = _jsonl_objects(content, "ledger.jsonl")
    events: list[LedgerEvent] = []
    previous = ZERO_HASH
    for expected_sequence, row in enumerate(rows, start=1):
        try:
            event = LedgerEvent.model_validate(row)
        except Exception as exc:
            raise ReplayError("ledger.jsonl contains an invalid event") from exc
        if event.sequence != expected_sequence or event.prev_hash != previous:
            raise ReplayError("ledger.jsonl sequence or previous hash is invalid")
        digest_input = {
            "event_id": event.event_id,
            "run_id": event.run_id,
            "sequence": event.sequence,
            "event_type": event.event_type,
            "timestamp": event.timestamp.isoformat(),
            "actor": event.actor,
            "dedupe_key": event.dedupe_key,
            "payload": event.payload,
            "prev_hash": event.prev_hash,
        }
        expected_hash = hashlib.sha256(canonical_json(digest_input).encode()).hexdigest()
        if event.hash != expected_hash:
            raise ReplayError("ledger.jsonl hash chain is invalid")
        previous = event.hash
        events.append(event)
    return events


def _jsonl_objects(content: bytes, path: str) -> list[dict[str, Any]]:
    try:
        text_content = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReplayError(f"{path} must use UTF-8") from exc
    objects: list[dict[str, Any]] = []
    for line_number, line in enumerate(text_content.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ReplayError(f"{path} line {line_number} is invalid JSON") from exc
        if not isinstance(value, dict):
            raise ReplayError(f"{path} line {line_number} must be a JSON object")
        objects.append(value)
    return objects


def _ledger_signature_payload(run_id: str, ledger_head_hash: str) -> bytes:
    if not run_id or not _DIGEST.fullmatch(ledger_head_hash):
        raise ReplayError("invalid ledger head signature binding")
    return canonical_json(
        {
            "domain": "secmind-ledger-head-v1",
            "run_id": run_id,
            "ledger_head_hash": ledger_head_hash.lower(),
        }
    ).encode("utf-8")


def _decode_signature(value: str) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise ReplayError("ledger head signature is malformed") from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value:
        raise ReplayError("ledger head signature encoding is not canonical")
    return decoded


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
