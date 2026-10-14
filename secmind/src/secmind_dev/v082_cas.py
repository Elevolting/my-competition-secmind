"""Content-addressed persistence and append-only sealing for v0.8.2 runs."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any, Literal

from .v082_contracts import (
    AgentReport,
    AttemptRecord,
    FailureCapsule,
    InputManifest,
    QuarantineRecord,
    RunIdentity,
    SealedEvaluation,
    canonical_digest,
    canonical_json,
    normalize_sha256,
    sha256_bytes,
    terminal_status,
)


class CASError(RuntimeError):
    """Raised when a content-addressed object or seal cannot be trusted."""


class _ClosingConnection(sqlite3.Connection):
    """Make ``with CASStore._connect()`` close the SQLite handle on Windows."""

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> Literal[False]:
        try:
            super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()
        return False


class CASStore:
    """Small filesystem CAS with a SQLite index.

    The object path is derived only from the SHA-256 digest.  A write is
    atomic and idempotent, while the SQLite row lets a run directory retain
    object kind/size metadata without duplicating the bytes in a database.
    """

    def __init__(self, root: Path, *, database_path: Path | None = None) -> None:
        self.root = root.resolve()
        self.object_root = self.root / "sha256"
        self.database_path = database_path or self.root / "cas.sqlite3"
        self.object_root.mkdir(parents=True, exist_ok=True)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=30, factory=_ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS cas_objects (
                    digest TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS evaluation_seals (
                    seal_id TEXT PRIMARY KEY,
                    envelope_digest TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS seal_objects (
                    seal_id TEXT NOT NULL REFERENCES evaluation_seals(seal_id),
                    name TEXT NOT NULL,
                    digest TEXT NOT NULL REFERENCES cas_objects(digest),
                    PRIMARY KEY (seal_id, name)
                );
                """
            )

    def _path(self, digest: str) -> Path:
        normalized = normalize_sha256(digest, field_name="CAS digest")
        return self.object_root / normalized[:2] / normalized[2:]

    def put_bytes(self, payload: bytes, *, kind: str) -> str:
        if not isinstance(payload, bytes):
            raise CASError("CAS payload must be bytes")
        if not kind or len(kind) > 128 or any(ord(char) < 32 for char in kind):
            raise CASError("CAS kind is invalid")
        digest = sha256_bytes(payload)
        target = self._path(digest)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            try:
                if target.read_bytes() != payload:
                    raise CASError(f"CAS collision for {digest}")
            except OSError as exc:
                raise CASError(f"cannot verify CAS object {digest}") from exc
        else:
            temporary: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="wb", dir=target.parent, prefix=f".{target.name}.", suffix=".tmp", delete=False
                ) as handle:
                    temporary = Path(handle.name)
                    handle.write(payload)
                    handle.flush()
                temporary.replace(target)
            except OSError as exc:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
                if not target.exists():
                    raise CASError(f"cannot persist CAS object {digest}") from exc
        with self._connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO cas_objects(digest, kind, size_bytes) VALUES (?, ?, ?)",
                (digest, kind, len(payload)),
            )
        return digest

    def put_json(self, value: Any, *, kind: str) -> str:
        return self.put_bytes(canonical_json(value), kind=kind)

    def contains(self, digest: str) -> bool:
        return self._path(digest).is_file()

    def get_bytes(self, digest: str) -> bytes:
        target = self._path(digest)
        try:
            payload = target.read_bytes()
        except OSError as exc:
            raise CASError(f"CAS object is missing: {digest}") from exc
        normalized = normalize_sha256(digest, field_name="CAS digest")
        if sha256_bytes(payload) != normalized:
            raise CASError(f"CAS object has a digest mismatch: {digest}")
        return payload

    def get_json(self, digest: str) -> Any:
        try:
            return json.loads(self.get_bytes(digest).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CASError(f"CAS object is not valid UTF-8 JSON: {digest}") from exc

    def metadata(self, digest: str) -> dict[str, Any]:
        normalized = normalize_sha256(digest, field_name="CAS digest")
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM cas_objects WHERE digest = ?", (normalized,)).fetchone()
        if row is None:
            raise CASError(f"CAS object is not indexed: {digest}")
        return dict(row)

    def verify(self, digest: str) -> bool:
        try:
            self.get_bytes(digest)
        except CASError:
            return False
        return True


class EvaluationSealStore:
    """Seal a report, evidence set, manifest, attempts and diagnostics."""

    def __init__(self, cas: CASStore) -> None:
        self.cas = cas

    def seal(
        self,
        *,
        identity: RunIdentity,
        report: AgentReport,
        input_manifest: InputManifest,
        attempts: Sequence[AttemptRecord] = (),
        failure_capsules: Sequence[FailureCapsule] = (),
        quarantine: Sequence[QuarantineRecord] = (),
        bridge_executions: Sequence[Mapping[str, Any]] = (),
    ) -> SealedEvaluation:
        # Some adapters avoid duplicating the input digest on both a Finding
        # and its linked Evidence.  Recover it only when the evidence link,
        # canonical path and digest agree uniquely; the manifest validation
        # below remains the authority and rejects a forged or stale digest.
        enriched_findings = []
        for finding in report.findings:
            if finding.file_sha256:
                enriched_findings.append(finding)
                continue
            linked_hashes = {
                evidence.file_sha256
                for evidence in report.evidence
                if evidence.finding_id == finding.finding_id and evidence.path == finding.path and evidence.file_sha256
            }
            enriched_findings.append(
                replace(finding, file_sha256=next(iter(linked_hashes))) if len(linked_hashes) == 1 else finding
            )
        report = replace(report, findings=tuple(enriched_findings))

        manifest_digest = input_manifest.digest
        if identity.input_manifest_digest not in {"UNKNOWN", manifest_digest}:
            raise CASError("run identity input_manifest_digest does not match the manifest")
        # The manifest is part of the seal boundary.  Filling this one
        # previously-unknown provenance field here prevents a caller from
        # accidentally producing an apparently sealed run that is not bound
        # to the actual input set.
        sealed_identity = (
            replace(identity, input_manifest_digest=manifest_digest)
            if identity.input_manifest_digest == "UNKNOWN"
            else identity
        )
        validation = report.validate_evidence(input_manifest)
        attempts_tuple = tuple(sorted(attempts, key=lambda item: item.attempt_ordinal))
        capsule_tuple = tuple(failure_capsules)
        quarantine_tuple = tuple(quarantine)
        status = terminal_status(report, validation, attempts_tuple)

        report_payload = report.to_dict(include_evidence=False)
        evidence_payload = {
            "schema_version": "secmind-evidence-set-v0.8.2",
            "task_id": report.task_id,
            "evidence": [item.to_dict() for item in report.evidence],
        }
        manifest_payload = input_manifest.to_dict()
        attempts_payload = {
            "schema_version": "secmind-attempts-v0.8.2",
            "attempts": [item.to_dict() for item in attempts_tuple],
        }
        bridge_payload = (
            {
                "schema_version": "secmind-bridge-executions-v0.8.2",
                "executions": [dict(item) for item in bridge_executions],
            }
            if bridge_executions
            else None
        )
        report_digest = self.cas.put_json(report_payload, kind="sealed-agent-report")
        evidence_digest = self.cas.put_json(evidence_payload, kind="sealed-evidence")
        manifest_digest = self.cas.put_json(manifest_payload, kind="sealed-input-manifest")
        attempts_digest = self.cas.put_json(attempts_payload, kind="sealed-attempts")
        bridge_digest = self.cas.put_json(bridge_payload, kind="sealed-bridge-executions") if bridge_payload else None
        capsule_digest = (
            self.cas.put_json(
                {
                    "schema_version": "secmind-failure-capsules-v0.8.2",
                    "capsules": [item.to_dict() for item in capsule_tuple],
                },
                kind="failure-capsule",
            )
            if capsule_tuple
            else None
        )
        quarantine_digest = (
            self.cas.put_json(
                {
                    "schema_version": "secmind-quarantine-v0.8.2",
                    "records": [item.to_dict() for item in quarantine_tuple],
                },
                kind="quarantine-records",
            )
            if quarantine_tuple
            else None
        )
        envelope_without_id = {
            "schema_version": "secmind-seal-v0.8.2",
            "identity": sealed_identity.to_dict(),
            "report_sha256": report_digest,
            "evidence_sha256": evidence_digest,
            "input_manifest_sha256": manifest_digest,
            "attempts_sha256": attempts_digest,
            "bridge_execution_sha256": bridge_digest,
            "failure_capsules_sha256": capsule_digest,
            "quarantine_sha256": quarantine_digest,
            "status": status,
            "evidence_validation": validation.to_dict(),
        }
        seal_id = f"seal-{canonical_digest(envelope_without_id)}"
        envelope = {"seal_id": seal_id, **envelope_without_id}
        envelope_digest = self.cas.put_json(envelope, kind="evaluation-seal")
        with self.cas._connect() as connection:  # noqa: SLF001 - seal/index are one atomic boundary
            existing = connection.execute(
                "SELECT envelope_digest FROM evaluation_seals WHERE seal_id = ?", (seal_id,)
            ).fetchone()
            if existing is not None:
                if str(existing["envelope_digest"]) != envelope_digest:
                    raise CASError(f"seal {seal_id} already exists with different content")
            else:
                try:
                    connection.execute(
                        "INSERT INTO evaluation_seals(seal_id, envelope_digest, status) VALUES (?, ?, ?)",
                        (seal_id, envelope_digest, status),
                    )
                    for name, digest in (
                        ("report", report_digest),
                        ("evidence", evidence_digest),
                        ("input_manifest", manifest_digest),
                        ("attempts", attempts_digest),
                        ("bridge_executions", bridge_digest),
                        ("failure_capsules", capsule_digest),
                        ("quarantine", quarantine_digest),
                    ):
                        if digest is not None:
                            connection.execute(
                                "INSERT INTO seal_objects(seal_id, name, digest) VALUES (?, ?, ?)",
                                (seal_id, name, digest),
                            )
                except sqlite3.IntegrityError as exc:
                    raise CASError(f"seal {seal_id} already exists with different content") from exc
        return SealedEvaluation(
            seal_id=seal_id,
            schema_version="secmind-seal-v0.8.2",
            identity=sealed_identity,
            report_sha256=report_digest,
            evidence_sha256=evidence_digest,
            input_manifest_sha256=manifest_digest,
            attempts_sha256=attempts_digest,
            failure_capsules_sha256=capsule_digest,
            quarantine_sha256=quarantine_digest,
            status=status,
            evidence_validation=validation,
            bridge_execution_sha256=bridge_digest,
        )

    def load(self, seal_id_or_digest: str) -> dict[str, Any]:
        digest = seal_id_or_digest
        with self.cas._connect() as connection:  # noqa: SLF001
            row = connection.execute(
                "SELECT envelope_digest FROM evaluation_seals WHERE seal_id = ?", (seal_id_or_digest,)
            ).fetchone()
        if row is not None:
            digest = str(row["envelope_digest"])
        raw = self.cas.get_json(digest)
        if not isinstance(raw, Mapping) or raw.get("schema_version") != "secmind-seal-v0.8.2":
            raise CASError("unsupported or malformed evaluation seal")
        if raw.get("seal_id") != seal_id_or_digest and seal_id_or_digest.startswith("seal-"):
            raise CASError("evaluation seal identity mismatch")
        material = {key: value for key, value in raw.items() if key != "seal_id"}
        if raw.get("seal_id") != f"seal-{canonical_digest(material)}":
            raise CASError("evaluation seal content identity mismatch")
        return dict(raw)

    def verify(self, seal_id_or_digest: str) -> dict[str, Any]:
        envelope = self.load(seal_id_or_digest)
        refs = {
            "report": envelope.get("report_sha256"),
            "evidence": envelope.get("evidence_sha256"),
            "input_manifest": envelope.get("input_manifest_sha256"),
            "attempts": envelope.get("attempts_sha256"),
        }
        for name, digest in refs.items():
            if not isinstance(digest, str) or not self.cas.verify(digest):
                raise CASError(f"sealed {name} object is missing or corrupt")
        for name in ("failure_capsules_sha256", "quarantine_sha256"):
            digest = envelope.get(name)
            if digest is not None and (not isinstance(digest, str) or not self.cas.verify(digest)):
                raise CASError(f"sealed {name} object is missing or corrupt")
        bridge_digest = envelope.get("bridge_execution_sha256")
        if bridge_digest is not None and (not isinstance(bridge_digest, str) or not self.cas.verify(bridge_digest)):
            raise CASError("sealed bridge execution object is missing or corrupt")
        manifest = InputManifest.from_dict(self.cas.get_json(str(refs["input_manifest"])))
        report_raw = self.cas.get_json(str(refs["report"]))
        evidence_raw = self.cas.get_json(str(refs["evidence"]))
        if not isinstance(evidence_raw, Mapping) or not isinstance(evidence_raw.get("evidence"), list):
            raise CASError("sealed evidence object is malformed")
        report_with_evidence = {**report_raw, "evidence": evidence_raw["evidence"]}
        report = AgentReport.from_dict(report_with_evidence)
        validation = report.validate_evidence(manifest)
        recorded = envelope.get("evidence_validation")
        if validation.to_dict() != recorded:
            raise CASError("sealed evidence validation digest does not match")
        if envelope.get("status") != terminal_status(
            report,
            validation,
            tuple(AttemptRecord(**item) for item in self.cas.get_json(str(refs["attempts"])).get("attempts", [])),
        ):
            raise CASError("sealed status does not match report/attempt semantics")
        return {
            "valid": True,
            "seal_id": envelope["seal_id"],
            "status": envelope["status"],
            "identity": envelope.get("identity"),
            "report": report.to_dict(),
            "input_manifest": manifest.to_dict(),
            "evidence_validation": validation.to_dict(),
            "object_digests": refs,
            "bridge_execution_sha256": bridge_digest,
        }

    def export_failure_capsule(self, seal_id_or_digest: str, output: Path) -> Path:
        """Export only typed failure telemetry; never export provider bodies."""

        envelope = self.load(seal_id_or_digest)
        digest = envelope.get("failure_capsules_sha256")
        payload = self.cas.get_json(digest) if isinstance(digest, str) else {"capsules": []}
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(canonical_json(payload))
        return output


def seal_evaluation(
    cas_root: Path,
    *,
    identity: RunIdentity,
    report: AgentReport,
    input_manifest: InputManifest,
    attempts: Sequence[AttemptRecord] = (),
    failure_capsules: Sequence[FailureCapsule] = (),
    quarantine: Sequence[QuarantineRecord] = (),
    bridge_executions: Sequence[Mapping[str, Any]] = (),
) -> SealedEvaluation:
    return EvaluationSealStore(CASStore(cas_root)).seal(
        identity=identity,
        report=report,
        input_manifest=input_manifest,
        attempts=attempts,
        failure_capsules=failure_capsules,
        quarantine=quarantine,
        bridge_executions=bridge_executions,
    )


__all__ = ["CASError", "CASStore", "EvaluationSealStore", "seal_evaluation"]
