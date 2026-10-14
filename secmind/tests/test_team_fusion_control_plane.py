from __future__ import annotations

import hashlib
import io
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from conftest import seal_execution_contract
from sqlalchemy import create_engine, inspect, text

from secmind.artifact_store import ArtifactStoreError, ContentAddressedArtifactStore
from secmind.orchestration.scenario_execution import (
    ScenarioEvidenceCache,
    ScenarioExecutor,
    verify_scenario_evidence,
)
from secmind.schemas import AgentState, Evidence, InputArtifact, TaskRequest
from secmind.task_specs import TaskSpecRepository
from secmind.unit_of_work import EvidenceLinkRow


def test_evidence_link_migration_and_orm_accept_long_identifiers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SECMIND_DATABASE_URL", raising=False)
    database = tmp_path / "fusion-migration.db"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database.as_posix()}")
    command.upgrade(config, "0014_v08_cache_telemetry")
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO evidence_links "
                "(link_id, run_id, claim_id, evidence_id, relation, weight, verifier_status, created_at) "
                "VALUES (:link, :run, :claim, :evidence, :relation, :weight, :status, :created)"
            ),
            {
                "link": "link-before-upgrade",
                "run": "run",
                "claim": "claim",
                "evidence": "e" * 36,
                "relation": "supports",
                "weight": 1.0,
                "status": "verified",
                "created": datetime.now(UTC),
            },
        )
    engine.dispose()

    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    evidence_column = next(
        column for column in inspect(engine).get_columns("evidence_links") if column["name"] == "evidence_id"
    )
    assert evidence_column["type"].length == 100
    assert EvidenceLinkRow.__table__.c.evidence_id.type.length == 100
    long_id = "evidence:sha256:" + ("a" * 64)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO evidence_links "
                "(link_id, run_id, claim_id, evidence_id, relation, weight, verifier_status, created_at) "
                "VALUES (:link, :run, :claim, :evidence, :relation, :weight, :status, :created)"
            ),
            {
                "link": "link-after-upgrade",
                "run": "run",
                "claim": "claim",
                "evidence": long_id,
                "relation": "supports",
                "weight": 1.0,
                "status": "verified",
                "created": datetime.now(UTC),
            },
        )
        stored = connection.execute(
            text("SELECT evidence_id FROM evidence_links WHERE link_id = 'link-after-upgrade'")
        ).scalar_one()
    engine.dispose()
    assert stored == long_id


class _CountingArtifactStore:
    def __init__(
        self,
        *,
        content: bytes | None = None,
        error: Exception | None = None,
        run_ids: tuple[str, ...] = ("run-a",),
        globally_bound: bool = False,
    ) -> None:
        self.content = content
        self.error = error
        self.run_ids = run_ids
        self.globally_bound = globally_bound
        self.reads = 0

    def metadata_for(self, _artifact_ref: str) -> SimpleNamespace:
        return SimpleNamespace(run_ids=self.run_ids, globally_bound=self.globally_bound)

    def read(self, _artifact_ref: str) -> bytes:
        self.reads += 1
        if self.error is not None:
            raise self.error
        assert self.content is not None
        return self.content


def test_scenario_evidence_cache_reads_once_and_preserves_typed_failures() -> None:
    content = b"immutable evidence"
    digest = hashlib.sha256(content).hexdigest()
    store = _CountingArtifactStore(content=content)
    failures: dict[str, tuple[str, ...]] = {}
    cache = ScenarioEvidenceCache(run_id="run-a", max_entries=2)
    evidence = [
        Evidence(evidence_id="valid", source="test", summary="valid", artifact_ref="ref", sha256=digest),
        Evidence(evidence_id="wrong", source="test", summary="wrong", artifact_ref="ref", sha256="0" * 64),
    ]

    verified = verify_scenario_evidence(  # type: ignore[arg-type]
        store,
        evidence,
        run_id="run-a",
        cache=cache,
        failure_reasons=failures,
    )

    assert verified == {"valid"}
    assert failures == {"wrong": ("CAS_DIGEST_MISMATCH",)}
    assert store.reads == 1
    assert len(cache) == 1

    denied = _CountingArtifactStore(error=PermissionError("denied"))
    denied_failures: dict[str, tuple[str, ...]] = {}
    assert not verify_scenario_evidence(  # type: ignore[arg-type]
        denied,
        [Evidence(evidence_id="denied", source="test", summary="denied", artifact_ref="ref", sha256=digest)],
        run_id="run-a",
        failure_reasons=denied_failures,
    )
    assert denied_failures == {"denied": ("CAS_PERMISSION_DENIED",)}

    missing = _CountingArtifactStore(error=FileNotFoundError("missing"))
    missing_failures: dict[str, tuple[str, ...]] = {}
    assert not verify_scenario_evidence(  # type: ignore[arg-type]
        missing,
        [Evidence(evidence_id="missing", source="test", summary="missing", artifact_ref="ref", sha256=digest)],
        run_id="run-a",
        failure_reasons=missing_failures,
    )
    assert missing_failures == {"missing": ("CAS_OBJECT_UNAVAILABLE",)}

    corrupt = _CountingArtifactStore(error=ArtifactStoreError("stored artifact digest verification failed"))
    corrupt_failures: dict[str, tuple[str, ...]] = {}
    assert not verify_scenario_evidence(  # type: ignore[arg-type]
        corrupt,
        [Evidence(evidence_id="corrupt", source="test", summary="corrupt", artifact_ref="ref", sha256=digest)],
        run_id="run-a",
        failure_reasons=corrupt_failures,
    )
    assert corrupt_failures == {"corrupt": ("CAS_DIGEST_MISMATCH",)}

    scope_failures: dict[str, tuple[str, ...]] = {}
    other_run = _CountingArtifactStore(content=content, run_ids=("run-b",))
    assert not verify_scenario_evidence(  # type: ignore[arg-type]
        other_run,
        [Evidence(evidence_id="foreign", source="test", summary="foreign", artifact_ref="ref", sha256=digest)],
        run_id="run-a",
        failure_reasons=scope_failures,
    )
    assert scope_failures == {"foreign": ("CAS_SCOPE_MISMATCH",)}
    assert other_run.reads == 0


def test_scenario_executor_reads_run_bound_cas_instead_of_mutable_workspace(tmp_path: Path) -> None:
    content = b'{"timestamp":"2026-08-07T00:00:00Z","message":"login accepted"}\n'
    digest = hashlib.sha256(content).hexdigest()
    store = ContentAddressedArtifactStore(tmp_path / "cas")
    store.put(content, expected_sha256=digest, run_id="run-a", media_type="application/x-ndjson")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "events.jsonl").write_bytes(b"mutated after ingest")
    artifact = InputArtifact(
        artifact_id="input-a",
        original_name="events.jsonl",
        relative_path="events.jsonl",
        sha256=digest,
        size_bytes=len(content),
        media_type="application/x-ndjson",
    )
    state = AgentState(
        run_id="run-a",
        task=TaskRequest(objective="analyze immutable logs"),
        workspace=str(workspace),
        input_artifacts=[artifact],
    )
    executor = ScenarioExecutor(store, TaskSpecRepository(), binary_log_parsers_enabled=False)

    result = executor._analyze_log_input(state, artifact)

    assert result.events
    assert result.evidence[0].artifact_ref == digest
    denied_state = state.model_copy(update={"run_id": "run-b"})
    with pytest.raises(PermissionError, match="not bound"):
        executor._analyze_log_input(denied_state, artifact)


def test_log_scenario_does_not_trust_platform_derived_path_names(tmp_path: Path) -> None:
    original = b'{"timestamp":"2026-08-07T00:00:00Z","message":"login accepted"}\n'
    derived = b"\n".join(b"[]" for _ in range(1_000))
    store = ContentAddressedArtifactStore(tmp_path / "cas")
    artifacts: list[InputArtifact] = []
    for path, content in (
        ("events.jsonl", original),
        (".secmind-derived/packets/events.json", derived),
    ):
        digest = hashlib.sha256(content).hexdigest()
        store.put(content, expected_sha256=digest, run_id="run-derived", media_type="application/json")
        artifacts.append(
            InputArtifact(
                artifact_id=digest,
                original_name=Path(path).name,
                relative_path=path,
                sha256=digest,
                size_bytes=len(content),
                media_type="application/json",
            )
        )
    state = seal_execution_contract(
        AgentState(
            run_id="run-derived",
            task=TaskRequest(objective="analyze immutable logs"),
            input_artifacts=artifacts,
        )
    )

    ScenarioExecutor(store, TaskSpecRepository(), binary_log_parsers_enabled=True).execute_log_analysis(state)

    assert "scenario_derived_views_skipped" not in state.audit_coverage
    assert len(state.observations) == 2
    assert {item.data["source"] for item in state.observations} == {
        ".secmind-derived/packets/events.json",
        "events.jsonl",
    }


def test_zip_member_evidence_is_persisted_and_verified_in_run_bound_cas(tmp_path: Path) -> None:
    member_content = b'{"message":"login failed"}\n'
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("logs/events.jsonl", member_content)
    content = buffer.getvalue()
    digest = hashlib.sha256(content).hexdigest()
    member_digest = hashlib.sha256(member_content).hexdigest()
    store = ContentAddressedArtifactStore(tmp_path / "cas")
    store.put(content, expected_sha256=digest, run_id="run-zip", media_type="application/zip")
    artifact = InputArtifact(
        artifact_id="input-zip",
        original_name="bundle.zip",
        relative_path="bundle.zip",
        sha256=digest,
        size_bytes=len(content),
        media_type="application/zip",
    )
    state = AgentState(
        run_id="run-zip",
        task=TaskRequest(objective="analyze immutable archive logs"),
        input_artifacts=[artifact],
    )
    executor = ScenarioExecutor(store, TaskSpecRepository(), binary_log_parsers_enabled=True)

    result = executor._analyze_log_input(state, artifact)
    member_evidence = [item for item in result.evidence if item.artifact_ref == member_digest]

    assert member_evidence
    assert store.read(member_digest) == member_content
    assert verify_scenario_evidence(store, result.evidence, run_id="run-zip") == {
        item.evidence_id for item in result.evidence
    }
