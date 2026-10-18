"""Compilation and durable revision history for immutable TaskSpec records.

The compiler turns parsed assets and operator clarifications into a normalized
task contract. The repository enforces revision and digest consistency so
routing never depends on mutable request text after acceptance.
"""

from __future__ import annotations

import hashlib
import re
import threading
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid5

from pydantic_core import to_jsonable_python
from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Mapped, Session, mapped_column

from secmind.coordinator import RunJobRow
from secmind.ledger import canonical_json
from secmind.schemas import (
    ClarificationRequest,
    ClarificationResponse,
    ClarificationStatus,
    FieldProvenance,
    ParsedAsset,
    ParserRun,
    Scenario,
    TaskRequest,
    TaskSpec,
    TaskSpecRef,
)
from secmind.unit_of_work import CognitiveBase


class TaskSpecConflict(RuntimeError):
    pass


class TaskSpecRow(CognitiveBase):
    __tablename__ = "task_specs"

    task_spec_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    current_revision: Mapped[int] = mapped_column(Integer)
    content_digest: Mapped[str] = mapped_column(String(64))
    spec_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class TaskSpecRevisionRow(CognitiveBase):
    __tablename__ = "task_spec_revisions"
    __table_args__ = (UniqueConstraint("run_id", "revision"),)

    revision_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    task_spec_id: Mapped[str] = mapped_column(String(36), index=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    content_digest: Mapped[str] = mapped_column(String(64))
    parent_revision_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reason: Mapped[str] = mapped_column(String(200))
    spec_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ParserRunRow(CognitiveBase):
    __tablename__ = "parser_runs"

    parser_run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    artifact_id: Mapped[str] = mapped_column(String(36), index=True)
    parser_id: Mapped[str] = mapped_column(String(100))
    parser_version: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(30))
    input_digest: Mapped[str] = mapped_column(String(64))
    output_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    run_json: Mapped[str] = mapped_column(Text)
    parsed_asset_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ClarificationRequestRow(CognitiveBase):
    __tablename__ = "clarification_requests"

    request_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    task_spec_id: Mapped[str] = mapped_column(String(36))
    task_spec_revision: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(30), index=True)
    request_json: Mapped[str] = mapped_column(Text)
    response_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resolution_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    requested_fence: Mapped[int] = mapped_column(Integer, default=0)
    consumed_fence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class TaskSpecRepository:
    """Durable TaskSpec, parser-run and one-shot clarification repository."""

    def __init__(self, engine: Engine | None = None, *, initialize_schema: bool = True) -> None:
        self.engine = engine
        self._lock = threading.RLock()
        self._specs: dict[str, TaskSpec] = {}
        self._parser_runs: dict[str, tuple[ParserRun, ParsedAsset | None]] = {}
        self._clarifications: dict[str, tuple[ClarificationRequest, ClarificationResponse | None]] = {}
        if engine is not None and initialize_schema:
            CognitiveBase.metadata.create_all(engine)

    def save_parser_result(self, parser_run: ParserRun, parsed_asset: ParsedAsset | None) -> None:
        if parser_run.run_id == "":
            raise TaskSpecConflict("parser run must be bound to a run")
        if self.engine is None:
            memory_existing = self._parser_runs.get(parser_run.parser_run_id)
            value = (parser_run, parsed_asset)
            if memory_existing is not None and memory_existing != value:
                raise TaskSpecConflict("parser run identity was reused with different output")
            self._parser_runs[parser_run.parser_run_id] = value
            return
        with self._lock, Session(self.engine) as session:
            existing_row = session.get(ParserRunRow, parser_run.parser_run_id)
            run_json = canonical_json(parser_run.model_dump(mode="json"))
            asset_json = None if parsed_asset is None else canonical_json(parsed_asset.model_dump(mode="json"))
            if existing_row is not None:
                if existing_row.run_json != run_json or existing_row.parsed_asset_json != asset_json:
                    raise TaskSpecConflict("parser run identity was reused with different output")
                return
            session.add(
                ParserRunRow(
                    parser_run_id=parser_run.parser_run_id,
                    run_id=parser_run.run_id,
                    artifact_id=parser_run.artifact_id,
                    parser_id=parser_run.parser_id,
                    parser_version=parser_run.parser_version,
                    status=parser_run.status,
                    input_digest=parser_run.input_digest,
                    output_digest=parser_run.output_digest,
                    run_json=run_json,
                    parsed_asset_json=asset_json,
                    created_at=parser_run.created_at,
                )
            )
            session.commit()

    def parsed_assets(self, run_id: str) -> list[ParsedAsset]:
        if self.engine is None:
            return sorted(
                (asset for run, asset in self._parser_runs.values() if run.run_id == run_id and asset is not None),
                key=lambda item: (item.relative_path, item.parsed_asset_id),
            )
        with Session(self.engine) as session:
            rows = session.scalars(
                select(ParserRunRow)
                .where(ParserRunRow.run_id == run_id, ParserRunRow.parsed_asset_json.is_not(None))
                .order_by(ParserRunRow.created_at, ParserRunRow.parser_run_id)
            ).all()
            return [ParsedAsset.model_validate_json(row.parsed_asset_json) for row in rows if row.parsed_asset_json]

    def parser_runs(self, run_id: str) -> list[ParserRun]:
        if self.engine is None:
            return sorted(
                (run for run, _asset in self._parser_runs.values() if run.run_id == run_id),
                key=lambda item: (item.created_at, item.parser_run_id),
            )
        with Session(self.engine) as session:
            rows = session.scalars(
                select(ParserRunRow)
                .where(ParserRunRow.run_id == run_id)
                .order_by(ParserRunRow.created_at, ParserRunRow.parser_run_id)
            ).all()
            return [ParserRun.model_validate_json(row.run_json) for row in rows]

    def save_spec(self, spec: TaskSpec, *, reason: str) -> TaskSpecRef:
        _validate_task_spec_digest(spec)
        if self.engine is None:
            memory_current = self._specs.get(spec.run_id)
            _validate_revision(memory_current, spec)
            self._specs[spec.run_id] = spec
            return _reference(spec)
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, spec.run_id)
            current_row = session.scalar(select(TaskSpecRow).where(TaskSpecRow.run_id == spec.run_id))
            if current_row is not None:
                stored = TaskSpec.model_validate_json(current_row.spec_json)
                if stored.revision == spec.revision and stored.content_digest == spec.content_digest:
                    return _reference(stored)
                _validate_revision(stored, spec)
            revision_id = str(uuid5(NAMESPACE_URL, f"secmind:taskspec:{spec.run_id}:{spec.revision}"))
            revision = session.get(TaskSpecRevisionRow, revision_id)
            payload = spec.model_dump_json()
            if revision is not None and revision.content_digest != spec.content_digest:
                raise TaskSpecConflict("TaskSpec revision identity was reused")
            if revision is None:
                session.add(
                    TaskSpecRevisionRow(
                        revision_id=revision_id,
                        task_spec_id=spec.task_spec_id,
                        run_id=spec.run_id,
                        revision=spec.revision,
                        content_digest=spec.content_digest,
                        parent_revision_digest=spec.parent_revision_digest,
                        reason=reason[:200],
                        spec_json=payload,
                        created_at=spec.created_at,
                    )
                )
            if current_row is None:
                session.add(
                    TaskSpecRow(
                        task_spec_id=spec.task_spec_id,
                        run_id=spec.run_id,
                        current_revision=spec.revision,
                        content_digest=spec.content_digest,
                        spec_json=payload,
                        created_at=spec.created_at,
                        updated_at=now,
                    )
                )
            else:
                current_row.current_revision = spec.revision
                current_row.content_digest = spec.content_digest
                current_row.spec_json = payload
                current_row.updated_at = now
            session.commit()
            return _reference(spec)

    def load_spec(self, run_id: str) -> TaskSpec:
        if self.engine is None:
            try:
                return self._specs[run_id]
            except KeyError as exc:
                raise KeyError(run_id) from exc
        with Session(self.engine) as session:
            row = session.scalar(select(TaskSpecRow).where(TaskSpecRow.run_id == run_id))
            if row is None:
                raise KeyError(run_id)
            spec = TaskSpec.model_validate_json(row.spec_json)
            _validate_task_spec_digest(spec)
            return spec

    def create_clarification(self, request: ClarificationRequest, *, fence: int) -> None:
        if self.engine is None:
            memory_existing = self._clarifications.get(request.request_id)
            if memory_existing is not None and memory_existing[0] != request:
                raise TaskSpecConflict("clarification identity was reused")
            self._clarifications.setdefault(request.request_id, (request, None))
            return
        with self._lock, Session(self.engine) as session:
            existing_row = session.get(ClarificationRequestRow, request.request_id)
            payload = canonical_json(request.model_dump(mode="json"))
            if existing_row is not None:
                if existing_row.request_json != payload or existing_row.run_id != request.run_id:
                    raise TaskSpecConflict("clarification identity was reused")
                return
            session.add(
                ClarificationRequestRow(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    task_spec_id=request.task_spec_id,
                    task_spec_revision=request.task_spec_revision,
                    status=request.status.value,
                    request_json=payload,
                    requested_fence=fence,
                    created_at=request.created_at,
                )
            )
            session.commit()

    def resolve_clarification(
        self,
        request_id: str,
        response: ClarificationResponse,
        *,
        run_id: str,
    ) -> tuple[str, bool]:
        safe_response = response.model_copy(update={"resolution_id": None})
        response_json = canonical_json(safe_response.model_dump(mode="json"))
        response_digest = hashlib.sha256(response_json.encode()).hexdigest()
        resolution_id = response.resolution_id or str(
            uuid5(NAMESPACE_URL, f"secmind:clarification:{request_id}:{response_digest}")
        )
        if self.engine is None:
            try:
                request, existing = self._clarifications[request_id]
            except KeyError as exc:
                raise KeyError(request_id) from exc
            if request.run_id != run_id:
                raise TaskSpecConflict("clarification belongs to a different run")
            if existing is not None:
                if (
                    canonical_json(existing.model_copy(update={"resolution_id": None}).model_dump(mode="json"))
                    != response_json
                ):
                    raise TaskSpecConflict("clarification already has a conflicting resolution")
                return existing.resolution_id or resolution_id, False
            resolved = response.model_copy(update={"resolution_id": resolution_id})
            self._clarifications[request_id] = (
                request.model_copy(update={"status": ClarificationStatus.RESOLVED_UNCONSUMED}),
                resolved,
            )
            return resolution_id, True
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            row = session.get(ClarificationRequestRow, request_id)
            if row is None:
                raise KeyError(request_id)
            if row.run_id != run_id:
                raise TaskSpecConflict("clarification belongs to a different run")
            if row.status != ClarificationStatus.PENDING.value:
                if row.response_digest != response_digest:
                    raise TaskSpecConflict("clarification already has a conflicting resolution")
                return str(row.resolution_id), False
            resolved = response.model_copy(update={"resolution_id": resolution_id})
            row.status = ClarificationStatus.RESOLVED_UNCONSUMED.value
            row.response_json = canonical_json(resolved.model_dump(mode="json"))
            row.response_digest = response_digest
            row.resolution_id = resolution_id
            row.resolved_at = datetime.now(UTC)
            session.commit()
            return resolution_id, True

    def clarification_response(self, request_id: str, *, run_id: str) -> ClarificationResponse:
        if self.engine is None:
            request, response = self._clarifications[request_id]
            if request.run_id != run_id or response is None:
                raise KeyError(request_id)
            return response
        with Session(self.engine) as session:
            row = session.get(ClarificationRequestRow, request_id)
            if row is None or row.run_id != run_id or row.response_json is None:
                raise KeyError(request_id)
            return ClarificationResponse.model_validate_json(row.response_json)

    def consume_clarification(self, request_id: str, *, run_id: str, fence: int) -> ClarificationResponse:
        if self.engine is None:
            request, response = self._clarifications[request_id]
            if request.run_id != run_id or response is None:
                raise KeyError(request_id)
            self._clarifications[request_id] = (
                request.model_copy(update={"status": ClarificationStatus.CONSUMED}),
                response,
            )
            return response
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            row = session.get(ClarificationRequestRow, request_id)
            if row is None or row.run_id != run_id or row.response_json is None:
                raise KeyError(request_id)
            if row.status not in {
                ClarificationStatus.RESOLVED_UNCONSUMED.value,
                ClarificationStatus.CONSUMED.value,
            }:
                raise TaskSpecConflict("clarification has not been resolved")
            if row.status == ClarificationStatus.RESOLVED_UNCONSUMED.value:
                row.status = ClarificationStatus.CONSUMED.value
                row.consumed_fence = fence
                row.consumed_at = datetime.now(UTC)
                session.commit()
            return ClarificationResponse.model_validate_json(row.response_json)

    def consume_and_revise(
        self,
        request_id: str,
        *,
        run_id: str,
        owner_id: str,
        fence: int,
        compiler: TaskSpecCompiler,
    ) -> TaskSpec:
        """Fence, consume and persist exactly one TaskSpec revision in one transaction."""

        if self.engine is None:
            response = self.consume_clarification(request_id, run_id=run_id, fence=fence)
            current = self.load_spec(run_id)
            if request_id in current.clarification_request_ids:
                return current
            revised = compiler.revise(current, response, request_id=request_id)
            self.save_spec(revised, reason="operator_clarification")
            return revised

        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            lease_query = select(RunJobRow).where(RunJobRow.run_id == run_id)
            if self.engine.dialect.name == "postgresql":
                lease_query = lease_query.with_for_update()
            job = session.scalar(lease_query)
            lease_until = None if job is None else job.lease_until
            if lease_until is not None and lease_until.tzinfo is None:
                lease_until = lease_until.replace(tzinfo=UTC)
            if (
                job is None
                or job.status != "leased"
                or job.owner_id != owner_id
                or job.fence != fence
                or lease_until is None
                or lease_until <= now
            ):
                raise TaskSpecConflict("clarification revision requires the current run lease and fence")

            clarification = session.get(ClarificationRequestRow, request_id)
            if clarification is None or clarification.run_id != run_id or clarification.response_json is None:
                raise TaskSpecConflict("clarification is missing, cross-run, or unresolved")
            current_row = session.scalar(select(TaskSpecRow).where(TaskSpecRow.run_id == run_id))
            if current_row is None:
                raise TaskSpecConflict("clarification revision requires an existing TaskSpec")
            current = TaskSpec.model_validate_json(current_row.spec_json)

            if clarification.status == ClarificationStatus.CONSUMED.value:
                if request_id not in current.clarification_request_ids:
                    raise TaskSpecConflict("consumed clarification is not represented by the current TaskSpec")
                return current
            if clarification.status != ClarificationStatus.RESOLVED_UNCONSUMED.value:
                raise TaskSpecConflict("clarification has not reached the resolvable state")

            response = ClarificationResponse.model_validate_json(clarification.response_json)
            revised = compiler.revise(current, response, request_id=request_id)
            _validate_task_spec_digest(revised)
            _validate_revision(current, revised)
            revision_id = str(uuid5(NAMESPACE_URL, f"secmind:taskspec:{run_id}:{revised.revision}"))
            existing_revision = session.get(TaskSpecRevisionRow, revision_id)
            payload = revised.model_dump_json()
            if existing_revision is not None:
                if existing_revision.content_digest != revised.content_digest:
                    raise TaskSpecConflict("TaskSpec revision identity was reused")
            else:
                session.add(
                    TaskSpecRevisionRow(
                        revision_id=revision_id,
                        task_spec_id=revised.task_spec_id,
                        run_id=run_id,
                        revision=revised.revision,
                        content_digest=revised.content_digest,
                        parent_revision_digest=revised.parent_revision_digest,
                        reason="operator_clarification",
                        spec_json=payload,
                        created_at=revised.created_at,
                    )
                )
            current_row.current_revision = revised.revision
            current_row.content_digest = revised.content_digest
            current_row.spec_json = payload
            current_row.updated_at = now
            clarification.status = ClarificationStatus.CONSUMED.value
            clarification.consumed_fence = fence
            clarification.consumed_at = now
            session.commit()
            return revised

    def _database_lock(self, session: Session, key: str) -> None:
        if self.engine is not None and self.engine.dialect.name == "postgresql":
            session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": f"taskspec:{key}"})
        elif self.engine is not None and self.engine.dialect.name == "sqlite":
            session.execute(text("BEGIN IMMEDIATE"))


class TaskSpecCompiler:
    """Deterministic compiler; parser and repository content remain untrusted data."""

    version = "taskspec-1.6"
    policy_version = "task-policy-1.6"
    _SUPPORTED_SCORING_MODES = frozenset(
        {
            "security_finding",
            "agent_policy_compliance",
            "forensic_attribution",
            "evidence_gap",
            "exact_answer_with_evidence",
            "patch_validator",
            "reverse_behavior",
        }
    )

    # These values are supplied by the trusted adapter/operator envelope. They
    # outrank filename and objective heuristics, but they never expand scope or
    # grant tool permissions. Universal domains intentionally map to UNKNOWN:
    # the Canonical Primary can answer them without pretending they are code,
    # log, API or penetration-test jobs.  An explicit specialist capability is
    # the exception: it is routed through the existing governed pre-primary
    # lane so the deterministic specialist can run without changing the graph
    # router.  The capability remains in the sealed contract and the Primary
    # remains a supplemental semantic lane.
    _TRUSTED_DOMAIN_SCENARIOS: dict[str, Scenario] = {
        "code_audit_and_patch": Scenario.CODE_AUDIT,
        "logs_ir_hunting": Scenario.LOG_ANALYSIS,
        "digital_forensics": Scenario.LOG_ANALYSIS,
        "incident_response": Scenario.INCIDENT_RESPONSE,
        "api_web_security": Scenario.API_ASSESSMENT,
        "api_assessment": Scenario.API_ASSESSMENT,
        "forensics_static_reverse": Scenario.REVERSE_TRIAGE,
        "agent_safety": Scenario.UNKNOWN,
        "complex_input_understanding": Scenario.UNKNOWN,
        "orchestration_recovery_uncertainty": Scenario.UNKNOWN,
    }

    _SCENARIO_TERMS: dict[Scenario, tuple[str, ...]] = {
        Scenario.CODE_AUDIT: (
            "代码",
            "源码",
            "代码审计",
            "仓库漏洞",
            "修复补丁",
            "source code",
            "code",
            "repository",
            "code audit",
            "sast",
            "bandit",
        ),
        Scenario.LOG_ANALYSIS: (
            "日志",
            "数字取证",
            "流量取证",
            "攻击链",
            "时间线",
            "log",
            "forensic",
            "pcap",
            "evtx",
            "splunk",
            "timeline",
            "ioc",
        ),
        Scenario.INCIDENT_RESPONSE: (
            "应急响应",
            "遏制",
            "处置建议",
            "incident response",
            "containment",
        ),
        Scenario.API_ASSESSMENT: (
            "接口文档",
            "api 安全",
            "访问控制",
            "令牌处理",
            "openapi",
            "swagger",
            "postman",
        ),
        Scenario.REVERSE_TRIAGE: (
            "逆向",
            "恶意样本",
            "移动样本",
            "固件",
            "binary",
            "reverse",
            "malware",
            "firmware",
            "apk",
            "yara",
        ),
        Scenario.PENETRATION_TEST: (
            "动态渗透",
            "动态利用",
            "受控服务",
            "获取 flag",
            "exploit",
            "penetration",
            "pwn",
        ),
    }
    _PROHIBITED_DEFAULTS = (
        "no destructive host changes",
        "no credential theft",
        "no persistence",
        "no unapproved network access",
    )
    _CODE_AUDIT_ACTION_TERMS = (
        "audit",
        "security review",
        "vulnerability review",
        "vulnerability report",
        "vulnerability scan",
        "find vulnerabilities",
        "审计",
        "漏洞",
        "安全检查",
    )
    _SOURCE_OBJECT_TERMS = (
        "source",
        "code",
        "repository",
        "repo",
        "php",
        "python",
        "java",
        "javascript",
        "typescript",
        "源码",
        "代码",
        "仓库",
    )

    def compile(
        self, run_id: str, task: TaskRequest, assets: list[ParsedAsset], parser_runs: list[ParserRun]
    ) -> TaskSpec:
        objective = task.objective.strip()
        if task.scoring_mode and task.scoring_mode.strip().casefold() not in self._SUPPORTED_SCORING_MODES:
            raise TaskSpecConflict(f"unsupported scoring_mode: {task.scoring_mode}")
        inferred_scenarios = self._scenario_candidates(objective, assets)
        trusted_domain = task.primary_domain.casefold() if task.primary_domain else None
        trusted_scenario = self._TRUSTED_DOMAIN_SCENARIOS.get(trusted_domain or "")
        has_trusted_domain = trusted_domain is not None
        firmware_static_requested = any(
            str(capability).strip().casefold() == "firmware_static_audit" for capability in task.secondary_capabilities
        )
        if has_trusted_domain:
            primary = trusted_scenario or Scenario.UNKNOWN
            scenarios = [primary, *[item for item in inferred_scenarios if item != primary]]
        else:
            scenarios = inferred_scenarios
            primary = scenarios[0] if scenarios else Scenario.UNKNOWN
        if firmware_static_requested:
            # ``orchestrator.py`` intentionally keeps a closed set of graph
            # scenario edges.  LOG_ANALYSIS is the existing offline,
            # manifest/CAS-bound pre-primary edge; ScenarioExecutor dispatches
            # this explicit capability to the firmware specialist before any
            # model Primary call.  No firmware task is inferred from filenames
            # or objective text alone.
            primary = Scenario.LOG_ANALYSIS
            scenarios = [primary, *[item for item in scenarios if item != primary]]
        ambiguities: list[str] = []
        if not has_trusted_domain and len(scenarios) > 1:
            ambiguities.append("MULTIPLE_SCENARIOS")
        if not has_trusted_domain and primary == Scenario.UNKNOWN:
            ambiguities.append("SCENARIO_UNCLEAR")
        lowered = objective.casefold()
        if not task.target_scope and any(term in lowered for term in ("生产", "公网", "production", "internet")):
            ambiguities.append("AUTHORIZATION_SCOPE_REQUIRED")
        authorized_scope = sorted(dict.fromkeys(task.target_scope))
        if not authorized_scope and task.attachments:
            # The uploaded immutable assets are authorized for offline analysis only;
            # this never authorizes a host, URL or network target inferred by a parser.
            authorized_scope = sorted({f"artifact:{item.ref}" for item in task.attachments})
        provenance = self._provenance(task, assets)
        confidence = 1.0 if has_trusted_domain else (0.98 if len(scenarios) == 1 else (0.45 if scenarios else 0.25))
        task_spec_id = str(uuid5(NAMESPACE_URL, f"secmind:taskspec:{run_id}"))
        values: dict[str, Any] = {
            "schema_version": "1.5",
            "task_spec_id": task_spec_id,
            "run_id": run_id,
            "client_request_id": task.client_request_id,
            "revision": 1,
            "parent_revision_digest": None,
            "objectives": [objective],
            "primary_scenario": primary,
            "primary_domain": task.primary_domain,
            "secondary_capabilities": sorted(dict.fromkeys(task.secondary_capabilities)),
            "scoring_mode": task.scoring_mode,
            "output_contract": dict(task.output_contract),
            "evaluation_metadata": dict(task.evaluation_metadata),
            "evaluation_contract_digest": task.evaluation_contract_digest,
            "interaction_mode": task.interaction_mode,
            "autonomy_policy": task.autonomy_policy,
            "secondary_scenarios": scenarios[1:],
            "asset_ids": sorted(item.parsed_asset_id for item in assets),
            "authorized_scope": authorized_scope,
            "temporal_scope": next(
                (hint.temporal_scope for item in assets for hint in item.hints if hint.temporal_scope), None
            ),
            "constraints": sorted(dict.fromkeys(task.constraints)),
            "prohibited_actions": list(self._PROHIBITED_DEFAULTS),
            "expected_outputs": list(dict.fromkeys(task.expected_outputs)),
            "success_criteria": self._success_criteria(primary, task.expected_outputs),
            "ambiguities": sorted(set(ambiguities)),
            "clarification_request_ids": [],
            "parser_run_ids": sorted(item.parser_run_id for item in parser_runs),
            "confidence": confidence,
            "field_provenance": provenance,
            "compiler_version": self.version,
            "policy_version": self.policy_version,
        }
        values["content_digest"] = _content_digest(values)
        return TaskSpec.model_validate(values)

    def revise(self, current: TaskSpec, response: ClarificationResponse, *, request_id: str) -> TaskSpec:
        values = current.model_dump(mode="json", exclude={"content_digest", "created_at"})
        values["revision"] = current.revision + 1
        values["parent_revision_digest"] = current.content_digest
        values["clarification_request_ids"] = [*current.clarification_request_ids, request_id]
        if response.confirmed_scope is not None:
            values["authorized_scope"] = sorted(dict.fromkeys(response.confirmed_scope))
            values["field_provenance"]["authorized_scope"] = [
                self._provenance_item("clarification", request_id, canonical_json(response.confirmed_scope), 1.0)
            ]
        if response.confirmed_scenario is not None:
            values["primary_scenario"] = response.confirmed_scenario.value
            values["secondary_scenarios"] = []
            values["field_provenance"]["primary_scenario"] = [
                self._provenance_item("clarification", request_id, response.confirmed_scenario.value, 1.0)
            ]
        constraints = [*current.constraints, *response.additional_constraints]
        values["constraints"] = sorted(dict.fromkeys(constraints))
        objective = response.answers.get("objective", "").strip()
        if objective:
            values["objectives"] = [objective]
            values["field_provenance"]["objectives"] = [
                self._provenance_item("clarification", request_id, objective, 1.0)
            ]
        temporal_scope = response.answers.get("temporal_scope", "").strip()
        if temporal_scope:
            values["temporal_scope"] = temporal_scope
        values["ambiguities"] = self._remaining_ambiguities(values)
        values["confidence"] = 1.0 if not values["ambiguities"] else max(current.confidence, 0.7)
        values["content_digest"] = _content_digest(values)
        values["created_at"] = datetime.now(UTC)
        return TaskSpec.model_validate(values)

    def clarification_request(self, spec: TaskSpec) -> ClarificationRequest | None:
        questions: list[str] = []
        if "SCENARIO_UNCLEAR" in spec.ambiguities or "MULTIPLE_SCENARIOS" in spec.ambiguities:
            questions.append("请确认本任务的主要场景。")
        if "AUTHORIZATION_SCOPE_REQUIRED" in spec.ambiguities:
            questions.append("请提供明确的授权目标范围；系统不会从附件或接口文档自动扩大授权。")
        if not questions:
            return None
        identity = canonical_json({"digest": spec.content_digest, "questions": questions})
        request_id = str(uuid5(NAMESPACE_URL, f"secmind:clarification:{spec.run_id}:{identity}"))
        return ClarificationRequest(
            request_id=request_id,
            run_id=spec.run_id,
            task_spec_id=spec.task_spec_id,
            task_spec_revision=spec.revision,
            questions=questions,
            ambiguity_codes=list(spec.ambiguities),
        )

    def _scenario_candidates(self, objective: str, assets: list[ParsedAsset]) -> list[Scenario]:
        text = objective.casefold()
        scored: dict[Scenario, int] = {}
        for scenario, terms in self._SCENARIO_TERMS.items():
            score = sum(2 for term in terms if term in text)
            if score:
                scored[scenario] = score
        # Natural audit requests often place a language name between the
        # action and the object (for example, "audit the PHP source").  Plain
        # substring phrases such as "code audit" miss that common form.  A
        # bounded action+source conjunction recovers the intent without
        # treating every attached source file as authorization for an audit.
        if any(_contains_bounded_term(text, term) for term in self._CODE_AUDIT_ACTION_TERMS) and any(
            _contains_bounded_term(text, term) for term in self._SOURCE_OBJECT_TERMS
        ):
            scored[Scenario.CODE_AUDIT] = scored.get(Scenario.CODE_AUDIT, 0) + 4
        for asset in assets:
            if asset.asset_type in {"openapi", "postman"}:
                scored[Scenario.API_ASSESSMENT] = scored.get(Scenario.API_ASSESSMENT, 0) + 1
            if asset.asset_type in {"security_log", "ndjson"}:
                scored[Scenario.LOG_ANALYSIS] = scored.get(Scenario.LOG_ANALYSIS, 0) + 1
            for hint in asset.hints:
                for scenario in hint.scenario_candidates:
                    scored[scenario] = scored.get(scenario, 0) + max(1, int(hint.confidence * 2))
        return [item[0] for item in sorted(scored.items(), key=lambda item: (-item[1], item[0].value))]

    def _provenance(self, task: TaskRequest, assets: list[ParsedAsset]) -> dict[str, list[FieldProvenance]]:
        result = {
            "objectives": [self._provenance_item("operator", "TaskRequest.objective", task.objective, 1.0)],
            "authorized_scope": [
                self._provenance_item("operator", "TaskRequest.target_scope", canonical_json(task.target_scope), 1.0)
            ],
            "constraints": [
                self._provenance_item("operator", "TaskRequest.constraints", canonical_json(task.constraints), 1.0)
            ],
        }
        parser_items: list[FieldProvenance] = []
        for asset in assets:
            parser_items.append(
                self._provenance_item(
                    "parser",
                    f"{asset.parser_id}:{asset.relative_path}",
                    asset.content_digest,
                    max((hint.confidence for hint in asset.hints), default=0.5),
                )
            )
        if parser_items:
            result["primary_scenario"] = parser_items
        if task.primary_domain:
            result["primary_domain"] = [
                self._provenance_item("operator", "TaskRequest.primary_domain", task.primary_domain, 1.0)
            ]
        if task.secondary_capabilities:
            result["secondary_capabilities"] = [
                self._provenance_item(
                    "operator",
                    "TaskRequest.secondary_capabilities",
                    canonical_json(sorted(dict.fromkeys(task.secondary_capabilities))),
                    1.0,
                )
            ]
        return result

    @staticmethod
    def _provenance_item(
        source_type: Literal["operator", "attachment", "parser", "default", "clarification"],
        source_ref: str,
        content: str,
        confidence: float,
    ) -> FieldProvenance:
        return FieldProvenance(
            source_type=source_type,
            source_ref=source_ref,
            confidence=confidence,
            content_digest=hashlib.sha256(content.encode()).hexdigest(),
        )

    @staticmethod
    def _success_criteria(scenario: Scenario, expected_outputs: list[str]) -> list[str]:
        common = ["Every final conclusion is linked to verifier-approved immutable evidence"]
        if scenario == Scenario.CODE_AUDIT:
            return [*common, "The report identifies scanned scope, tool versions, and coverage gaps"]
        if scenario == Scenario.LOG_ANALYSIS:
            return [*common, "The report preserves source offsets and timeline coverage gaps"]
        if scenario == Scenario.API_ASSESSMENT:
            return [
                *common,
                "The report preserves endpoint, authentication, resource, and source-locator relationships",
            ]
        if scenario == Scenario.INCIDENT_RESPONSE:
            return [
                *common,
                "The dry-run plan preserves hypotheses, evidence requirements, and rollback conditions",
            ]
        return [*common, *[f"Produce {item}" for item in expected_outputs]]

    @staticmethod
    def _remaining_ambiguities(values: dict[str, Any]) -> list[str]:
        ambiguities = set(values.get("ambiguities", []))
        if values.get("primary_scenario") not in {Scenario.UNKNOWN, Scenario.UNKNOWN.value}:
            ambiguities.discard("SCENARIO_UNCLEAR")
            ambiguities.discard("MULTIPLE_SCENARIOS")
        if values.get("authorized_scope"):
            ambiguities.discard("AUTHORIZATION_SCOPE_REQUIRED")
        return sorted(ambiguities)


def _content_digest(values: dict[str, Any]) -> str:
    body = dict(values)
    body.pop("content_digest", None)
    body.pop("created_at", None)
    # Compilation sees Pydantic models and enums while persistence reloads
    # JSON-native values.  Normalize both forms before hashing so a TaskSpec
    # has the same identity on either side of the storage boundary.
    normalized = to_jsonable_python(body)
    return hashlib.sha256(canonical_json(normalized).encode()).hexdigest()


def _contains_bounded_term(text: str, term: str) -> bool:
    """Match Latin routing terms as tokens and CJK terms as phrases."""

    if not term.isascii():
        return term in text
    return re.search(rf"(?<![a-z0-9_]){re.escape(term)}(?![a-z0-9_])", text) is not None


def _validate_task_spec_digest(spec: TaskSpec) -> None:
    values = spec.model_dump(mode="json", exclude={"content_digest", "created_at"})
    if _content_digest(values) != spec.content_digest:
        raise TaskSpecConflict("TaskSpec content digest does not match its canonical content")
    for scope in spec.authorized_scope:
        if "\x00" in scope or any(ord(char) < 32 for char in scope):
            raise TaskSpecConflict("authorized scope contains a control character")
        if ".." in PurePosixPath(scope.replace("\\", "/")).parts:
            raise TaskSpecConflict("authorized scope contains path traversal")


def _validate_revision(current: TaskSpec | None, candidate: TaskSpec) -> None:
    if current is None:
        if candidate.revision != 1 or candidate.parent_revision_digest is not None:
            raise TaskSpecConflict("first TaskSpec revision must be revision 1")
        return
    if current.task_spec_id != candidate.task_spec_id or current.run_id != candidate.run_id:
        raise TaskSpecConflict("TaskSpec identity cannot change across revisions")
    if candidate.revision != current.revision + 1:
        raise TaskSpecConflict("TaskSpec revisions must be contiguous")
    if candidate.parent_revision_digest != current.content_digest:
        raise TaskSpecConflict("TaskSpec parent digest does not match current revision")


def _reference(spec: TaskSpec) -> TaskSpecRef:
    return TaskSpecRef(
        task_spec_id=spec.task_spec_id,
        revision=spec.revision,
        content_digest=spec.content_digest,
    )
