from __future__ import annotations

import hashlib
import json
import logging
import os
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from pathlib import Path
from typing import Any

import httpx
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import InMemorySaver

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.capability import CapabilityTicketIssuer
from secmind.capsule import FailureCapsuleStore
from secmind.config import Settings
from secmind.coordinator import CoordinatorStore
from secmind.execution import ExecutionStore
from secmind.guardrail import Guardrail
from secmind.investigation.store import InvestigationStore
from secmind.knowledge import OfflineKnowledgeStore
from secmind.ledger import LedgerStore
from secmind.llm import QwenGateway, close_gateway_safely
from secmind.log_parsers import binary_parser_dependency_status
from secmind.migration_guard import verify_database_at_head
from secmind.model_snapshots import ModelSnapshotStore, sanitize_snapshot
from secmind.orchestrator import SecMindOrchestrator
from secmind.runtime_profile import resolve_runtime_profile
from secmind.sandbox import SandboxToolSpec, default_allowlist, invocation_input_sha256
from secmind.sandbox_client import SandboxBanditTool
from secmind.service import EventHub, RunService
from secmind.tool_assurance import require_tool_assurance_readiness
from secmind.tools import (
    SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST,
    BaseTool,
    DevelopmentSemgrepTool,
    SandboxJsonTool,
    ToolBroker,
    default_registry,
    external_audit_manifests,
)
from secmind.unit_of_work import ControlPlaneUnitOfWork

logger = logging.getLogger(__name__)


def reviewed_semgrep_rules_path() -> Path:
    """Resolve the reviewed rule bundle from an installed wheel or source tree."""

    candidates = (
        Path(__file__).resolve().parent / "resources" / "semgrep" / "reviewed",
        Path(__file__).resolve().parent.parent / "secmind_distribution" / "resources" / "semgrep" / "reviewed",
        Path.cwd() / "docker" / "tools" / "semgrep" / "rules" / "reviewed",
        Path(__file__).resolve().parents[2] / "docker" / "tools" / "semgrep" / "rules" / "reviewed",
    )
    for candidate in candidates:
        if candidate.is_dir():
            return candidate.resolve()
    raise RuntimeError("reviewed Semgrep rule bundle is unavailable")


def build_runtime(
    settings: Settings,
    checkpointer: BaseCheckpointSaver[Any] | None = None,
) -> tuple[RunService, QwenGateway]:
    """Build the application services around an already-open checkpointer."""
    settings.prepare_directories()
    strict = settings.env.lower() in {"production", "competition"}
    execution_role = settings.runtime_role in {"worker", "embedded"}
    initialize_schema = not strict
    if strict and not settings.sandbox_runner_url:
        raise RuntimeError("production requires SECMIND_SANDBOX_RUNNER_URL")
    if strict and settings.unsafe_development_tools:
        raise RuntimeError("unsafe development tools cannot be enabled in production")
    if settings.enable_api_dynamic_probes:
        raise RuntimeError("dynamic API probes are not implemented; static assessment remains fail-closed")
    if settings.binary_log_parsers_enabled:
        dependencies = binary_parser_dependency_status()
        if not all(dependencies.values()):
            missing = ", ".join(sorted(name for name, available in dependencies.items() if not available))
            raise RuntimeError(f"binary log parsers are enabled but optional dependencies are missing: {missing}")
    if strict and execution_role and settings.sandbox_ticket_private_key_file is None:
        raise RuntimeError("production requires an Ed25519 sandbox ticket private key")
    if strict and not settings.sandbox_control_token:
        raise RuntimeError("production requires a dedicated sandbox control token")
    if strict and execution_role:
        # Scanner output in a competition/production worker is itself a
        # signed trust-boundary claim.  Require both sides of the Ed25519 root
        # and the held-out calibration identity before any tool can execute.
        require_tool_assurance_readiness()
    if not settings.sandbox_runner_url and not settings.unsafe_development_tools:
        raise RuntimeError(
            "tool execution requires the sandbox runner; local subprocess tools require "
            "SECMIND_UNSAFE_DEVELOPMENT_TOOLS=true"
        )
    if strict:
        verify_database_at_head(settings.database_url, settings.alembic_config_path)

    coordinator = CoordinatorStore(settings.database_url, initialize_schema=initialize_schema)
    # One process owns one SQLAlchemy Engine/pool.  Stores keep their bounded
    # repository APIs but share the same long-lived database runtime.
    ledger = LedgerStore(engine=coordinator.engine, initialize_schema=initialize_schema)
    unit_of_work = ControlPlaneUnitOfWork(coordinator.engine, initialize_schema=initialize_schema)
    investigation_store = InvestigationStore(engine=coordinator.engine, initialize_schema=initialize_schema)
    hub = EventHub()
    gateway = QwenGateway(
        settings,
        usage_store=investigation_store,
        attempt_sink=coordinator.record_model_attempts,
        snapshot_store=ModelSnapshotStore(
            coordinator.engine, sanitize=sanitize_snapshot, initialize_schema=initialize_schema,
        ),
    )
    offline_knowledge = OfflineKnowledgeStore(engine=coordinator.engine, initialize_schema=initialize_schema)
    knowledge_store: OfflineKnowledgeStore = offline_knowledge
    if settings.hybrid_knowledge_enabled:
        _bootstrap_reviewed_knowledge(offline_knowledge)
        from secmind.hybrid_knowledge import (
            GovernedQdrantSearch,
            HybridKnowledgeStore,
            PrecomputedQueryVectors,
        )

        if settings.knowledge_query_vectors_path is None or not settings.knowledge_vector_corpus_digest:
            if not settings.hybrid_knowledge_offline_fallback_enabled:
                raise RuntimeError(
                    "hybrid knowledge requires a precomputed query-vector catalog and governed corpus digest"
                )
        else:
            vectors = PrecomputedQueryVectors(
                settings.knowledge_query_vectors_path,
                vector_size=settings.qdrant_vector_size,
                corpus_digest=settings.knowledge_vector_corpus_digest,
            )
            semantic = GovernedQdrantSearch(
                url=settings.qdrant_url,
                collection_name=settings.qdrant_collection,
                vectors=vectors,
                corpus_digest=settings.knowledge_vector_corpus_digest,
                request_timeout_seconds=settings.hybrid_knowledge_timeout_seconds,
            )
            knowledge_store = HybridKnowledgeStore(
                offline_knowledge,
                semantic,
                timeout_seconds=settings.hybrid_knowledge_timeout_seconds,
            )
    artifact_store = ContentAddressedArtifactStore(settings.artifact_root)
    capsule_store = FailureCapsuleStore(settings.artifact_root / "failure-capsules")
    bandit_tool = None
    external_tools: list[BaseTool] = []
    sandbox_http_client: httpx.AsyncClient | None = None
    if settings.sandbox_runner_url:
        sandbox_http_client = httpx.AsyncClient(
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
        )
        ticket_provider: Callable[[Any], str] | None = None
        allowlist = _runtime_allowlist(settings)
        if settings.sandbox_ticket_private_key_file is not None:
            issuer = CapabilityTicketIssuer.from_pem(settings.sandbox_ticket_private_key_file.read_bytes())

            def issue_ticket(invocation: Any) -> str:
                spec = allowlist[invocation.tool_name]
                return issuer.issue(
                    invocation_id=invocation.invocation_id,
                    tool_name=invocation.tool_name,
                    input_sha256=invocation_input_sha256(invocation),
                    fence=invocation.lease_fence,
                    policy=spec.capability_policy(),
                )

            ticket_provider = issue_ticket
        elif strict and settings.runtime_role == "api":

            def reject_ticket_issue(_invocation: Any) -> str:
                raise RuntimeError("API runtime is not authorized to issue sandbox capability tickets")

            ticket_provider = reject_ticket_issue
        service_token = None if strict else settings.sandbox_token or None
        bandit_tool = SandboxBanditTool(
            settings.sandbox_runner_url,
            service_token,
            sandbox_http_client,
            capability_ticket_provider=ticket_provider,
        )
        for manifest in external_audit_manifests(allowlist):
            if manifest.name not in allowlist:
                continue
            external_tools.append(
                SandboxJsonTool(
                    manifest,
                    settings.sandbox_runner_url,
                    service_token,
                    sandbox_http_client,
                    capability_ticket_provider=ticket_provider,
                    artifact_store=artifact_store,
                )
            )
    elif settings.semgrep_candidate_rules_enabled and settings.unsafe_development_tools:
        configured_digest = os.getenv("SECMIND_SEMGREP_SAST_RULE_BUNDLE_DIGEST", "")
        if configured_digest != SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST:
            raise RuntimeError("Semgrep candidate rules require the approved immutable rule bundle digest")
        rules = reviewed_semgrep_rules_path()
        external_tools.append(DevelopmentSemgrepTool(rules))
    broker = ToolBroker(
        default_registry(bandit_tool, external_tools),
        Guardrail(),
        execution_store=ExecutionStore(engine=coordinator.engine, initialize_schema=initialize_schema),
        ledger=ledger,
        coordinator=coordinator,
        unit_of_work=unit_of_work,
        artifact_store=artifact_store,
        investigation_store=investigation_store,
        owned_async_clients=[sandbox_http_client] if sandbox_http_client is not None else None,
    )
    orchestrator = SecMindOrchestrator(
        settings,
        ledger,
        gateway,
        broker,
        hub.publish,
        checkpointer=checkpointer,
        coordinator=coordinator,
        knowledge_store=knowledge_store,
        artifact_store=artifact_store,
        investigation_store=investigation_store,
        capsule_store=capsule_store,
    )
    return RunService(
        orchestrator,
        ledger,
        hub,
        coordinator,
        artifact_store,
        unit_of_work,
        investigation_store=investigation_store,
    ), gateway


def _runtime_allowlist(settings: Settings) -> dict[str, SandboxToolSpec]:
    allowlist = default_allowlist()
    if not settings.semgrep_candidate_rules_enabled:
        # The image/runner contract can be exercised in isolation, but
        # candidate rules are not advertised or ticketed until their
        # precision gate has been approved by the operator.
        allowlist.pop("semgrep_sast", None)
    else:
        if "semgrep_sast" not in allowlist:
            raise RuntimeError("Semgrep candidate rules require an immutable sandbox image digest")
        configured_digest = os.getenv("SECMIND_SEMGREP_SAST_RULE_BUNDLE_DIGEST", "")
        if configured_digest != SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST:
            raise RuntimeError("Semgrep candidate rules require the approved immutable rule bundle digest")
    return allowlist


def _bootstrap_reviewed_knowledge(store: OfflineKnowledgeStore) -> None:
    """Seed the offline half of full retrieval from the pinned skill catalog."""

    from secmind.external_skills import ExternalSkillCatalog

    catalog = ExternalSkillCatalog.builtin()
    for card in catalog.catalog():
        content = " ".join(
            (
                card.skill_id.replace("-", " "),
                card.description,
                "capabilities:",
                ", ".join(card.capability_tags),
                "tools:",
                ", ".join(card.tool_mentions),
            )
        ).strip()
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        store.upsert(
            content=content,
            source=f"{catalog.source.repository}/{card.source_path}",
            version=catalog.source.commit,
            content_hash=digest,
            kind="knowledge",
            verified=True,
            trust_score=max(0.5, min(1.0, card.quality_score / 100)),
        )


class ApplicationRuntime:
    """Own long-lived async resources used by the FastAPI process."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._service: RunService | None = None
        self._gateway: QwenGateway | None = None
        self._checkpoint_context: AbstractAsyncContextManager[Any] | None = None

    @property
    def service(self) -> RunService:
        if self._service is None:
            raise RuntimeError("SecMind runtime has not been started")
        return self._service

    async def startup(self) -> None:
        if self._service is not None:
            return
        checkpointer: BaseCheckpointSaver[Any] = InMemorySaver()
        if self.settings.checkpoint_database_url:
            from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

            context = AsyncPostgresSaver.from_conn_string(self.settings.checkpoint_database_url)
            self._checkpoint_context = context
            postgres_checkpointer = await context.__aenter__()
            try:
                await postgres_checkpointer.setup()
            except BaseException:
                await context.__aexit__(None, None, None)
                self._checkpoint_context = None
                raise
            checkpointer = postgres_checkpointer
        elif self.settings.env.lower() in {"production", "competition"}:
            raise RuntimeError("SECMIND_CHECKPOINT_DATABASE_URL is required outside development/test")

        try:
            self._service, self._gateway = build_runtime(self.settings, checkpointer)
            profile = resolve_runtime_profile(self.settings)
            logger.info(
                "SecMind resolved runtime capability profile: %s",
                json.dumps(profile.model_dump(mode="json"), sort_keys=True, separators=(",", ":")),
            )
            await self._service.recover_incomplete()
            await self._service.startup()
        except BaseException:
            await self.shutdown()
            raise

    async def shutdown(self) -> None:
        if self._service is not None:
            await self._service.shutdown()
        if self._gateway is not None:
            await close_gateway_safely(self._gateway)
        self._service = None
        self._gateway = None
        if self._checkpoint_context is not None:
            await self._checkpoint_context.__aexit__(None, None, None)
            self._checkpoint_context = None
