from __future__ import annotations

import json
from typing import Any

import pytest
from conftest import seal_execution_contract

from secmind.agent_profiles import AgentProfileRegistry
from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.bounded_worker import BoundedWorker
from secmind.context_manager import MaterializedContext
from secmind.dag import DagScheduler, PlanValidationError, PlanValidator
from secmind.dependency_resolver import (
    ArtifactOwnershipRecord,
    DependencyResolutionError,
    DependencyResolver,
    InMemoryArtifactOwnershipStore,
    ownership_record,
)
from secmind.guardrail import Guardrail
from secmind.schemas import (
    AgentProfile,
    AgentState,
    ArtifactRef,
    BudgetState,
    DependencyBinding,
    PlanStep,
    RiskLevel,
    Scenario,
    StepStatus,
    TaskRequest,
    ToolContext,
    ToolManifest,
    ToolResult,
    ToolStatus,
    WorkItem,
)
from secmind.tools import BaseTool, ToolBroker, ToolRegistry

CYCLONEDX_MEDIA = "application/vnd.cyclonedx+json"
CYCLONEDX_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {"bomFormat": {"const": "CycloneDX"}},
    "required": ["bomFormat"],
    "additionalProperties": True,
}


def artifact_ref(stored, *, media_type: str = CYCLONEDX_MEDIA) -> ArtifactRef:
    return ArtifactRef(
        artifact_id=stored.artifact_id,
        ref=stored.artifact_id,
        sha256=stored.sha256,
        size_bytes=stored.size_bytes,
        media_type=media_type,
    )


def resolver_fixture(tmp_path) -> tuple[DependencyResolver, InMemoryArtifactOwnershipStore, ArtifactRef]:
    store = ContentAddressedArtifactStore(tmp_path / "artifacts")
    content = json.dumps({"bomFormat": "CycloneDX", "components": []}).encode()
    stored = store.put(content, media_type=CYCLONEDX_MEDIA)
    artifact = artifact_ref(stored)
    ownership = InMemoryArtifactOwnershipStore()
    ownership.register(
        ArtifactOwnershipRecord(
            run_id="run-deps",
            producer_step_id="syft",
            output_name="sbom",
            artifact_id=artifact.artifact_id,
            sha256=artifact.sha256,
            size_bytes=artifact.size_bytes,
            media_type=artifact.media_type,
        )
    )
    return DependencyResolver(store, ownership), ownership, artifact


def binding(artifact_id: str | None, **updates: Any) -> DependencyBinding:
    values: dict[str, Any] = {
        "upstream_step_id": "syft",
        "output_name": "sbom",
        "artifact_id": artifact_id,
        "expected_media_type": CYCLONEDX_MEDIA,
        "expected_schema": CYCLONEDX_SCHEMA,
        "mount_mode": "reference_only",
    }
    values.update(updates)
    return DependencyBinding.model_validate(values)


def manifest(name: str, capability: str) -> ToolManifest:
    return ToolManifest(
        name=name,
        version="1",
        description="dependency DAG test tool",
        scenarios=[Scenario.CODE_AUDIT],
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        risk_level=RiskLevel.R1,
        capability_tags=[capability],
    )


def dependency_plan(artifact_id: str | None = None) -> list[PlanStep]:
    return [
        PlanStep(
            step_id="syft",
            objective="build SBOM",
            agent_role="dependency_specialist",
            capability="sbom",
            tool_candidates=["syft"],
            success_criteria=["CycloneDX artifact"],
            output_contract={
                "type": "object",
                "properties": {"sbom": {"type": "string"}},
            },
            risk_hint=RiskLevel.R1,
            concurrency_key="dependency",
        ),
        PlanStep(
            step_id="osv",
            objective="match offline advisories",
            agent_role="dependency_specialist",
            capability="dependency_audit",
            dependencies=["syft"],
            dependency_bindings=[binding(artifact_id)],
            tool_candidates=["osv"],
            success_criteria=["advisory results"],
            risk_hint=RiskLevel.R1,
            concurrency_key="dependency",
        ),
    ]


def agent_state(plan: list[PlanStep]) -> AgentState:
    return seal_execution_contract(
        AgentState(
            run_id="run-deps",
            task=TaskRequest(objective="audit dependency graph"),
            scenario=Scenario.CODE_AUDIT,
            workspace=".",
            plan=plan,
        )
    )


def test_dependency_resolver_returns_only_verified_broker_handle(tmp_path) -> None:
    resolver, _, artifact = resolver_fixture(tmp_path)
    resolved = resolver.resolve("run-deps", binding(artifact.artifact_id))

    assert resolved.artifact.artifact_id == artifact.artifact_id
    assert resolved.input_digest != artifact.sha256
    serialized = resolved.model_dump(mode="json")
    assert "path" not in serialized
    assert "content" not in serialized


@pytest.mark.parametrize(
    ("run_id", "updates", "message"),
    [
        ("other-run", {}, "not owned"),
        ("run-deps", {"upstream_step_id": "other-step"}, "producer step"),
        ("run-deps", {"output_name": "other-output"}, "output name"),
        ("run-deps", {"expected_media_type": "application/json"}, "media type"),
        (
            "run-deps",
            {"expected_schema": {"type": "object", "required": ["serialNumber"]}},
            "JSON Schema",
        ),
    ],
)
def test_dependency_resolver_rejects_ownership_media_and_schema_mismatches(
    tmp_path,
    run_id: str,
    updates: dict[str, Any],
    message: str,
) -> None:
    resolver, _, artifact = resolver_fixture(tmp_path)
    with pytest.raises(DependencyResolutionError, match=message):
        resolver.resolve(run_id, binding(artifact.artifact_id, **updates))


def test_dependency_resolver_detects_artifact_tampering(tmp_path) -> None:
    resolver, _, artifact = resolver_fixture(tmp_path)
    path = resolver.artifact_store.path_for(artifact.artifact_id)
    path.write_bytes(b"tampered")
    with pytest.raises(DependencyResolutionError, match="cannot be read or verified"):
        resolver.resolve("run-deps", binding(artifact.artifact_id))


def test_dependency_resolver_rejects_invalid_id_duplicate_output_and_bad_metadata(tmp_path) -> None:
    resolver, ownership, artifact = resolver_fixture(tmp_path)
    with pytest.raises(DependencyResolutionError, match="valid immutable artifact"):
        resolver.resolve("run-deps", binding(None))
    with pytest.raises(DependencyResolutionError, match="output names must be unique"):
        resolver.resolve_many(
            "run-deps",
            [binding(artifact.artifact_id), binding(artifact.artifact_id)],
        )

    bad_ownership = InMemoryArtifactOwnershipStore()
    bad_record = ArtifactOwnershipRecord(
        run_id="run-deps",
        producer_step_id="syft",
        output_name="sbom",
        artifact_id=artifact.artifact_id,
        sha256="f" * 64,
        size_bytes=artifact.size_bytes,
        media_type=artifact.media_type,
    )
    bad_ownership.register(bad_record)
    bad_resolver = DependencyResolver(resolver.artifact_store, bad_ownership)
    with pytest.raises(DependencyResolutionError, match="not content-addressed"):
        bad_resolver.resolve("run-deps", binding(artifact.artifact_id))

    with pytest.raises(DependencyResolutionError, match="reused with different metadata"):
        ownership.register(bad_record.model_copy(update={"sha256": artifact.sha256, "media_type": "application/json"}))


def test_dependency_schema_validation_rejects_non_json_and_invalid_schema(tmp_path) -> None:
    resolver, _, artifact = resolver_fixture(tmp_path)
    text_ownership = InMemoryArtifactOwnershipStore()
    text_ownership.register(
        ArtifactOwnershipRecord(
            run_id="run-deps",
            producer_step_id="syft",
            output_name="sbom",
            artifact_id=artifact.artifact_id,
            sha256=artifact.sha256,
            size_bytes=artifact.size_bytes,
            media_type="text/plain; charset=utf-8",
        )
    )
    text_resolver = DependencyResolver(resolver.artifact_store, text_ownership)
    with pytest.raises(DependencyResolutionError, match="requires a JSON media type"):
        text_resolver.resolve(
            "run-deps",
            binding(artifact.artifact_id, expected_media_type="text/plain", expected_schema={"type": "object"}),
        )
    with pytest.raises(DependencyResolutionError, match="invalid JSON Schema"):
        resolver.resolve(
            "run-deps",
            binding(artifact.artifact_id, expected_schema={"type": "not-a-json-schema-type"}),
        )
    assert (
        resolver.resolve(
            "run-deps",
            binding(artifact.artifact_id, expected_schema={}),
        ).artifact.artifact_id
        == artifact.artifact_id
    )


def test_ownership_record_requires_content_addressed_reference(tmp_path) -> None:
    _, _, artifact = resolver_fixture(tmp_path)
    record = ownership_record(
        run_id="run-deps",
        producer_step_id="syft",
        output_name="sbom",
        artifact=artifact,
    )
    assert record.artifact_id == artifact.artifact_id
    with pytest.raises(DependencyResolutionError, match="not content-addressed"):
        ownership_record(
            run_id="run-deps",
            producer_step_id="syft",
            output_name="sbom",
            artifact=artifact.model_copy(update={"artifact_id": "e" * 64}),
        )


def test_plan_validator_checks_data_dependency_contracts() -> None:
    plan = dependency_plan("not-a-sha256")
    plan[1].dependencies = []
    plan[1].dependency_bindings[0].expected_schema = {"type": "not-a-json-schema-type"}
    plan[1].dependency_bindings[0].output_name = "undeclared"
    state = agent_state(plan)

    errors = PlanValidator([manifest("syft", "sbom"), manifest("osv", "dependency_audit")]).validate(
        plan,
        Scenario.CODE_AUDIT,
        state,
    )

    assert any("undeclared dependency" in error for error in errors)
    assert any("invalid artifact id" in error for error in errors)
    assert any("invalid JSON Schema" in error for error in errors)
    assert any("undeclared output" in error for error in errors)


def test_scheduler_resolves_single_dependency_artifact_into_work_item(tmp_path) -> None:
    _, _, artifact = resolver_fixture(tmp_path)
    plan = dependency_plan()
    state = agent_state(plan)
    scheduler = DagScheduler()
    scheduler.initialize(state)
    state.lease.owner_id = "worker-7"
    state.lease.fence = 11
    state.step_runtime["syft"].status = StepStatus.SUCCEEDED
    state.step_runtime["syft"].artifact_ids = [artifact.artifact_id]

    item = scheduler.build_work_item(state, plan[1])

    assert item.dependency_refs == [artifact.artifact_id]
    assert item.dependency_bindings[0].artifact_id == artifact.artifact_id
    assert item.capability_candidates == ["osv"]
    assert item.agent_profile == "dependency-investigator"
    assert item.attempt == 1
    assert item.lease_fence == 11


def test_scheduler_rejects_ambiguous_or_foreign_dependency_artifacts() -> None:
    plan = dependency_plan()
    state = agent_state(plan)
    scheduler = DagScheduler()
    scheduler.initialize(state)
    state.step_runtime["syft"].status = StepStatus.SUCCEEDED
    state.step_runtime["syft"].artifact_ids = ["a" * 64, "b" * 64]
    with pytest.raises(PlanValidationError, match="unambiguously"):
        scheduler.build_work_item(state, plan[1])

    plan[1].dependency_bindings[0].artifact_id = "c" * 64
    with pytest.raises(PlanValidationError, match="not owned"):
        scheduler.build_work_item(state, plan[1])


def test_scheduler_enforces_concurrency_key_capacity() -> None:
    plan = dependency_plan()
    extra = plan[0].model_copy(update={"step_id": "syft-2"})
    state = agent_state([plan[0], extra])
    scheduler = DagScheduler(concurrency_limits={"dependency": 1})
    scheduler.initialize(state)
    state.step_runtime["syft"].status = StepStatus.RUNNING

    assert scheduler.ready_steps(state) == []


class DependencyConsumerTool(BaseTool):
    def __init__(self) -> None:
        self.arguments: list[dict[str, Any]] = []
        self.manifest = ToolManifest(
            name="osv",
            version="1",
            description="consume immutable SBOM handle",
            scenarios=[Scenario.CODE_AUDIT],
            input_schema={
                "type": "object",
                "properties": {"sbom": {"type": "string", "pattern": "^[a-f0-9]{64}$"}},
                "required": ["sbom"],
                "additionalProperties": False,
            },
            output_schema={
                "type": "object",
                "properties": {"findings": {"type": "array"}},
                "required": ["findings"],
            },
            risk_level=RiskLevel.R1,
            capability_tags=["dependency_audit"],
        )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        del context
        self.arguments.append(dict(args))
        return ToolResult(status=ToolStatus.SUCCESS, data={"findings": []})


class DependencyContextProvider:
    def materialize(self, pack_id: str) -> MaterializedContext:
        return MaterializedContext(
            pack_id=pack_id,
            pack_digest="d" * 64,
            system_text="policy",
            user_text="dependency task",
            token_estimate=64,
        )

    def request_context(self, item: WorkItem, current_pack_id: str, reason: str) -> str | None:
        del item, current_pack_id, reason
        return None


@pytest.mark.asyncio
async def test_worker_binds_verified_dependency_id_before_atomic_broker(tmp_path) -> None:
    resolver, _, artifact = resolver_fixture(tmp_path)
    tool = DependencyConsumerTool()
    registry = ToolRegistry()
    registry.register(tool)
    broker = ToolBroker(registry, Guardrail())
    profile = AgentProfile(
        profile_id="dependency-profile",
        purpose="consume verified SBOM",
        allowed_capabilities=["dependency_audit"],
        max_turns=1,
        max_tool_calls=1,
    )
    worker = BoundedWorker(
        broker=broker,
        profile_registry=AgentProfileRegistry([profile]),
        context_provider=DependencyContextProvider(),
        dependency_resolver=resolver,
    )
    item = WorkItem(
        run_id="run-deps",
        step_id="osv",
        capability="dependency_audit",
        tool_name="osv",
        inputs={},
        workspace_ref=".",
        dependency_refs=[artifact.artifact_id],
        dependency_bindings=[binding(artifact.artifact_id)],
        context_pack_id="context-pack",
        capability_candidates=["osv"],
        agent_profile="dependency-profile",
        transition_id="transition-dependency",
        lease_fence=12,
        attempt=3,
        budget_reservation=BudgetState(),
    )
    try:
        patch = await worker.run(item)
    finally:
        broker.close()

    assert patch.status == StepStatus.SUCCEEDED
    assert patch.attempt == 3
    assert patch.lease_fence == 12
    assert tool.arguments == [{"sbom": artifact.artifact_id}]
