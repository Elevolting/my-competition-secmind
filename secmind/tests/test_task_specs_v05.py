from __future__ import annotations

from hashlib import sha256

import pytest
from sqlalchemy import create_engine

from secmind.coordinator import CoordinatorStore
from secmind.schemas import (
    AttachmentRef,
    ClarificationResponse,
    ParsedAsset,
    ParserRun,
    Scenario,
    TaskHint,
    TaskRequest,
)
from secmind.task_specs import TaskSpecCompiler, TaskSpecConflict, TaskSpecRepository


def _parsed_asset() -> ParsedAsset:
    return ParsedAsset(
        parsed_asset_id="parsed-openapi-1",
        parser_id="openapi-json",
        parser_version="1.0.0",
        artifact_id="artifact-openapi-1",
        relative_path="spec/openapi.json",
        media_type="application/json",
        asset_type="openapi",
        content_digest=sha256(b"openapi fixture").hexdigest(),
        hints=[
            TaskHint(
                source_ref="spec/openapi.json",
                scenario_candidates=[Scenario.API_ASSESSMENT],
                # Parser hints are untrusted and must not grant authorization.
                authorized_scope_candidates=[
                    "https://production.example.internal",
                    "../../host-secrets",
                ],
                confidence=0.95,
            )
        ],
    )


def _parser_run(run_id: str) -> ParserRun:
    return ParserRun(
        parser_run_id=f"parser-{run_id}",
        run_id=run_id,
        artifact_id="artifact-openapi-1",
        parser_id="openapi-json",
        parser_version="1.0.0",
        status="completed",
        parsed_asset_id="parsed-openapi-1",
        input_digest=sha256(b"openapi fixture").hexdigest(),
        output_digest=sha256(b"parsed fixture").hexdigest(),
    )


def test_taskspec_digest_provenance_and_revision_chain_are_durable(tmp_path) -> None:
    run_id = "task-spec-durable"
    compiler = TaskSpecCompiler()
    task = TaskRequest(
        objective="Assess the attached OpenAPI document",
        attachments=[AttachmentRef(ref="openapi.json")],
        target_scope=["tenant-a/api-doc"],
        constraints=["offline only"],
    )
    parser_run = _parser_run(run_id)
    initial = compiler.compile(run_id, task, [_parsed_asset()], [parser_run])

    # Canonical content, not wall-clock creation time, defines TaskSpec identity.
    repeated = compiler.compile(run_id, task, [_parsed_asset()], [parser_run])
    assert repeated.task_spec_id == initial.task_spec_id
    assert repeated.content_digest == initial.content_digest
    assert initial.field_provenance["objectives"][0].source_type == "operator"
    assert initial.field_provenance["primary_scenario"][0].source_type == "parser"
    assert initial.parser_run_ids == [parser_run.parser_run_id]

    engine = create_engine(f"sqlite:///{(tmp_path / 'taskspec.db').as_posix()}")
    repository = TaskSpecRepository(engine)
    ref_v1 = repository.save_spec(initial, reason="initial_compile")
    assert repository.load_spec(run_id).content_digest == ref_v1.content_digest

    response = ClarificationResponse(
        confirmed_scenario=Scenario.API_ASSESSMENT,
        additional_constraints=["do not contact documented servers"],
    )
    revised = compiler.revise(initial, response, request_id="clarification-1")
    ref_v2 = repository.save_spec(revised, reason="operator_clarification")

    assert ref_v2.revision == 2
    assert revised.parent_revision_digest == initial.content_digest
    assert revised.content_digest != initial.content_digest
    assert repository.load_spec(run_id).content_digest == revised.content_digest

    tampered = revised.model_copy(update={"objectives": ["silently changed"]})
    with pytest.raises(TaskSpecConflict, match="content digest"):
        repository.save_spec(tampered, reason="tamper attempt")


def test_parser_hints_never_expand_authorized_scope() -> None:
    compiler = TaskSpecCompiler()
    task = TaskRequest(
        objective="Assess this OpenAPI definition",
        attachments=[AttachmentRef(ref="openapi.json")],
    )

    spec = compiler.compile("scope-run", task, [_parsed_asset()], [_parser_run("scope-run")])

    assert spec.authorized_scope == ["artifact:openapi.json"]
    assert "https://production.example.internal" not in spec.authorized_scope
    assert "../../host-secrets" not in spec.authorized_scope
    assert spec.primary_scenario == Scenario.API_ASSESSMENT


def test_clarification_resolution_is_idempotent_but_conflicts_are_rejected() -> None:
    compiler = TaskSpecCompiler()
    repository = TaskSpecRepository()
    spec = compiler.compile("clarify-run", TaskRequest(objective="review this material"), [], [])
    repository.save_spec(spec, reason="initial_compile")
    request = compiler.clarification_request(spec)
    assert request is not None
    repository.create_clarification(request, fence=7)

    response = ClarificationResponse(confirmed_scenario=Scenario.CODE_AUDIT)
    resolution_id, created = repository.resolve_clarification(
        request.request_id,
        response,
        run_id=spec.run_id,
    )
    duplicate_id, duplicate_created = repository.resolve_clarification(
        request.request_id,
        response,
        run_id=spec.run_id,
    )

    assert created is True
    assert duplicate_created is False
    assert duplicate_id == resolution_id
    consumed = repository.consume_clarification(request.request_id, run_id=spec.run_id, fence=7)
    replayed = repository.consume_clarification(request.request_id, run_id=spec.run_id, fence=7)
    assert consumed.resolution_id == resolution_id
    assert replayed == consumed

    with pytest.raises(TaskSpecConflict, match="conflicting resolution"):
        repository.resolve_clarification(
            request.request_id,
            ClarificationResponse(confirmed_scenario=Scenario.LOG_ANALYSIS),
            run_id=spec.run_id,
        )


def test_clarification_cannot_be_resolved_or_consumed_by_another_run() -> None:
    compiler = TaskSpecCompiler()
    repository = TaskSpecRepository()
    spec = compiler.compile("owner-run", TaskRequest(objective="review this material"), [], [])
    request = compiler.clarification_request(spec)
    assert request is not None
    repository.create_clarification(request, fence=1)

    response = ClarificationResponse(confirmed_scenario=Scenario.CODE_AUDIT)
    with pytest.raises(TaskSpecConflict, match="different run"):
        repository.resolve_clarification(request.request_id, response, run_id="attacker-run")

    repository.resolve_clarification(request.request_id, response, run_id=spec.run_id)
    with pytest.raises(KeyError):
        repository.consume_clarification(request.request_id, run_id="attacker-run", fence=1)


def test_clarification_revision_is_fenced_atomic_and_replay_idempotent(tmp_path) -> None:
    url = f"sqlite:///{(tmp_path / 'atomic-clarification.db').as_posix()}"
    coordinator = CoordinatorStore(url)
    repository = TaskSpecRepository(coordinator.engine)
    compiler = TaskSpecCompiler()
    run_id = "atomic-clarification"
    initial = compiler.compile(run_id, TaskRequest(objective="review this material"), [], [])
    repository.save_spec(initial, reason="initial_compile")
    request = compiler.clarification_request(initial)
    assert request is not None
    repository.create_clarification(request, fence=0)
    repository.resolve_clarification(
        request.request_id,
        ClarificationResponse(confirmed_scenario=Scenario.CODE_AUDIT, confirmed_scope=["."]),
        run_id=run_id,
    )
    coordinator.enqueue_run(run_id)
    lease = coordinator.claim_jobs("clarification-worker", lease_seconds=60)[0]

    revised = repository.consume_and_revise(
        request.request_id,
        run_id=run_id,
        owner_id=lease.owner_id,
        fence=lease.fence,
        compiler=compiler,
    )
    replayed = repository.consume_and_revise(
        request.request_id,
        run_id=run_id,
        owner_id=lease.owner_id,
        fence=lease.fence,
        compiler=compiler,
    )
    assert revised.revision == replayed.revision == 2
    assert revised.content_digest == replayed.content_digest
    assert revised.clarification_request_ids == [request.request_id]

    coordinator.park_job(run_id, owner_id=lease.owner_id, fence=lease.fence)
    coordinator.ensure_job_awake(run_id)
    replacement = coordinator.claim_jobs("replacement-worker", lease_seconds=60)[0]
    with pytest.raises(TaskSpecConflict, match="current run lease"):
        repository.consume_and_revise(
            request.request_id,
            run_id=run_id,
            owner_id=lease.owner_id,
            fence=lease.fence,
            compiler=compiler,
        )
    assert replacement.fence > lease.fence
    coordinator.close()
