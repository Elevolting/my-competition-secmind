from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from langgraph.checkpoint.memory import InMemorySaver

from secmind.checkpoint_archive import FencedCheckpointSaver
from secmind.guardrail import Guardrail
from secmind.investigation.contracts import RunAuthority, seal_contract
from secmind.ledger import LedgerStore
from secmind.llm import QwenGateway
from secmind.orchestrator import SecMindOrchestrator
from secmind.runtime import ApplicationRuntime
from secmind.schemas import AgentState, AttachmentRef, RunStatus, TaskRequest
from secmind.tools import ToolBroker, default_registry


def make_orchestrator(settings, saver: InMemorySaver | None = None) -> SecMindOrchestrator:
    ledger = LedgerStore(settings.database_url)
    return SecMindOrchestrator(
        settings,
        ledger,
        QwenGateway(settings),
        ToolBroker(default_registry(), Guardrail()),
        checkpointer=saver,
    )


def test_checkpointer_is_constructor_injected(settings) -> None:
    saver = InMemorySaver()
    orchestrator = make_orchestrator(settings, saver)
    assert orchestrator.checkpointer is saver


async def test_pending_run_without_checkpoint_starts_once(settings) -> None:
    settings.prepare_directories()
    (settings.input_root / "clean.py").write_text("print('ok')", encoding="utf-8")
    orchestrator = make_orchestrator(settings)
    state = AgentState(
        run_id="pending-recovery",
        task=TaskRequest(
            objective="audit code",
            attachments=[AttachmentRef(ref="clean.py")],
        ),
        status=RunStatus.PENDING,
    )
    orchestrator.ledger.save_state(state)

    recovered = await orchestrator.recover(state.run_id)

    assert recovered.status == RunStatus.COMPLETED
    assert [event.event_type for event in orchestrator.ledger.events(state.run_id)].count("run.created") == 1


async def test_non_pending_run_without_checkpoint_is_not_replayed(settings) -> None:
    orchestrator = make_orchestrator(settings)
    state = AgentState(
        run_id="missing-checkpoint",
        task=TaskRequest(objective="audit code"),
        status=RunStatus.RUNNING,
    )
    orchestrator.ledger.save_state(state)

    try:
        await orchestrator.recover(state.run_id)
    except RuntimeError as exc:
        assert "no durable LangGraph checkpoint" in str(exc)
    else:
        raise AssertionError("A running task without a checkpoint must not replay from START")


async def test_recovery_rebinds_fresh_authority_without_mutating_checkpoint(settings, monkeypatch) -> None:
    orchestrator = make_orchestrator(settings)
    state = AgentState(
        run_id="authority-recovery",
        task=TaskRequest(objective="audit code"),
        status=RunStatus.RUNNING,
    )
    state.lease.owner_id = "stale-worker"
    state.lease.fence = 1
    orchestrator.ledger.save_state(state)
    monkeypatch.setattr(
        orchestrator.checkpointer,
        "aget_tuple",
        lambda _config: _async_value(SimpleNamespace(checkpoint={"pending_writes": ["preserve-me"]})),
    )

    async def resume_checkpoint(input_value, _config):
        assert input_value is None
        return {"agent": state.model_dump(mode="json")}

    monkeypatch.setattr(orchestrator.graph, "ainvoke", resume_checkpoint)
    authority = seal_contract(
        RunAuthority,
        digest_field="authority_digest",
        run_id=state.run_id,
        owner_id="fresh-worker",
        run_fence=2,
        claimed_state_version=state.state_version,
        claim_transition_id="claim:authority-recovery:2",
        lease_until=datetime.now(UTC) + timedelta(minutes=1),
    )

    recovered = await orchestrator.recover(state.run_id, authority=authority)

    assert recovered.lease.owner_id == "fresh-worker"
    assert recovered.lease.fence == 2


async def _async_value(value):
    return value


async def test_development_runtime_uses_memory_checkpointer(settings) -> None:
    runtime = ApplicationRuntime(settings)
    await runtime.startup()
    try:
        checkpointer = runtime.service.orchestrator.checkpointer
        assert isinstance(checkpointer, FencedCheckpointSaver)
        assert isinstance(checkpointer.delegate, InMemorySaver)
    finally:
        await runtime.shutdown()
