from __future__ import annotations

from types import SimpleNamespace
from typing import Any, TypedDict
from uuid import NAMESPACE_URL, uuid5

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.coordinator import CoordinatorStore
from secmind.investigation.store import InvestigationStore
from secmind.ledger import LedgerStore
from secmind.schemas import AgentState, RunStatus, TaskRequest
from secmind.service import EventHub, RunService
from secmind.unit_of_work import ControlPlaneUnitOfWork


class _GraphState(TypedDict):
    agent: dict[str, Any]


@pytest.mark.asyncio
async def test_checkpoint_fork_restarts_selected_node_under_child_identity(tmp_path, monkeypatch) -> None:
    saver = InMemorySaver()
    builder = StateGraph(_GraphState)

    def prepare(value: _GraphState) -> _GraphState:
        agent = dict(value["agent"])
        agent["completion_reasons"] = ["prepared"]
        return {"agent": agent}

    def finish(value: _GraphState) -> _GraphState:
        agent = dict(value["agent"])
        agent["completion_reasons"] = [*agent["completion_reasons"], agent["run_id"]]
        return {"agent": agent}

    builder.add_node("prepare", prepare)
    builder.add_node("finish", finish)
    builder.add_edge(START, "prepare")
    builder.add_edge("prepare", "finish")
    builder.add_edge("finish", END)
    graph = builder.compile(checkpointer=saver)
    database_url = f"sqlite:///{(tmp_path / 'fork.db').as_posix()}"
    ledger = LedgerStore(database_url)
    coordinator = CoordinatorStore(database_url)
    settings = SimpleNamespace(
        max_steps=4, max_tool_calls=4, max_model_calls=4,
        max_provider_requests=8, max_input_tokens=1000,
        max_output_tokens=1000, max_cost_units=1.0, max_runtime_seconds=60,
    )
    orchestrator = SimpleNamespace(checkpointer=saver, graph=graph, settings=settings)
    service = RunService(
        orchestrator, ledger, EventHub(), coordinator,
        ContentAddressedArtifactStore(tmp_path / "artifacts"),
    )
    parent = AgentState(run_id="parent", task=TaskRequest(objective="Audit code"))
    ledger.save_state(parent)
    await graph.ainvoke({"agent": parent.model_dump(mode="json")}, {"configurable": {"thread_id": parent.run_id}})

    checkpoints = [item async for item in saver.alist({"configurable": {"thread_id": parent.run_id}})]
    selected = None
    for item in checkpoints:
        if (await graph.aget_state(item.config)).next == ("finish",):
            selected = item
            break
    assert selected is not None
    assert "next" not in selected.checkpoint
    assert selected.pending_writes  # Parent's later work must not enter the child.

    request_id = "fork-request-receipt-lost"

    def lost_notification() -> None:
        raise RuntimeError("fork response was lost after commit")

    notify = service.worker.notify
    monkeypatch.setattr(service.worker, "notify", lost_notification)
    with pytest.raises(RuntimeError, match="response was lost"):
        await service.checkpoint_fork(
            parent.run_id, selected.checkpoint["id"], fork_request_id=request_id,
        )
    monkeypatch.setattr(service.worker, "notify", notify)
    child = await service.checkpoint_fork(
        parent.run_id, selected.checkpoint["id"], fork_request_id=request_id,
    )
    assert child.run_id == str(uuid5(NAMESPACE_URL, f"secmind:checkpoint-fork:{request_id}"))
    assert len(ledger.events(parent.run_id)) == 1
    with pytest.raises(RuntimeError, match="reused with different inputs"):
        await service.checkpoint_fork(
            parent.run_id, selected.checkpoint["id"],
            fork_request_id=request_id, task=TaskRequest(objective="Different task"),
        )
    assert child.parent_run_id == parent.run_id
    assert child.fork_checkpoint_id == selected.checkpoint["id"]
    assert child.run_id != parent.run_id
    assert ledger.verify(child.run_id)
    assert ledger.verify(parent.run_id)
    assert coordinator.job_status(child.run_id)[0] == "queued"

    resumed = await graph.ainvoke(None, {"configurable": {"thread_id": child.run_id}})
    assert resumed["agent"]["completion_reasons"] == ["prepared", child.run_id]

    checkpoint_retry_id = "fork-request-checkpoint-retry"
    checkpoint_child_id = str(uuid5(NAMESPACE_URL, f"secmind:checkpoint-fork:{checkpoint_retry_id}"))
    put = saver.aput

    async def fail_child_checkpoint(config, checkpoint, metadata, new_versions):
        if config["configurable"]["thread_id"] == checkpoint_child_id:
            raise RuntimeError("checkpoint store unavailable")
        return await put(config, checkpoint, metadata, new_versions)

    monkeypatch.setattr(saver, "aput", fail_child_checkpoint)
    with pytest.raises(RuntimeError, match="checkpoint store unavailable"):
        await service.checkpoint_fork(
            parent.run_id, selected.checkpoint["id"], fork_request_id=checkpoint_retry_id,
        )
    assert ledger.load_state(checkpoint_child_id).status == RunStatus.PENDING
    with pytest.raises(KeyError):
        coordinator.job_status(checkpoint_child_id)
    monkeypatch.setattr(saver, "aput", put)
    recovered = await service.checkpoint_fork(
        parent.run_id, selected.checkpoint["id"], fork_request_id=checkpoint_retry_id,
    )
    assert recovered.run_id == checkpoint_child_id
    assert coordinator.job_status(recovered.run_id)[0] == "queued"

    publish_retry_id = "fork-request-publish-retry"
    publish_child_id = str(uuid5(NAMESPACE_URL, f"secmind:checkpoint-fork:{publish_retry_id}"))
    publish = ControlPlaneUnitOfWork.submit_checkpoint_fork

    def fail_publication(self, state, **kwargs):
        if state.run_id == publish_child_id:
            raise RuntimeError("control-plane commit unavailable")
        return publish(self, state, **kwargs)

    monkeypatch.setattr(ControlPlaneUnitOfWork, "submit_checkpoint_fork", fail_publication)
    with pytest.raises(RuntimeError, match="control-plane commit unavailable"):
        await service.checkpoint_fork(
            parent.run_id, selected.checkpoint["id"], fork_request_id=publish_retry_id,
        )
    assert ledger.load_state(publish_child_id).status == RunStatus.PENDING
    with pytest.raises(KeyError):
        coordinator.job_status(publish_child_id)
    monkeypatch.setattr(ControlPlaneUnitOfWork, "submit_checkpoint_fork", publish)
    published = await service.checkpoint_fork(
        parent.run_id, selected.checkpoint["id"], fork_request_id=publish_retry_id,
    )
    assert published.run_id == publish_child_id
    assert coordinator.job_status(published.run_id)[0] == "queued"

    terminal = checkpoints[0]
    with pytest.raises(RuntimeError, match="terminal checkpoints"):
        await service.checkpoint_fork(parent.run_id, terminal.checkpoint["id"])

    scoped = AgentState(
        run_id="scoped-parent",
        task=TaskRequest(objective="Audit code"),
        workspace="parent-owned-workspace",
    )
    ledger.save_state(scoped)
    await graph.ainvoke(
        {"agent": scoped.model_dump(mode="json")},
        {"configurable": {"thread_id": scoped.run_id}},
    )
    scoped_checkpoints = [item async for item in saver.alist({"configurable": {"thread_id": scoped.run_id}})]
    scoped_selected = None
    for item in scoped_checkpoints:
        if (await graph.aget_state(item.config)).next == ("finish",):
            scoped_selected = item
            break
    assert scoped_selected is not None
    with pytest.raises(RuntimeError, match="run-scoped records"):
        await service.checkpoint_fork(scoped.run_id, scoped_selected.checkpoint["id"])


def test_checkpoint_fork_publication_rolls_back_all_database_records(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{(tmp_path / 'fork-commit.db').as_posix()}"
    coordinator = CoordinatorStore(database_url)
    ledger = LedgerStore(engine=coordinator.engine)
    investigation = InvestigationStore(engine=coordinator.engine)
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    parent = AgentState(run_id="parent", task=TaskRequest(objective="Audit code"))
    ledger.save_state(parent)
    child = AgentState(
        run_id="child", task=parent.task,
        parent_run_id=parent.run_id, fork_checkpoint_id="checkpoint-1",
        fork_request_id="fork-request-1", fork_child_checkpoint_id="child-checkpoint-1",
    )
    uow.prepare_checkpoint_fork(child)
    published_child = child.model_copy(update={"status": RunStatus.RUNNING, "state_version": 2})
    reservation = RunService._root_budget_reservation(published_child)
    append = LedgerStore.append_in_session

    def fail_parent_event(session, run_id, event_type, payload, actor="system", dedupe_key=None):
        if run_id == parent.run_id:
            raise RuntimeError("parent audit write failed")
        return append(session, run_id, event_type, payload, actor, dedupe_key)

    monkeypatch.setattr(LedgerStore, "append_in_session", staticmethod(fail_parent_event))
    with pytest.raises(RuntimeError, match="parent audit write failed"):
        uow.submit_checkpoint_fork(
            published_child, parent_run_id=parent.run_id,
            checkpoint_id="checkpoint-1", actor="operator",
            root_reservation=reservation,
        )
    assert ledger.load_state(child.run_id).status == RunStatus.PENDING
    assert ledger.events(parent.run_id) == []
    assert ledger.events(child.run_id) == []
    assert investigation.unsettled_reservation_ids(child.run_id, include_run_envelope=True) == []
    with pytest.raises(KeyError):
        coordinator.job_status(child.run_id)

    monkeypatch.setattr(LedgerStore, "append_in_session", staticmethod(append))
    uow.submit_checkpoint_fork(
        published_child, parent_run_id=parent.run_id,
        checkpoint_id="checkpoint-1", actor="operator",
        root_reservation=reservation,
    )
    assert coordinator.job_status(child.run_id)[0] == "queued"
    assert investigation.unsettled_reservation_ids(child.run_id, include_run_envelope=True) == [
        reservation.reservation_id,
    ]
    assert [event.event_type for event in ledger.events(parent.run_id)] == ["run.checkpoint_forked"]
    assert [event.event_type for event in ledger.events(child.run_id)] == ["run.checkpoint_forked"]
    assert ledger.verify(parent.run_id)
    assert ledger.verify(child.run_id)
