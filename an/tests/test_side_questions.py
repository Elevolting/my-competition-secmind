from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from security_agent.model_snapshots import ModelConfiguration, ModelSnapshotStore, SnapshotParent
from security_agent.side_questions import (
    SideQuestionBudget,
    SideQuestionConflict,
    SideQuestionRow,
    SideQuestionRunner,
    SideQuestionStore,
)


def setup_store():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    snapshots = ModelSnapshotStore(engine, sanitize=lambda value: value)
    parent = SnapshotParent("run-side", "secmind")
    configuration = ModelConfiguration(
        base_url="https://model.test/v1", provider="compatible-api", model_id="model",
        planner_model="model", worker_model="worker", fallback_model="fallback",
    )
    snapshot = snapshots.capture(
        parent=parent, configuration=configuration,
        request={"model": "model", "messages": [{"role": "user", "content": "evidence"}]},
        provenance={"call_id": "primary-1", "attempt": 1},
    )
    store = SideQuestionStore(
        engine, snapshots, sanitize=lambda value: value,
        max_concurrency=1, budget_input_tokens=100, budget_output_tokens=40,
    )
    return store, parent, configuration, snapshot


@pytest.mark.asyncio
async def test_side_question_is_idempotent_and_settles_budget():
    store, parent, configuration, snapshot = setup_store()
    calls = []

    async def answer(context, question):
        calls.append((context["snapshot_id"], question))
        return "依据快照回答", SideQuestionBudget(8, 12, 1)

    runner = SideQuestionRunner(store)
    first = await runner.ask(
        parent=parent, snapshot_id=snapshot["snapshot_id"], configuration=configuration,
        request_key="question-1", question="依据是什么？", estimated_input_tokens=20, call_model=answer,
    )
    second = await runner.ask(
        parent=parent, snapshot_id=snapshot["snapshot_id"], configuration=configuration,
        request_key="question-1", question="依据是什么？", estimated_input_tokens=20, call_model=answer,
    )
    assert first.status == second.status == "completed"
    assert first.answer == second.answer == "依据快照回答"
    assert len(calls) == 1
    assert store.get(first.question_id)["settled"] == {"input_tokens": 8, "output_tokens": 12, "provider_requests": 1}


def test_side_question_request_key_and_configuration_are_fenced():
    store, parent, configuration, snapshot = setup_store()
    store.reserve(
        parent=parent, snapshot_id=snapshot["snapshot_id"], configuration=configuration,
        request_key="question-1", question="one", estimated_input_tokens=10,
    )
    with pytest.raises(SideQuestionConflict):
        store.reserve(
            parent=parent, snapshot_id=snapshot["snapshot_id"], configuration=configuration,
            request_key="question-1", question="two", estimated_input_tokens=10,
        )
    changed = ModelConfiguration(
        base_url=configuration.base_url, provider=configuration.provider, model_id="changed",
        planner_model="changed", worker_model=configuration.worker_model, fallback_model=configuration.fallback_model,
    )
    with pytest.raises(ValueError, match="configuration changed"):
        store.reserve(
            parent=parent, snapshot_id=snapshot["snapshot_id"], configuration=changed,
            request_key="question-2", question="one", estimated_input_tokens=10,
        )


@pytest.mark.asyncio
async def test_running_question_cancel_is_independent_and_late_answer_is_discarded():
    store, parent, configuration, snapshot = setup_store()
    entered = asyncio.Event()
    release = asyncio.Event()

    async def answer(_context, _question):
        entered.set()
        await release.wait()
        return "迟到回答", SideQuestionBudget(10, 10, 1)

    runner = SideQuestionRunner(store)
    task = asyncio.create_task(runner.ask(
        parent=parent, snapshot_id=snapshot["snapshot_id"], configuration=configuration,
        request_key="question-cancel", question="停止吗？", estimated_input_tokens=20, call_model=answer,
    ))
    await entered.wait()
    with Session(store.engine) as session:
        question_id = session.scalars(select(SideQuestionRow.question_id).where(
            SideQuestionRow.request_key == "question-cancel"
        )).one()
    store.cancel(question_id)
    release.set()
    result = await task
    assert result.status == "cancelled"
    assert store.get(question_id)["answer"] is None
