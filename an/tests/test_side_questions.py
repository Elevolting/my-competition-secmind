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

    async def answer(context, question, _on_delta):
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

    async def answer(_context, _question, _on_delta):
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


def test_output_events_are_ordered_and_clear_fences_late_chunks():
    store, parent, configuration, snapshot = setup_store()
    reserved = store.reserve(
        parent=parent, snapshot_id=snapshot["snapshot_id"], configuration=configuration,
        request_key="question-stream", question="流式回答", estimated_input_tokens=10,
    )
    question_id = reserved["question_id"]
    store.mark_running(question_id)
    store.append_output(question_id, "第一段", clear_version=0)
    store.append_output(question_id, "第二段", clear_version=0)
    cleared = store.clear_output(question_id)
    assert cleared["clear_version"] == 1
    with pytest.raises(SideQuestionConflict):
        store.append_output(question_id, "迟到片段", clear_version=0)
    store.append_output(question_id, "新回答", clear_version=1)
    assert store.get(question_id)["answer"] == "新回答"
    assert [event["type"] for event in store.output_events(question_id)] == ["delta", "delta", "clear", "delta"]
    assert [event["sequence"] for event in store.output_events(question_id)] == [1, 2, 3, 4]


@pytest.mark.asyncio
async def test_runner_publishes_partial_answer_before_model_finishes():
    store, parent, configuration, snapshot = setup_store()
    first_chunk = asyncio.Event()
    release = asyncio.Event()

    async def answer(_context, _question, on_delta):
        await on_delta("第一段")
        first_chunk.set()
        await release.wait()
        await on_delta("第二段")
        return "第一段第二段", SideQuestionBudget(15, 8, 1)

    task = asyncio.create_task(SideQuestionRunner(store).ask(
        parent=parent, snapshot_id=snapshot["snapshot_id"], configuration=configuration,
        request_key="partial-stream", question="实时回答", estimated_input_tokens=20, call_model=answer,
    ))
    await first_chunk.wait()
    with Session(store.engine) as session:
        question_id = session.scalars(select(SideQuestionRow.question_id).where(
            SideQuestionRow.request_key == "partial-stream"
        )).one()
    partial = store.get(question_id)
    assert partial["status"] == "running"
    assert partial["answer"] == "第一段"
    assert [event["text"] for event in store.output_events(question_id)] == ["第一段"]
    release.set()
    result = await task
    assert result.status == "completed"
    assert result.answer == "第一段第二段"
    assert [event["delta"] for event in store.output_events(question_id)] == ["第一段", "第二段"]


@pytest.mark.asyncio
async def test_completed_answer_can_be_cleared_without_changing_status_or_usage():
    store, parent, configuration, snapshot = setup_store()

    async def answer(_context, _question, on_delta):
        await on_delta("回答")
        return "回答", SideQuestionBudget(10, 4, 1)

    result = await SideQuestionRunner(store).ask(
        parent=parent, snapshot_id=snapshot["snapshot_id"], configuration=configuration,
        request_key="clear-completed", question="可以清除吗？", estimated_input_tokens=20, call_model=answer,
    )
    cleared = store.clear_output(result.question_id)
    assert cleared["status"] == "completed"
    assert cleared["answer"] is None
    assert cleared["settled"] == {"input_tokens": 10, "output_tokens": 4, "provider_requests": 1}
    assert [event["type"] for event in store.output_events(result.question_id)] == ["delta", "clear"]


@pytest.mark.asyncio
async def test_restart_marks_running_interrupted_and_does_not_replay():
    store, parent, configuration, snapshot = setup_store()
    reserved = store.reserve(
        parent=parent, snapshot_id=snapshot["snapshot_id"], configuration=configuration,
        request_key="question-restart", question="重启后怎么办？", estimated_input_tokens=10,
    )
    question_id = reserved["question_id"]
    store.mark_running(question_id)
    store.append_output(question_id, "已经收到", clear_version=0)
    store.record_usage(question_id, SideQuestionBudget(5, 4, 1))
    assert store.interrupt_running() == 1
    interrupted = store.get(question_id)
    assert interrupted["status"] == "interrupted"
    assert interrupted["answer"] == "已经收到"
    assert interrupted["settled"] == {"input_tokens": 5, "output_tokens": 4, "provider_requests": 1}

    calls = 0

    async def should_not_run(_context, _question, _on_delta):
        nonlocal calls
        calls += 1
        raise AssertionError("interrupted side question must not be replayed")

    result = await SideQuestionRunner(store).ask(
        parent=parent, snapshot_id=snapshot["snapshot_id"], configuration=configuration,
        request_key="question-restart", question="重启后怎么办？", estimated_input_tokens=10,
        call_model=should_not_run,
    )
    assert result.status == "interrupted"
    assert result.answer == "已经收到"
    assert calls == 0
