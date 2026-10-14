from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from types import SimpleNamespace
from uuid import uuid4

import pytest

from security_agent.batch import BatchError, BatchService
from security_agent.schemas import AgentState, BatchCreateRequest, BatchTaskStatus, RunStatus, TaskRequest


class FakeQuestionBanks:
    def __init__(self, root):
        self.root = root

    def _workspace(self, bank_id):
        return self.root / bank_id


def _record(batch_id, bank_id, task_id, run_id):
    return {
        "batch_id": batch_id,
        "bank_id": bank_id,
        "status": "running",
        "parallel": False,
        "max_concurrency": 1,
        "tasks": [{
            "task_id": task_id,
            "question_id": "q1",
            "name": "question",
            "module_route": "code_audit",
            "depends_on": [],
            "status": BatchTaskStatus.RUNNING.value,
            "run_id": run_id,
            "root": "questions/q1",
            "error": None,
            "result": None,
        }],
    }


def _question():
    return {
        "id": "q1", "name": "question", "objective": "audit input",
        "root": "questions/q1", "type": "code_audit", "files": [],
    }


@pytest.mark.asyncio
async def test_batch_create_request_id_returns_original_batch(settings, monkeypatch):
    settings.prepare_directories()
    bank_id = str(uuid4())
    banks = FakeQuestionBanks(settings.question_bank_root)
    banks.execution_questions = lambda _bank_id: [_question()]
    banks.get = lambda _bank_id: {}
    batches = BatchService(settings, banks, None)
    dispatched = []
    monkeypatch.setattr(batches, "_spawn", lambda coroutine: (dispatched.append(coroutine), coroutine.close()))
    request = BatchCreateRequest(question_bank_id=bank_id)

    first = batches.create(request, request_id="batch-request-001")
    replay = batches.create(request, request_id="batch-request-001")

    assert replay["batch_id"] == first["batch_id"]
    assert replay["tasks"] == first["tasks"]
    assert len(dispatched) == 1
    with pytest.raises(BatchError, match="请求 ID 已绑定"):
        batches.create(BatchCreateRequest(question_bank_id=str(uuid4())), request_id="batch-request-001")


@pytest.mark.asyncio
async def test_batch_retry_resumes_saved_batch_after_dispatch_was_lost(settings, monkeypatch):
    settings.prepare_directories()
    bank_id = str(uuid4())
    banks = FakeQuestionBanks(settings.question_bank_root)
    banks.execution_questions = lambda _bank_id: [_question()]
    banks.get = lambda _bank_id: {}
    request = BatchCreateRequest(question_bank_id=bank_id)
    first = BatchService(settings, banks, None)
    monkeypatch.setattr(first, "_spawn", lambda coroutine: coroutine.close())
    saved = first.create(request, request_id="batch-recovery-request-001")

    restarted = BatchService(settings, banks, None)
    resumed = []
    monkeypatch.setattr(restarted, "_spawn", lambda coroutine: (resumed.append(coroutine), coroutine.close()))
    replay = restarted.create(request, request_id="batch-recovery-request-001")

    assert replay["batch_id"] == saved["batch_id"]
    assert replay["tasks"] == saved["tasks"]
    assert len(resumed) == 1


def test_batch_create_request_id_across_processes(settings, tmp_path):
    settings.prepare_directories()
    bank_id = str(uuid4())
    gate = tmp_path / "start"
    observations = tmp_path / "question-loads.txt"
    script = """
import json, sys, time
from pathlib import Path
from security_agent.batch import BatchService
from security_agent.config import Settings
from security_agent.schemas import BatchCreateRequest

root, bank_id, gate, observations = sys.argv[1:]
settings = Settings(run_root=Path(root) / 'runs', input_root=Path(root) / 'inputs',
                    question_bank_root=Path(root) / 'banks')
settings.prepare_directories()
class Banks:
    def execution_questions(self, _bank_id):
        with open(observations, 'a', encoding='utf-8') as stream:
            stream.write('load\\n')
        time.sleep(0.15)
        return [{'id': 'q1', 'name': 'question', 'objective': 'audit input',
                 'root': 'questions/q1', 'type': 'code_audit', 'files': []}]
    def get(self, _bank_id):
        return {}
batches = BatchService(settings, Banks(), None)
batches._spawn = lambda coroutine: coroutine.close()
while not Path(gate).exists():
    time.sleep(0.01)
result = batches.create(BatchCreateRequest(question_bank_id=bank_id), request_id='batch-process-request-001')
print(json.dumps({'batch_id': result['batch_id'], 'tasks': result['tasks']}))
"""
    command = [sys.executable, "-c", script, str(tmp_path), bank_id, str(gate), str(observations)]
    processes = [subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
    gate.touch()
    results = []
    for process in processes:
        output, error = process.communicate(timeout=20)
        assert process.returncode == 0, error
        results.append(json.loads(output))
    assert results[0] == results[1]
    assert observations.read_text(encoding="utf-8").splitlines() == ["load"]


def test_batch_lookup_rejects_path_fragments(settings):
    settings.prepare_directories()
    batches = BatchService(settings, FakeQuestionBanks(settings.question_bank_root), None)
    for value in ("../outside", "..\\outside", "../../private", "not-a-uuid"):
        with pytest.raises(KeyError):
            batches.get(value)


@pytest.mark.asyncio
async def test_parallel_coordinators_submit_batch_task_once(settings, monkeypatch):
    settings.prepare_directories()
    batch_id, bank_id, task_id = (str(uuid4()) for _ in range(3))
    input_dir = settings.input_root / "batches" / batch_id / "tasks" / task_id / "input"
    input_dir.mkdir(parents=True)
    submitted = []
    state = AgentState(run_id=str(uuid4()), task=TaskRequest(objective="audit input"), status=RunStatus.COMPLETED)
    runs = SimpleNamespace(
        ledger=SimpleNamespace(load_state=lambda _id: None, events=lambda _id, limit: []),
        state=lambda _id: state,
        submit=lambda _request, *, run_id: submitted.append(run_id),
    )
    first = BatchService(settings, FakeQuestionBanks(settings.question_bank_root), runs)
    second = BatchService(settings, FakeQuestionBanks(settings.question_bank_root), runs)
    record = _record(batch_id, bank_id, task_id, None)
    first._save(record)
    monkeypatch.setattr(first, "_materialize", lambda *_args: input_dir)
    monkeypatch.setattr(second, "_materialize", lambda *_args: input_dir)

    await asyncio.gather(first._dispatch(batch_id, [_question()], record),
                         second._dispatch(batch_id, [_question()], record))

    assert len(submitted) == 1
    assert first.get(batch_id)["tasks"][0]["run_id"] == submitted[0]
    assert first.get(batch_id)["status"] == "completed"


@pytest.mark.asyncio
async def test_batch_recovery_observes_existing_run_without_replacing_input(settings, monkeypatch):
    settings.prepare_directories()
    batch_id, bank_id, task_id, run_id = (str(uuid4()) for _ in range(4))
    input_dir = settings.input_root / "batches" / batch_id / "tasks" / task_id / "input"
    input_dir.mkdir(parents=True)
    marker = input_dir / "marker.txt"
    marker.write_text("existing input", encoding="utf-8")
    state = AgentState(run_id=run_id, task=TaskRequest(objective="audit input"), status=RunStatus.COMPLETED)
    runs = SimpleNamespace(
        ledger=SimpleNamespace(load_state=lambda _id: state, events=lambda _id, limit: []),
        state=lambda _id: state,
        submit=lambda *_args, **_kwargs: pytest.fail("existing run was submitted again"),
    )
    batches = BatchService(settings, FakeQuestionBanks(settings.question_bank_root), runs)
    batches._save(_record(batch_id, bank_id, task_id, run_id))
    monkeypatch.setattr(batches, "_materialize", lambda *_args: pytest.fail("existing input was rebuilt"))

    await batches._dispatch(batch_id, [_question()], {})

    assert marker.read_text(encoding="utf-8") == "existing input"
    assert batches.get(batch_id)["tasks"][0]["status"] == BatchTaskStatus.SUCCEEDED.value


@pytest.mark.asyncio
async def test_batch_recovery_uses_saved_questions_when_bank_is_unavailable(settings):
    settings.prepare_directories()
    batch_id, bank_id, task_id, run_id = (str(uuid4()) for _ in range(4))
    state = AgentState(run_id=run_id, task=TaskRequest(objective="audit input"), status=RunStatus.COMPLETED)
    runs = SimpleNamespace(
        ledger=SimpleNamespace(load_state=lambda _id: state, events=lambda _id, limit: []),
        state=lambda _id: state,
        submit=lambda *_args, **_kwargs: pytest.fail("existing run was submitted again"),
    )
    banks = FakeQuestionBanks(settings.question_bank_root)
    batches = BatchService(settings, banks, runs)
    record = _record(batch_id, bank_id, task_id, run_id)
    record["question_snapshot"] = [_question()]
    batches._save(record)

    await batches.recover_incomplete()
    await asyncio.gather(*tuple(batches._tasks))

    assert batches.get(batch_id)["tasks"][0]["status"] == BatchTaskStatus.SUCCEEDED.value


@pytest.mark.asyncio
async def test_batch_persists_run_id_before_submission(settings, monkeypatch):
    settings.prepare_directories()
    batch_id, bank_id, task_id = (str(uuid4()) for _ in range(3))
    batches = BatchService(settings, FakeQuestionBanks(settings.question_bank_root), None)

    def submit(_request, *, run_id):
        assert batches.get(batch_id)["tasks"][0]["run_id"] == run_id
        raise RuntimeError("submission interrupted")

    batches.runs = SimpleNamespace(
        ledger=SimpleNamespace(load_state=lambda _id: None), submit=submit,
    )
    batches._save(_record(batch_id, bank_id, task_id, None))
    input_dir = settings.input_root / "batches" / batch_id / "tasks" / task_id / "input"
    input_dir.mkdir(parents=True)
    monkeypatch.setattr(batches, "_materialize", lambda *_args: input_dir)

    await batches._dispatch(batch_id, [_question()], {})

    task = batches.get(batch_id)["tasks"][0]
    assert task["run_id"]
    assert task["status"] == BatchTaskStatus.FAILED.value


@pytest.mark.asyncio
async def test_batch_recovery_does_not_retry_failed_task(settings):
    settings.prepare_directories()
    batch_id, bank_id, task_id = (str(uuid4()) for _ in range(3))
    record = _record(batch_id, bank_id, task_id, None)
    record["tasks"][0]["status"] = BatchTaskStatus.FAILED.value
    record["tasks"][0]["error"] = "prior failure"
    record["tasks"][0]["depends_on"] = ["pending-dependency"]
    runs = SimpleNamespace(
        ledger=SimpleNamespace(load_state=lambda _id: pytest.fail("failed task was read")),
        submit=lambda *_args, **_kwargs: pytest.fail("failed task was submitted"),
    )
    batches = BatchService(settings, FakeQuestionBanks(settings.question_bank_root), runs)
    batches._save(record)

    await batches._dispatch(batch_id, [_question()], {})

    task = batches.get(batch_id)["tasks"][0]
    assert task["status"] == BatchTaskStatus.FAILED.value
    assert task["error"] == "prior failure"
