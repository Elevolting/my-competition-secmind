from __future__ import annotations

import asyncio
import errno
import hashlib
import json
import os
import shutil
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from security_agent.question_bank import QUESTION_TYPE_MODULES, QuestionBankService
from security_agent.schemas import (
    AttachmentRef,
    BatchCreateRequest,
    BatchStatus,
    BatchTaskStatus,
    RunStatus,
    TaskRequest,
)
from security_agent.service import RunService

TERMINAL_RUNS = {RunStatus.COMPLETED, RunStatus.PARTIAL, RunStatus.FAILED, RunStatus.DENIED}


class BatchError(ValueError):
    pass


@contextmanager
def _batch_lock(path: Path, *, wait: bool):
    """Use an OS lock so a crashed coordinator releases its batch ownership."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
        deadline = time.monotonic() + 30 if wait else 0
        acquired = False
        while not acquired:
            try:
                if os.name == "nt":
                    import msvcrt

                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN} and getattr(exc, "winerror", None) not in {33, 36}:
                    raise
                if not wait:
                    yield False
                    return
                if time.monotonic() >= deadline:
                    raise BatchError("题库批次正由另一进程创建，请稍后重试") from exc
                time.sleep(0.02)
        try:
            yield True
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


class BatchService:
    """Durable batch coordinator built on top of the existing single-run service."""

    def __init__(self, settings: Any, question_banks: QuestionBankService, runs: RunService) -> None:
        self.settings = settings
        self.question_banks = question_banks
        self.runs = runs
        self.root = settings.run_root / "batches"
        self.root.mkdir(parents=True, exist_ok=True)
        self._tasks: set[asyncio.Task[Any]] = set()
        self._active_batches: set[str] = set()

    def create(self, request: BatchCreateRequest, *, request_id: str | None = None) -> dict[str, Any]:
        record, questions = self._create_locked_record(request, request_id=request_id)
        if questions is not None:
            self._spawn_dispatch(record, questions)
        return record

    async def create_async(self, request: BatchCreateRequest, *, request_id: str | None = None) -> dict[str, Any]:
        record, questions = await asyncio.to_thread(self._create_locked_record, request, request_id=request_id)
        if questions is not None:
            self._spawn_dispatch(record, questions)
        return record

    def _spawn_dispatch(self, record: dict[str, Any], questions: list[dict[str, Any]]) -> None:
        batch_id = record["batch_id"]
        if batch_id in self._active_batches:
            return
        self._active_batches.add(batch_id)
        async def dispatch() -> None:
            try:
                await self._dispatch(batch_id, questions, record)
            finally:
                self._active_batches.discard(batch_id)
        self._spawn(dispatch())

    def _create_locked_record(self, request: BatchCreateRequest, *, request_id: str | None = None
                              ) -> tuple[dict[str, Any], list[dict[str, Any]] | None]:
        lock_name = str(uuid5(NAMESPACE_URL, f"question-bank-batch:{request_id}")) if request_id else str(uuid4())
        with _batch_lock(self.root / ".create" / f"{lock_name}.lock", wait=True):
            return self._create_record_unlocked(request, request_id=request_id)

    def _create_record_unlocked(self, request: BatchCreateRequest, *, request_id: str | None = None
                                ) -> tuple[dict[str, Any], list[dict[str, Any]] | None]:
        try:
            bank_id = str(UUID(request.question_bank_id))
        except ValueError as exc:
            raise BatchError("无效的题库 ID") from exc
        batch_id = str(uuid5(NAMESPACE_URL, f"question-bank-batch:{request_id}")) if request_id else str(uuid4())
        request_payload = request.model_dump(mode="json")
        try:
            existing = self.get(batch_id)
        except KeyError:
            existing = None
        if existing is not None:
            if existing.get("request_payload") != request_payload:
                raise BatchError("请求 ID 已绑定另一项题库批次，拒绝重复创建")
            questions = existing.get("question_snapshot")
            if existing.get("status") in {BatchStatus.DISPATCHING.value, BatchStatus.RUNNING.value}:
                if not isinstance(questions, list) or not questions:
                    questions = self.question_banks.execution_questions(bank_id)
                return existing, questions
            return existing, None
        questions = self.question_banks.execution_questions(bank_id)
        ids = {q["id"] for q in questions}
        graph = {q["id"]: set(q.get("depends_on", [])) for q in questions}
        if any(dep not in ids for deps in graph.values() for dep in deps):
            raise BatchError("题目依赖引用了不存在的题目 ID")
        visiting: set[str] = set()
        visited: set[str] = set()
        def visit(node: str) -> None:
            if node in visiting:
                raise BatchError("题目依赖关系存在环")
            if node in visited:
                return
            visiting.add(node)
            for dep in graph[node]:
                visit(dep)
            visiting.remove(node)
            visited.add(node)
        for node in graph:
            visit(node)
        inspection = self.question_banks.get(bank_id)
        execution = inspection.get("formatted_metadata", {}).get("body", {}).get("execution", {})
        parallel = request.execution.parallel if request.execution.parallel is not None else bool(execution.get("parallel", False))
        max_concurrency = request.execution.max_concurrency or int(execution.get("max_concurrency", 1) or 1)
        if max_concurrency < 1 or max_concurrency > 64:
            raise BatchError("max_concurrency 超出范围")
        record = {
            "schema_version": "1.0",
            "batch_id": batch_id,
            "bank_id": bank_id,
            "request_payload": request_payload,
            "status": BatchStatus.DISPATCHING.value,
            "parallel": parallel,
            "max_concurrency": max_concurrency,
            "created_at": datetime.now(UTC).isoformat(),
            "completed_at": None,
            "question_snapshot": questions,
            "tasks": [],
        }
        for question in questions:
            task_id = str(uuid4())
            route = QUESTION_TYPE_MODULES.get(question["type"], "code_audit")
            task = {
                "task_id": task_id,
                "question_id": question["id"],
                "name": question["name"],
                "module_route": route,
                "depends_on": question.get("depends_on", []),
                "status": BatchTaskStatus.PENDING.value,
                "run_id": None,
                "root": question["root"],
                "workspace": f"batches/{batch_id}/tasks/{task_id}/input",
                "error": None,
                "result": None,
            }
            record["tasks"].append(task)
        self._save(record)
        for task in record["tasks"]:
            self._write_task(batch_id, task)
        self._append_event(batch_id, "batch.created", {"question_count": len(questions)})
        return self.get(batch_id), questions

    def get(self, batch_id: str) -> dict[str, Any]:
        try:
            normalized = str(UUID(batch_id))
        except ValueError as exc:
            raise KeyError(batch_id) from exc
        path = self.root / f"{normalized}.json"
        if not path.is_file():
            raise KeyError(batch_id)
        return json.loads(path.read_text(encoding="utf-8"))

    def list_tasks(self, batch_id: str) -> list[dict[str, Any]]:
        return self.get(batch_id).get("tasks", [])

    def contains_run(self, run_id: str) -> bool:
        for path in self.root.glob("*.json"):
            record = json.loads(path.read_text(encoding="utf-8"))
            if any(task.get("run_id") == run_id for task in record.get("tasks", [])):
                return True
        return False

    async def recover_incomplete(self) -> None:
        for path in self.root.glob("*.json"):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
                if record.get("status") not in {BatchStatus.DISPATCHING.value, BatchStatus.RUNNING.value}:
                    continue
                questions = record.get("question_snapshot")
                if not isinstance(questions, list) or not questions:
                    questions = self.question_banks.execution_questions(record["bank_id"])
                self._spawn_dispatch(record, questions)
            except (OSError, ValueError, KeyError, BatchError):
                continue

    async def _dispatch(self, batch_id: str, questions: list[dict[str, Any]], record: dict[str, Any]) -> None:
        lock_path = self.root / ".dispatch" / f"{batch_id}.lock"
        while True:
            with _batch_lock(lock_path, wait=False) as acquired:
                if acquired:
                    current = self.get(batch_id)
                    if current["status"] not in {BatchStatus.DISPATCHING.value, BatchStatus.RUNNING.value}:
                        return
                    return await self._dispatch_unlocked(batch_id, questions, record)
            await asyncio.sleep(0.25)

    async def _dispatch_unlocked(self, batch_id: str, questions: list[dict[str, Any]], record: dict[str, Any]) -> None:
        record = self.get(batch_id)
        record["status"] = BatchStatus.RUNNING.value
        self._save(record)
        sem = asyncio.Semaphore(int(record["max_concurrency"]) if record["parallel"] else 1)
        question_by_id = {q["id"]: q for q in questions}

        async def run_one(task: dict[str, Any]) -> None:
            terminal_tasks = {
                BatchTaskStatus.SUCCEEDED.value, BatchTaskStatus.PARTIAL.value,
                BatchTaskStatus.DENIED.value, BatchTaskStatus.FAILED.value,
                BatchTaskStatus.BLOCKED.value, BatchTaskStatus.CANCELLED.value,
            }
            if task["status"] in terminal_tasks:
                return
            dependencies = set(task.get("depends_on", []))
            while dependencies:
                current = self.get(batch_id)
                dependency_tasks = {item["question_id"]: item for item in current["tasks"]}
                if any(dependency_tasks.get(dep, {}).get("status") in {BatchTaskStatus.FAILED.value, BatchTaskStatus.DENIED.value, BatchTaskStatus.BLOCKED.value} for dep in dependencies):
                    task["status"] = BatchTaskStatus.BLOCKED.value
                    task["error"] = "依赖题目未成功完成"
                    self._update_task(batch_id, task)
                    return
                if all(dependency_tasks.get(dep, {}).get("status") in {BatchTaskStatus.SUCCEEDED.value, BatchTaskStatus.PARTIAL.value} for dep in dependencies):
                    break
                await asyncio.sleep(0.05)
            async with sem:
                if task["status"] in terminal_tasks:
                    return
                question = question_by_id[task["question_id"]]
                task["status"] = BatchTaskStatus.QUEUED.value
                self._update_task(batch_id, task)
                try:
                    run_id = task.get("run_id")
                    if not run_id or self.runs.ledger.load_state(run_id) is None:
                        input_dir = self._materialize(record["bank_id"], batch_id, task["task_id"], question)
                        request = TaskRequest(
                            name=question["name"],
                            objective=question["objective"] or question["name"],
                            attachments=[AttachmentRef(
                                ref=str(input_dir.relative_to(self.settings.input_root)), name=task["task_id"]
                            )],
                            target_scope=question.get("target_scope", []),
                            constraints=question.get("constraints", []),
                            expected_outputs=question.get("expected_outputs", ["security_report"]),
                            autonomy_policy="automatic",
                        )
                        run_id = run_id or str(uuid4())
                        task["run_id"] = run_id
                        self._update_task(batch_id, task)
                        self.runs.submit(request, run_id=run_id)
                    task["status"] = BatchTaskStatus.RUNNING.value
                    self._update_task(batch_id, task)
                    while True:
                        await asyncio.sleep(0.05)
                        state = self.runs.state(run_id)
                        if state.status in TERMINAL_RUNS:
                            task["status"] = {
                                RunStatus.COMPLETED: BatchTaskStatus.SUCCEEDED.value,
                                RunStatus.PARTIAL: BatchTaskStatus.PARTIAL.value,
                                RunStatus.DENIED: BatchTaskStatus.DENIED.value,
                                RunStatus.FAILED: BatchTaskStatus.FAILED.value,
                            }[state.status]
                            task["result"] = state.report.model_dump(mode="json") if state.report else None
                            task["error"] = state.last_error
                            self._update_task(batch_id, task)
                            self._export_run_events(batch_id, task["task_id"], run_id)
                            break
                except Exception as exc:
                    task["status"] = BatchTaskStatus.FAILED.value
                    task["error"] = f"{type(exc).__name__}: {exc}"
                    self._update_task(batch_id, task)
                self._append_event(batch_id, "task.completed", {"task_id": task["task_id"], "status": task["status"]})

        await asyncio.gather(*(run_one(task) for task in record["tasks"]))
        record = self.get(batch_id)
        statuses = [item["status"] for item in record["tasks"]]
        if all(status == BatchTaskStatus.SUCCEEDED.value for status in statuses):
            record["status"] = BatchStatus.COMPLETED.value
        elif any(status in {BatchTaskStatus.SUCCEEDED.value, BatchTaskStatus.PARTIAL.value} for status in statuses):
            record["status"] = BatchStatus.PARTIAL_FAILED.value
        else:
            record["status"] = BatchStatus.FAILED.value
        record["completed_at"] = datetime.now(UTC).isoformat()
        record["summary"] = {status: statuses.count(status) for status in sorted(set(statuses))}
        self._save(record)
        self._append_event(batch_id, "batch.completed", {"status": record["status"], "summary": record["summary"]})

    def _materialize(self, bank_id: str, batch_id: str, task_id: str, question: dict[str, Any]) -> Path:
        source_root = self.question_banks._workspace(bank_id) / "extracted"
        destination = self.settings.input_root / "batches" / batch_id / "tasks" / task_id / "input"
        if destination.is_symlink():
            raise BatchError("批量任务输入目录不能是符号链接")
        if destination.exists():
            shutil.rmtree(destination)
        destination.mkdir(parents=True, exist_ok=True)
        task_root = self.root / batch_id / "tasks" / task_id
        (task_root / "evidence").mkdir(parents=True, exist_ok=True)
        (task_root / "events.jsonl").touch(exist_ok=True)
        root = PurePosixPath(question["root"])
        source_root_resolved = source_root.resolve()
        destination_root_resolved = destination.resolve()
        for item in question.get("files", []):
            source = source_root / PurePosixPath(item["path"])
            try:
                source_resolved = source.resolve(strict=True)
                source_resolved.relative_to(source_root_resolved)
                relative = PurePosixPath(item["path"]).relative_to(root)
                target = destination / relative
                target.resolve().relative_to(destination_root_resolved)
            except (OSError, ValueError) as exc:
                raise BatchError(f"题库输入路径越界或不可用：{item['path']}") from exc
            target.parent.mkdir(parents=True, exist_ok=True)
            if not source.is_file() or source.is_symlink():
                raise BatchError(f"题目输入文件不可用：{item['path']}")
            expected_sha256 = item.get("sha256")
            if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
                raise BatchError(f"题库输入文件缺少确认摘要：{item['path']}")
            digest = hashlib.sha256()
            with source.open("rb") as reader, target.open("xb") as writer:
                for chunk in iter(lambda: reader.read(1024 * 1024), b""):
                    digest.update(chunk)
                    writer.write(chunk)
            if digest.hexdigest() != expected_sha256:
                target.unlink(missing_ok=True)
                raise BatchError(f"题库输入文件摘要已变化：{item['path']}")
        return destination

    def _write_task(self, batch_id: str, task: dict[str, Any]) -> None:
        task_root = self.root / batch_id / "tasks" / task["task_id"]
        task_root.mkdir(parents=True, exist_ok=True)
        (task_root / "task.json").write_text(json.dumps(task, ensure_ascii=False, indent=2), encoding="utf-8")
        (task_root / "status.json").write_text(
            json.dumps({"task_id": task["task_id"], "question_id": task["question_id"], "status": task["status"], "run_id": task.get("run_id"), "error": task.get("error")}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        if task.get("result") is not None:
            (task_root / "result.json").write_text(json.dumps(task["result"], ensure_ascii=False, indent=2), encoding="utf-8")

    def _update_task(self, batch_id: str, task: dict[str, Any]) -> None:
        self._write_task(batch_id, task)
        record = self.get(batch_id)
        for index, item in enumerate(record["tasks"]):
            if item["task_id"] == task["task_id"]:
                record["tasks"][index] = task
                break
        self._save(record)

    def _save(self, record: dict[str, Any]) -> None:
        path = self.root / f"{record['batch_id']}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.{uuid4().hex}.tmp")
        try:
            tmp.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(path)
        finally:
            tmp.unlink(missing_ok=True)

    def _append_event(self, batch_id: str, event_type: str, payload: dict[str, Any]) -> None:
        path = self.root / batch_id / "batch-events.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"timestamp": datetime.now(UTC).isoformat(), "type": event_type, **payload}, ensure_ascii=False) + "\n")

    def _export_run_events(self, batch_id: str, task_id: str, run_id: str) -> None:
        path = self.root / batch_id / "tasks" / task_id / "events.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as stream:
            for event in self.runs.ledger.events(run_id, limit=1_000_000):
                stream.write(event.model_dump_json() + "\n")

    def _spawn(self, coroutine: Any) -> None:
        task = asyncio.create_task(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def shutdown(self) -> None:
        for task in tuple(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)
