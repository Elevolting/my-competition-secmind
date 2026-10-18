from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from security_agent.config import Settings
from security_agent.ingest import sha256_file
from security_agent.schemas import (
    AgentState,
    BenchmarkTaskSummary,
    EvaluationCreateRequest,
    EvaluationJob,
    EvaluationMode,
    EvaluationStatus,
    RunStatus,
    TaskRequest,
)
from security_agent.service import RunService


class EvaluationError(ValueError):
    pass


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvaluationError("Benchmark metadata is unavailable or invalid") from exc
    if not isinstance(value, dict):
        raise EvaluationError("Benchmark metadata must be a JSON object")
    return value


class BenchmarkCatalog:

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _manifest(self) -> tuple[Path, dict[str, Any]]:
        root = self.settings.benchmark_dataset_root
        if root is None or not root.is_dir():
            raise EvaluationError("Test3.0 public dataset is not configured")
        matches: list[tuple[Path, dict[str, Any]]] = []
        for path in root.rglob("manifest.json"):
            value = _read_object(path)
            if value.get("suite") == "S-Suite" and isinstance(value.get("cases"), list):
                matches.append((path, value))
        if len(matches) != 1:
            raise EvaluationError("Expected exactly one registered S-Suite manifest")
        path, manifest = matches[0]
        if manifest.get("dataset_version") != self.settings.benchmark_dataset_version:
            raise EvaluationError("Registered benchmark dataset version does not match the runtime")
        return path, manifest

    def list_tasks(self) -> list[BenchmarkTaskSummary]:
        manifest_path, manifest = self._manifest()
        result: list[BenchmarkTaskSummary] = []
        for case in manifest["cases"]:
            task_id = str(case.get("task_id") or "")
            if not task_id.startswith("T3S-"):
                continue
            task_root = manifest_path.parent / "cases" / task_id
            task = _read_object(task_root / "task.json")
            input_manifest_path = task_root / "input_manifest.json"
            input_manifest = _read_object(input_manifest_path)
            files = input_manifest.get("files") or []
            result.append(
                BenchmarkTaskSummary(
                    task_id=task_id,
                    suite="S-Suite",
                    dataset_version=str(task.get("dataset_version") or ""),
                    prompt=str(task.get("prompt") or ""),
                    difficulty=str(task.get("difficulty") or case.get("difficulty") or "unknown"),
                    primary_domain=str(task.get("primary_domain") or case.get("primary_domain") or "unknown"),
                    scoring_mode=str((task.get("required_output") or {}).get("scoring_mode") or "unknown"),
                    input_file_count=len(files),
                    input_size_bytes=sum(int(item.get("size_bytes") or 0) for item in files if isinstance(item, dict)),
                    input_manifest_sha256=sha256_file(input_manifest_path),
                )
            )
        return result

    def prepare_task(
        self,
        task_id: str,
        evaluation_id: str,
        task_name: str | None = None,
    ) -> tuple[TaskRequest, str]:
        manifest_path, manifest = self._manifest()
        cases = {str(item.get("task_id")): item for item in manifest["cases"] if isinstance(item, dict)}
        if task_id not in cases:
            raise EvaluationError("Benchmark task is not registered")
        case_root = (manifest_path.parent / "cases" / task_id).resolve(strict=True)
        task = _read_object(case_root / "task.json")
        input_manifest_path = case_root / "input_manifest.json"
        input_manifest = _read_object(input_manifest_path)
        if task.get("task_id") != task_id or task.get("dataset_version") != self.settings.benchmark_dataset_version:
            raise EvaluationError("Benchmark task identity does not match the registered manifest")
        input_root = (case_root / str((task.get("input") or {}).get("root") or "input")).resolve(strict=True)
        if case_root not in input_root.parents:
            raise EvaluationError("Benchmark input root escapes its registered case")
        files = input_manifest.get("files")
        if not isinstance(files, list):
            raise EvaluationError("Benchmark input manifest has no file list")
        declared: set[str] = set()
        for item in files:
            if not isinstance(item, dict):
                raise EvaluationError("Benchmark input manifest contains an invalid entry")
            relative = Path(str(item.get("path") or ""))
            source = (input_root / relative).resolve(strict=True)
            if input_root not in source.parents or not source.is_file() or source.is_symlink():
                raise EvaluationError("Benchmark input contains an unsafe file reference")
            normalized = relative.as_posix()
            declared.add(normalized)
            if source.stat().st_size != int(item.get("size_bytes") or -1) or sha256_file(source) != item.get("sha256"):
                raise EvaluationError("Benchmark input does not match its immutable manifest")
        observed = {
            path.relative_to(input_root).as_posix()
            for path in input_root.rglob("*")
            if path.is_file() and not path.is_symlink()
        }
        if observed != declared:
            raise EvaluationError("Benchmark input file set does not match its immutable manifest")

        stage = self.settings.input_root / "benchmark" / evaluation_id / task_id
        if stage.exists():
            shutil.rmtree(stage)
        stage.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(input_root, stage)
        reference = stage.relative_to(self.settings.input_root).as_posix()
        request = TaskRequest(
            name=task_name or f"Test3.0 {task_id}",
            objective=str(task.get("prompt") or "Analyze the registered benchmark input."),
            attachments=[{"ref": reference, "name": "input"}],
            target_scope=[f"registered-benchmark:{task_id}"],
            constraints=[
                "Only the staged public input may be read.",
                "No network, exploitation, private evaluator, Gold, solver or oracle access.",
                "Return an evidence-backed report with file and line locators.",
            ],
            expected_outputs=["security_report", "test3_task_result"],
            autonomy_policy="automatic",
        )
        return request, sha256_file(input_manifest_path)


class EvaluationStore:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def directory(self, evaluation_id: str) -> Path:
        return self.root / evaluation_id

    def save(self, job: EvaluationJob) -> None:
        job.updated_at = datetime.now(UTC)
        directory = self.directory(job.evaluation_id)
        directory.mkdir(parents=True, exist_ok=True)
        destination = directory / "job.json"
        temporary = directory / "job.json.tmp"
        temporary.write_text(job.model_dump_json(indent=2), encoding="utf-8")
        os.replace(temporary, destination)

    def load(self, evaluation_id: str) -> EvaluationJob | None:
        path = self.directory(evaluation_id) / "job.json"
        return EvaluationJob.model_validate_json(path.read_text(encoding="utf-8")) if path.is_file() else None

    def list(self) -> list[EvaluationJob]:
        jobs = [self.load(path.parent.name) for path in self.root.glob("*/job.json")]
        return sorted((item for item in jobs if item is not None), key=lambda item: item.updated_at, reverse=True)

    def append_event(self, evaluation_id: str, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        path = self.directory(evaluation_id) / "events.jsonl"
        sequence = 1
        if path.is_file():
            with path.open("r", encoding="utf-8") as stream:
                sequence += sum(1 for line in stream if line.strip())
        event = {
            "event_id": str(uuid4()),
            "evaluation_id": evaluation_id,
            "sequence": sequence,
            "event_type": event_type,
            "timestamp": datetime.now(UTC).isoformat(),
            "payload": payload,
        }
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
        return event

    def events(self, evaluation_id: str, after_sequence: int = 0) -> list[dict[str, Any]]:
        path = self.directory(evaluation_id) / "events.jsonl"
        if not path.is_file():
            return []
        with path.open("r", encoding="utf-8") as stream:
            values = [json.loads(line) for line in stream if line.strip()]
        return [item for item in values if int(item.get("sequence") or 0) > after_sequence]


class EvaluationService:
    def __init__(self, settings: Settings, runs: RunService) -> None:
        self.settings = settings
        self.runs = runs
        self.catalog = BenchmarkCatalog(settings)
        self.store = EvaluationStore(settings.evaluation_root)
        self._tasks: set[asyncio.Task[Any]] = set()
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = {}

    async def create(self, request: EvaluationCreateRequest) -> EvaluationJob:
        evaluation_id = str(uuid4())
        if request.mode != EvaluationMode.BENCHMARK or not request.benchmark_task_id:
            job = EvaluationJob(
                evaluation_id=evaluation_id,
                mode=request.mode,
                dataset_version=request.dataset_version,
                status=EvaluationStatus.UNSCORABLE_NO_GOLD,
                error_code="UNSCORABLE_NO_GOLD",
                error_message="Arbitrary analysis inputs have no registered private Gold.",
            )
            self.store.save(job)
            return job
        if request.dataset_version != self.settings.benchmark_dataset_version:
            raise EvaluationError("Requested dataset version does not match the registered benchmark")
        job = EvaluationJob(
            evaluation_id=evaluation_id,
            mode=request.mode,
            benchmark_task_id=request.benchmark_task_id,
            dataset_version=request.dataset_version,
            status=EvaluationStatus.INPUT_VALIDATING,
            dashboard_url=self.settings.benchmark_dashboard_url or None,
        )
        self.store.save(job)
        await self._emit(job, "evaluation.input.validating", {"task_id": request.benchmark_task_id})
        try:
            task, digest = self.catalog.prepare_task(
                request.benchmark_task_id,
                evaluation_id,
                request.name,
            )
        except EvaluationError:
            job.status = EvaluationStatus.INPUT_MISMATCH
            job.error_code = "INPUT_MISMATCH"
            job.error_message = "Registered benchmark input failed identity or integrity validation."
            self.store.save(job)
            await self._emit(job, "evaluation.input.failed", {"error_code": job.error_code})
            raise
        job.input_manifest_sha256 = digest
        await self._emit(
            job,
            "evaluation.input.validated",
            {
                "task_id": request.benchmark_task_id,
                "dataset_version": request.dataset_version,
                "manifest_sha256": digest,
            },
        )
        job.run_id = self.runs.submit(task)
        job.status = EvaluationStatus.AGENT_QUEUED
        self.store.save(job)
        await self._emit(job, "evaluation.agent.queued", {"run_id": job.run_id})
        self._spawn(self._monitor(job.evaluation_id))
        return job

    async def _monitor(self, evaluation_id: str) -> None:
        job = self.get(evaluation_id)
        if not job.run_id:
            return
        announced = False
        report_wait_started: float | None = None
        while True:
            state = self.runs.state(job.run_id)
            if state.status in {RunStatus.PENDING, RunStatus.RUNNING, RunStatus.WAITING_APPROVAL} or (
                state.status == RunStatus.PARTIAL and state.report is None
            ):
                if not announced and state.status != RunStatus.PENDING:
                    announced = True
                    job.status = EvaluationStatus.AGENT_RUNNING
                    self.store.save(job)
                    await self._emit(job, "evaluation.agent.started", {"run_id": job.run_id})
                if state.status == RunStatus.PARTIAL and state.report is None:
                    report_wait_started = report_wait_started or asyncio.get_running_loop().time()
                    if asyncio.get_running_loop().time() - report_wait_started >= 10:
                        job.status = EvaluationStatus.AGENT_FAILED
                        job.error_code = "AGENT_REPORT_TIMEOUT"
                        job.error_message = "The Agent stopped without producing a scoreable report."
                        self.store.save(job)
                        await self._emit(job, "evaluation.agent.failed", {"run_id": job.run_id})
                        return
                await asyncio.sleep(0.1)
                continue
            if state.report is None or state.status in {RunStatus.FAILED, RunStatus.DENIED}:
                job.status = EvaluationStatus.AGENT_FAILED
                job.error_code = "AGENT_FAILED"
                job.error_message = "The Agent did not produce a scoreable report."
                self.store.save(job)
                await self._emit(job, "evaluation.agent.failed", {"run_id": job.run_id, "status": state.status})
                return
            await self._score(job, state)
            return

    async def _score(self, job: EvaluationJob, state: AgentState) -> None:
        job.status = EvaluationStatus.REPORT_READY
        self.store.save(job)
        await self._emit(job, "evaluation.report.ready", {"run_id": state.run_id})
        directory = self.store.directory(job.evaluation_id)
        submission = self._submission(job, state)
        submission_path = directory / "submission.json"
        self._atomic_json(submission_path, submission)
        job.submission_sha256 = _canonical_sha256(submission)
        job.report_available = False
        job.status = EvaluationStatus.SCORE_QUEUED
        self.store.save(job)
        await self._emit(job, "evaluation.scoring.queued", {"submission_sha256": job.submission_sha256})

        scorer_root = self.settings.benchmark_scorer_root
        private_root = self.settings.benchmark_private_root
        dataset_root = self.settings.benchmark_dataset_root
        if scorer_root is None or private_root is None or dataset_root is None:
            job.status = EvaluationStatus.SCORING_FAILED
            job.error_code = "SCORER_NOT_CONFIGURED"
            job.error_message = "The isolated Test3.0 scorer is not configured."
            self.store.save(job)
            await self._emit(job, "evaluation.scoring.failed", {"error_code": job.error_code})
            return
        job.status = EvaluationStatus.SCORING
        self.store.save(job)
        await self._emit(job, "evaluation.scoring.started", {})
        score_dir = directory / "score"
        score_dir.mkdir(parents=True, exist_ok=True)
        process = await asyncio.create_subprocess_exec(
            self.settings.benchmark_python_executable,
            "-m",
            "benchmark.test3_harness",
            "score",
            "--dataset-root",
            str(dataset_root),
            "--private-root",
            str(private_root),
            "--submission",
            str(submission_path),
            "--output-dir",
            str(score_dir),
            cwd=scorer_root,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
        except TimeoutError:
            process.kill()
            await process.communicate()
            stdout, stderr = b"", b"scoring timeout"
        evaluation_path = score_dir / "evaluation.json"
        if not evaluation_path.is_file():
            job.status = EvaluationStatus.SCORING_FAILED
            job.error_code = "SCORING_FAILED"
            job.error_message = "The isolated scorer did not produce an evaluation."
            self.store.save(job)
            self._write_scorer_telemetry(directory, process.returncode, stdout, stderr)
            await self._emit(job, "evaluation.scoring.failed", {"error_code": job.error_code})
            return
        evaluation = _read_object(evaluation_path)
        task_result = next(
            (item for item in evaluation.get("tasks", []) if item.get("task_id") == job.benchmark_task_id),
            None,
        )
        job.score_available = task_result is not None and task_result.get("score") is not None
        job.task_score = float(task_result["score"]) if job.score_available else None
        job.report_status = str(evaluation.get("report_status") or "INCOMPLETE")
        if task_result and task_result.get("score_status") == "PRIVATE_VERIFIER_REQUIRED":
            job.status = EvaluationStatus.VERIFIER_REQUIRED
        else:
            job.status = EvaluationStatus.SCORED if job.score_available else EvaluationStatus.SCORING_FAILED
        if job.status == EvaluationStatus.SCORING_FAILED:
            job.error_code = "NO_TASK_SCORE"
            job.error_message = "The scorer completed without a score for this task."
        else:
            self._write_public_report(directory, job, task_result)
            job.report_available = True
        self.store.save(job)
        self._write_scorer_telemetry(directory, process.returncode, stdout, stderr)
        await self._emit(
            job,
            "evaluation.scoring.completed"
            if job.status in {EvaluationStatus.SCORED, EvaluationStatus.VERIFIER_REQUIRED}
            else "evaluation.scoring.failed",
            {"task_score": job.task_score, "report_status": job.report_status, "status": job.status},
        )

    def _submission(self, job: EvaluationJob, state: AgentState) -> dict[str, Any]:
        report = state.report
        assert report is not None
        result = {
            "task_id": job.benchmark_task_id,
            "status": "SUCCESS" if state.status == RunStatus.COMPLETED else "PARTIAL",
            "answer": {"final_answer": report.executive_summary},
            "findings": [
                {
                    "finding_id": item.finding_id,
                    "title": item.title,
                    "description": item.description,
                    "root_cause": item.description,
                    "impact": item.severity,
                    "severity": item.severity,
                    "classification": item.rule_id,
                    "cwe": item.rule_id,
                    "path": item.path,
                    "line": item.line,
                    "remediation": item.remediation,
                    "evidence_ids": item.evidence_ids,
                }
                for item in report.findings
            ],
            "evidence": [
                {
                    "evidence_id": item.evidence_id,
                    "source": item.source,
                    "summary": item.summary,
                    "sha256": item.sha256,
                    "path": item.metadata.get("path") or item.artifact_ref,
                    "line": item.metadata.get("line"),
                }
                for item in report.evidence
            ],
            "limitations": report.limitations,
            "usage": {
                "wall_time_seconds": max(0.0, (report.generated_at - state.started_at).total_seconds()),
                "model_tokens": state.budget.prompt_tokens_used + state.budget.completion_tokens_used,
                "input_tokens": state.budget.prompt_tokens_used,
                "output_tokens": state.budget.completion_tokens_used,
                "provider_requests": state.budget.model_calls_used,
                "tool_calls": state.budget.tool_calls_used,
            },
            "decision_summary": {
                "plan": [item.objective for item in state.plan],
                "tool_selection": [tool for item in state.plan for tool in item.tool_candidates],
                "stop_reason": state.status.value,
                "outcome": report.executive_summary,
            },
            "run_proof": {
                "ledger_chain_valid": self.runs.ledger.verify(state.run_id),
                "completion_gate_passed": state.status == RunStatus.COMPLETED,
                "scope_compliant": state.status != RunStatus.DENIED,
                "cleanup_verified": False,
            },
            "violations": [],
        }
        candidate = {
            "candidate_id": self.settings.benchmark_candidate_id,
            "version": self.settings.benchmark_candidate_version,
            "provider": "compatible-api",
            "model_id": self.settings.worker_model,
            "model_parameters_hash": _canonical_sha256(
                {"planner": self.settings.planner_model, "worker": self.settings.worker_model}
            ),
            "tool_bundle_digest": _canonical_sha256(
                sorted(item.name for item in self.runs.orchestrator.broker.registry.manifests())
            ),
            "environment_digest": _canonical_sha256({"schema": "1.0", "agent": "security_agent"}),
            "budget_profile": "workbench-single-task",
            "system_safety_policy_hash": _canonical_sha256(
                {"autonomy": state.task.autonomy_policy, "constraints": state.task.constraints}
            ),
        }
        return {
            "schema_version": "3.0",
            "dataset_version": job.dataset_version,
            "suite": "S-Suite",
            "candidate": candidate,
            "results": [result],
        }

    def get(self, evaluation_id: str) -> EvaluationJob:
        job = self.store.load(evaluation_id)
        if job is None:
            raise KeyError(evaluation_id)
        return job

    def by_run(self, run_id: str) -> EvaluationJob | None:
        return next((item for item in self.store.list() if item.run_id == run_id), None)

    def score(self, evaluation_id: str) -> dict[str, Any]:
        job = self.get(evaluation_id)
        path = self.store.directory(evaluation_id) / "score" / "evaluation.json"
        if not path.is_file():
            raise FileNotFoundError(evaluation_id)
        evaluation = _read_object(path)
        task = next(
            (item for item in evaluation.get("tasks", []) if item.get("task_id") == job.benchmark_task_id),
            None,
        )
        public_task = None
        if task is not None:
            public_task = {
                key: task.get(key)
                for key in (
                    "task_id",
                    "status",
                    "completed",
                    "correct",
                    "score",
                    "score_status",
                    "scoring_mode",
                    "primary_domain",
                    "components",
                    "critical_violation",
                    "fabricated_evidence",
                    "ledger_valid",
                    "prompt_injection_violation",
                )
                if key in task
            }
        return {
            "schema_version": "1.0",
            "evaluation_id": evaluation_id,
            "benchmark_task_id": job.benchmark_task_id,
            "status": job.status,
            "report_status": job.report_status,
            "task_score": job.task_score,
            "task": public_task,
            "suite": evaluation.get("suite"),
            "score_scope": "single_task_provisional",
            "private_values_exported": False,
        }

    def report_path(self, evaluation_id: str) -> Path:
        self.get(evaluation_id)
        path = self.store.directory(evaluation_id) / "evaluation-report.md"
        if not path.is_file():
            raise FileNotFoundError(evaluation_id)
        return path

    async def recover_incomplete(self) -> None:
        active = {
            EvaluationStatus.AGENT_QUEUED,
            EvaluationStatus.AGENT_RUNNING,
            EvaluationStatus.REPORT_READY,
            EvaluationStatus.SCORE_QUEUED,
            EvaluationStatus.SCORING,
        }
        for job in self.store.list():
            if job.status in active and job.run_id:
                self._spawn(self._monitor(job.evaluation_id))
            elif job.status == EvaluationStatus.AGENT_FAILED and job.run_id:
                state = self.runs.state(job.run_id)
                if state.report is not None and state.status not in {RunStatus.FAILED, RunStatus.DENIED}:
                    job.error_code = None
                    job.error_message = None
                    self.store.save(job)
                    self._spawn(self._score(job, state))
            elif (
                job.status == EvaluationStatus.SCORING_FAILED
                and job.error_code == "SCORING_FAILED"
                and job.run_id
            ):
                state = self.runs.state(job.run_id)
                if state.report is not None:
                    job.error_code = None
                    job.error_message = None
                    self.store.save(job)
                    self._spawn(self._score(job, state))

    async def shutdown(self) -> None:
        for task in tuple(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)

    @asynccontextmanager
    async def subscribe(self, evaluation_id: str) -> AsyncIterator[asyncio.Queue[dict[str, Any]]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        self._subscribers.setdefault(evaluation_id, set()).add(queue)
        try:
            yield queue
        finally:
            self._subscribers.get(evaluation_id, set()).discard(queue)

    async def _emit(self, job: EvaluationJob, event_type: str, payload: dict[str, Any]) -> None:
        event = self.store.append_event(job.evaluation_id, event_type, payload)
        for queue in tuple(self._subscribers.get(job.evaluation_id, ())):
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(event)

    def _spawn(self, coroutine: Any) -> None:
        task = asyncio.create_task(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    @staticmethod
    def _atomic_json(path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)

    @staticmethod
    def _write_scorer_telemetry(directory: Path, exit_code: int | None, stdout: bytes, stderr: bytes) -> None:
        EvaluationService._atomic_json(
            directory / "scorer-telemetry.json",
            {
                "exit_code": exit_code,
                "stdout_tail": stdout.decode("utf-8", "replace")[-4000:],
                "stderr_tail": stderr.decode("utf-8", "replace")[-4000:],
            },
        )

    @staticmethod
    def _write_public_report(directory: Path, job: EvaluationJob, task: dict[str, Any] | None) -> None:
        components = (task or {}).get("components") or {}
        component_rows = "\n".join(
            f"| {name} | {float(value):.2f} |" for name, value in sorted(components.items())
        ) or "| - | - |"
        score = "待私有验证" if job.task_score is None else f"{job.task_score:.2f} / 100"
        scoring_status = str((task or {}).get("score_status") or job.status.value)
        content = (
            "# 安全任务单题评分报告\n\n"
            f"- 评测 ID：`{job.evaluation_id}`\n"
            f"- 题目：`{job.benchmark_task_id}`\n"
            f"- 数据版本：`{job.dataset_version}`\n"
            f"- 单题得分：**{score}**\n"
            f"- 判分状态：`{scoring_status}`\n"
            f"- 评分器报告状态：`{job.report_status or 'INCOMPLETE'}`\n\n"
            "## 评分分量\n\n| 分量 | 得分 |\n|---|---:|\n"
            f"{component_rows}\n\n"
            "> 本报告仅表示当前注册题目的临时结果，不是 Full60 正式综合分。"
            "私有 Gold、私有路径与评分器日志均未导出。\n"
        )
        destination = directory / "evaluation-report.md"
        temporary = destination.with_suffix(".md.tmp")
        temporary.write_text(content, encoding="utf-8")
        os.replace(temporary, destination)
