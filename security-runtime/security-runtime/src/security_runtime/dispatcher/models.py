from __future__ import annotations

from dataclasses import dataclass

from security_runtime.dispatcher.runtime.cancellation import TaskCancellation


@dataclass(slots=True)
class RunningTask:
    project_id: str
    task_type: str
    worker_name: str
    cancellation: TaskCancellation
    intent_id: str | None = None
    fact_count: int | None = None
    hint_count: int | None = None
    open_intent_count: int | None = None
    terminal_attempts: tuple[tuple[str, str | None, str], ...] = ()


@dataclass(slots=True)
class ReasonCheckpoint:
    fact_count: int
    hint_count: int
    open_intent_count: int
    terminal_attempts: tuple[tuple[str, str | None, str], ...] = ()
