"""Bounded recovery rules shared by planning, execution and run summaries."""
from typing import Any

from security_agent.schemas import AgentState, RunStatus, ToolStatus


# External Runtime statuses that mean the project finished successfully.  The
# workbench records them under ``external_status``; reading any other key would
# silently treat a finished project as still running.
RUNTIME_SUCCESS_STATUSES = frozenset({"completed", "complete", "succeeded", "success"})


def runtime_observation_succeeded(state: AgentState, item: Any) -> bool:
    """Whether one observation proves asynchronous Runtime work succeeded.

    Adapter submission is not completion: a penetration observation only counts
    once the Runtime project reached a success status *and* the goal was
    independently verified.  ``_runtime_wait`` historically recorded that status
    under ``status`` while ``_penetration_step`` used ``external_status``, so
    read either key rather than losing a finished project.
    """
    if item.status != ToolStatus.SUCCESS or item.data.get("degraded"):
        return False
    if state.module_route != "penetration" or item.data.get("adapter") == "mcp":
        return True
    terminal = item.data.get("external_status") or item.data.get("status")
    return terminal in RUNTIME_SUCCESS_STATUSES and item.data.get("objective_reached") is True


def runtime_goal_completed(state: AgentState) -> bool:
    """Re-derive completion from persisted evidence instead of a stale snapshot.

    Shared by the reporter and the report refresh so a verified flag can never
    stay displayed as ``partial`` after an earlier mis-projection.
    """
    if not any(runtime_observation_succeeded(state, item) for item in state.observations):
        return False
    if state.step_failures or (state.plan and state.current_step_index < len(state.plan)):
        return False
    if state.module_route == "penetration" and "flag" in state.task.objective.casefold():
        workbench = state.external_execution.get("blackboard", {}).get("planning_mode") == "workbench"
        if not (workbench and state.external_execution.get("validated_goal_outputs")):
            return False
    return True


def repeatable_call(manifest, inputs: dict) -> bool:
    if manifest.idempotent:
        return True
    # Review the invocation, not the entire HTTP tool: POST remains non-repeatable.
    return (
        manifest.name == "mcp:local-tscanplus:http_request"
        and str(inputs.get("method", "GET")).upper() in {"GET", "HEAD"}
        and not inputs.get("body")
    )


def transient_failure(result) -> bool:
    text = f"{result.error_code or ''} {result.error_message or ''}".lower()
    return result.status == ToolStatus.TIMEOUT or any(marker in text for marker in (
        "timeout", "timed out", "deadline exceeded", "connection reset", "temporarily unavailable", "transient",
    ))


def retry_blocked_reason(state: AgentState) -> str | None:
    if state.status not in {RunStatus.PARTIAL, RunStatus.FAILED}:
        return "仅部分完成或失败的任务可以重试"
    external = state.external_execution
    board = external.get("blackboard")
    blackboard_terminal = (state.module_route == "penetration" and isinstance(board, dict)
                           and board.get("project_id") == external.get("project_id")
                           and board.get("status") in {"stopped", "completed"})
    if (external.get("project_id") or external.get("remote_run_id")) and not (
        external.get("terminal") is True
        or blackboard_terminal
        or external.get("status") in {
            "completed", "complete", "succeeded", "success", "partial",
            "failed", "denied", "cancelled", "stopped",
        }
    ):
        return "外部任务尚未确认结束，请先刷新最新内容，确认停止后再重试"
    return None


def stop_reason(state: AgentState) -> str | None:
    if state.status not in {RunStatus.PARTIAL, RunStatus.FAILED, RunStatus.DENIED}:
        return None
    budget = state.budget
    # Refreshing an external report can overwrite last_error; retain the actual budget cause.
    if budget.runtime_seconds_used >= budget.max_runtime_seconds:
        return f"运行时间达到 {budget.max_runtime_seconds} 秒上限，任务已停止，现有证据已保留。"
    if state.last_error:
        return state.last_error
    if state.step_failures:
        return "；".join(f"{key}：{value}" for key, value in state.step_failures.items())[:3000]
    for result in reversed(state.observations):
        if result.status in {ToolStatus.ERROR, ToolStatus.TIMEOUT, ToolStatus.DENIED}:
            return result.error_message or result.summary or result.error_code or "工具执行未成功"
    if state.report and state.report.limitations:
        return "；".join(state.report.limitations[:3])[:3000]
    return "尚未取得足以确认目标完成的证据，请查看任务结果与执行摘要。"
