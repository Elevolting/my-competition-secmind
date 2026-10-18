from __future__ import annotations

import logging
import hashlib
import time

from security_runtime.dispatcher.config import DispatchConfig, WorkerConfig
from security_runtime.dispatcher.contracts import parse_json_output, validate_reason_payload
from security_runtime.dispatcher.prompting import (
    format_fact_ids,
    format_open_intents,
    load_prompt,
    render_prompt,
)
from security_runtime.dispatcher.protocol.client import SecurityRuntimeClient, bind_reason_attempt
from security_runtime.dispatcher.runtime.cancellation import TaskCancellation
from security_runtime.dispatcher.runtime.containers import ContainerManager
from security_runtime.dispatcher.runtime.heartbeat import HeartbeatLease
from security_runtime.dispatcher.tasks.common import (
    best_effort_release_reason,
    cancel_reason,
    did_timeout,
    preview,
    run_worker_process,
    task_healthcheck_enabled,
    write_graph_snapshot_reference,
)
from security_runtime.dispatcher.workers.registry import get_driver
from security_runtime.server.models import ProjectDetail
from security_runtime.server.services import planning_snapshot_hash

LOG = logging.getLogger(__name__)


def run_reason_task(
    config: DispatchConfig,
    client: SecurityRuntimeClient,
    container_manager: ContainerManager,
    project: ProjectDetail,
    export_yaml: str,
    worker: WorkerConfig,
    cancellation: TaskCancellation,
) -> str:
    client = bind_reason_attempt(client, project.project.id, project.project.reason_attempt_id)
    driver = get_driver(worker.type, config.runtime.execution)
    task_started = time.perf_counter()
    healthcheck_timeout = config.runtime.healthcheck_timeout
    lease = HeartbeatLease.for_reason(client, project.project.id, worker.name, config.runtime.interval)
    lease.start()
    try:
        if (config.runtime.reason_provider == "workbench"
                and _is_workbench_project(project)):
            return _run_workbench_reason_task(
                config, client, project, worker, cancellation, lease,
            )
        container_name = container_manager.ensure_running(project.project.id)

        if task_healthcheck_enabled(config):
            LOG.info(
                "checking worker health project=%s worker=%s timeout=%ss",
                project.project.id,
                worker.name,
                healthcheck_timeout,
            )
            health = driver.check_health(worker, timeout=healthcheck_timeout)
            if cancellation.is_cancelled:
                LOG.info(
                    "reason cancelled during healthcheck project=%s worker=%s reason=%s",
                    project.project.id,
                    worker.name,
                    cancellation.reason,
                )
                return "cancelled"
            if lease.failure is not None:
                LOG.warning(
                    "heartbeat lost during reason healthcheck project=%s worker=%s status=%s",
                    project.project.id,
                    worker.name,
                    lease.failure.status_code,
                )
                return "failed"
            if not health.ok:
                LOG.warning(
                    "worker unhealthy project=%s worker=%s status=%s detail=%s",
                    project.project.id,
                    worker.name,
                    health.status,
                    health.detail,
                )
                return "unhealthy"
        open_intents = [
            {
                "id": intent.id,
                "from": intent.from_,
                "description": intent.description,
                "worker": intent.worker,
            }
            for intent in project.intents
            if intent.to is None
        ]
        allowed_fact_ids = [fact.id for fact in project.facts if fact.id != "goal"]
        LOG.debug(
            "reason context prepared project=%s worker=%s facts=%s allowed_fact_ids=%s hints=%s open_intents=%s",
            project.project.id,
            worker.name,
            len(project.facts),
            len(allowed_fact_ids),
            len(project.hints),
            len(open_intents),
        )
        prompt = render_prompt(
            load_prompt(config.runtime.prompt_group, "reason.md"),
            {
                "graph_yaml": write_graph_snapshot_reference(
                    container_manager,
                    container_name,
                    export_yaml.strip(),
                    phase="reason_execute",
                ),
                "fact_ids": format_fact_ids(allowed_fact_ids),
                "open_intents": format_open_intents(open_intents),
                "max_intents": str(config.tasks.reason.max_intents),
            },
        )

        session = driver.prepare_session()
        command = driver.build_execute(worker, prompt, session)
        execute_started = time.perf_counter()
        result = run_worker_process(
            container_manager,
            container_name,
            worker,
            command.argv,
            phase="reason_execute",
            project_id=project.project.id,
            timeout_seconds=config.tasks.reason.timeout,
            lease=lease,
            cancellation=cancellation,
        )
        execute_ms = int((time.perf_counter() - execute_started) * 1000)
        total_ms = int((time.perf_counter() - task_started) * 1000)
        session = driver.extract_session(session, result.stdout, result.stderr)
        cancelled = cancel_reason(result, cancellation)
        if cancelled is not None:
            LOG.info(
                "reason cancelled project=%s worker=%s reason=%s execute_ms=%s",
                project.project.id,
                worker.name,
                cancelled,
                execute_ms,
            )
            return "cancelled"
        if lease.failure is not None:
            LOG.warning(
                "heartbeat lost during reason project=%s worker=%s status=%s execute_ms=%s",
                project.project.id,
                worker.name,
                lease.failure.status_code,
                execute_ms,
            )
            return "failed"
        if did_timeout(result):
            LOG.warning(
                "reason timed out project=%s worker=%s execute_ms=%s total_ms=%s stdout_preview=%s stderr_preview=%s",
                project.project.id,
                worker.name,
                execute_ms,
                total_ms,
                preview(result.stdout),
                preview(result.stderr),
            )
            return "failed"
        if result.returncode != 0:
            LOG.warning(
                "reason command failed project=%s worker=%s code=%s execute_ms=%s total_ms=%s stdout_preview=%s stderr_preview=%s",
                project.project.id,
                worker.name,
                result.returncode,
                execute_ms,
                total_ms,
                preview(result.stdout),
                preview(result.stderr),
            )
            return "failed"
        model_output = ""
        try:
            model_output = driver.extract_response_text(result.stdout, result.stderr)
            payload = parse_json_output(model_output)
            kind, data = validate_reason_payload(
                payload, open_intents_empty=not open_intents, max_intents=config.tasks.reason.max_intents,
            )
        except Exception as exc:
            LOG.warning(
                "reason parse failed project=%s worker=%s error=%s execute_ms=%s total_ms=%s response_preview=%s stderr_preview=%s",
                project.project.id,
                worker.name,
                exc,
                execute_ms,
                total_ms,
                preview(model_output),
                preview(result.stderr),
            )
            return "failed"
        if kind == "rejected":
            reason_text = payload.get("reason") if isinstance(payload.get("reason"), str) else ""
            LOG.warning(
                "reason rejected project=%s worker=%s execute_ms=%s total_ms=%s reason=%s",
                project.project.id,
                worker.name,
                execute_ms,
                total_ms,
                preview(reason_text),
            )
            if not open_intents and reason_text.strip():
                response = client.update_project_status(project.project.id, "stopped")
                if response.ok or response.status_code == 409:
                    LOG.info("project stopped after reason found no authorized direction project=%s worker=%s",
                             project.project.id, worker.name)
                    return "success"
                LOG.warning("reason stop write failed project=%s status=%s body=%s",
                            project.project.id, response.status_code, response.text)
                return "failed"
            return "rejected"
        if kind == "complete":
            response = client.complete(project.project.id, data["from"], data["description"], worker.name)
            if response.status_code == 403:
                LOG.info("project became inactive during reason complete project=%s worker=%s", project.project.id, worker.name)
                return "success"
            if not response.ok:
                LOG.warning(
                    "reason complete write failed project=%s worker=%s status=%s body=%s",
                    project.project.id,
                    worker.name,
                    response.status_code,
                    response.text,
                )
                return "failed"
            LOG.info(
                "project completed project=%s worker=%s from=%s execute_ms=%s total_ms=%s",
                project.project.id,
                worker.name,
                data["from"],
                execute_ms,
                total_ms,
            )
            return "success"
        if kind == "intents":
            created = 0
            for intent_data in data:
                response = client.create_intent(project.project.id, intent_data["from"], intent_data["description"], worker.name)
                if response.status_code == 403:
                    LOG.info("project became inactive during reason intent create project=%s worker=%s created=%s", project.project.id, worker.name, created)
                    return "success"
                if response.status_code == 409:
                    LOG.info("reason intent lost race project=%s worker=%s from=%s", project.project.id, worker.name, intent_data["from"])
                    continue
                if not response.ok:
                    LOG.warning(
                        "reason intent write failed project=%s worker=%s status=%s body=%s",
                        project.project.id,
                        worker.name,
                        response.status_code,
                        response.text,
                    )
                    continue
                created += 1
                LOG.info(
                    "reason created intent project=%s worker=%s from=%s description=%s",
                    project.project.id,
                    worker.name,
                    intent_data["from"],
                    intent_data["description"],
                )
            LOG.info(
                "reason finished project=%s worker=%s created_intents=%s/%s execute_ms=%s total_ms=%s",
                project.project.id,
                worker.name,
                created,
                len(data),
                execute_ms,
                total_ms,
            )
            if created == 0:
                LOG.warning(
                    "reason created no intents project=%s worker=%s attempted=%s execute_ms=%s total_ms=%s",
                    project.project.id,
                    worker.name,
                    len(data),
                    execute_ms,
                    total_ms,
                )
                return "failed"
            return "success"
        LOG.info(
            "reason finished without graph change project=%s worker=%s execute_ms=%s total_ms=%s",
            project.project.id,
            worker.name,
            execute_ms,
            total_ms,
        )
        return "success"
    finally:
        lease.stop()
        best_effort_release_reason(client, project.project.id, worker.name)


def _is_workbench_project(project: ProjectDetail) -> bool:
    """Only route explicitly bound workbench projects through its Planner.

    A dispatcher can serve standalone Runtime projects beside workbench runs;
    the global provider setting must not make those projects call an unrelated
    workbench URL or fail when no callback token is configured.
    """
    return any(
        hint.content.startswith("workbench_planner:run_id=")
        for hint in project.hints
    )


def _run_workbench_reason_task(
    config: DispatchConfig,
    client: SecurityRuntimeClient,
    project: ProjectDetail,
    worker: WorkerConfig,
    cancellation: TaskCancellation,
    lease: HeartbeatLease,
) -> str:
    """Ask the unified workbench Planner for a decision, then apply it atomically."""
    if cancellation.is_cancelled:
        return "cancelled"
    if lease.failure is not None:
        return "failed"
    snapshot_hash = planning_snapshot_hash(project)
    trigger = project.project.reason.trigger if project.project.reason else "reason"
    decision_id = "decision-" + hashlib.sha256(
        f"{project.project.id}:{snapshot_hash}".encode()
    ).hexdigest()[:48]
    callback = client.workbench_plan(
        worker.workbench_url,
        project,
        trigger,
        decision_id,
        budget={"max_new_intents": config.tasks.reason.max_intents,
                "execution_supported": config.runtime.execution == 'local' and any(
                    w.type == 'pi' and w.pi_blackboard_extension and 'explore' in w.task_types
                    for w in config.workers)},
        tool_event_ids=_workbench_tool_event_ids(client, project),
        callback_token=config.workbench_callback_token,
        timeout_seconds=config.tasks.reason.timeout,
    )
    if cancellation.is_cancelled:
        return "cancelled"
    if lease.failure is not None:
        return "failed"
    if not callback.ok or not isinstance(callback.data, dict):
        LOG.warning(
            "workbench planning callback failed project=%s worker=%s status=%s body=%s",
            project.project.id, worker.name, callback.status_code, callback.text[:500],
        )
        return "failed"
    payload = dict(callback.data)
    if payload.get("decision_id") != decision_id or payload.get("snapshot_hash") != snapshot_hash:
        LOG.warning("workbench planning callback identity mismatch project=%s", project.project.id)
        return "failed"
    # Runtime remains the only writer of the project graph.  This second write
    # is idempotent on the same decision ID and rejects stale snapshots.
    applied = client.planning_decision(project.project.id, {
        "decision_id": decision_id,
        "snapshot_hash": snapshot_hash,
        "trigger": trigger,
        "summary": payload.get("summary", ""),
        "intents": payload.get("intents", []),
        "validated_outputs": payload.get("validated_outputs", {}),
        "completion_validated": bool(payload.get("completion_validated")),
        "completion_fact_ids": payload.get("completion_fact_ids", []),
        "completion_reason": payload.get("completion_reason"),
        "stop_reason": payload.get("stop_reason"),
    }, callback_token=config.workbench_callback_token)
    if applied.status_code in (403, 409) and applied.data is not None:
        # A lost response may mean the atomic insert committed.  A fresh
        # project read on the next scheduler pass will reconcile the state.
        LOG.info(
            "workbench planning decision was superseded project=%s status=%s body=%s "
            "decision=%s attempt=%s snapshot_hash=%s",
            project.project.id,
            applied.status_code,
            preview(applied.text, 300),
            decision_id,
            project.project.reason_attempt_id,
            snapshot_hash,
        )
        return "failed"
    if applied.status_code == 422:
        # The same snapshot yields the same decision ID, so retrying an invalid
        # decision would repeat this failure indefinitely.
        fallback = client.planning_decision(project.project.id, {
            "decision_id": decision_id,
            "snapshot_hash": snapshot_hash,
            "trigger": trigger,
            "summary": "规划决策未通过 Runtime 校验，已保留现有证据。",
            "intents": [],
            "stop_reason": f"规划决策未通过 Runtime 校验（HTTP 422）：{applied.text[:300]}",
        }, callback_token=config.workbench_callback_token)
        if fallback.ok:
            LOG.warning("workbench project stopped after invalid decision project=%s", project.project.id)
            return "success"
        LOG.warning("workbench invalid decision stop failed project=%s status=%s",
                    project.project.id, fallback.status_code)
        return "failed"
    if not applied.ok:
        LOG.warning("workbench planning decision apply failed project=%s status=%s body=%s",
                    project.project.id, applied.status_code, applied.text[:500])
        return "failed"
    LOG.info("workbench planning decision applied project=%s decision=%s intents=%s",
             project.project.id, decision_id, len(payload.get("intents", [])))
    return "success"


def _workbench_tool_event_ids(client: SecurityRuntimeClient, project: ProjectDetail) -> list[str]:
    """Collect only receipt IDs from this project's persisted tool events."""
    ids: set[str] = set()
    cursor = 0
    while True:
        response = client.project_events(project.project.id, after=cursor, limit=1000)
        if not response.ok or not isinstance(response.data, dict):
            break
        events = response.data.get("events", [])
        if not isinstance(events, list):
            break
        for event in events:
            if not isinstance(event, dict) or event.get("event_type") not in {
                "mcp.call.completed",
            }:
                continue
            payload = event.get("payload")
            if isinstance(payload, dict) and isinstance(payload.get("call_id"), str):
                ids.add(payload["call_id"])
        next_cursor = response.data.get("next_cursor", cursor)
        if len(events) < 1000 or not isinstance(next_cursor, int) or next_cursor <= cursor:
            break
        cursor = next_cursor
    return sorted(ids)
