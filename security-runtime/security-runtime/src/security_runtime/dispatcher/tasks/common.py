from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from security_runtime.dispatcher.config import DispatchConfig, WorkerConfig
from security_runtime.dispatcher.protocol.client import SecurityRuntimeClient
from security_runtime.dispatcher.runtime.cancellation import TaskCancellation
from security_runtime.dispatcher.runtime.containers import ContainerManager
from security_runtime.dispatcher.runtime.heartbeat import HeartbeatLease
from security_runtime.dispatcher.runtime.process import ProcessResult
from security_runtime.dispatcher.usage import (
    claude_result,
    claude_usage,
    pi_usage,
    write_receipt,
)

PROCESS_COMMUNICATE_GRACE_SECONDS = 15
LOG_PREVIEW_LIMIT = 1200
GRAPH_SNAPSHOT_ROOT = "/tmp/security-runtime-prompts"
LOG = logging.getLogger(__name__)


@dataclass(slots=True)
class ConcludeWriteResult:
    status: str
    fact_id: str | None = None


def preview(text: str, limit: int = LOG_PREVIEW_LIMIT) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[:limit] + "..."


def did_timeout(result: ProcessResult) -> bool:
    return not result.cancelled and (result.timed_out or result.returncode in (124, 137))


def cancel_reason(result: ProcessResult, cancellation: TaskCancellation | None = None) -> str | None:
    if result.cancelled:
        return result.cancel_reason or "cancelled"
    if cancellation is not None:
        return cancellation.reason
    return None


def communicate_timeout(timeout_seconds: int, grace_seconds: int = PROCESS_COMMUNICATE_GRACE_SECONDS) -> int:
    return timeout_seconds + grace_seconds


def task_healthcheck_enabled(config: DispatchConfig) -> bool:
    if config.runtime.execution == "local":
        return False
    return config.runtime.worker_healthcheck == "startup_and_task"


def write_graph_snapshot_reference(
    container_manager: ContainerManager,
    container_name: str,
    graph_yaml: str,
    *,
    phase: str,
) -> str:
    snapshot_id = f"{phase}-{uuid.uuid4().hex[:12]}"
    if getattr(container_manager, "is_local", False):
        path = str(Path(container_name).resolve() / ".security-runtime-prompts" / snapshot_id / "graph.yaml")
        location = "current worker workspace"
    else:
        path = f"{GRAPH_SNAPSHOT_ROOT}/{snapshot_id}/graph.yaml"
        location = "current container"
    container_manager.write_text_file(container_name, path, graph_yaml)
    return (
        f"The graph YAML snapshot is stored in this file inside the {location}:\n\n"
        f"{path}\n\n"
        "Before using the graph, read the entire file and treat its contents as the YAML snapshot "
        "for this Graph section."
    )


def run_worker_process(
    container_manager: ContainerManager,
    container_name: str,
    worker: WorkerConfig,
    argv: list[str],
    *,
    phase: str,
    timeout_seconds: int,
    project_id: str = "",
    intent_id: str = "",
    attempt_id: str = "",
    lease: HeartbeatLease | None = None,
    cancellation: TaskCancellation | None = None,
) -> ProcessResult:
    LOG.info(
        "starting container exec container=%s worker=%s phase=%s timeout=%ss",
        container_name,
        worker.name,
        phase,
        timeout_seconds,
    )
    if worker.mcp_bridge_python is not None:
        if not getattr(container_manager, 'is_local', False) or worker.type != 'claudecode':
            raise ValueError('Workbench MCP bridge requires a local Claude Worker')
        servers = {}
        if phase in {'bootstrap', 'explore_execute'} and project_id and intent_id:
            servers['secmind-blackboard'] = {
                'type': 'stdio', 'command': str(worker.mcp_bridge_python),
                'args': ['-m', 'security_agent.blackboard_mcp_server'],
                'env': {'SECMIND_WORKBENCH_URL': worker.workbench_url,
                        'SECMIND_PROJECT_ID': project_id, 'SECMIND_INTENT_ID': intent_id,
                        'SECMIND_WORKER_NAME': worker.name, 'PYTHONIOENCODING': 'utf-8'},
            }
        config_path = str(Path(container_name).resolve() / '.security-runtime-prompts' / f'mcp-{uuid.uuid4().hex}.json')
        container_manager.write_text_file(container_name, config_path, json.dumps({'mcpServers': servers}))
        # Keep the prompt after the CLI option terminator. Restrict built-in
        # tools to reading the current worker workspace; all executable
        # security tools must go through the assigned blackboard MCP bridge.
        # A permissive CLI session would let the worker bypass the bridge via
        # Bash/PowerShell even with --strict-mcp-config.
        split = argv.index('--')
        options = [option for option in argv[:split] if option != '--dangerously-skip-permissions']
        allowed_tools = 'Read,mcp__secmind-blackboard__*' if servers else 'Read'
        argv = [
            *options,
            '--restricted', '--tools', 'Read',
            '--permission-mode', 'dontAsk', '--allowedTools', allowed_tools,
            '--strict-mcp-config', '--mcp-config', config_path,
            *argv[split:],
        ]
    # Claude Code can return a successful text response that ignores the
    # prompt's JSON-only instruction.  Exploration results are consumed by a
    # strict protocol parser, so ask the CLI to enforce that protocol at the
    # provider boundary.  This prevents a paid model call from being retried
    # forever merely because its response was prose.
    if worker.type == 'claudecode' and phase.startswith('explore'):
        schema = json.dumps({
            'type': 'object',
            'oneOf': [
                {'properties': {'accepted': {'const': False}, 'reason': {'type': 'string'}},
                 'required': ['accepted', 'reason'], 'additionalProperties': False},
                {'properties': {'accepted': {'const': True},
                                 'data': {'type': 'object', 'properties': {
                                     'description': {'type': 'string'}, 'title': {'type': 'string'},
                                     'items': {'type': 'array', 'items': {'type': 'object',
                                         'properties': {'id': {'type': 'string'}, 'type': {'type': 'string'},
                                                        'title': {'type': 'string'}, 'summary': {'type': 'string'},
                                                        'evidence_ids': {'type': 'array', 'items': {'type': 'string'}},
                                                        'finding_id': {'type': 'string'}, 'verification_status': {'type': 'string'},
                                                        'outcome': {'type': 'string', 'enum': ['observed', 'negative', 'unverified']}},
                                         'required': ['type', 'title', 'summary'], 'additionalProperties': False}}},
                                          'required': ['description'], 'additionalProperties': False}},
                 'required': ['accepted', 'data'], 'additionalProperties': False},
            ],
        }, ensure_ascii=False, separators=(',', ':'))
        try:
            split = argv.index('--')
        except ValueError:
            split = len(argv)
        argv = [*argv[:split], '--json-schema', schema, *argv[split:]]
    process_env = dict(worker.env)
    if worker.pi_blackboard_extension is not None:
        if not getattr(container_manager, 'is_local', False) or worker.type != 'pi':
            raise ValueError('Pi blackboard extension requires a local Pi worker')
        if phase in {'bootstrap', 'explore_execute', 'explore_conclude'} and project_id and intent_id:
            process_env.update({
                'SECMIND_WORKBENCH_URL': worker.workbench_url,
                'SECMIND_PROJECT_ID': project_id,
                'SECMIND_INTENT_ID': intent_id,
                'SECMIND_WORKER_NAME': worker.name,
                'SECMIND_ATTEMPT_ID': attempt_id,
                'SECMIND_MODEL_BUDGET': 'required' if attempt_id else 'legacy',
            })
            # Pi's extension flag belongs to Pi's CLI, after the Node entry
            # point when the local launcher is ``node <pi-cli.js>``. Putting
            # it before the entry point makes Node consume it and exit with
            # ``bad option: --extension`` before Pi starts.
            extension_args = ['--extension', str(worker.pi_blackboard_extension)]
            if len(argv) >= 2 and Path(argv[0]).stem.lower() in {'node', 'nodejs'}:
                argv = [argv[0], argv[1], *extension_args, *argv[2:]]
            else:
                argv = [argv[0], *extension_args, *argv[1:]]
            # --tools is a global allowlist in Pi, including extension tools.
            argv[argv.index('--tools') + 1] = ('read,blackboard_tools,blackboard_invoke'
                if phase in {'bootstrap', 'explore_execute'} else 'read')
    process = container_manager.build_exec_process(
        container_name,
        process_env,
        argv,
        timeout_seconds=timeout_seconds,
    )
    receipt = {"trace_id": str(uuid.uuid4()), "source": "security_runtime_worker",
               "project_id": project_id, "intent_id": intent_id, "worker": worker.name,
               "phase": phase, "model": worker.env.get("PI_MODEL") or worker.env.get("ANTHROPIC_MODEL", "unknown"),
               "call_unit": "cli_execution", "usage": {}}
    write_receipt(worker.usage_journal, {**receipt, "status": "started"})
    def stage(status):
        if lease is not None and callable(getattr(lease, "stage", None)):
            try:
                lease.stage(phase, status)
            except Exception:
                LOG.warning("Could not persist execution stage project=%s intent=%s", project_id, intent_id, exc_info=True)
    stage("running")
    try:
        process.start()
    except Exception:
        write_receipt(worker.usage_journal, {**receipt, "status": "failed"})
        stage("failed")
        raise
    if lease is not None:
        lease.attach_process(process)
    if cancellation is not None:
        cancellation.attach_process(process)
    try:
        result = process.communicate(timeout=communicate_timeout(timeout_seconds))
        envelope = claude_result(result.stdout) if worker.type == "claudecode" else None
        failed = result.returncode != 0 or result.timed_out or result.cancelled or bool(envelope and envelope.get("is_error"))
        stage("cancelled" if result.cancelled else "timeout" if did_timeout(result) else "failed" if failed else "completed")
        write_receipt(worker.usage_journal, {**receipt, "status": "failed" if failed else "completed",
            "usage": claude_usage(result.stdout) if worker.type == "claudecode" else
                     pi_usage(result.stdout) if worker.type == "pi" else {}})
        return result
    except Exception:
        write_receipt(worker.usage_journal, {**receipt, "status": "failed"})
        stage("failed")
        raise
    finally:
        if lease is not None:
            lease.attach_process(None)
        if cancellation is not None:
            cancellation.attach_process(None)


def project_allows_conclude_fallback(client: SecurityRuntimeClient, project_id: str, *, worker_name: str, intent_id: str) -> bool:
    project = client.get_project(project_id)
    if project.project.status == "active":
        return True
    LOG.info(
        "skip conclude fallback because project is no longer active project=%s intent=%s worker=%s status=%s",
        project_id,
        intent_id,
        worker_name,
        project.project.status,
    )
    return False


def best_effort_release_reason(client: SecurityRuntimeClient, project_id: str, worker_name: str) -> None:
    response = client.release_reason(project_id, worker_name)
    if not response.ok and response.status_code not in (403, 409):
        LOG.warning(
            "reason release failed project=%s worker=%s status=%s",
            project_id,
            worker_name,
            response.status_code,
        )
    elif response.ok:
        LOG.info("released reason project=%s worker=%s", project_id, worker_name)
    else:
        LOG.info(
            "reason release skipped project=%s worker=%s status=%s",
            project_id,
            worker_name,
            response.status_code,
        )


def write_conclude_result(
    client: SecurityRuntimeClient,
    project_id: str,
    intent_id: str,
    worker_name: str,
    description: str | dict[str, Any],
    *,
    source: str,
    phase_ms: int,
    total_ms: int | None = None,
) -> str:
    return write_conclude_result_with_fact_id(
        client,
        project_id,
        intent_id,
        worker_name,
        description,
        source=source,
        phase_ms=phase_ms,
        total_ms=total_ms,
    ).status


def write_conclude_result_with_fact_id(
    client: SecurityRuntimeClient,
    project_id: str,
    intent_id: str,
    worker_name: str,
    description: str | dict[str, Any],
    *,
    source: str,
    phase_ms: int,
    total_ms: int | None = None,
) -> ConcludeWriteResult:
    response = client.conclude(project_id, intent_id, worker_name, description)
    if response.ok:
        fact_id: str | None = None
        if isinstance(response.data, dict):
            fact = response.data.get("fact")
            if isinstance(fact, dict):
                candidate = fact.get("id")
                if isinstance(candidate, str) and candidate:
                    fact_id = candidate
        if total_ms is None:
            LOG.info(
                "intent concluded project=%s intent=%s worker=%s source=%s phase_ms=%s",
                project_id,
                intent_id,
                worker_name,
                source,
                phase_ms,
            )
        else:
            LOG.info(
                "intent concluded project=%s intent=%s worker=%s source=%s phase_ms=%s total_ms=%s",
                project_id,
                intent_id,
                worker_name,
                source,
                phase_ms,
                total_ms,
            )
        return ConcludeWriteResult(status="success", fact_id=fact_id)
    if response.status_code == 403:
        LOG.info(
            "project became inactive during conclude project=%s intent=%s worker=%s",
            project_id,
            intent_id,
            worker_name,
        )
    else:
        LOG.warning(
            "conclude write failed project=%s intent=%s worker=%s status=%s body=%s",
            project_id,
            intent_id,
            worker_name,
            response.status_code,
            response.text,
        )
    best_effort_release(client, project_id, intent_id, worker_name)
    return ConcludeWriteResult(status="failed", fact_id=None)


def best_effort_release(client: SecurityRuntimeClient, project_id: str, intent_id: str, worker_name: str, *, outcome: str = "failed") -> None:
    response = client.release(project_id, intent_id, worker_name, outcome=outcome)
    if not response.ok and response.status_code not in (403, 409):
        LOG.warning(
            "release failed project=%s intent=%s worker=%s status=%s",
            project_id,
            intent_id,
            worker_name,
            response.status_code,
        )
    elif response.ok:
        LOG.info("released intent project=%s intent=%s worker=%s", project_id, intent_id, worker_name)
    else:
        LOG.info(
            "release skipped project=%s intent=%s worker=%s status=%s",
            project_id,
            intent_id,
            worker_name,
            response.status_code,
        )
