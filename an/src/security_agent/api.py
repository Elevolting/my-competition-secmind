from __future__ import annotations

import asyncio
import hmac
import json
import re
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any
from uuid import NAMESPACE_URL, uuid4, uuid5
from zoneinfo import ZoneInfo

import httpx
import uvicorn
from fastapi import FastAPI, File, Header, HTTPException, Query, Response, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from security_agent.asset_graph import project_asset_graph
from security_agent.batch import BatchError, BatchService
from security_agent.budget_policy import TASK_BUDGET_LIMITS
from security_agent.config import Settings, get_settings
from security_agent.dashboard import dashboard_snapshot
from security_agent.evaluation import EvaluationError, EvaluationService
from security_agent.experience import ExperienceStore
from security_agent.experience_api import register_experiences
from security_agent.external_usage import SOURCES, ExternalUsageCollector
from security_agent.fusion import classify_task
from security_agent.guardrail import Guardrail
from security_agent.incident_response import IncidentManager
from security_agent.ledger import LedgerStore
from security_agent.llm import ModelGateway, ModelGatewayError, close_gateway_safely
from security_agent.mcp_agent import MCPToolRegistry
from security_agent.mcp_catalog import MCPCatalog
from security_agent.mcp_runtime import MCPRuntime
from security_agent.model_usage import normalize_usage
from security_agent.operations_api import register_operations
from security_agent.orchestrator import SecurityOrchestrator
from security_agent.penetration_integration import (
    PenetrationProtocolError,
    PenetrationUnavailableError,
    create_project_hint,
    normalize_penetration_graph,
    penetration_get,
    project_title_for_run,
    resolve_project_id,
)
from security_agent.question_bank import QuestionBankError, QuestionBankService
from security_agent.runtime_prompts import RuntimePrompts
from security_agent.schemas import (
    ApprovalResponse,
    BatchCreateRequest,
    EvaluationCreateRequest,
    ExperienceCreateRequest,
    MCPServerUpsertRequest,
    MCPToolUpsertRequest,
    ModelConfigUpdate,
    ModelConnectionTest,
    ModelUsageQuotaUpdate,
    PlanningCallbackRequest,
    QuestionBankConfirmRequest,
    QuestionBankInspectRequest,
    RunHintRequest,
    RunRetryRequest,
    RunStatus,
    TaskRequest,
)
from security_agent.service import EventHub, RunService
from security_agent.tools import ToolBroker, default_registry
from security_agent.tsec_api import register_tsec

REPORT_TIMEZONE = ZoneInfo("Asia/Shanghai")


def _shift_month(value: datetime, offset: int) -> datetime:
    index = value.year * 12 + value.month - 1 + offset
    return value.replace(year=index // 12, month=index % 12 + 1, day=1)


def _usage_numbers(value: Any) -> tuple[int, int, int, int]:
    """Normalize token fields emitted by OpenAI/DeepSeek-compatible APIs."""
    usage = normalize_usage(value)
    return tuple(usage.get(key, 0) for key in ('prompt_tokens', 'completion_tokens', 'total_tokens', 'cache_read_tokens'))


def _run_usage(ledger: LedgerStore, run_id: str, budget: Any | None = None,
               external_execution: dict | None = None, external_events: list | None = None,
               run_events: list | None = None,
               event_window: tuple[datetime, datetime] | None = None,
               run_status: RunStatus | None = None) -> dict[str, Any]:
    """Aggregate real Provider usage for one run from its ledger events.

    Usage is deliberately never estimated.  A provider normally reports usage
    on the terminal stream event; if it does not, the response exposes an
    explicit unavailable state so the UI cannot present made-up numbers.
    Duplicate terminal events for the same trace (for example a retry that
    records both completed and failed) are de-duplicated, preferring the event
    that contains usage and then a completed event.
    """
    events = list(run_events) if run_events is not None else ledger.events(run_id, limit=1_000_000)
    remote = external_execution or {}
    if event_window is None and remote.get('project_id'):
        event_window = ledger.event_windows([run_id]).get(run_id)
    if event_window:
        begun, ended = (value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
                        for value in event_window)
        # A local project number can be reused after Runtime data is reset.
        # Only receipts from this platform run's own event period belong here.
        if (run_status == RunStatus.RUNNING and remote.get('status') in {'submitted', 'running'} and
                not any(event.event_type == 'report.generated' for event in events) and
                not any(event.event_type.startswith('external.usage.') for event in events)):
            ended = max(ended, datetime.now(UTC))
    if remote.get('remote_run_id') or remote.get('project_id'):
        if external_events is None:
            external_events = [event for kind in ('started', 'completed', 'failed')
                               for event in ledger.events_by_type('external.usage.' + kind, limit=None)]
        for event in external_events:
            payload = event.payload
            if ((payload.get('source') == 'secmind' and remote.get('remote_run_id') and
                 payload.get('remote_run_id') == remote['remote_run_id']) or
                (payload.get('source') == 'security_runtime_worker' and remote.get('project_id') and
                 payload.get('project_id') == remote['project_id'] and
                 (not event_window or begun <= _event_local_time(event).astimezone(UTC) <= ended))):
                events.append(event)
    started = [event for event in events if event.event_type.endswith('.started') and
               event.event_type.startswith(('llm.stream.', 'external.usage.'))]
    terminal = [
        event
        for event in events
        if event.event_type in {"llm.stream.completed", "llm.stream.failed", "external.usage.completed", "external.usage.failed"}
    ]

    selected: dict[tuple[str, str], Any] = {}
    for event in terminal:
        payload = event.payload if isinstance(event.payload, dict) else {}
        trace_id = _usage_event_key(event)
        usage = payload.get("usage")
        has_usage = bool(normalize_usage(usage))
        score = (1 if has_usage else 0, 1 if event.event_type.endswith(".completed") else 0,
                 1 if payload.get('project_id') else 0)
        previous = selected.get(trace_id)
        if previous is None or score > previous[0]:
            selected[trace_id] = (score, event)

    usage_events = [item[1] for item in selected.values()]
    prompt_tokens = completion_tokens = total_tokens = cache_read_tokens = 0
    usage_available = False
    for event in usage_events:
        payload = event.payload if isinstance(event.payload, dict) else {}
        usage = payload.get("usage")
        prompt, completion, total, cache_hit = _usage_numbers(usage)
        prompt_tokens += prompt
        completion_tokens += completion
        total_tokens += total
        cache_read_tokens += cache_hit
        usage_available = usage_available or bool(normalize_usage(usage))

    started_traces = {
        _usage_event_key(event)
        for event in started
        if isinstance(event.payload, dict)
    }
    call_events = [event for event in usage_events if not _is_session_backfill(event) and
                   not _is_session_backfill_link(event)]
    provider_call_count = len(started_traces | {_usage_event_key(event) for event in call_events})
    budget_calls = int(getattr(budget, "model_calls_used", 0) or 0) if budget is not None else 0
    external_calls = {_usage_event_key(e) for e in events
                      if e.event_type.startswith('external.usage.') and not _is_session_backfill(e) and
                      not _is_session_backfill_link(e)}
    model_call_count = max(provider_call_count - len(external_calls), budget_calls) + len(external_calls)
    completed_call_count = sum(event.event_type.endswith(".completed") for event in call_events)
    incomplete_call_count = max(0, provider_call_count - len(call_events))
    return {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "cache_read_tokens": cache_read_tokens,
        "model_call_count": model_call_count,
        "completed_call_count": completed_call_count,
        "incomplete_call_count": incomplete_call_count,
        "token_usage_available": usage_available,
        "usage_estimated": False,
        "usage_source": "provider_ledger" if usage_available else "unavailable",
        "usage_scope": "platform_and_linked_external",
    }


def _summary_usage(budget: Any | None) -> dict[str, Any]:
    """Return a non-blocking usage summary for the run list.

    The list endpoint is polled frequently by the workbench. It must not
    scan and deserialize the complete event ledger for every historical run.
    Detailed provider usage remains available from the run-detail endpoint,
    which calls :func:`_run_usage` on demand.
    """
    budget = budget or object()
    prompt_tokens = int(getattr(budget, "prompt_tokens_used", 0) or 0)
    completion_tokens = int(getattr(budget, "completion_tokens_used", 0) or 0)
    calls = int(getattr(budget, "model_calls_used", 0) or 0)
    cache_read_tokens = int(getattr(budget, "cache_read_tokens_used", 0) or 0)
    usage_available = bool(getattr(budget, "model_usage_recorded", False))
    return {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
        "cache_read_tokens": cache_read_tokens,
        "model_call_count": calls,
        "completed_call_count": calls if usage_available else 0,
        "incomplete_call_count": 0 if usage_available else calls,
        "token_usage_available": usage_available,
        "usage_estimated": False,
        "usage_source": "budget_summary",
        "usage_scope": "platform_agent",
    }


def _event_local_time(event: Any) -> datetime:
    timestamp = event.timestamp
    original = event.payload.get("occurred_at") if event.event_type.startswith("external.usage.") else None
    if original:
        try:
            timestamp = datetime.fromisoformat(original)
        except (ValueError, TypeError):
            pass
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(REPORT_TIMEZONE)


def _usage_event_key(event: Any) -> tuple[str, str]:
    return event.run_id, str(event.payload.get("trace_id") or event.event_id)


def _is_session_backfill(event: Any) -> bool:
    return event.payload.get('call_unit') in {
        'pi_session_response_backfill',
        'claude_session_response_backfill',
    }


def _is_session_backfill_link(event: Any) -> bool:
    return event.payload.get('call_unit') == 'pi_session_response_backfill_link'


def _usage_events(ledger: LedgerStore, since: datetime | None = None) -> tuple[list, list]:
    # A failed and completed receipt may describe the same provider call.
    # Select one terminal receipt per run/trace, matching the run-detail API.
    selected = {}
    for kind in ("llm.stream.completed", "llm.stream.failed", "external.usage.completed", "external.usage.failed"):
        for event in ledger.events_by_type(kind, since=since, limit=None):
            key = _usage_event_key(event)
            score = (bool(normalize_usage(event.payload.get("usage"))), kind.endswith(".completed"),
                     bool(event.payload.get('project_id')))
            if key not in selected or score > selected[key][0]:
                selected[key] = (score, event)
    started = {_usage_event_key(event): event for kind in ("llm.stream.started", "external.usage.started")
               for event in ledger.events_by_type(kind, since=since, limit=None)}
    return list(started.values()), [entry[1] for entry in selected.values()]


def _usage_series(ledger: LedgerStore, events=None, model_id=None, source=None) -> dict[str, list[dict[str, Any]]]:
    """Build hourly/daily/monthly series from durable model stream events."""
    now = datetime.now(REPORT_TIMEZONE)
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    current_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    current_month = current_day.replace(day=1)
    keys = {
        "hourly": [(current_hour - timedelta(hours=i)).strftime("%Y-%m-%dT%H:00:00+08:00") for i in range(23, -1, -1)],
        "daily": [(current_day - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(29, -1, -1)],
        "monthly": [_shift_month(current_month, i).strftime("%Y-%m") for i in range(-11, 1)],
    }
    buckets = {
        period: {key: {"bucket": key, "tokens": 0, "calls": 0, "usage_receipt_count": 0,
                      "prompt_tokens": 0, "completion_tokens": 0, "cache_read_tokens": 0,
                      "other_input_tokens": 0, "unclassified_tokens": 0} for key in values}
        for period, values in keys.items()
    }
    since = _shift_month(current_month, -11).astimezone(UTC)
    started, terminal = events if events is not None else _usage_events(ledger, since)
    if source is not None:
        started = [e for e in started if e.payload.get('source', 'platform_agent') == source]
        terminal = [e for e in terminal if e.payload.get('source', 'platform_agent') == source]
    if model_id is not None:
        started = [e for e in started if (e.payload.get('model') or 'unknown') == model_id]
        terminal = [e for e in terminal if (e.payload.get('model') or 'unknown') == model_id]
    started_keys = {_usage_event_key(event) for event in started}
    for event in started:
        local = _event_local_time(event)
        bucket_keys = {
            "hourly": local.strftime("%Y-%m-%dT%H:00:00+08:00"),
            "daily": local.strftime("%Y-%m-%d"),
            "monthly": local.strftime("%Y-%m"),
        }
        for period, key in bucket_keys.items():
            if key in buckets[period]:
                buckets[period][key]["calls"] += 1
    for event in terminal:
        if _is_session_backfill_link(event):
            continue
        local = _event_local_time(event)
        bucket_keys = {
            "hourly": local.strftime("%Y-%m-%dT%H:00:00+08:00"),
            "daily": local.strftime("%Y-%m-%d"),
            "monthly": local.strftime("%Y-%m"),
        }
        prompt, completion, tokens, cache = _usage_numbers(event.payload.get("usage") if isinstance(event.payload, dict) else None)
        for period, key in bucket_keys.items():
            if key not in buckets[period]:
                continue
            buckets[period][key]["tokens"] += tokens
            buckets[period][key]['prompt_tokens'] += prompt
            buckets[period][key]['completion_tokens'] += completion
            buckets[period][key]['cache_read_tokens'] += cache
            buckets[period][key]['other_input_tokens'] += max(0, prompt - cache)
            buckets[period][key]['unclassified_tokens'] += max(0, tokens - prompt - completion)
            buckets[period][key]["usage_receipt_count"] += bool(normalize_usage(event.payload.get('usage')))
            if _usage_event_key(event) not in started_keys and not _is_session_backfill(event) and not _is_session_backfill_link(event):
                buckets[period][key]["calls"] += 1
    return {period: list(values.values()) for period, values in buckets.items()}


def _usage_totals(ledger: LedgerStore, states: list[Any]) -> dict[str, Any]:
    started, usage_events = _usage_events(ledger)
    started_keys = {_usage_event_key(event) for event in started if not _is_session_backfill(event)}
    terminal_keys = {_usage_event_key(event) for event in usage_events if not _is_session_backfill(event) and not _is_session_backfill_link(event)}
    event_run_ids = {event.run_id for event in usage_events}
    totals: dict[str, Any] = {
        "model_call_count": len(started_keys | terminal_keys),
        "completed_call_count": sum(event.event_type.endswith(".completed") and not _is_session_backfill(event) and not _is_session_backfill_link(event)
                                     for event in usage_events),
        "incomplete_call_count": len(started_keys - terminal_keys),
        "failed_call_count": sum(e.event_type.endswith('.failed') and not _is_session_backfill(e) and not _is_session_backfill_link(e)
                                 for e in usage_events),
        "usage_receipt_count": sum(bool(normalize_usage(e.payload.get('usage'))) and not _is_session_backfill(e) and not _is_session_backfill_link(e)
                                   for e in usage_events),
        "partial_usage_count": sum(bool(e.payload.get('usage_partial')) for e in usage_events),
        "backfilled_response_count": sum(_is_session_backfill(e) for e in usage_events),
        "missing_usage_count": len(started_keys | terminal_keys) - sum(
            bool(normalize_usage(e.payload.get('usage'))) and not _is_session_backfill(e) and not _is_session_backfill_link(e) for e in usage_events),
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "cache_read_tokens": 0,
        "token_usage_available": False,
        "usage_estimated": False,
    }
    for event in usage_events:
        if _is_session_backfill_link(event):
            continue
        usage = event.payload.get("usage") if isinstance(event.payload, dict) else None
        prompt, completion, total, cache_hit = _usage_numbers(usage)
        totals["prompt_tokens"] += prompt
        totals["completion_tokens"] += completion
        totals["total_tokens"] += total
        totals["cache_read_tokens"] += cache_hit
        totals["token_usage_available"] = totals["token_usage_available"] or bool(normalize_usage(usage))
    for state in states:
        if state.run_id in event_run_ids:
            continue
        if not any(event.run_id == state.run_id for event in started):
            totals["model_call_count"] += state.budget.model_calls_used
            totals["completed_call_count"] += state.budget.model_calls_used
        totals["prompt_tokens"] += state.budget.prompt_tokens_used
        totals["completion_tokens"] += state.budget.completion_tokens_used
        totals["total_tokens"] += state.budget.prompt_tokens_used + state.budget.completion_tokens_used
        totals["cache_read_tokens"] += state.budget.cache_read_tokens_used
        totals["token_usage_available"] = totals["token_usage_available"] or state.budget.model_usage_recorded
    return totals


def build_runtime(settings: Settings) -> tuple[RunService, EvaluationService, ModelGateway, ExperienceStore]:
    settings.prepare_directories()
    ledger = LedgerStore(settings.database_url)
    hub = EventHub()
    gateway = ModelGateway(settings)
    experiences = ExperienceStore(ledger.engine)
    experiences.backfill(ledger)
    catalog = MCPCatalog(generated_root=settings.mcp_generated_root, storage_path=settings.run_root.parent / 'mcp-catalog.json')
    mcp = MCPRuntime(catalog, settings.run_root.parent,
        [settings.upload_root, settings.input_root, settings.run_root, settings.run_root.parent / 'incident/samples'],
        ledger, kali_enabled=settings.kali_mcp_enabled, kali_container=settings.kali_container)
    from security_agent.trace_tools import TraceTool
    from security_agent.traces import TraceStore
    from security_agent.receipt_traces import ReceiptTraceImporter, TraceSources
    from security_agent.worker_traces import WorkerTraceImporter
    native = default_registry()
    trace_store = TraceStore(ledger, TraceSources(
        WorkerTraceImporter(ledger, settings.runtime_model_config_path.resolve().parent / 'worker-usage.db'),
        ReceiptTraceImporter(ledger, mcp.store),
    ))
    native.register(TraceTool(trace_store))
    native.register(TraceTool(trace_store, detail=True))
    broker = ToolBroker(MCPToolRegistry(native, mcp), Guardrail())
    orchestrator = SecurityOrchestrator(settings, ledger, gateway, broker, hub.publish, experiences, mcp_runtime=mcp)
    service = RunService(orchestrator, ledger, hub)
    service.traces = trace_store
    return service, EvaluationService(settings, service), gateway, experiences


def create_app(settings: Settings | None = None) -> FastAPI:
    actual_settings = settings or get_settings()
    service, evaluation_service, gateway, experiences = build_runtime(actual_settings)
    usage_collector = ExternalUsageCollector(actual_settings, service.ledger)
    question_banks = QuestionBankService(actual_settings, gateway)
    batches = BatchService(actual_settings, question_banks, service)
    incident_manager = IncidentManager(actual_settings.run_root.parent / "incident", [actual_settings.upload_root, actual_settings.input_root])

    async def allow_websocket_origin(websocket: WebSocket) -> bool:
        origin = websocket.headers.get("origin")
        allowed = {f"http://{host}:{port}" for host in ("127.0.0.1", "localhost")
                   for port in (5173, actual_settings.api_port)}
        allowed.update(value.strip() for value in actual_settings.allowed_browser_origins.split(",") if value.strip())
        if origin and origin not in allowed:
            await websocket.close(code=1008, reason="WebSocket origin is not allowed")
            return False
        return True

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await service.recover_incomplete()
        await evaluation_service.recover_incomplete()
        await question_banks.recover_incomplete()
        await batches.recover_incomplete()
        # Monitoring is operator-controlled. Starting the API must not create
        # synthetic scan records or imply that a host collector is connected.
        yield
        await incident_manager.shutdown()
        await question_banks.shutdown()
        await batches.shutdown()
        await evaluation_service.shutdown()
        await service.shutdown()
        await close_gateway_safely(gateway)

    app = FastAPI(
        title="安全任务 API",
        version="0.1.0",
        description="Auditable and recoverable security-task runtime.",
        lifespan=lifespan,
    )
    allowed_hosts = ["127.0.0.1", "localhost"]
    allowed_hosts.extend(host.strip() for host in actual_settings.allowed_hosts.split(",") if host.strip())
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
    app.state.service = service
    app.state.evaluation_service = evaluation_service
    app.state.question_banks = question_banks
    app.state.batches = batches
    app.state.experiences = experiences
    app.state.settings = actual_settings
    app.state.usage_collector = usage_collector
    app.state.incident_manager = incident_manager
    # The management page and task broker share the same MCP runtime and receipts.
    app.state.prompt_catalog = RuntimePrompts(actual_settings.run_root.parent)
    app.state.mcp_runtime = service.orchestrator.mcp_runtime
    app.state.mcp_catalog = app.state.mcp_runtime.catalog
    # Dispatcher workers can invoke the same reviewed module adapters through
    # the blackboard bridge.  This keeps code audit and reverse analysis on
    # the Runtime lease/event path instead of starting a second executor.
    app.state.workbench_tool_registry = service.orchestrator.broker.registry
    app.state.traces = service.traces
    register_operations(app, incident_manager, app.state.mcp_runtime, app.state.prompt_catalog)
    from security_agent.blackboard_mcp import register_blackboard_mcp
    register_blackboard_mcp(app, app.state.mcp_runtime, actual_settings)
    from security_agent.traces_api import register_traces
    register_traces(app, service.traces)
    register_experiences(app, experiences, service, gateway)
    register_tsec(app, actual_settings)

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "schema_version": "1.0",
            "demo_mode": actual_settings.demo_mode,
        }

    @app.get("/api/v1/dashboard")
    async def dashboard() -> dict[str, Any]:
        return {**dashboard_snapshot(service.ledger.list_states(limit=None)), "host": incident_manager.snapshot()}

    @app.get("/api/v1/tools")
    async def runtime_tools() -> dict[str, Any]:
        await app.state.mcp_runtime.refresh_agent_tools()
        return {"tools": [tool.model_dump(mode="json") for tool in service.orchestrator.broker.registry.manifests()]}

    @app.get("/api/v1/model-config")
    async def model_config() -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "provider": "compatible-api",
            "base_url": actual_settings.model_base_url,
            "planner_model": actual_settings.planner_model,
            "worker_model": actual_settings.worker_model,
            "fallback_model": actual_settings.fallback_model,
            "embedding_model": actual_settings.embedding_model,
            "api_key_configured": bool(actual_settings.model_api_key),
            "demo_mode": actual_settings.demo_mode,
            "timeout_seconds": actual_settings.model_timeout_seconds,
        }

    def model_credentials(base_url, api_key):
        try:
            normalized = actual_settings.validate_model_base_url(base_url)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        key = api_key.strip() if api_key is not None else None
        if key is not None and not key:
            raise HTTPException(422, 'API Key 不能只包含空格')
        if key is None and normalized != actual_settings.model_base_url.rstrip('/'):
            raise HTTPException(422, '更换服务地址时请提供该服务的 API Key，已保存密钥仅用于原地址')
        return normalized, key if key is not None else actual_settings.model_api_key

    @app.post("/api/v1/model-config/test")
    async def test_model_config(payload: ModelConnectionTest) -> dict[str, Any]:
        base_url, api_key = model_credentials(payload.base_url, payload.api_key)
        if not api_key:
            raise HTTPException(422, "API Key is required for connection testing")
        requested_models = list(dict.fromkeys((value or default).strip() for value, default in (
            (payload.planner_model, actual_settings.planner_model),
            (payload.worker_model, actual_settings.worker_model),
            (payload.fallback_model, actual_settings.fallback_model))))
        if any(not model for model in requested_models):
            raise HTTPException(422, '模型 ID 不能为空')
        test_id = 'model-test-' + str(uuid4())

        async def observe(kind, data):
            event = service.ledger.append(test_id, kind, data, actor='model_config_test')
            await service.event_hub.publish(event.model_dump(mode='json'))

        try:
            results = [await gateway.probe_model(base_url, api_key, model, observe) for model in requested_models]
        except ModelGatewayError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {'schema_version': '1.0', 'ok': True, 'test_kind': 'chat_completion',
                'model_count': len(results), 'model_ids': requested_models, 'results': results,
                'latency_ms': sum(r['latency_ms'] for r in results), 'test_id': test_id}

    @app.post("/api/v1/model-config/models")
    async def list_model_config_models(payload: ModelConnectionTest) -> dict[str, Any]:
        """Discover provider model IDs without exposing the API key to the browser."""
        base_url, api_key = model_credentials(payload.base_url, payload.api_key)
        if not api_key:
            raise HTTPException(422, "API Key is required to fetch model list")
        try:
            result = await gateway.test_connection(base_url, api_key)
        except ModelGatewayError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {
            "schema_version": "1.0",
            "models": result.get("model_ids", []),
            "model_count": result.get("model_count", 0),
            "latency_ms": result.get("latency_ms", 0),
        }

    @app.put("/api/v1/model-config")
    async def update_model_config(payload: ModelConfigUpdate) -> dict[str, Any]:
        try:
            base_url = actual_settings.validate_model_base_url(payload.base_url)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        changes = {'model_base_url': base_url}
        if payload.clear_api_key:
            if payload.api_key is not None:
                raise HTTPException(422, '不能同时设置和清除密钥')
            changes['model_api_key'] = ''
        else:
            _, changes['model_api_key'] = model_credentials(payload.base_url, payload.api_key)
        for field_name in ("planner_model", "worker_model", "fallback_model"):
            value = getattr(payload, field_name)
            if value is not None:
                normalized = value.strip()
                if not normalized:
                    raise HTTPException(422, f"{field_name} must not be empty")
                changes[field_name] = normalized
        changes['demo_mode'] = not bool(changes['model_api_key'])
        try:
            actual_settings.apply_model_changes(changes)
        except OSError as exc:
            raise HTTPException(500, '配置写入失败，运行中的配置未改变') from exc
        gateway._failures.clear()
        gateway._open_until.clear()
        return {
            "schema_version": "1.0",
            "updated": True,
            "base_url": actual_settings.model_base_url,
            "planner_model": actual_settings.planner_model,
            "worker_model": actual_settings.worker_model,
            "fallback_model": actual_settings.fallback_model,
            "api_key_configured": bool(actual_settings.model_api_key),
            "demo_mode": actual_settings.demo_mode,
        }

    @app.get("/api/v1/model-usage")
    async def model_usage() -> dict[str, Any]:
        sync_status = await asyncio.to_thread(usage_collector.sync)
        states = service.ledger.list_states(limit=None)
        started, receipts = _usage_events(service.ledger)
        by_model = {}
        by_source = {source: {'source': source, 'call_count': 0, 'total_tokens': 0,
            'usage_receipt_count': 0, 'partial_usage_count': 0,
            'backfilled_response_count': 0, 'missing_usage_count': 0,
            'token_usage_available': False,
            'call_unit': 'cli_execution' if source == 'security_runtime_worker' else 'provider_request',
            **sync_status.get(source, {'status': 'synced'})} for source in SOURCES}
        calls = {_usage_event_key(e): e for e in started}
        calls.update({_usage_event_key(e): e for e in receipts})
        for event in calls.values():
            if _is_session_backfill_link(event):
                continue
            source = by_source[event.payload.get('source', 'platform_agent')]
            known = bool(normalize_usage(event.payload.get('usage')))
            backfill = _is_session_backfill(event)
            source['call_count'] += not backfill
            source['total_tokens'] += _usage_numbers(event.payload.get('usage'))[2]
            source['usage_receipt_count'] += known and not backfill
            source['partial_usage_count'] += bool(event.payload.get('usage_partial'))
            source['backfilled_response_count'] += backfill
            source['missing_usage_count'] += not known and not backfill
            source['token_usage_available'] |= known
            model = event.payload.get('model') or 'unknown'
            item = by_model.setdefault(model, {'model': model, 'call_count': 0, 'total_tokens': 0,
                'usage_receipt_count': 0, 'failed_call_count': 0, 'run_ids': set()})
            item['call_count'] += not backfill
            item['run_ids'].add(event.run_id)
            item['total_tokens'] += _usage_numbers(event.payload.get('usage'))[2]
            item['usage_receipt_count'] += known and not backfill
            item['failed_call_count'] += event.event_type.endswith('.failed') and not backfill
        models = [{**{k: v for k, v in item.items() if k != 'run_ids'}, 'run_count': len(item['run_ids'])}
                  for item in by_model.values()]
        models.sort(key=lambda item: (-item['call_count'], item['model']))
        totals = _usage_totals(service.ledger, states)
        return {
            "schema_version": "1.0",
            "run_count": len(states),
            **totals,
            "usage_scope": "local_ledger",
            "provider_account_usage_synced": False,
            "quota_mode": "warning_only",
            "timezone": "Asia/Shanghai",
            "quota": {
                "hourly": actual_settings.model_hourly_token_quota,
                "daily": actual_settings.model_daily_token_quota,
                "monthly": actual_settings.model_monthly_token_quota,
            },
            "series": _usage_series(service.ledger, events=(started, receipts)),
            "model_series": {item['model']: _usage_series(service.ledger, events=(started, receipts), model_id=item['model'])
                             for item in models},
            "models": models,
            "usage_by_source": list(by_source.values()),
            "source_series": {source: _usage_series(service.ledger, events=(started, receipts), source=source)
                              for source in SOURCES},
            "note": (
                "Includes platform Agent, SecMind provider receipts and Worker CLI execution receipts; quotas are warning only."
                if totals["token_usage_available"]
                else "No provider usage has been recorded yet."
            ),
        }

    @app.put("/api/v1/model-usage/quota")
    async def update_model_usage_quota(payload: ModelUsageQuotaUpdate) -> dict[str, Any]:
        try:
            actual_settings.apply_model_changes({'model_hourly_token_quota': payload.hourly_tokens,
                'model_daily_token_quota': payload.daily_tokens, 'model_monthly_token_quota': payload.monthly_tokens})
        except OSError as exc:
            raise HTTPException(500, '预算写入失败，原设置未改变') from exc
        return {
            "schema_version": "1.0",
            "updated": True,
            "quota": {
                "hourly": actual_settings.model_hourly_token_quota,
                "daily": actual_settings.model_daily_token_quota,
                "monthly": actual_settings.model_monthly_token_quota,
            },
        }

    @app.websocket("/api/v1/model-usage/events")
    async def model_usage_events(websocket: WebSocket) -> None:
        if not await allow_websocket_origin(websocket):
            return
        await websocket.accept()
        try:
            async with service.event_hub.subscribe_all() as queue:
                while True:
                    event = await queue.get()
                    if event.get('event_type') not in {'llm.stream.started', 'llm.stream.completed', 'llm.stream.failed'}:
                        continue
                    await websocket.send_json(
                        {
                            "type": "usage.changed",
                            "run_id": event.get("run_id"),
                            "sequence": event.get("sequence"),
                            "event_type": event.get("event_type"),
                        }
                    )
        except WebSocketDisconnect:
            return

    @app.post("/api/v1/uploads", status_code=201)
    async def upload(file: Annotated[UploadFile, File(...)]) -> dict[str, Any]:
        safe_name = Path(file.filename or "upload.bin").name
        reserved_name = re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", safe_name, re.IGNORECASE)
        if (not safe_name or safe_name in {".", ".."} or reserved_name
                or any(ord(char) < 32 or char in ':<>"|?*\\' for char in safe_name)
                or safe_name.rstrip(' .') != safe_name):
            raise HTTPException(400, "Invalid filename")
        reference = f"{uuid4()}-{safe_name}"
        destination = actual_settings.upload_root / reference
        total = 0
        try:
            with destination.open("wb") as stream:
                while chunk := await file.read(1024 * 1024):
                    total += len(chunk)
                    if total > actual_settings.max_upload_bytes:
                        raise HTTPException(413, "Upload exceeds configured size limit")
                    stream.write(chunk)
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        return {"schema_version": "1.0", "ref": reference, "name": safe_name, "size_bytes": total}

    @app.get("/api/v1/task-budget-defaults")
    async def task_budget_defaults() -> dict[str, Any]:
        return {
            "defaults": {
                "max_runtime_seconds": actual_settings.max_runtime_seconds,
                "penetration_max_runtime_seconds": actual_settings.penetration_max_runtime_seconds,
                "max_tool_calls": actual_settings.max_tool_calls,
                "max_model_calls": actual_settings.max_model_calls,
                "penetration_max_model_calls": actual_settings.penetration_max_model_calls,
            },
            "limits": TASK_BUDGET_LIMITS,
        }

    @app.post("/api/v1/tasks", status_code=202)
    async def create_task(
        task: TaskRequest,
        request_id: Annotated[str | None, Header(alias="X-Request-Id", min_length=16, max_length=100,
                                                  pattern=r"^[a-zA-Z0-9_-]+$")] = None,
    ) -> dict[str, Any]:
        dispatch_plan = None
        formatted_metadata = None
        if task.question_bank_id:
            try:
                question_banks.require_confirmed(task.question_bank_id, task.attachments)
                inspection = question_banks.get(task.question_bank_id)
                dispatch_plan = inspection.get("dispatch_plan") or []
                formatted_metadata = inspection.get("formatted_metadata")
            except KeyError as exc:
                raise HTTPException(404, "Question bank inspection not found") from exc
            except QuestionBankError as exc:
                raise HTTPException(409, str(exc)) from exc
        try:
            run_id = service.submit(task, run_id=str(uuid5(NAMESPACE_URL, f"task-create:{request_id}"))
                                    if request_id else None)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        response = {"schema_version": "1.0", "run_id": run_id, "status": service.state(run_id).status}
        if dispatch_plan is not None:
            response["dispatch_plan"] = dispatch_plan
        if formatted_metadata is not None:
            response["formatted_metadata"] = formatted_metadata
        return response

    @app.post("/api/v1/batches", status_code=202)
    async def create_batch(
        payload: BatchCreateRequest,
        request_id: Annotated[str | None, Header(alias="X-Request-Id", min_length=16, max_length=100,
                                                  pattern=r"^[a-zA-Z0-9_-]+$")] = None,
    ) -> dict[str, Any]:
        try:
            return await batches.create_async(payload, request_id=request_id)
        except KeyError as exc:
            raise HTTPException(404, "Question bank inspection not found") from exc
        except BatchError as exc:
            raise HTTPException(409, str(exc)) from exc
        except QuestionBankError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/api/v1/batches/{batch_id}")
    async def get_batch(batch_id: str) -> dict[str, Any]:
        try:
            return batches.get(batch_id)
        except KeyError as exc:
            raise HTTPException(404, "Batch not found") from exc

    @app.get("/api/v1/batches/{batch_id}/tasks")
    async def get_batch_tasks(batch_id: str) -> dict[str, Any]:
        try:
            return {"schema_version": "1.0", "batch_id": batch_id, "tasks": batches.list_tasks(batch_id)}
        except KeyError as exc:
            raise HTTPException(404, "Batch not found") from exc

    @app.get("/api/v1/batches/{batch_id}/events")
    async def get_batch_events(batch_id: str) -> dict[str, Any]:
        try:
            batches.get(batch_id)
        except KeyError as exc:
            raise HTTPException(404, "Batch not found") from exc
        path = batches.root / batches.get(batch_id)["batch_id"] / "batch-events.jsonl"
        events = []
        if path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return {"schema_version": "1.0", "batch_id": batch_id, "events": events}

    @app.post("/api/v1/tasks/classify")
    async def classify_task_route(task: TaskRequest) -> dict[str, Any]:
        result = classify_task(task.objective, task.attachments, task.target_scope)
        result["scenario"] = result["scenario"].value
        return {"schema_version": "1.0", **result}

    async def _module_health(base_url: str, path: str) -> tuple[bool, str | None]:
        """Probe an external module so the UI does not report a dead adapter as ready."""
        try:
            # Module adapters are local services in the normal deployment.  Do
            # not inherit HTTP(S)_PROXY from the shell that launched the API:
            # proxy settings can route loopback probes away from 127.0.0.1 and
            # turn a healthy service into a misleading ConnectTimeout.  A
            # short explicit timeout also keeps the status endpoint responsive
            # while a module is genuinely starting or unavailable.
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(connect=1.0, read=1.5, write=1.5, pool=1.0),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.get(f"{base_url.rstrip('/')}{path}")
            if response.status_code < 400:
                return True, None
            return False, f"HTTP_{response.status_code}"
        except (httpx.HTTPError, TimeoutError) as exc:
            return False, type(exc).__name__

    @app.get("/api/v1/modules")
    async def list_modules() -> dict[str, Any]:
        # Probe both adapters concurrently.  This bounds the endpoint latency
        # to the slowest probe instead of adding the reverse and penetration
        # startup delays together.
        reverse_result, penetration_result = await asyncio.gather(
            _module_health(actual_settings.reverse_base_url, "/health/ready"),
            # The penetration adapter exposes its project collection as the
            # stable readiness probe (it intentionally has no /health/live).
            _module_health(actual_settings.penetration_base_url, "/projects"),
        )
        reverse_ok, reverse_error = reverse_result
        penetration_ok, penetration_error = penetration_result
        return {"schema_version": "1.0", "modules": [
            {"id": "code_audit", "name": "代码审计", "adapter": "workspace_security_audit",
             "available": actual_settings.demo_mode or reverse_ok, "local_available": True,
             "engine_available": reverse_ok, "default_backend": "local" if actual_settings.demo_mode else "secmind"},
            {"id": "log_analysis", "name": "日志分析", "adapter": "log_analysis_module", "available": reverse_ok,
             **({"error": reverse_error} if reverse_error else {})},
            {
                "id": "reverse", "name": "逆向分析", "adapter": "reverse_module",
                "available": reverse_ok, "base_url": actual_settings.reverse_base_url,
                **({"error": reverse_error} if reverse_error else {}),
            },
            {
                "id": "penetration", "name": "渗透测试", "adapter": "penetration_module",
                "available": penetration_ok, "base_url": actual_settings.penetration_base_url,
                **({"error": penetration_error} if penetration_error else {}),
            },
            {"id": "incident_response", "name": "应急响应", "adapter": "local_incident_runtime", "available": True},
        ]}

    @app.get("/api/v1/incident/status")
    async def incident_status() -> dict[str, Any]:
        return incident_manager.snapshot()

    @app.get("/api/v1/incident/commands")
    async def incident_commands() -> dict[str, Any]:
        return {"schema_version": "1.0", "groups": incident_manager.command_catalog()}

    @app.post("/api/v1/incident/monitor/start")
    async def incident_monitor_start() -> dict[str, Any]:
        return await incident_manager.start()

    @app.post("/api/v1/incident/monitor/stop")
    async def incident_monitor_stop() -> dict[str, Any]:
        return await incident_manager.stop()

    @app.get("/api/v1/incident/logs")
    async def incident_logs(limit: Annotated[int, Query(ge=1, le=500)] = 100,
                            offset: Annotated[int, Query(ge=0)] = 0) -> dict[str, Any]:
        return {"schema_version": "1.0", "logs": incident_manager.logs(limit, offset),
                "total": incident_manager.store.receipt_count('incident')}

    @app.get("/api/v1/incident/actions")
    async def incident_actions(limit: Annotated[int, Query(ge=1, le=200)] = 100,
                               offset: Annotated[int, Query(ge=0)] = 0) -> dict[str, Any]:
        return {"schema_version": "1.0", "actions": incident_manager.actions(limit, offset),
                "total": len(incident_manager._actions)}

    @app.get("/api/v1/incident/approvals")
    async def incident_approvals(limit: Annotated[int, Query(ge=1, le=200)] = 100,
                                 offset: Annotated[int, Query(ge=0)] = 0) -> dict[str, Any]:
        return {"schema_version": "1.0", "approvals": incident_manager.approvals(limit, offset),
                "total": len(incident_manager._approvals)}

    @app.get("/api/v1/incident/pending-approvals")
    async def incident_pending_approvals() -> dict[str, Any]:
        return {"schema_version": "1.0", "approvals": incident_manager.pending_approvals()}

    @app.get("/api/v1/incident/eligible-unblocks")
    async def incident_eligible_unblocks() -> dict[str, Any]:
        return {"schema_version": "1.0", "actions": incident_manager.eligible_unblocks()}

    @app.post("/api/v1/incident/command")
    async def incident_command(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            return await incident_manager.submit_command(
                str(payload.get("command", "")),
                str(payload.get("target", "测试环境")),
                str(payload.get("reason", "")),
            )
        except (ValueError, OSError) as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.post("/api/v1/incident/approvals/{approval_id}")
    async def incident_resolve_approval(approval_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            return await incident_manager.resolve_approval(
                approval_id,
                str(payload.get("decision", "")),
                str(payload.get("note", "")),
            )
        except KeyError as exc:
            raise HTTPException(404, "Approval request not found") from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.websocket("/api/v1/incident/events")
    async def incident_events(websocket: WebSocket) -> None:
        if not await allow_websocket_origin(websocket):
            return
        await websocket.accept()
        await websocket.send_json({"type": "incident.snapshot", "payload": incident_manager.snapshot()})
        try:
            async with incident_manager.subscribe() as queue:
                for event in incident_manager.logs(100)[::-1]:
                    await websocket.send_json({"type": "incident.event", "payload": event})
                while True:
                    await websocket.send_json(await queue.get())
        except WebSocketDisconnect:
            return

    @app.get("/api/v1/experiences")
    async def list_experiences(
        module_route: Annotated[str | None, Query(max_length=80)] = None,
        source_type: Annotated[str | None, Query(pattern="^(run|manual)$")] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 200,
        offset: Annotated[int, Query(ge=0)] = 0,
        review_status: Annotated[str | None, Query(pattern="^(draft|approved|rejected|retired)$")] = None,
        q: Annotated[str, Query(max_length=4000)] = "",
    ) -> dict[str, Any]:
        records = experiences.list(module_route=module_route, source_type=source_type, review_status=review_status, q=q, limit=None)
        return {
            "schema_version": "1.0",
            "statistics": {
                "total": len(records),
                "verified": sum(1 for item in records if item["verified"]),
                "draft": sum(1 for item in records if item["review_status"] == "draft"),
                "usage_count": sum(item["usage_count"] for item in records),
                "run_sourced": sum(1 for item in records if item["source_type"] == "run"),
                "manual": sum(1 for item in records if item["source_type"] == "manual"),
                "success_patterns": sum(1 for item in records if item["experience_kind"] == "success_pattern"),
                "failure_lessons": sum(1 for item in records if item["experience_kind"] == "failure_lesson"),
            },
            "experiences": records[offset:offset + limit],
            "offset": offset,
            "has_more": len(records) > offset + limit,
        }

    @app.get("/api/v1/prompts")
    async def list_prompts() -> dict[str, Any]:
        entries = app.state.prompt_catalog.list_metadata()
        return {
            "schema_version": "1.0",
            "runtime_injected": True,
            "count": len(entries),
            "prompts": entries,
        }

    @app.get("/api/v1/prompts/{prompt_key}")
    async def get_prompt(prompt_key: str) -> dict[str, Any]:
        entry = app.state.prompt_catalog.get(prompt_key, include_content=True)
        if entry is None:
            raise HTTPException(404, "Prompt not found")
        return {"schema_version": "1.0", **entry}

    @app.get("/api/v1/mcp/catalog")
    async def mcp_catalog() -> dict[str, Any]:
        return app.state.mcp_runtime.catalog_payload()

    @app.get("/api/v1/mcp/servers/{server_id}")
    async def get_mcp_server(server_id: str) -> dict[str, Any]:
        server = app.state.mcp_catalog.get_server(server_id)
        if server is None:
            raise HTTPException(404, "MCP server not found")
        return {"schema_version": "1.0", "server": server}

    @app.post("/api/v1/mcp/servers", status_code=201)
    async def create_mcp_server(payload: MCPServerUpsertRequest) -> dict[str, Any]:
        try:
            server = app.state.mcp_catalog.create_server(payload.model_dump(mode="json"))
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"schema_version": "1.0", "server": server}

    @app.put("/api/v1/mcp/servers/{server_id}")
    async def update_mcp_server(server_id: str, payload: MCPServerUpsertRequest) -> dict[str, Any]:
        server = app.state.mcp_catalog.update_server(server_id, payload.model_dump(mode="json"))
        if server is None:
            raise HTTPException(404, "MCP server not found")
        return {"schema_version": "1.0", "server": server}

    @app.delete("/api/v1/mcp/servers/{server_id}", status_code=204)
    async def delete_mcp_server(server_id: str) -> Response:
        if not app.state.mcp_catalog.delete_server(server_id):
            raise HTTPException(404, "MCP server not found")
        return Response(status_code=204)

    @app.post("/api/v1/mcp/servers/{server_id}/tools", status_code=201)
    async def create_mcp_tool(server_id: str, payload: MCPToolUpsertRequest) -> dict[str, Any]:
        try:
            tool = app.state.mcp_catalog.create_tool(server_id, payload.model_dump(mode="json"))
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        if tool is None:
            raise HTTPException(404, "MCP server not found")
        return {"schema_version": "1.0", "tool": tool}

    @app.put("/api/v1/mcp/servers/{server_id}/tools/{tool_name}")
    async def update_mcp_tool(
        server_id: str,
        tool_name: str,
        payload: MCPToolUpsertRequest,
    ) -> dict[str, Any]:
        tool = app.state.mcp_catalog.update_tool(server_id, tool_name, payload.model_dump(mode="json"))
        if tool is None:
            raise HTTPException(404, "MCP server or tool not found")
        return {"schema_version": "1.0", "tool": tool}

    @app.delete("/api/v1/mcp/servers/{server_id}/tools/{tool_name}", status_code=204)
    async def delete_mcp_tool(server_id: str, tool_name: str) -> Response:
        if not app.state.mcp_catalog.delete_tool(server_id, tool_name):
            raise HTTPException(404, "MCP server or tool not found")
        return Response(status_code=204)

    @app.get("/api/v1/integration-status")
    async def integration_status() -> dict[str, Any]:
        mcp = app.state.mcp_catalog.payload()
        prompts = app.state.prompt_catalog.list_metadata()
        return {
            "schema_version": "1.0",
            "baseline_version": actual_settings.benchmark_candidate_version,
            "prompt_count": len(prompts),
            "mcp_server_count": mcp["server_count"],
            "mcp_candidate_count": mcp["candidate_count"],
            "mcp_runtime_enabled": True,
            "mcp_invocation_enabled": True,
            "native_tool_count": len(default_registry().manifests()),
            "module_routes": ["code_audit", "reverse", "log_analysis", "penetration", "incident_response"],
            "model_configuration_scope": "unified_platform",
            "model_usage_scope": "platform_and_local_engines",
            "independent_model_components": ["secmind"],
        }

    @app.post("/api/v1/experiences", status_code=201)
    async def create_experience(payload: ExperienceCreateRequest) -> dict[str, Any]:
        return {"schema_version": "1.0", "experience": experiences.create_manual(payload)}

    @app.delete("/api/v1/experiences/{experience_id}", status_code=204)
    async def delete_experience(experience_id: str) -> Response:
        if not experiences.delete(experience_id):
            raise HTTPException(404, "Experience not found")
        return Response(status_code=204)

    @app.post("/api/v1/experiences/backfill")
    async def backfill_experiences() -> dict[str, Any]:
        result = experiences.backfill(service.ledger)
        return {"schema_version": "1.0", **result}

    @app.get("/api/v1/penetration/projects")
    async def list_penetration_projects() -> dict[str, Any]:
        try:
            projects = await penetration_get(
                actual_settings.penetration_base_url,
                "/projects",
                actual_settings.module_timeout_seconds,
            )
        except (PenetrationUnavailableError, PenetrationProtocolError) as exc:
            raise HTTPException(503, str(exc)) from exc
        if not isinstance(projects, list):
            raise HTTPException(502, "Penetration project list has an invalid shape")
        return {"schema_version": "1.0", "source": "penetration", "projects": projects}

    @app.get("/api/v1/runs/{run_id}/penetration-graph")
    async def get_penetration_graph(run_id: str) -> dict[str, Any]:
        try:
            state = service.state(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        if state.module_route != "penetration":
            raise HTTPException(409, "Run is not routed to the penetration module")
        try:
            project_id = await resolve_project_id(
                state,
                actual_settings.penetration_base_url,
                actual_settings.module_timeout_seconds,
            )
            if project_id is None:
                return {
                    "schema_version": "1.0",
                    "source": "penetration",
                    "available": True,
                    "linked": False,
                    "project_id": None,
                    "project": None,
                    "nodes": [],
                    "edges": [],
                    "counts": {},
                }
            detail = await penetration_get(
                actual_settings.penetration_base_url,
                f"/projects/{project_id}",
                actual_settings.module_timeout_seconds,
            )
            if not isinstance(detail, dict):
                raise PenetrationProtocolError("Penetration project detail must be an object")
            return normalize_penetration_graph(detail, state.external_execution.get("fact_assessments"),
                                               service.ledger.events(run_id, limit=100000), state,
                                               app.state.mcp_runtime.store.pending_mcp_approvals(run_id))
        except KeyError as exc:
            raise HTTPException(404, "Linked Penetration project was not found") from exc
        except PenetrationUnavailableError as exc:
            raise HTTPException(503, str(exc)) from exc
        except PenetrationProtocolError as exc:
            raise HTTPException(502, str(exc)) from exc

    @app.post("/api/v1/internal/runs/{run_id}/planning", response_model=dict)
    async def runtime_planning_callback(
        run_id: str,
        payload: PlanningCallbackRequest,
        runtime_token: Annotated[str | None, Header(alias="X-Security-Runtime-Token")] = None,
    ) -> dict[str, Any]:
        """Receive one idempotent reason decision from Security Runtime.

        This endpoint exposes only the bounded planning contract.  It never
        returns model messages or hidden reasoning, and verifies both the URL
        run ID and the project binding before invoking PlannerAgent.
        """
        expected = actual_settings.security_runtime_callback_token.strip()
        if not expected:
            raise HTTPException(503, "Security Runtime callback is not configured")
        if not runtime_token or not hmac.compare_digest(runtime_token, expected):
            raise HTTPException(401, "Security Runtime callback authentication failed")
        if payload.run_id != run_id:
            raise HTTPException(409, "Planning callback run identity mismatch")
        try:
            result = await service.orchestrator.planning_callback(payload)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return result.model_dump(mode="json", by_alias=True)

    @app.get("/api/v1/runs/{run_id}/blackboard-graph")
    async def get_blackboard_graph(run_id: str) -> dict[str, Any]:
        try:
            state = service.state(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        board = state.external_execution.get("blackboard", {})
        if not isinstance(board, dict) or not board.get("project_id"):
            return {"schema_version": "1.1", "source": "blackboard", "available": True,
                    "linked": False, "project_id": None, "project": None,
                    "nodes": [], "edges": [], "counts": {}}
        project_id = board["project_id"]
        if board.get("backend") == "local":
            graph = board.get("graph")
            if (project_id != "local:" + run_id or not isinstance(graph, dict)
                    or graph.get("title") != project_title_for_run(run_id)):
                raise HTTPException(409, "Local blackboard identity mismatch")
            detail = {"project": {"id": project_id, "title": graph["title"],
                                  "status": graph.get("status")},
                    "facts": graph.get("facts", []), "intents": graph.get("intents", []),
                    "hints": graph.get("hints", [])}
        elif board.get("backend") == "remote":
            try:
                detail = await penetration_get(
                    actual_settings.penetration_base_url, f"/projects/{project_id}",
                    actual_settings.module_timeout_seconds,
                )
            except KeyError as exc:
                raise HTTPException(404, "Linked blackboard project was not found") from exc
            except PenetrationUnavailableError as exc:
                raise HTTPException(503, str(exc)) from exc
            if (not isinstance(detail, dict) or not isinstance(detail.get("project"), dict)
                    or detail["project"].get("id") != project_id
                    or detail["project"].get("title") != project_title_for_run(run_id)):
                raise HTTPException(409, "Blackboard project identity mismatch")
        else:
            raise HTTPException(409, "Unknown blackboard backend")
        try:
            result = normalize_penetration_graph(detail, state.external_execution.get("fact_assessments"),
                                                 service.ledger.events(run_id, limit=100000), state,
                                                 app.state.mcp_runtime.store.pending_mcp_approvals(run_id))
        except PenetrationProtocolError as exc:
            raise HTTPException(502, str(exc)) from exc
        result["source"] = "blackboard"
        result["sync_error"] = board.get("sync_error")
        return result

    @app.get("/api/v1/runs/{run_id}/asset-graph")
    async def get_asset_graph(run_id: str) -> dict[str, Any]:
        try:
            state = service.state(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        receipts = app.state.mcp_runtime.store.items('call:')
        return project_asset_graph(state, (receipt for _, receipt in receipts))

    @app.post("/api/v1/question-banks/inspect", status_code=202)
    async def inspect_question_bank(payload: QuestionBankInspectRequest) -> dict[str, Any]:
        try:
            return question_banks.create_inspection(payload)
        except QuestionBankError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get("/api/v1/question-banks/{bank_id}/inspection")
    def get_question_bank_inspection(bank_id: str) -> dict[str, Any]:
        try:
            return question_banks.get(bank_id)
        except KeyError as exc:
            raise HTTPException(404, "Question bank inspection not found") from exc

    @app.post("/api/v1/question-banks/{bank_id}/confirm")
    def confirm_question_bank(bank_id: str, payload: QuestionBankConfirmRequest) -> dict[str, Any]:
        try:
            return question_banks.confirm(bank_id, payload)
        except KeyError as exc:
            raise HTTPException(404, "Question bank inspection not found") from exc
        except QuestionBankError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.websocket("/api/v1/question-banks/{bank_id}/events")
    async def question_bank_events(websocket: WebSocket, bank_id: str) -> None:
        if not await allow_websocket_origin(websocket):
            return
        try:
            current = question_banks.get(bank_id)
        except KeyError:
            await websocket.close(code=4404, reason="Question bank inspection not found")
            return
        await websocket.accept()
        await websocket.send_json({"type": "inspection.snapshot", "bank_id": bank_id, "payload": current})
        if current["status"] != "inspecting":
            return
        try:
            async with question_banks.subscribe(bank_id) as queue:
                latest = question_banks.get(bank_id)
                if latest["status"] != "inspecting":
                    await websocket.send_json(
                        {"type": "inspection.snapshot", "bank_id": bank_id, "payload": latest}
                    )
                    return
                while True:
                    event = await queue.get()
                    await websocket.send_json(event)
                    if event["type"] in {
                        "inspection.completed",
                        "inspection.manual_required",
                        "inspection.failed",
                    }:
                        return
        except WebSocketDisconnect:
            return

    @app.get("/api/v1/benchmark/tasks")
    async def list_benchmark_tasks() -> dict[str, Any]:
        try:
            tasks = evaluation_service.catalog.list_tasks()
        except EvaluationError as exc:
            raise HTTPException(503, str(exc)) from exc
        return {
            "schema_version": "1.0",
            "dataset_version": actual_settings.benchmark_dataset_version,
            "suite": "S-Suite",
            "tasks": [item.model_dump(mode="json") for item in tasks],
        }

    @app.post("/api/v1/evaluations", status_code=202)
    async def create_evaluation(payload: EvaluationCreateRequest) -> dict[str, Any]:
        try:
            job = await evaluation_service.create(payload)
        except EvaluationError as exc:
            raise HTTPException(422, str(exc)) from exc
        return job.model_dump(mode="json")

    @app.get("/api/v1/evaluations/by-run/{run_id}")
    async def get_evaluation_by_run(run_id: str) -> dict[str, Any]:
        job = evaluation_service.by_run(run_id)
        if job is None:
            raise HTTPException(404, "Evaluation not found")
        return job.model_dump(mode="json")

    @app.get("/api/v1/evaluations/{evaluation_id}")
    async def get_evaluation(evaluation_id: str) -> dict[str, Any]:
        try:
            return evaluation_service.get(evaluation_id).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(404, "Evaluation not found") from exc

    @app.get("/api/v1/evaluations/{evaluation_id}/score")
    async def get_evaluation_score(evaluation_id: str) -> dict[str, Any]:
        try:
            return evaluation_service.score(evaluation_id)
        except KeyError as exc:
            raise HTTPException(404, "Evaluation not found") from exc
        except FileNotFoundError as exc:
            raise HTTPException(409, "Score is not available yet") from exc

    @app.get("/api/v1/evaluations/{evaluation_id}/report", response_class=FileResponse)
    async def get_evaluation_report(evaluation_id: str) -> FileResponse:
        try:
            path = evaluation_service.report_path(evaluation_id)
        except KeyError as exc:
            raise HTTPException(404, "Evaluation not found") from exc
        except FileNotFoundError as exc:
            raise HTTPException(409, "Evaluation report is not available yet") from exc
        return FileResponse(path, media_type="text/markdown", filename=f"{evaluation_id}-score-report.md")

    @app.websocket("/api/v1/evaluations/{evaluation_id}/events")
    async def evaluation_events_socket(
        websocket: WebSocket,
        evaluation_id: str,
        after_sequence: int = 0,
    ) -> None:
        if not await allow_websocket_origin(websocket):
            return
        try:
            evaluation_service.get(evaluation_id)
        except KeyError:
            await websocket.close(code=4404, reason="Evaluation not found")
            return
        await websocket.accept()
        try:
            for event in evaluation_service.store.events(evaluation_id, after_sequence):
                await websocket.send_json(event)
            async with evaluation_service.subscribe(evaluation_id) as queue:
                while True:
                    await websocket.send_json(await queue.get())
        except WebSocketDisconnect:
            return

    @app.get("/api/v1/runs")
    async def list_runs(
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
        before: str | None = None,
    ) -> dict[str, Any]:
        await asyncio.to_thread(usage_collector.sync)
        cursor = None
        if before:
            try:
                created_at, run_id = before.rsplit('|', 1)
                cursor = (datetime.fromisoformat(created_at), run_id)
            except ValueError as exc:
                raise HTTPException(422, 'Invalid run cursor') from exc
        page = service.summaries(limit + 1, offset, cursor)
        summaries = page[:limit]
        event_windows = service.ledger.event_windows([summary.run_id for summary in summaries])
        llm_by_run: dict[str, list] = {}
        for kind in ('llm.stream.started', 'llm.stream.completed', 'llm.stream.failed'):
            for event in service.ledger.events_by_type(kind, limit=None):
                llm_by_run.setdefault(event.run_id, []).append(event)
        external_events = [event for kind in ('started', 'completed', 'failed')
                           for event in service.ledger.events_by_type('external.usage.' + kind, limit=None)] \
            if any(summary.external_execution for summary in summaries) else []
        by_project: dict[str, list] = {}
        by_remote: dict[str, list] = {}
        for event in external_events:
            payload = event.payload
            if payload.get('source') == 'security_runtime_worker' and payload.get('project_id'):
                by_project.setdefault(payload['project_id'], []).append(event)
            elif payload.get('source') == 'secmind' and payload.get('remote_run_id'):
                by_remote.setdefault(payload['remote_run_id'], []).append(event)
        return {
            "schema_version": "1.0",
            "total": service.ledger.count_states(),
            "offset": offset,
            "has_more": len(page) > limit,
            "next_cursor": service.ledger.run_cursor(summaries[-1].run_id) if len(page) > limit else None,
            "runs": [
                {
                    **summary.model_dump(mode="json"),
                    # Keep list and detail pages on the same provider ledger
                    # accounting, including linked external Worker receipts.
                    "usage": _run_usage(service.ledger, summary.run_id, summary.budget,
                                        summary.external_execution,
                                        [*by_project.get(summary.external_execution.get('project_id'), []),
                                         *by_remote.get(summary.external_execution.get('remote_run_id'), [])],
                                        llm_by_run.get(summary.run_id, []), event_windows.get(summary.run_id),
                                        summary.status),
                }
                for summary in summaries
            ],
        }

    @app.get("/api/v1/runs/{run_id}")
    async def get_run(run_id: str) -> dict[str, Any]:
        try:
            summary = service.summary(run_id)
            if summary.external_execution:
                await asyncio.to_thread(usage_collector.sync)
            pending = []
            if summary.status == RunStatus.RUNNING:
                for record in app.state.mcp_runtime.store.pending_mcp_approvals(run_id):
                    if await app.state.mcp_approval_is_live(record):
                        pending.append(record)
            return {
                **summary.model_dump(mode="json"),
                "mcp_pending_approvals": pending,
                "usage": _run_usage(service.ledger, summary.run_id, summary.budget, summary.external_execution,
                                    run_status=summary.status),
            }
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc

    @app.post("/api/v1/runs/{run_id}/cancel")
    async def cancel_run(run_id: str) -> dict[str, Any]:
        try:
            state = await service.cancel(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        return {
            "schema_version": "1.0",
            "run_id": run_id,
            "accepted": True,
            "status": state.status,
            "cancellation_requested": bool(state.external_execution.get("cancellation_requested"))
            or state.external_execution.get("status") == "cancelled",
        }

    @app.post("/api/v1/runs/{run_id}/hint", status_code=201)
    async def create_run_hint(run_id: str, request: RunHintRequest) -> dict[str, Any]:
        try:
            state = service.state(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        if state.status not in {RunStatus.PENDING, RunStatus.RUNNING, RunStatus.WAITING_APPROVAL}:
            raise HTTPException(409, "任务已结束，不能提交提示")
        board = state.external_execution.get("blackboard")
        if not isinstance(board, dict) or not board.get("project_id"):
            raise HTTPException(409, "任务尚未建立黑板项目")
        project_id = board["project_id"]
        if board.get("backend") == "local":
            graph = board.get("graph")
            if not isinstance(graph, dict) or graph.get("title") != project_title_for_run(run_id):
                raise HTTPException(409, "本地黑板身份不匹配")
            hints = graph.setdefault("hints", [])
            hint = {"id": f"hint-{len(hints) + 1}", "content": request.content,
                    "creator": request.creator, "created_at": datetime.now(UTC).isoformat()}
            hints.append(hint)
            service.ledger.save_state(state)
        elif board.get("backend") == "remote":
            try:
                detail = await penetration_get(actual_settings.penetration_base_url, f"/projects/{project_id}",
                                               actual_settings.module_timeout_seconds)
                project = detail.get("project") if isinstance(detail, dict) else None
                if (not isinstance(project, dict) or project.get("id") != project_id
                        or project.get("title") != project_title_for_run(run_id)
                        or project.get("status") != "active"):
                    raise HTTPException(409, "黑板项目身份或状态不匹配")
                hint = await create_project_hint(actual_settings.penetration_base_url, project_id,
                                                 request.content, request.creator,
                                                 actual_settings.module_timeout_seconds)
            except KeyError as exc:
                raise HTTPException(404, "Linked blackboard project was not found") from exc
            except PenetrationUnavailableError as exc:
                raise HTTPException(503, str(exc)) from exc
            except PenetrationProtocolError as exc:
                raise HTTPException(502, str(exc)) from exc
        else:
            raise HTTPException(409, "Unknown blackboard backend")
        event = service.ledger.append(run_id, "blackboard.hint.created", {
            "project_id": project_id, "content": request.content, "creator": request.creator,
        }, actor=request.creator)
        await service.event_hub.publish(event.model_dump(mode="json"))
        return {"schema_version": "1.0", "run_id": run_id, "project_id": project_id, "hint": hint}

    @app.post("/api/v1/runs/{run_id}/retry", status_code=202)
    async def retry_run(run_id: str, request: RunRetryRequest) -> dict[str, Any]:
        try:
            # Check before taking the execution lock; an active run holds it for its lifetime.
            state = service.state(run_id)
            if state.status not in {RunStatus.PARTIAL, RunStatus.FAILED}:
                raise ValueError("仅部分完成或失败的任务可以重试")
            async with service.run_lock(run_id):
                child_id = service.retry(run_id, request)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"schema_version": "1.0", "run_id": child_id, "retry_of": run_id, "accepted": True}

    @app.get("/api/v1/runs/{run_id}/report")
    async def get_report(run_id: str) -> dict[str, Any]:
        try:
            state = service.state(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        if state.report is None:
            raise HTTPException(409, "Report is not available yet")
        return state.report.model_dump(mode="json")

    @app.post("/api/v1/runs/{run_id}/report/refresh")
    async def refresh_report(run_id: str) -> dict[str, Any]:
        from security_agent.report_sync import ReportNotReady, synchronize_report
        try:
            current = service.state(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        if current.status in {RunStatus.PENDING, RunStatus.RUNNING, RunStatus.WAITING_APPROVAL}:
            raise HTTPException(409, "任务仍在执行或等待审批，请等待报告生成")
        async with service.run_lock(run_id):
            try:
                state = service.state(run_id)
                if state.status in {RunStatus.PENDING, RunStatus.RUNNING, RunStatus.WAITING_APPROVAL}:
                    raise ReportNotReady("任务仍在执行或等待审批，请等待报告生成")
                state = await synchronize_report(state, actual_settings, gateway)
            except KeyError as exc:
                raise HTTPException(404, "Run not found") from exc
            except ReportNotReady as exc:
                raise HTTPException(409, str(exc)) from exc
            except (PenetrationUnavailableError, PenetrationProtocolError, httpx.HTTPError, ValueError) as exc:
                raise HTTPException(503, f"外部报告同步失败：{type(exc).__name__}") from exc
            service.ledger.save_state(state)
            event = service.ledger.append(run_id, "report.refreshed",
                {"source": state.external_execution.get("module", "local"), "status": state.status}, actor="api")
            await service.event_hub.publish(event.model_dump(mode="json"))
            return state.report.model_dump(mode="json")

    @app.get("/api/v1/runs/{run_id}/ledger")
    async def get_ledger(
        run_id: str,
        after_sequence: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=5000)] = 1000,
    ) -> dict[str, Any]:
        if service.ledger.load_state(run_id) is None:
            raise HTTPException(404, "Run not found")
        events = service.ledger.events(run_id, after_sequence, limit)
        return {
            "schema_version": "1.0",
            "run_id": run_id,
            "events": [event.model_dump(mode="json") for event in events],
            "chain_valid": service.ledger.verify(run_id),
        }

    @app.get("/api/v1/runs/{run_id}/ledger/export", response_class=FileResponse)
    async def export_ledger(run_id: str) -> FileResponse:
        if service.ledger.load_state(run_id) is None:
            raise HTTPException(404, "Run not found")
        destination = actual_settings.run_root / run_id / "ledger.jsonl"
        service.ledger.export_jsonl(run_id, destination)
        return FileResponse(destination, filename=f"{run_id}-ledger.jsonl")

    @app.get("/api/v1/runs/{run_id}/thoughts/export", response_class=FileResponse)
    async def export_thoughts(run_id: str) -> FileResponse:
        state = service.ledger.load_state(run_id)
        if state is None:
            raise HTTPException(404, "Run not found")
        terminal = {
            RunStatus.COMPLETED,
            RunStatus.PARTIAL,
            RunStatus.FAILED,
            RunStatus.DENIED,
        }
        if state.status not in terminal:
            raise HTTPException(409, "Thought process is available after the run reaches a terminal state")
        destination = actual_settings.run_root / run_id / "thought-process.md"
        service.ledger.export_thought_markdown(run_id, destination)
        return FileResponse(
            destination,
            media_type="text/markdown; charset=utf-8",
            filename=f"{run_id}-thought-process.md",
        )

    @app.post("/api/v1/runs/{run_id}/approvals/{request_id}", status_code=202)
    async def resolve_approval(run_id: str, request_id: str, response: ApprovalResponse) -> dict[str, Any]:
        try:
            state = service.state(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        if state.pending_approval is None or state.pending_approval.request_id != request_id:
            raise HTTPException(409, "Approval request is not active")
        try:
            service.submit_approval(run_id, response)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"schema_version": "1.0", "run_id": run_id, "accepted": True}

    @app.websocket("/api/v1/runs/{run_id}/events")
    async def events_socket(websocket: WebSocket, run_id: str, after_sequence: int = 0) -> None:
        if not await allow_websocket_origin(websocket):
            return
        if service.ledger.load_state(run_id) is None:
            await websocket.close(code=4404, reason="Run not found")
            return
        await websocket.accept()
        try:
            async with service.event_hub.subscribe(run_id) as queue:
                # Subscribe before reading the backlog.  Reading the backlog
                # first creates a race where events emitted during that read
                # are lost, which makes the UI appear frozen until its next
                # polling pass.
                last_sequence = after_sequence
                async def send_stored_events() -> None:
                    nonlocal last_sequence
                    while True:
                        page = service.ledger.events(run_id, after_sequence=last_sequence, limit=1000)
                        for stored_event in page:
                            await websocket.send_text(stored_event.model_dump_json())
                            last_sequence = stored_event.sequence
                        if len(page) < 1000:
                            break

                await send_stored_events()
                while True:
                    live_event = await queue.get()
                    # The event may already have been included in the
                    # backlog. Read durable events again to fill any gap if
                    # the bounded subscriber queue overflowed during replay.
                    sequence = int(live_event.get("sequence") or 0)
                    if sequence <= last_sequence:
                        continue
                    if sequence == last_sequence + 1:
                        last_sequence = sequence
                        await websocket.send_text(json.dumps(live_event, ensure_ascii=False))
                    else:
                        await send_stored_events()
        except WebSocketDisconnect:
            return

    return app


def __getattr__(name: str):
    # Preserve the Docker/ASGI ``api:app`` entry point without touching the
    # configured database when tests and library users only import create_app.
    if name == "app":
        application = create_app()
        globals()["app"] = application
        return application
    raise AttributeError(name)


def run() -> None:
    settings = get_settings()
    uvicorn.run(
        "security_agent.api:create_app",
        factory=True,
        host=settings.api_host,
        port=settings.api_port,
        reload=False,
    )
