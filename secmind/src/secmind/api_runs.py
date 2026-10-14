"""HTTP adapters for task and run lifecycle operations.

The handlers in this module translate HTTP inputs and errors only. Run state,
leases, approvals, replay, and ledger semantics remain owned by ``RunService``.
Keeping these routes out of :mod:`secmind.api` makes application construction
small enough to review without hiding domain behavior in a framework callback.
"""

from __future__ import annotations

import json
import re
import secrets
from typing import Annotated, Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse, JSONResponse, Response

from secmind import PUBLIC_VERSION
from secmind.config import Settings
from secmind.execution import ExecutionConflict
from secmind.log_governance import authorize_data_view
from secmind.replay import REPLAY_MEDIA_TYPE, ReplayError
from secmind.reporting import render_markdown, render_sarif
from secmind.runtime import ApplicationRuntime
from secmind.schemas import (
    SCHEMA_VERSION,
    AgentReport,
    ApprovalBatchRequest,
    ApprovalResponse,
    ClaimStatus,
    ClarificationResponse,
    DataView,
    LogLayer,
    RecoveryRequest,
    ReplayRequest,
    RetentionHoldRequest,
    RunStatus,
    TaskRequest,
)
from secmind.secret_scrubber import ArtifactLeakageError, scrub_artifact
from secmind.session_projection import RunSessionSnapshot

_ARTIFACT_ID = re.compile(r"^[a-f0-9]{64}$")


def run_state(runtime: ApplicationRuntime, run_id: str) -> Any:
    """Return a run state while presenting a stable HTTP 404 boundary."""

    try:
        return runtime.service.state(run_id)
    except KeyError as exc:
        raise HTTPException(404, "Run not found") from exc


def _evaluation_release_allowed(request: Request, settings: Settings, audience: str) -> bool:
    """Authorize the value-bearing report projection for the sealed bridge.

    The normal operator bearer boundary is intentionally not sufficient here:
    a leaked operator credential must not become an exact-answer release
    capability.  The bridge token is injected per evaluator process and is
    never persisted in reports or error messages.
    """

    if audience != "evaluation" or not settings.evaluation_bridge_token:
        return False
    presented = request.headers.get("x-secmind-evaluation-bridge", "")
    return bool(presented) and secrets.compare_digest(presented, settings.evaluation_bridge_token)


def _redacted_report(report: AgentReport) -> AgentReport:
    """Return a schema-valid report with tainted values scrubbed.

    Admission remains the immutable source of truth.  This is only a
    read-boundary projection: it intentionally does not carry the bridge's
    trusted exact-answer exception and therefore cannot release a raw secret
    merely because the sealed report contains one.
    """

    try:
        payload = scrub_artifact(report.model_dump(mode="json"), max_depth=12, max_items=256)
    except ArtifactLeakageError as exc:
        raise HTTPException(409, "report cannot be safely redacted") from exc
    if not isinstance(payload, dict):
        raise HTTPException(500, "report redaction failed closed")
    try:
        return AgentReport.model_validate(payload)
    except Exception as exc:
        raise HTTPException(500, "report redaction produced an invalid projection") from exc


def _redacted_admission_snapshot(snapshot: Any) -> dict[str, Any]:
    """Project an admission snapshot while preserving its envelope metadata."""

    payload = snapshot.model_dump(mode="json")
    report = payload.get("report")
    if isinstance(report, dict):
        payload["report"] = _redacted_report(snapshot.report).model_dump(mode="json")
    return payload


def register_run_routes(app: FastAPI, runtime: ApplicationRuntime, settings: Settings) -> None:
    """Register the complete public task/run API without mutating its contract."""

    _register_task_routes(app, runtime)
    _register_run_views(app, runtime, settings)
    _register_report_and_replay_routes(app, runtime, settings)
    _register_ledger_routes(app, runtime, settings)
    _register_run_commands(app, runtime)


def _register_task_routes(app: FastAPI, runtime: ApplicationRuntime) -> None:
    """Register task submission and clarification endpoints."""

    @app.post("/api/v1/tasks", status_code=202)
    async def create_task(task: TaskRequest) -> dict[str, Any]:
        try:
            run_id = runtime.service.submit(task)
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"schema_version": SCHEMA_VERSION, "run_id": run_id, "status": RunStatus.PENDING}

    @app.post("/api/v1/runs/{run_id}/clarifications/{request_id}", status_code=202)
    async def resolve_clarification(
        run_id: str,
        request_id: str,
        response: ClarificationResponse,
    ) -> dict[str, Any]:
        try:
            resolution_id, changed = runtime.service.submit_clarification_resolution(
                run_id,
                request_id,
                response,
            )
        except KeyError as exc:
            raise HTTPException(404, "Run or clarification request not found") from exc
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "request_id": request_id,
            "resolution_id": resolution_id,
            "resolution_status": "accepted" if changed else "already_resolved",
        }


def _register_run_views(app: FastAPI, runtime: ApplicationRuntime, settings: Settings) -> None:
    """Register read-only projections of current run state."""

    @app.get("/api/v1/runs")
    async def list_runs(
        status_filter: Annotated[list[RunStatus] | None, Query(alias="status")] = None,
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        statuses = set(status_filter) if status_filter else None
        page = runtime.service.list_summaries(statuses=statuses, offset=offset, limit=limit + 1)
        has_more = len(page) > limit
        items = page[:limit]
        return {
            "schema_version": SCHEMA_VERSION,
            "items": [item.model_dump(mode="json") for item in items],
            "offset": offset,
            "limit": limit,
            "next_offset": offset + len(items),
            "has_more": has_more,
        }

    @app.get("/api/v1/runs/{run_id}")
    async def get_run(run_id: str) -> dict[str, Any]:
        try:
            return runtime.service.summary(run_id).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc

    @app.get("/api/v1/runs/{run_id}/task-spec")
    async def get_task_spec(run_id: str) -> dict[str, Any]:
        try:
            spec = runtime.service.task_spec(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run or TaskSpec not found") from exc
        return spec.model_dump(mode="json")

    @app.get("/api/v1/runs/{run_id}/routes")
    async def get_run_routes(run_id: str) -> dict[str, Any]:
        state = run_state(runtime, run_id)
        routes = [] if state.active_route is None else [state.active_route.model_dump(mode="json")]
        return {"schema_version": SCHEMA_VERSION, "run_id": run_id, "routes": routes}

    @app.get("/api/v1/runs/{run_id}/evidence-gaps")
    async def get_evidence_gaps(run_id: str) -> dict[str, Any]:
        state = run_state(runtime, run_id)
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "compiler": state.audit_coverage.get("evidence_gap_compiler", {}),
            "tickets": [item.model_dump(mode="json") for item in state.evidence_gap_tickets],
        }

    @app.get("/api/v1/runs/{run_id}/admission")
    async def get_admission_snapshot(
        run_id: str,
        request: Request,
        audience: Annotated[str, Query(pattern="^(operator|evaluation)$")] = "operator",
    ) -> dict[str, Any]:
        try:
            snapshot = runtime.service.public_admission_snapshot(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        evaluation_release = _evaluation_release_allowed(request, settings, audience)
        if audience == "evaluation" and not evaluation_release:
            raise HTTPException(403, "evaluation report release is not authorized")
        if evaluation_release:
            return snapshot.model_dump(mode="json")
        return _redacted_admission_snapshot(snapshot)

    @app.get("/api/v1/runs/{run_id}/steps")
    async def get_run_steps(run_id: str) -> dict[str, Any]:
        state = run_state(runtime, run_id)
        queue_status: str | None = None
        coordinator_lease: Any = None
        coordinator = getattr(runtime.service, "coordinator", None)
        if coordinator is not None and callable(getattr(coordinator, "job_status", None)):
            try:
                queue_status, coordinator_lease = coordinator.job_status(run_id)
            except KeyError:
                pass
        steps = [
            {
                "plan": step.model_dump(mode="json"),
                "runtime": (
                    state.step_runtime[step.step_id].model_dump(mode="json")
                    if step.step_id in state.step_runtime
                    else None
                ),
            }
            for step in state.plan
        ]
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "state_version": state.state_version,
            "queue_status": queue_status,
            "lease": jsonable_encoder(coordinator_lease or state.lease),
            "current_step_id": (
                state.plan[state.current_step_index].step_id if state.current_step_index < len(state.plan) else None
            ),
            "steps": steps,
            "count": len(steps),
        }

    @app.get("/api/v1/runs/{run_id}/session", response_model=RunSessionSnapshot)
    async def get_run_session(run_id: str, response: Response) -> RunSessionSnapshot:
        try:
            snapshot = runtime.service.session_snapshot(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        response.headers["Cache-Control"] = "no-store"
        # ``observed_at`` changes between semantically equivalent reads, so the
        # consistency-vector validator is intentionally a weak ETag.
        response.headers["ETag"] = f'W/"{snapshot.snapshot_id}"'
        return snapshot

    @app.get("/api/v1/runs/{run_id}/input-envelopes/{invocation_id}")
    async def get_input_envelope(run_id: str, invocation_id: str) -> dict[str, Any]:
        try:
            envelope = runtime.service.input_envelope(run_id, invocation_id)
        except KeyError as exc:
            raise HTTPException(404, "Input envelope not found") from exc
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "input_envelope": envelope.model_dump(mode="json"),
            "execution_arguments_included": False,
        }

    @app.get("/api/v1/runs/{run_id}/claims")
    async def get_run_claims(
        run_id: str,
        status_filter: Annotated[list[ClaimStatus] | None, Query(alias="status")] = None,
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=5000)] = 1000,
    ) -> dict[str, Any]:
        state = run_state(runtime, run_id)
        counts = {status.value: 0 for status in ClaimStatus}
        for claim in state.claims:
            counts[claim.status.value] += 1
        allowed = set(status_filter) if status_filter else None
        filtered = [claim for claim in state.claims if allowed is None or claim.status in allowed]
        page = filtered[offset : offset + limit]
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "claims": [claim.model_dump(mode="json") for claim in page],
            "counts_by_status": counts,
            "total": len(filtered),
            "offset": offset,
            "limit": limit,
            "next_offset": offset + len(page),
            "has_more": offset + len(page) < len(filtered),
        }

    @app.get("/api/v1/runs/{run_id}/evidence-graph")
    async def get_evidence_graph(run_id: str) -> dict[str, Any]:
        state = run_state(runtime, run_id)
        claim_ids = {claim.claim_id for claim in state.claims}
        evidence_ids = {evidence.evidence_id for evidence in state.evidence}
        dangling_claim_ids = sorted({link.claim_id for link in state.evidence_links if link.claim_id not in claim_ids})
        dangling_evidence_ids = sorted(
            {link.evidence_id for link in state.evidence_links if link.evidence_id not in evidence_ids}
        )
        ledger_chain_valid: bool | None = None
        ledger = getattr(runtime.service, "ledger", None)
        if ledger is not None and callable(getattr(ledger, "verify", None)):
            ledger_chain_valid = bool(ledger.verify(run_id))
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "claims": [claim.model_dump(mode="json") for claim in state.claims],
            "evidence": [evidence.model_dump(mode="json") for evidence in state.evidence],
            "links": [link.model_dump(mode="json") for link in state.evidence_links],
            "verification_results": [result.model_dump(mode="json") for result in state.verification_results],
            "integrity": {
                "dangling_claim_ids": dangling_claim_ids,
                "dangling_evidence_ids": dangling_evidence_ids,
                "complete": not dangling_claim_ids and not dangling_evidence_ids,
                "ledger_chain_valid": ledger_chain_valid,
            },
        }

    @app.get("/api/v1/runs/{run_id}/timeline")
    async def get_security_timeline(run_id: str) -> dict[str, Any]:
        try:
            report = runtime.service.public_report(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        raw_ids = report.coverage.get("timeline_artifact_ids", [])
        if not isinstance(raw_ids, list) or any(not isinstance(item, str) for item in raw_ids):
            raise HTTPException(409, "Timeline manifest is invalid")
        sources: list[dict[str, Any]] = []
        for artifact_id in raw_ids[:100]:
            if not _ARTIFACT_ID.fullmatch(artifact_id):
                raise HTTPException(409, "Timeline artifact identity is invalid")
            try:
                content = runtime.service.artifact_store.read(artifact_id)
                payload = json.loads(content)
            except (FileNotFoundError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise HTTPException(409, "Timeline artifact failed integrity verification") from exc
            if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
                raise HTTPException(409, "Timeline artifact contract is invalid")
            sources.append(payload)
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "sources": sources,
            "source_count": len(sources),
            "raw_log_content_included": False,
        }

    @app.get("/api/v1/runs/{run_id}/context-packs")
    async def get_context_packs(
        run_id: str,
        step_id: Annotated[str | None, Query()] = None,
        agent_profile: Annotated[str | None, Query()] = None,
    ) -> dict[str, Any]:
        state = run_state(runtime, run_id)
        packs = [
            pack
            for pack in state.context_packs
            if (step_id is None or pack.step_id == step_id)
            and (agent_profile is None or pack.agent_profile == agent_profile)
        ]
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "context_packs": [
                {
                    "pack_id": pack.pack_id,
                    "run_id": pack.run_id,
                    "step_id": pack.step_id,
                    "agent_profile": pack.agent_profile,
                    "immutable_policy_refs": pack.immutable_policy_refs,
                    "repository_slice_refs": pack.repository_slice_refs,
                    "selected_skill_refs": pack.selected_skill_refs,
                    "knowledge_refs": pack.knowledge_refs,
                    "evidence_handles": pack.evidence_handles,
                    "tool_schema_refs": pack.tool_schema_refs,
                    "token_budget": pack.token_budget.model_dump(mode="json"),
                    "pack_digest": pack.pack_digest,
                    "created_at": pack.created_at.isoformat(),
                }
                for pack in packs
            ],
            "count": len(packs),
            "content_included": False,
        }


def _register_report_and_replay_routes(app: FastAPI, runtime: ApplicationRuntime, settings: Settings) -> None:
    """Register report rendering and deterministic replay endpoints."""

    @app.get("/api/v1/runs/{run_id}/report")
    async def get_report(
        run_id: str,
        request: Request,
        output_format: Annotated[str, Query(alias="format", pattern="^(json|markdown|sarif)$")] = "json",
        audience: Annotated[str, Query(pattern="^(operator|evaluation)$")] = "operator",
    ) -> Any:
        try:
            report = runtime.service.public_report(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        evaluation_release = _evaluation_release_allowed(request, settings, audience)
        if audience == "evaluation" and not evaluation_release:
            raise HTTPException(403, "evaluation report release is not authorized")
        report = report if evaluation_release else _redacted_report(report)
        if output_format == "markdown":
            return Response(render_markdown(report), media_type="text/markdown; charset=utf-8")
        if output_format == "sarif":
            return JSONResponse(render_sarif(report), media_type="application/sarif+json")
        return report.model_dump(mode="json")

    @app.get("/api/v1/runs/{run_id}/replay-bundle")
    async def get_replay_bundle(
        run_id: str,
        download: Annotated[bool, Query()] = False,
    ) -> Any:
        try:
            replay_ref = runtime.service.get_replay_bundle(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        except (ReplayError, RuntimeError) as exc:
            raise HTTPException(409, str(exc)) from exc
        if download:
            try:
                content = runtime.service.artifact_store.read(replay_ref.artifact_id)
            except (FileNotFoundError, ValueError) as exc:
                raise HTTPException(409, "Replay bundle failed integrity verification") from exc
            return Response(
                content,
                media_type=REPLAY_MEDIA_TYPE,
                headers={
                    "Content-Disposition": f'attachment; filename="{run_id}-replay.zip"',
                    "ETag": f'"sha256:{replay_ref.artifact_id}"',
                    "Cache-Control": "private, immutable",
                },
            )
        return {
            "schema_version": SCHEMA_VERSION,
            "replay_bundle": replay_ref.model_dump(mode="json"),
            "download_url": f"/api/v1/runs/{run_id}/replay-bundle?download=true",
        }

    @app.post("/api/v1/runs/{run_id}/replay")
    async def replay_run(run_id: str, request: ReplayRequest) -> dict[str, Any]:
        if request.mode == "checkpoint-fork":
            fork = getattr(runtime.service, "checkpoint_fork", None)
            if not callable(fork):
                raise HTTPException(501, f"Checkpoint fork replay is unavailable in v{PUBLIC_VERSION}")
            if not request.checkpoint_id:
                raise HTTPException(422, "checkpoint_id is required for checkpoint-fork replay")
            if not request.fork_request_id:
                raise HTTPException(422, "fork_request_id is required for checkpoint-fork replay")
            try:
                child = await fork(
                    run_id, request.checkpoint_id,
                    task=request.task, fork_request_id=request.fork_request_id,
                )
            except KeyError as exc:
                raise HTTPException(404, "Run not found") from exc
            except (ReplayError, RuntimeError, ValueError) as exc:
                raise HTTPException(409, str(exc)) from exc
            return {
                "schema_version": SCHEMA_VERSION,
                "mode": request.mode,
                "run_id": child.run_id,
                "parent_run_id": child.parent_run_id,
                "checkpoint_id": child.fork_checkpoint_id,
                "status": child.status,
            }
        try:
            replay_ref = (
                runtime.service.build_replay_bundle(run_id)
                if request.build_if_missing
                else runtime.service.get_replay_bundle(run_id)
            )
            if request.mode == "deterministic-replay":
                result = runtime.service.deterministic_replay(run_id)
                return {
                    "schema_version": SCHEMA_VERSION,
                    "mode": request.mode,
                    "replay_bundle": replay_ref.model_dump(mode="json"),
                    "result": {
                        "run_id": result.run_id,
                        "final_sequence": result.final_sequence,
                        "ledger_head_hash": result.ledger_head_hash,
                        "ledger_event_count": len(result.ledger_events),
                        "step_patch_count": len(result.step_patches),
                        "model_calls": result.model_calls,
                        "tool_calls": result.tool_calls,
                    },
                }
            verification = runtime.service.verify_replay_bundle(run_id)
            return {
                "schema_version": SCHEMA_VERSION,
                "mode": request.mode,
                "replay_bundle": replay_ref.model_dump(mode="json"),
                "result": {
                    "run_id": verification.run_id,
                    "manifest_digest": verification.manifest_digest,
                    "ledger_head_hash": verification.ledger_head_hash,
                    "entry_count": len(verification.entry_digests),
                    "ledger_event_count": len(verification.ledger_events),
                    "model_calls": verification.model_calls,
                    "tool_calls": verification.tool_calls,
                },
            }
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        except (ReplayError, RuntimeError) as exc:
            raise HTTPException(409, str(exc)) from exc


def _register_ledger_routes(app: FastAPI, runtime: ApplicationRuntime, settings: Settings) -> None:
    """Register append-only audit views and governed exports."""

    @app.get("/api/v1/runs/{run_id}/ledger")
    async def get_ledger(
        run_id: str,
        after_sequence: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=5000)] = 1000,
    ) -> dict[str, Any]:
        service = runtime.service
        if service.ledger.load_state(run_id) is None:
            raise HTTPException(404, "Run not found")
        page = service.ledger.events(run_id, after_sequence, limit + 1)
        has_more = len(page) > limit
        events = page[:limit]
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "events": [event.model_dump(mode="json") for event in events],
            "next_sequence": events[-1].sequence if events else after_sequence,
            "has_more": has_more,
            "chain_valid": service.ledger.verify(run_id),
        }

    @app.get("/api/v1/runs/{run_id}/logs")
    async def get_governed_logs(
        run_id: str,
        layer: Annotated[LogLayer, Query()] = LogLayer.DECISION_AUDIT,
        view: Annotated[DataView, Query()] = DataView.OBSERVABLE,
        event_type: Annotated[list[str] | None, Query()] = None,
        after_sequence: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    ) -> dict[str, Any]:
        service = runtime.service
        if service.ledger.load_state(run_id) is None:
            raise HTTPException(404, "Run not found")
        decision = authorize_data_view(
            run_id=run_id,
            requested_view=view,
            actor_id="operator",
            actor_role="operator",
            bound_run_ids=frozenset({run_id}),
            details={"layer": layer.value, "purpose": "operator_query"},
        )
        if not decision.allowed:
            raise HTTPException(403, decision.reason_code)
        if layer != LogLayer.DECISION_AUDIT or view != DataView.OBSERVABLE:
            raise HTTPException(409, "This release exposes only the observable L1 append-only decision ledger")
        requested_types = set(event_type or [])
        scan = service.ledger.events(run_id, after_sequence, 5000)
        filtered = [item for item in scan if not requested_types or item.event_type in requested_types]
        page = filtered[:limit]
        next_sequence = page[-1].sequence if len(filtered) > limit else (scan[-1].sequence if scan else after_sequence)
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "layer": layer.value,
            "view": view.value,
            "events": [item.model_dump(mode="json") for item in page],
            "next_sequence": next_sequence,
            "has_more": len(filtered) > limit or len(scan) == 5000,
            "raw_content_included": False,
            "access_decision_digest": decision.payload_digest,
        }

    @app.get("/api/v1/runs/{run_id}/ledger/export", response_class=FileResponse)
    async def export_ledger(run_id: str) -> FileResponse:
        service = runtime.service
        if service.ledger.load_state(run_id) is None:
            raise HTTPException(404, "Run not found")
        destination = settings.run_root / run_id / "ledger.jsonl"
        service.ledger.export_jsonl(run_id, destination)
        return FileResponse(destination, filename=f"{run_id}-ledger.jsonl")


def _register_run_commands(app: FastAPI, runtime: ApplicationRuntime) -> None:
    """Register state-changing operator commands and their conflict mapping."""

    @app.get("/api/v1/runs/{run_id}/retention-holds")
    async def list_retention_holds(run_id: str) -> dict[str, Any]:
        try:
            holds = runtime.service.retention_holds(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "holds": [item.model_dump(mode="json") for item in holds],
        }

    @app.post("/api/v1/runs/{run_id}/retention-holds", status_code=201)
    async def create_retention_hold(run_id: str, request: RetentionHoldRequest) -> dict[str, Any]:
        try:
            hold = runtime.service.create_retention_hold(
                run_id,
                reason=request.reason,
                expires_at=request.expires_at,
                actor="operator",
                client_request_id=request.client_request_id,
            )
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"schema_version": SCHEMA_VERSION, "retention_hold": hold.model_dump(mode="json")}

    @app.post("/api/v1/runs/{run_id}/approvals/batch", status_code=202)
    async def resolve_approvals_batch(run_id: str, request: ApprovalBatchRequest) -> dict[str, Any]:
        try:
            results = runtime.service.submit_approvals_batch(
                run_id,
                [(item.request_id, item.response) for item in request.items],
                actor="operator",
            )
        except KeyError as exc:
            raise HTTPException(404, "Run or approval request not found") from exc
        except (RuntimeError, ExecutionConflict) as exc:
            raise HTTPException(409, str(exc)) from exc
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "resolutions": results,
        }

    @app.post("/api/v1/runs/{run_id}/approvals/{request_id}", status_code=202)
    async def resolve_approval(run_id: str, request_id: str, response: ApprovalResponse) -> dict[str, Any]:
        state = run_state(runtime, run_id)
        active_ids = {
            item.request_id
            for item in [
                *state.pending_approvals,
                *([state.pending_approval] if state.pending_approval is not None else []),
            ]
        }
        if active_ids and request_id not in active_ids:
            raise HTTPException(409, "Approval request is not active")
        try:
            resolution_id, resumed = runtime.service.submit_approval_resolution(
                run_id,
                request_id,
                response,
                actor="operator",
            )
        except KeyError as exc:
            raise HTTPException(404, "Approval request not found") from exc
        except (RuntimeError, ExecutionConflict) as exc:
            raise HTTPException(409, str(exc)) from exc
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "request_id": request_id,
            "resolution_id": resolution_id,
            "resolution_status": "accepted" if resumed else "already_resolved",
        }

    @app.post("/api/v1/runs/{run_id}/cancel", status_code=202)
    async def cancel_run(run_id: str) -> dict[str, Any]:
        try:
            await runtime.service.cancel(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        return {"schema_version": SCHEMA_VERSION, "run_id": run_id, "status": "cancelled"}

    @app.post("/api/v1/runs/{run_id}/recover", status_code=202)
    async def recover_run(run_id: str, request: RecoveryRequest | None = None) -> dict[str, Any]:
        if request is None:
            run_state(runtime, run_id)
            raise HTTPException(409, "Recovery requires an immutable assessment id and digest")
        try:
            consumption_id = await runtime.service.recover(
                run_id,
                assessment_id=request.assessment_id,
                assessment_digest=request.assessment_digest,
                actor="operator",
            )
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "status": "queued",
            "assessment_digest": request.assessment_digest,
            "consumption_id": consumption_id,
        }

    @app.post("/api/v1/runs/{run_id}/recovery-assessment", status_code=201)
    async def create_recovery_assessment(run_id: str) -> dict[str, Any]:
        try:
            assessment = await runtime.service.recovery_assessment(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        return assessment.model_dump(mode="json")

    @app.get("/api/v1/runs/{run_id}/recovery-assessment")
    async def get_recovery_assessment(run_id: str) -> dict[str, Any]:
        try:
            assessment = runtime.service.latest_recovery_assessment(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        return assessment.model_dump(mode="json")
