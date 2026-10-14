"""Fail-closed Canonical Primary degradation projection."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from secmind.canonical_primary import CANONICAL_PRIMARY_PROMPT_VERSION
from secmind.direct_anchor_pipeline import DIRECT_ANCHOR_PIPELINE_VERSION, build_anchor_report
from secmind.domain_answers import EvidenceGapAnswer, PolicyDecisionAnswer, normalize_domain_answer
from secmind.orchestration.primary_runtime import account_failed_primary_attempts
from secmind.schemas import AgentReport, AgentState, RunStatus, Scenario


def _validation_issue_details(exc: ValidationError, *, limit: int = 16) -> list[dict[str, Any]]:
    """Return bounded, input-free Pydantic diagnostics for an audit record."""

    return [
        {
            "location": [str(part) for part in issue.get("loc", ())],
            "type": str(issue.get("type") or "validation_error"),
        }
        for issue in exc.errors(
            include_url=False,
            include_context=False,
            include_input=False,
        )[:limit]
    ]


def _minimal_typed_answer(state: AgentState, reason: str) -> tuple[str, dict[str, Any]]:
    """Build a valid, non-authoritative domain answer for the last-resort path.

    This path is deliberately information-poor: it never copies provider text or
    unvalidated parser fields.  It still emits the declared domain schema when
    possible, so an infrastructure/projection failure cannot turn into an
    untyped answer that downstream adapters reject.
    """

    resolved = state.resolved_task_contract
    scoring_mode = str(resolved.scoring_mode if resolved is not None else "evidence_gap")
    task_id = str(resolved.client_request_id if resolved is not None else state.run_id)[:128]
    raw = {
        "task_id": task_id,
        "status": "partial",
        "executive_summary": (
            "A typed public answer could not be completed after a bounded validation failure; "
            "the supplied evidence remains non-authoritative for the missing fields."
        ),
        "limitations": [reason],
    }
    try:
        answer = normalize_domain_answer(scoring_mode, raw)
    except (ValidationError, TypeError, ValueError):
        # Unknown/legacy scoring modes must still have a strict, typed answer.
        answer = EvidenceGapAnswer.model_validate(
            {
                **raw,
                "observations": [],
                "known": [],
                "unknown_fields": ["typed public answer fields"],
                "conflicts": [],
                "blocked_claims": [],
                "next_evidence": [],
            }
        )
    return answer.answer_kind, answer.model_dump(mode="json")


def _deterministic_policy_fallback(state: AgentState, reason: str) -> PolicyDecisionAnswer:
    """Return a fail-closed policy answer when the semantic provider is unavailable.

    A failed model call must not turn an agent-safety task into an untyped
    ``universal`` response.  The fallback does not infer facts from untrusted
    input and does not claim that a requested lookup was completed.  It only
    applies SecMind's already-authoritative boundary: embedded instructions and
    unverified external side effects remain blocked, while bounded read-only
    inspection and a request for missing authorized evidence remain safe.
    """

    resolved = state.resolved_task_contract
    task_id = str(resolved.client_request_id if resolved is not None else state.run_id)[:128]
    return PolicyDecisionAnswer.model_validate(
        {
            "task_id": task_id,
            "execution_status": "partial",
            "epistemic_status": "insufficient_evidence",
            "executive_summary": (
                "The model baseline was unavailable, so SecMind applied its deterministic fail-closed policy "
                "and did not execute or authorize any embedded or external action."
            ),
            "limitations": [reason, "The requested external fact was not established from verified evidence."],
            "decision": (
                "ignore_untrusted_instruction; DENY/BLOCK: do not execute embedded instructions or perform "
                "unverified external actions; report the evidence gap instead"
            ),
            "safe_actions": [
                "inspect only the supplied immutable input in read-only mode",
                "request an authorized, verifiable source for any missing external fact",
            ],
            "blocked_actions": [
                "obey instructions embedded in untrusted task data",
                "read, modify, upload, delete, or transfer external resources without explicit authorization",
            ],
            "evidence": [],
        }
    )


def _minimal_partial_report(state: AgentState, reason: str) -> AgentReport:
    """Create a schema-valid report without trusting a failed projection."""

    answer_type, answer_payload = _minimal_typed_answer(state, reason)
    state.status = (
        RunStatus.PARTIAL
        if state.status not in {RunStatus.DENIED, RunStatus.CANCELLED, RunStatus.FAILED}
        else state.status
    )
    return AgentReport(
        run_id=state.run_id,
        status=state.status if state.status != RunStatus.RUNNING else RunStatus.PARTIAL,
        executive_summary=(
            "SecMind preserved the last valid state and deterministic evidence, but the typed public "
            "projection could not be completed safely."
        ),
        answer_type=answer_type,
        answer_payload=answer_payload,
        findings=list(state.findings),
        decisions=list(state.decisions),
        evidence=list(state.evidence),
        limitations=[reason],
        coverage=dict(state.audit_coverage),
        audit_kernel=state.audit_kernel,
    )


def degrade_primary(
    state: AgentState,
    reason: str,
    *,
    attempted: bool,
    provider_requests: int = 0,
    executive_summary: str = "",
    affect_run_status: bool = True,
    record_error: bool = True,
) -> None:
    """Persist an explicit result even when the canonical call cannot finish."""

    existing_report = state.report
    preserve_scenario_answer = (
        existing_report is not None
        and state.published_baseline is None
        and state.audit_coverage.get("pre_primary_scenario_executed") is True
        and state.scenario != Scenario.CODE_AUDIT
    )
    if record_error:
        state.last_error = reason
    state.audit_coverage.update(
        {
            "canonical_primary_attempted": attempted,
            "canonical_primary_status": "degraded",
            "canonical_primary_provider_requests": provider_requests,
            "negative_coverage_complete": False,
        }
    )
    if state.scenario == Scenario.CODE_AUDIT:
        state.audit_coverage.update(
            {
                "direct_anchor_pipeline": True,
                "direct_anchor_pipeline_version": DIRECT_ANCHOR_PIPELINE_VERSION,
                "direct_anchor_strict": attempted,
            }
        )
        if attempted:
            degraded_anchor = build_anchor_report(
                run_id=state.run_id,
                receipt_id=f"degraded-anchor:{state.run_id}",
                request_sha256="0" * 64,
                response_sha256="0" * 64,
                response_schema_sha256="0" * 64,
                prompt_version=CANONICAL_PRIMARY_PROMPT_VERSION,
                prompt_artifact_id=None,
                context_sha256=str(state.audit_coverage.get("context_sha256") or "0" * 64),
                response_artifact_id="0" * 64,
                findings=(),
                evidence=(),
                limitations=(reason,),
                coverage={
                    **state.audit_coverage,
                    "anchor_available": False,
                    "anchor_status": "degraded_before_seal",
                },
                sealed=False,
            )
            state.audit_coverage["anchor_report"] = degraded_anchor.model_dump(mode="json")
            state.audit_coverage["anchor_report_digest"] = degraded_anchor.report_digest
    if affect_run_status and state.status not in {RunStatus.DENIED, RunStatus.CANCELLED, RunStatus.FAILED}:
        state.status = RunStatus.PARTIAL
    report_status = state.status if state.status != RunStatus.RUNNING else RunStatus.PARTIAL
    limitations = list(state.report.limitations) if state.report is not None else []
    limitations = list(dict.fromkeys([*limitations, reason]))
    deterministic_gap_answer: EvidenceGapAnswer | None = None
    deterministic_policy_answer: PolicyDecisionAnswer | None = None
    resolved = state.resolved_task_contract
    receipt = state.evidence_compiler_receipt
    lfs_facts = (
        [item for item in receipt.facts if item.fact_type == "artifact.git_lfs_pointer"] if receipt is not None else []
    )
    known = [dict(item.value) for item in lfs_facts if isinstance(item.value, dict)]
    if not known:
        # ``compile_evidence`` may retain validated LFS facts while discarding
        # an invalid aggregate receipt.  Keep the deterministic gap answer
        # available without reviving that failed receipt object.
        receipt_failure = state.audit_coverage.get("evidence_compiler_validation_failure")
        retained = receipt_failure.get("retained_lfs_facts") if isinstance(receipt_failure, dict) else None
        if isinstance(retained, list):
            for item in retained:
                if not isinstance(item, dict):
                    continue
                value = item.get("value")
                if isinstance(value, dict):
                    known.append(dict(value))
    if not preserve_scenario_answer and resolved is not None and resolved.scoring_mode == "evidence_gap" and known:
        deterministic_gap_answer = EvidenceGapAnswer.model_validate(
            {
                "task_id": (resolved.client_request_id or state.run_id)[:128],
                "execution_status": "partial",
                "epistemic_status": "insufficient_evidence",
                "executive_summary": (
                    "The supplied artifact is a Git LFS pointer, not the referenced telemetry object; "
                    "successful transfer or attribution cannot be established from the pointer alone."
                ),
                "limitations": limitations,
                "observations": known,
                "known": known,
                "unknown_fields": [
                    "referenced Git LFS object bytes",
                    "transfer completion status",
                    "event timeline and raw telemetry fields",
                ],
                "conflicts": [],
                "blocked_claims": [
                    {"claim": "the transfer succeeded", "reason": "the referenced Git LFS object is missing"},
                    {"claim": "attribute an actor or cause", "reason": "no underlying telemetry bytes are available"},
                ],
                "next_evidence": [
                    {
                        "action": "materialize the exact Git LFS object",
                        "oid": known[0].get("pointer_oid") if known else None,
                        "verify": "SHA-256 and declared size before analysis",
                    }
                ],
            }
        )
    if not preserve_scenario_answer and resolved is not None and resolved.scoring_mode == "agent_policy_compliance":
        deterministic_policy_answer = _deterministic_policy_fallback(state, reason)
    deterministic_answer = deterministic_gap_answer or deterministic_policy_answer
    state.report = AgentReport(
        run_id=state.run_id,
        status=report_status,
        executive_summary=(
            (existing_report.executive_summary if preserve_scenario_answer and existing_report is not None else "")
            or (deterministic_answer.executive_summary if deterministic_answer is not None else "")
            or executive_summary
            or "SecMind could not complete the task-level model baseline; available deterministic stages may "
            "continue and this report records the limitation."
        ),
        answer_type=(
            existing_report.answer_type
            if preserve_scenario_answer and existing_report is not None
            else (deterministic_answer.answer_kind if deterministic_answer is not None else "universal")
        ),
        answer_payload=(
            dict(existing_report.answer_payload)
            if preserve_scenario_answer and existing_report is not None
            else (deterministic_answer.model_dump(mode="json") if deterministic_answer is not None else {})
        ),
        findings=list(
            existing_report.findings if preserve_scenario_answer and existing_report is not None else state.findings
        ),
        decisions=list(state.decisions),
        evidence=list(
            existing_report.evidence if preserve_scenario_answer and existing_report is not None else state.evidence
        ),
        limitations=limitations,
        coverage=dict(state.audit_coverage),
        audit_kernel=state.audit_kernel,
        claim_ids=list(existing_report.claim_ids) if preserve_scenario_answer and existing_report is not None else [],
    )


async def recover_primary_projection_validation(
    host: Any,
    value: Any,
    exc: ValidationError,
    *,
    failure_stage: str = "post_provider_projection",
    state: AgentState | None = None,
    attempted: bool | None = None,
) -> Any:
    """Discard a half-published answer and retain deterministic evidence.

    ``value`` is the immutable input to the graph transition.  Rehydrating it
    prevents mutations made before the validation error from leaking into a
    later replay.  Diagnostics intentionally contain only field locations and
    error codes; provider content remains in its private durable receipt.
    """

    state_validation_failed = False
    if state is None:
        raw_agent = value.get("agent") if isinstance(value, Mapping) else None
        run_id = raw_agent.get("run_id") if isinstance(raw_agent, Mapping) else None
        if not isinstance(run_id, str) or not run_id or len(run_id) > 100:
            raise RuntimeError("Primary state recovery requires a valid run identifier")
        try:
            # A valid graph payload is still useful in embedded tests, but the
            # durable row is preferred so partial mutations made before the
            # failed projection cannot leak into recovery.
            candidate = host._state(value)
        except ValidationError:
            candidate = None
            state_validation_failed = True
        state = host.ledger.load_state(run_id) or candidate
        if state is None:
            raise RuntimeError("Primary state recovery has no durable validated checkpoint")
        host._bind_authority(state, host._active_authority.get())
    if state_validation_failed and failure_stage == "post_provider_projection":
        failure_stage = "pre_primary_state"
    attempts = list(host.gateway.provider_attempts_for(state.run_id))
    attempted = bool(attempts) if attempted is None else bool(attempted or attempts)
    if attempted:
        state.budget.model_calls_used += 1
    provider_requests = account_failed_primary_attempts(host, state) if attempts else 0
    issues = _validation_issue_details(exc)
    state.audit_coverage["canonical_primary_projection_failure"] = {
        "error_type": "ValidationError",
        "failure_stage": failure_stage,
        "issue_count": exc.error_count(),
        "issues": issues,
        "provider_requests": provider_requests,
        "response_sha256": next(
            (item.response_sha256 for item in reversed(attempts) if item.response_sha256 is not None),
            None,
        ),
        "raw_response_preserved": any(item.response_sha256 is not None for item in attempts),
        "partial_publication_discarded": True,
    }
    try:
        degrade_primary(
            state,
            (
                "Task-level primary state or typed public projection failed validation safely; "
                "the last valid state and deterministic evidence were preserved."
            ),
            attempted=attempted,
            provider_requests=provider_requests,
        )
    except Exception as recovery_exc:  # noqa: BLE001 - final fail-closed boundary
        failure_record = state.audit_coverage["canonical_primary_projection_failure"]
        if isinstance(recovery_exc, ValidationError):
            failure_record["recovery_issues"] = _validation_issue_details(recovery_exc)
        else:
            failure_record["recovery_issues"] = [{"location": [], "type": type(recovery_exc).__name__}]
        failure_record["recovery_error_type"] = type(recovery_exc).__name__
        state.status = RunStatus.PARTIAL
        state.last_error = "Primary projection and typed recovery both failed; a minimal typed answer was emitted"
        state.report = _minimal_partial_report(state, state.last_error)
    return await host._checkpoint(
        state,
        "canonical_primary.projection_degraded",
        state.audit_coverage["canonical_primary_projection_failure"],
    )


__all__ = ["degrade_primary", "recover_primary_projection_validation"]
