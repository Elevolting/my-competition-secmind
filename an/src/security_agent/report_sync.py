"""Refresh existing external evidence without submitting tasks."""
from __future__ import annotations

import hashlib
import json

from security_agent.config import Settings
from security_agent.penetration_integration import (
    assess_project_facts,
    evaluate_project_completion,
    normalize_penetration_graph,
    penetration_get,
    resolve_project_id,
)
from security_agent.schemas import AgentReport, AgentState, Evidence, Finding, RunStatus, ToolContext, ToolStatus
from security_agent.secmind_adapter import invoke_secmind
from security_agent.run_recovery import runtime_goal_completed
from security_agent.verified_outputs import include_verified_outputs


class ReportNotReady(ValueError):
    pass


def confirmed_penetration_nodes(detail: dict, assessments: dict | None = None) -> list[dict]:
    """Return the blackboard nodes that count as verified platform findings.

    Legacy objective facts remain report records with insufficient verification; intent,
    hint, worker and goal bookkeeping nodes stay out of the finding graph.
    """
    graph = normalize_penetration_graph(detail, assessments)
    return [node for node in graph.get("nodes", [])
        if node.get("type") in {"vulnerability", "fact"} and node.get("status") in {"completed", "confirmed"}]


def apply_penetration_evidence(state: AgentState, project_id: str, confirmed: list[dict]) -> list[str]:
    """Fold legacy blackboard nodes into findings/evidence as Worker reports.

    A Fact retains its finding and evidence IDs when its classification changes.
    """
    evidence = {item.evidence_id: item for item in state.evidence}
    findings = {item.finding_id: item for item in state.findings
        if item.rule_id != "PENETRATION-CONFIRMED-RESULT"}
    for node in confirmed:
        raw = json.dumps(node, ensure_ascii=False, sort_keys=True)
        digest = hashlib.sha256(raw.encode()).hexdigest()
        fid = f"penetration:{project_id}:{node.get('raw_id', node.get('id'))}"
        previous = next((item for item in state.findings if item.finding_id == fid), None)
        eid = (previous.evidence_ids[0] if previous and previous.evidence_ids
               else f"runtime:{project_id}:{digest[:24]}")
        description = str(node.get("description") or node.get("label") or "运行时已确认事实")
        if eid not in evidence or evidence[eid].summary != description:
            evidence[eid] = Evidence(evidence_id=eid, source="security_runtime", summary=description,
                sha256=digest, metadata={"project_id": project_id, "node": node})
        findings[fid] = Finding(finding_id=fid, rule_id="PENETRATION-CONFIRMED-RESULT",
            severity=node.get("severity", "UNKNOWN"), confidence="UNKNOWN",
            path=state.task.target_scope[0] if state.task.target_scope else project_id,
            title="渗透模块结果记录（Worker 报告）",
            description=description, evidence_ids=[eid],
            raw={"source": "security_runtime", "project_id": project_id,
                 "assessment_rule": node.get("assessment_rule"),
                 "assessment_reason": node.get("assessment_reason"), "verification_status": "insufficient"})
    referenced = {ref for item in findings.values() for ref in item.evidence_ids}
    evidence = {key: item for key, item in evidence.items()
                if key in referenced or not (item.source == "security_runtime"
                    and item.metadata.get("project_id") == project_id)}
    state.findings, state.evidence = list(findings.values()), list(evidence.values())
    # Graph status cannot substitute for the workbench goal evidence review.
    return []


async def synchronize_report(state: AgentState, settings: Settings, gateway=None) -> AgentState:
    if state.external_execution.get('blackboard', {}).get('planning_mode') == 'workbench':
        if state.report is None or state.status in {RunStatus.PENDING, RunStatus.RUNNING, RunStatus.WAITING_APPROVAL}:
            raise ReportNotReady('任务仍在执行，请等待报告生成')
        # Refresh is a projection of persisted validation, never a new model
        # assessment or a conversion of ordinary graph facts into Findings.
        # It does re-derive the terminal status, because an earlier projection
        # could have sealed a verified goal as partial (for example when the
        # external status was recorded under a different key).
        if state.status == RunStatus.PARTIAL and runtime_goal_completed(state):
            state.status = RunStatus.COMPLETED
            state.last_error = None
            if state.report is not None:
                state.report.limitations = [item for item in state.report.limitations
                                            if "未返回成功结果" not in item]
        from security_agent.report_sections import report_sections
        state.report = state.report.model_copy(update={**report_sections(state),
            'findings': state.findings, 'evidence': state.evidence, 'decisions': state.decisions,
            'verified_outputs': state.external_execution.get('validated_goal_outputs', []),
            'status': state.status})
        return state
    if state.routing.get('execution_backend') == 'mcp':
        return state
    if state.report is None or state.status in {RunStatus.PENDING, RunStatus.RUNNING, RunStatus.WAITING_APPROVAL}:
        raise ReportNotReady("任务仍在执行或等待审批，请等待报告生成")
    if state.external_execution.get("remote_run_id"):
        context = ToolContext(run_id=state.run_id, step_id="report-refresh", workspace=state.workspace,
            allowed_paths=[state.workspace], module_base_url=settings.reverse_base_url,
            module_auth_token=settings.secmind_operator_token, external_execution=dict(state.external_execution))
        result = await invoke_secmind([], context, domain="", wait_for_completion=False)
        if result.error_code in {"REMOTE_NOT_FINISHED", "REMOTE_APPROVAL_REQUIRED"} or (
            result.status != ToolStatus.SUCCESS and not result.data.get("partial_evidence")
        ):
            raise ReportNotReady(result.summary)
        state.external_execution = context.external_execution
        evidence = {item.evidence_id: item for item in state.evidence}
        evidence.update({item.evidence_id: item for item in result.evidence})
        findings = {item.finding_id: item for item in state.findings}
        findings.update({item["finding_id"]: Finding.model_validate(item) for item in result.data.get("findings", [])})
        state.evidence, state.findings = list(evidence.values()), list(findings.values())
        limitations = list(result.data.get("limitations", []))
        broken = any(not item.evidence_ids or any(ref not in evidence for ref in item.evidence_ids) for item in state.findings)
        if broken:
            limitations.append("远程报告包含缺少证据或引用失效的发现，不能标记为完成。")
        completed = result.status == ToolStatus.SUCCESS and not broken
        if not completed and result.error_message:
            limitations.append(result.error_message)
        state.status = RunStatus.COMPLETED if completed else RunStatus.PARTIAL
        state.last_error = None if completed else "外部分析未完整通过，详见报告限制说明"
        state.observations.append(result)
        state.report = AgentReport(run_id=state.run_id, status=state.status,
            executive_summary=result.summary, findings=state.findings, evidence=state.evidence,
            decisions=state.decisions, limitations=limitations)
        return state
    if state.module_route != "penetration":
        return state

    project_id = await resolve_project_id(state, settings.penetration_base_url, settings.module_timeout_seconds)
    if project_id is None:
        raise ReportNotReady("渗透项目尚未创建")
    detail = await penetration_get(settings.penetration_base_url, f"/projects/{project_id}", settings.module_timeout_seconds)
    decision = evaluate_project_completion(detail)
    assessments = state.external_execution.setdefault("fact_assessments", {})
    await assess_project_facts(detail, assessments, gateway, model_budget=3 if gateway else 0)
    confirmed = confirmed_penetration_nodes(detail, assessments)
    verified_outputs = apply_penetration_evidence(state, project_id, confirmed)
    complete = decision["objective_reached"] and not (
        "flag" in state.task.objective.casefold() and not verified_outputs
    )
    previous_status = state.status
    previous = state.report
    state.status = RunStatus.COMPLETED if complete else RunStatus.PARTIAL
    state.external_execution.update(module="penetration", project_id=project_id,
        exploration_complete=decision["terminal"], **decision)
    state.last_error = None if complete else (
        "目标要求取得 flag，但旧 Runtime 路径没有独立核验的目标输出"
        if decision["objective_reached"] and "flag" in state.task.objective.casefold()
        else "尚无终态及已完成的目标意图，不能认定渗透目标完成"
    )
    retracted = (previous_status == RunStatus.COMPLETED and not complete) or any(
        value not in verified_outputs for value in (previous.verified_outputs if previous else []))
    summary = previous.executive_summary if previous and previous.executive_summary and not retracted else (
        "渗透模块已通过终态与目标意图验证。" if complete else "渗透结果已同步，目标尚未验证完成。")
    if not previous or retracted:
        summary += f"已保留 {len(confirmed)} 条已确认事实。"
    summary = include_verified_outputs(summary, verified_outputs)
    outputs = verified_outputs
    state.report = AgentReport(run_id=state.run_id, status=state.status,
        executive_summary=summary, verified_outputs=outputs,
        findings=state.findings, evidence=state.evidence, decisions=state.decisions,
        limitations=previous.limitations if previous else ([] if complete else [state.last_error]),
        **({"generated_at": previous.generated_at} if previous else {}))
    return state
