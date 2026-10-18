"""Report projections keep exploration records separate from vulnerability claims."""
from __future__ import annotations

from security_agent.schemas import AgentState


def report_sections(state: AgentState) -> dict:
    evidence = {item.evidence_id for item in state.evidence}
    confirmed, candidates, insufficient, ruled_out, worker = [], [], [], [], []
    workbench = state.external_execution.get("blackboard", {}).get("planning_mode") == "workbench"
    for finding in state.findings:
        valid = bool(finding.evidence_ids) and set(finding.evidence_ids).issubset(evidence)
        verified = any(
            decision.decision == "finding_verification_passed"
            and f"finding:{finding.finding_id}" in decision.policy_ids
            and bool(decision.evidence_ids) and set(decision.evidence_ids).issubset(finding.evidence_ids)
            for decision in state.decisions
        )
        if not workbench:
            verified |= any(d.decision == "verification_passed"
                            and set(finding.evidence_ids).issubset(d.evidence_ids) for d in state.decisions)
        if finding.rule_id == "PENETRATION-CONFIRMED-RESULT":
            worker.append(finding.description)
        elif valid and any(d.decision == 'finding_verification_excluded'
                          and f'finding:{finding.finding_id}' in d.policy_ids
                          and bool(d.evidence_ids) and set(d.evidence_ids).issubset(finding.evidence_ids)
                          for d in state.decisions):
            ruled_out.append(finding.title + '：' + finding.description)
        elif valid and verified:
            confirmed.append(finding)
        else:
            candidates.append(finding)
            if not valid:
                insufficient.append(f"{finding.title}：缺少有效证据引用")
            elif finding.raw.get('verification_status') == 'insufficient':
                insufficient.append(f'{finding.title}：现有证据不足以确认该漏洞')

    facts = state.external_execution.get("external_facts", [])
    if not facts:
        facts = next((obs.data["external_facts"] for obs in reversed(state.observations)
                      if isinstance(obs.data.get("external_facts"), list)), [])
    for fact in facts:
        if not isinstance(fact, dict) or fact.get("id") in {"origin", "goal"}:
            continue
        items = fact.get("items") or []
        if not items:
            worker.append("历史记录：" + str(fact.get("description") or ""))
        for item in items:
            if not isinstance(item, dict):
                continue
            text = str(item.get("title") or "探索记录")
            if item.get("summary"):
                text += "：" + str(item["summary"])
            refs = item.get("evidence_ids") or []
            valid = bool(refs) and set(refs).issubset(evidence)
            if item.get("outcome") == "negative":
                ruled_out.append(text + ("（Worker 报告，待核对证据）" if not valid else ""))
            if item.get("type") == "finding" and not valid:
                insufficient.append(text)
            if not valid:
                worker.append(text)
    return {
        "confirmed_findings": confirmed,
        "candidate_findings": candidates,
        "ruled_out_directions": list(dict.fromkeys(ruled_out)),
        "insufficient_evidence": list(dict.fromkeys(insufficient)),
        "worker_reports": list(dict.fromkeys(worker)),
    }
