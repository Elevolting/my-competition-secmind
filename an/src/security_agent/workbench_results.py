"""Persist graph results using receipts from the assigned execution attempt."""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy

from security_agent.schemas import AgentState, Evidence, Finding


def merge_workbench_results(state: AgentState, facts: list[dict], receipts: dict[str, dict]) -> None:
    evidence = {item.evidence_id: item for item in state.evidence}
    findings = {item.finding_id: item for item in state.findings}
    facts = deepcopy(facts)
    state.external_execution['external_facts'] = facts
    for fact in facts:
        if not isinstance(fact, dict) or fact.get('id') in {'origin', 'goal'}:
            continue
        items = list(fact.get('items') or [])
        supplied = {i.get('finding_id') for i in items if isinstance(i, dict)}
        for receipt in receipts.values():
            if receipt.get('fact_id') != fact.get('id'):
                continue
            native = receipt.get('result', {}).get('structuredContent', {})
            for raw_finding in native.get('data', {}).get('findings', []) if isinstance(native, dict) else []:
                source = raw_finding.get('finding_id')
                if not source or source in supplied:
                    continue
                supplied.add(source)
                items.append({'id': f'native:{source}', 'type': 'finding', 'finding_id': source,
                              'title': raw_finding.get('title'), 'summary': raw_finding.get('description'),
                              'evidence_ids': raw_finding.get('evidence_ids', [])})
        fact['items'] = items
        for item in items:
            if not isinstance(item, dict):
                continue
            refs = []
            for ref in item.get('evidence_ids') or []:
                receipt = receipts.get(ref)
                if not receipt or receipt.get('fact_id') != fact.get('id'):
                    continue
                raw = json.dumps(receipt, ensure_ascii=False, sort_keys=True)
                evidence[ref] = Evidence(evidence_id=ref, source='security_runtime_tool',
                    summary=str(item.get('summary') or item.get('title') or '工具回执'),
                    sha256=hashlib.sha256(raw.encode()).hexdigest(),
                    metadata={'receipt': receipt, 'fact_id': fact['id'],
                              'blackboard': receipt.get('blackboard', {})})
                refs.append(ref)
            if item.get('type') != 'finding':
                continue
            # IDs supplied by a Worker are local to its project and cannot
            # overwrite a Finding from a different branch or prior adapter.
            key = str(item.get('finding_id') or item.get('id') or item.get('title'))
            project = state.external_execution['blackboard']['project_id']
            fid = f'workbench:{project}:{fact["id"]}:{key}'
            previous = findings.get(fid)
            if previous and previous.raw.get('verification_status') in {'confirmed', 'excluded'}:
                continue
            findings[fid] = Finding(finding_id=fid, rule_id='WORKBENCH-CANDIDATE',
                title=str(item.get('title') or '漏洞候选'),
                description=str(item.get('summary') or ''),
                path=state.task.target_scope[0] if state.task.target_scope else state.workspace,
                evidence_ids=refs,
                raw={**(previous.raw if previous else {}), 'fact_id': fact['id'],
                     'item_id': item.get('id'), 'source_finding_id': item.get('finding_id'),
                     'verification_status': (previous.raw.get('verification_status', 'pending')
                                             if previous and refs and set(refs) == set(previous.evidence_ids)
                                             else 'pending' if refs else 'insufficient')})
    state.evidence = list(evidence.values())
    state.findings = list(findings.values())
