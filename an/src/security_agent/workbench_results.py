"""Persist graph results using receipts from the assigned execution attempt."""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy

from security_agent.schemas import AgentState, Evidence, Finding


def validated_step_outputs(intents: list[dict], facts: list[dict], receipts: dict[str, dict]) -> dict[str, list[str]]:
    """Confirm observed outputs against successful receipts of their producing fact.

    The caller has already bound receipts to the current intent/attempt. Failed
    tool calls remain useful evidence of a limitation, but cannot unlock steps.
    """
    facts_by_id = {fact['id']: fact for fact in facts if isinstance(fact, dict) and isinstance(fact.get('id'), str)}
    confirmed = {}
    for intent in intents:
        if not isinstance(intent, dict) or intent.get('execution_status') != 'completed':
            continue
        key, fact_id = intent.get('step_id'), intent.get('to')
        if not isinstance(key, str) or not key.strip() or not isinstance(fact_id, str):
            continue
        items = facts_by_id.get(fact_id, {}).get('items')
        if not isinstance(items, list):
            continue
        outputs = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            output = item.get('output_key')
            refs = item.get('evidence_ids')
            if (not isinstance(output, str) or not output.strip() or len(output) > 120
                    # A captured flag is reported as a finding, so findings must
                    # be able to carry a named output too; excluding them kept
                    # the flag output unconfirmable and stalled its dependent
                    # step even though the evidence was on the blackboard.
                    or item.get('type') not in {'fact', 'artifact', 'observation', 'finding'}
                    or item.get('outcome') != 'observed' or not isinstance(refs, list)):
                continue
            for ref in refs:
                receipt = receipt_for_ref(ref, receipts, fact_id)
                if receipt is None:
                    continue
                result = receipt.get('result')
                if not isinstance(result, dict) or result.get('isError'):
                    continue
                native = result.get('structuredContent')
                if (receipt.get('status') in {'failed', 'cancelled', 'timeout'}
                        or receipt.get('error')
                        or isinstance(native, dict) and native.get('status') in {
                            'failed', 'error', 'cancelled', 'timeout', 'unavailable', 'denied'}):
                    continue
                outputs.add(output)
                break
        if outputs:
            confirmed[key] = sorted(outputs)
    return confirmed


def receipt_for_ref(ref, receipts: dict[str, dict], fact_id: str) -> dict | None:
    """Resolve one evidence reference to a successful receipt of ``fact_id``.

    Workers cite the receipt file the MCP bridge handed them
    (``.mcp-results/<call_id>.json``) while the ledger keys receipts by call ID,
    so a bare dictionary lookup never matched and a named output could never be
    confirmed. Accept either form.
    """
    if not isinstance(ref, str) or not ref.strip():
        return None
    name = ref.replace("\\", "/").rsplit("/", 1)[-1]
    candidates = (ref, name, name[:-5] if name.endswith(".json") else name)
    for candidate in candidates:
        receipt = receipts.get(candidate)
        if isinstance(receipt, dict) and receipt.get("fact_id") == fact_id:
            return receipt
    return None


def has_live_planning_work(intents: list[dict], confirmations: dict[str, list[str]]) -> bool:
    """Whether unfinished work can progress without a new Planner decision.

    A waiting chain remains live while an upstream step can run. A failed or
    cancelled upstream, or a completed step lacking its required output, needs
    a new decision instead of leaving an idle task alive indefinitely.
    """
    steps = {item['step_id']: item for item in intents
             if isinstance(item, dict) and isinstance(item.get('step_id'), str)}

    def can_progress(item, visiting):
        if item.get('execution_status') in {'failed', 'timeout', 'cancelled'}:
            return False
        key = item.get('step_id')
        if key in visiting:
            return False
        required = item.get('required_outputs') or {}
        for parent_key in item.get('depends_on') or []:
            parent = steps.get(parent_key)
            if not parent:
                return False
            if parent.get('to') or parent.get('concluded_at'):
                if parent.get('execution_status') != 'completed':
                    return False
                available = set(parent.get('validated_outputs') or []) | set(confirmations.get(parent_key, []))
                if not set(required.get(parent_key, [])).issubset(available):
                    return False
            elif not can_progress(parent, visiting | {key}):
                return False
        return True

    return any(can_progress(item, set()) for item in intents
               if isinstance(item, dict) and not item.get('to') and not item.get('concluded_at'))


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
                receipt = receipt_for_ref(ref, receipts, fact['id'])
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
