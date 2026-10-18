from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import httpx
from pydantic import BaseModel

from security_agent.schemas import AgentState

ASSESSMENT_VERSION = "2"
_VULNERABILITY_PATTERN = re.compile(
    r"(?:漏洞|高风险|未授权|越权|注入|命令执行|任意文件|文件上传|目录遍历|"
    r"反序列化|弱口令|口令爆破|信息泄露|跨站|"
    r"\b(?:path traversal|directory traversal|LFI|local file inclusion|arbitrary file read|"
    r"XSS|CSRF|SSRF|RCE|SQLi|CVE-\d+|CWE-\d+)\b)", re.IGNORECASE,
)
_SUCCESS_PATTERN = re.compile(
    r"(?:已确认|确认存在|成功|证实|验证|发现|读取到|获得|返回了|存在.{0,32}漏洞|"
    r"\b(?:confirmed|verified|achieved|succeeded|successful|exploited|obtained|"
    r"read|returned|response contains|response included)\b)", re.IGNORECASE,
)
_NEGATIVE_FACT_PATTERN = re.compile(
    r"(?:未发现|未确认|仅尝试|尝试但|无法验证|尚未验证|未成功|被拒绝|怀疑|可能存在|目标不可达|不在.*授权范围|"
    r"\b(?:out of scope|no (?:successful|authorized|reachable|confirmed)|not confirmed|"
    r"could not|failed|rejected|blocked|attempted only|unverified)\b)", re.IGNORECASE,
)
_CRITICAL = re.compile(r"(?:完全控制|无限制(?:远程)?命令执行|完全接管|\b(?:full control|unrestricted remote code execution|complete takeover)\b)", re.I)
_HIGH = re.compile(r"(?:敏感文件|目标文件|任意文件读取|文件内容|数据外泄|认证绕过|权限提升|提权|"
                   r"\b(?:sensitive file|arbitrary file read|file contents?|flag\.txt|data exfiltration|"
                   r"authentication bypass|privilege escalation|read the target file)\b)", re.I)
_LOW = re.compile(r"(?:轻微信息暴露|版本信息泄露|\b(?:minor exposure|version disclosure)\b)", re.I)
_MEDIUM = re.compile(r"(?:受限利用|有限影响|\b(?:limited impact|restricted exploit)\b)", re.I)
_OBSERVED_EFFECT = re.compile(r"(?:成功|读取|泄露|绕过|执行|回显|获取|\b(?:exposed|executed|bypassed|"
                              r"accessed|retrieved|read|returned|disclosed|leaked|achieved|obtained)\b)", re.I)


class ModelFactAssessment(BaseModel):
    vulnerability: bool
    severity: str
    reason: str
    evidence_quote: str


def fact_assessment(description: str) -> dict[str, str] | None:
    """Classify explicit evidence clause by clause; None requests semantic review."""
    clauses = [part.strip() for part in re.split(r"[\n。；;]+|(?<=[.!?])\s+(?=[A-Z])", description) if part.strip()]
    positive = [part for part in clauses if _VULNERABILITY_PATTERN.search(part)
                and _SUCCESS_PATTERN.search(part) and not _NEGATIVE_FACT_PATTERN.search(part)]
    if positive:
        proof = positive[0]
        impact_proof = next((part for part in clauses if _HIGH.search(part)
                             and _SUCCESS_PATTERN.search(part) and not _NEGATIVE_FACT_PATTERN.search(part)), None)
        if _CRITICAL.search(proof):
            severity, impact = "CRITICAL", "已证实完全控制或无限制远程执行"
        elif impact_proof:
            proof = impact_proof
            severity, impact = "HIGH", "成功证据指向敏感文件读取、数据外泄或权限突破"
        elif _LOW.search(proof):
            severity, impact = "LOW", "已证实轻微信息暴露"
        elif _MEDIUM.search(proof):
            severity, impact = "MEDIUM", "已证实影响受限的利用"
        else:
            severity, impact = "UNKNOWN", "已确认漏洞，但缺少可判定影响的证据"
        return {"type": "vulnerability", "severity": severity, "rule": "explicit-success",
                "reason": f"{impact}；依据：{proof[:240]}"}
    if _NEGATIVE_FACT_PATTERN.search(description):
        return {"type": "fact", "severity": "UNKNOWN", "rule": "negative-or-unverified",
                "reason": "只有未确认、失败或被拒绝的结果，缺少成功利用证据"}
    return None


def fallback_assessment(description: str) -> dict[str, str]:
    return fact_assessment(description) or {"type": "fact", "severity": "UNKNOWN",
        "rule": "insufficient-evidence", "reason": "当前文字缺少可核验的成功利用及影响证据"}


async def assess_project_facts(detail: dict[str, Any], cache: dict[str, Any], gateway: Any = None,
                               observer: Any = None, model_budget: int = 0) -> dict[str, Any]:
    """Assess new or changed Facts once per content/version; failures stay conservative."""
    for fact in detail.get("facts", []):
        if not isinstance(fact, dict) or not isinstance(fact.get("id"), str):
            continue
        fact_id, description = fact["id"], str(fact.get("description", ""))
        if fact_id in {"origin", "goal"}:
            continue
        digest = hashlib.sha256((ASSESSMENT_VERSION + description).encode()).hexdigest()
        if isinstance(cache.get(fact_id), dict) and cache[fact_id].get("digest") == digest:
            continue
        result = fact_assessment(description)
        if result is None and gateway is not None and model_budget > 0:
            model_budget -= 1
            try:
                answer, _ = await asyncio.wait_for(gateway.structured(
                    role="worker", stage="penetration_fact_assessment", call_purpose="auxiliary", prompt_version=ASSESSMENT_VERSION,
                    system_prompt=("Classify a security Fact using only its literal text. Return vulnerability true only "
                                   "for observed successful exploitation. Quote an exact substring proving success; "
                                   "if uncertain return false and UNKNOWN. Severity: CRITICAL only full control or "
                                   "unrestricted RCE; HIGH sensitive file read, exfiltration, auth bypass or privilege "
                                   "escalation; MEDIUM limited confirmed impact; LOW minor exposure; otherwise UNKNOWN."),
                    user_prompt=description[:6000], output_model=ModelFactAssessment,
                    stream_observer=observer, timeout_seconds=8), timeout=12)
                quote = answer.evidence_quote.strip()
                severity = answer.severity.upper()
                if (answer.vulnerability and quote and quote in description
                        and _OBSERVED_EFFECT.search(quote)
                        and not _NEGATIVE_FACT_PATTERN.search(quote)):
                    if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}:
                        severity = "UNKNOWN"
                    # A model cannot supply missing impact evidence through its rationale.
                    if severity == "CRITICAL" and not _CRITICAL.search(description):
                        severity = "UNKNOWN"
                    if severity == "HIGH" and not _HIGH.search(quote):
                        severity = "UNKNOWN"
                    result = {"type": "vulnerability", "severity": severity, "rule": "semantic-success",
                              "reason": f"模型引用已验证结果：{quote[:240]}"}
            except Exception:
                pass
        cache[fact_id] = {**(result or fallback_assessment(description)), "digest": digest}
    return cache


class PenetrationUnavailableError(RuntimeError):
    pass


class PenetrationProtocolError(RuntimeError):
    pass


TERMINAL_PROJECT_STATUSES = frozenset(
    {"completed", "complete", "succeeded", "success", "failed", "denied", "cancelled", "canceled", "stopped", "error"}
)
FAILED_PROJECT_STATUSES = frozenset({"failed", "denied", "cancelled", "canceled", "stopped", "error"})


def evaluate_project_completion(detail: dict[str, Any]) -> dict[str, Any]:
    """Return a conservative completion decision from a Security Runtime project detail.

    A project being marked completed is not sufficient by itself: the blackboard
    must also contain a concluded intent targeting the goal fact.  This prevents
    an early/optimistic worker status from being exposed as a solved task.
    """
    project = detail.get("project") if isinstance(detail.get("project"), dict) else {}
    status = str(project.get("status", "unknown")).strip().casefold()
    facts = detail.get("facts") if isinstance(detail.get("facts"), list) else []
    intents = detail.get("intents") if isinstance(detail.get("intents"), list) else []
    goal_intents = [
        item for item in intents
        if isinstance(item, dict)
        and item.get("to") == "goal"
        and (item.get("concluded_at") or item.get("status") in {"completed", "confirmed"})
    ]
    objective_reached = status in {"completed", "complete", "succeeded", "success"} and bool(goal_intents)
    return {
        "status": status,
        "terminal": status in TERMINAL_PROJECT_STATUSES,
        "failed": status in FAILED_PROJECT_STATUSES,
        "objective_reached": objective_reached,
        "fact_count": len(facts),
        "intent_count": len(intents),
        "goal_intent_count": len(goal_intents),
    }


async def wait_for_project_terminal(
    base_url: str,
    project_id: str,
    *,
    timeout_seconds: float,
    interval_seconds: float,
    on_update: Callable[[dict[str, Any]], Awaitable[None] | None] | None = None,
) -> dict[str, Any]:
    """Poll Security Runtime until a terminal project state or a bounded timeout."""
    started = time.monotonic()
    last_update: dict[str, Any] = {"status": "unknown", "terminal": False, "objective_reached": False}
    while True:
        detail: dict[str, Any] = {}
        try:
            detail = await penetration_get(
                base_url,
                f"/projects/{project_id}",
                timeout_seconds=min(10.0, timeout_seconds),
            )
            decision = evaluate_project_completion(detail)
        except KeyError:
            return {
                "status": "failed",
                "terminal": True,
                "failed": True,
                "objective_reached": False,
                "project_id": project_id,
                "fact_count": 0,
                "intent_count": 0,
                "error": "Security Runtime project was not found",
            }
        except Exception as exc:
            decision = {
                "status": "poll_error",
                "terminal": False,
                "failed": False,
                "objective_reached": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
        decision = {
            **decision,
            "project_id": project_id,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }
        last_update = decision
        if on_update is not None:
            update_result = on_update({**decision, "detail": detail})
            if asyncio.iscoroutine(update_result):
                await update_result
        if decision["terminal"]:
            return {"detail": detail, **decision}
        if time.monotonic() - started >= timeout_seconds:
            # Keep the unified run and the external runtime in one lifecycle.
            # Without this transition the caller becomes terminal while the
            # external project remains active forever, consuming dispatcher
            # attention and potentially starving later projects.
            stop_requested = False
            stop_error: str | None = None
            try:
                await penetration_update_status(
                    base_url,
                    project_id,
                    "stopped",
                    timeout_seconds=min(10.0, timeout_seconds),
                )
                stop_requested = True
            except Exception as exc:
                stop_error = f"{type(exc).__name__}: {exc}"
            return {
                "detail": detail,
                **last_update,
                "status": "timeout",
                "terminal": True,
                "timed_out": True,
                "objective_reached": False,
                "external_stop_requested": stop_requested,
                **({"external_stop_error": stop_error} if stop_error else {}),
            }
        await asyncio.sleep(min(interval_seconds, max(0.0, timeout_seconds - (time.monotonic() - started))))


def project_title_for_run(run_id: str) -> str:
    """Return the neutral project title used to link a run to its graph."""
    return f"sec-task-{run_id}"


def extract_project_id(state: AgentState) -> str | None:
    saved = state.external_execution.get("project_id")
    if isinstance(saved, str) and saved.strip():
        return saved.strip()
    for observation in reversed(state.observations):
        data = observation.data
        adapter = data.get("adapter")
        if not isinstance(adapter, str) or not adapter.strip():
            continue
        direct = data.get("project_id")
        if isinstance(direct, str) and direct.strip():
            return direct.strip()
        project = data.get("project")
        if isinstance(project, dict):
            project_id = project.get("id")
            if isinstance(project_id, str) and project_id.strip():
                return project_id.strip()
        raw = data.get("response")
        if not isinstance(raw, str):
            continue
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        project_id = payload.get("project", {}).get("id") if isinstance(payload, dict) else None
        if isinstance(project_id, str) and project_id.strip():
            return project_id.strip()
    return None


async def penetration_get(base_url: str, path: str, timeout_seconds: float) -> Any:
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False, trust_env=False) as client:
            response = await client.get(url)
    except httpx.HTTPError as exc:
        raise PenetrationUnavailableError(f"Penetration service is unavailable: {exc}") from exc
    if response.status_code == 404:
        raise KeyError(path)
    if response.status_code >= 400:
        raise PenetrationUnavailableError(f"Penetration service returned HTTP {response.status_code}")
    try:
        return response.json()
    except ValueError as exc:
        raise PenetrationProtocolError("Penetration service returned an invalid JSON response") from exc


async def penetration_update_status(
    base_url: str,
    project_id: str,
    status: str,
    timeout_seconds: float,
) -> Any:
    url = f"{base_url.rstrip('/')}/projects/{project_id}/status"
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False, trust_env=False) as client:
            response = await client.put(url, json={"status": status})
    except httpx.HTTPError as exc:
        raise PenetrationUnavailableError(f"Penetration service is unavailable: {exc}") from exc
    if response.status_code == 404:
        raise KeyError(project_id)
    if response.status_code >= 400:
        raise PenetrationUnavailableError(f"Penetration service returned HTTP {response.status_code}")
    try:
        return response.json()
    except ValueError as exc:
        raise PenetrationProtocolError("Penetration service returned an invalid JSON response") from exc


async def resolve_project_id(
    state: AgentState,
    base_url: str,
    timeout_seconds: float,
) -> str | None:
    persisted = extract_project_id(state)
    if persisted:
        return persisted
    projects = await penetration_get(base_url, "/projects", timeout_seconds)
    if not isinstance(projects, list):
        raise PenetrationProtocolError("Penetration project list must be an array")
    matches = [
        item for item in projects
        if (
            isinstance(item, dict)
            and isinstance(item.get("title"), str)
            and (
                item.get("title") == project_title_for_run(state.run_id)
                # Existing projects used a branded prefix. Matching the
                # immutable run-id suffix keeps old blackboards readable
                # without coupling new project titles to that label.
                or item["title"].endswith(state.run_id)
            )
            and isinstance(item.get("id"), str)
        )
    ]
    if not matches:
        return None
    matches.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)
    return str(matches[0]["id"])


async def create_project_hint(base_url: str, project_id: str, content: str,
                              creator: str, timeout_seconds: float) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}/projects/{project_id}/hints"
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False, trust_env=False) as client:
            response = await client.post(url, json={"content": content, "creator": creator})
    except httpx.HTTPError as exc:
        raise PenetrationUnavailableError(f"Penetration service is unavailable: {exc}") from exc
    if response.status_code == 404:
        raise KeyError(project_id)
    if response.status_code >= 400:
        raise PenetrationUnavailableError(f"Penetration service returned HTTP {response.status_code}")
    try:
        value = response.json()
    except ValueError as exc:
        raise PenetrationProtocolError("Penetration service returned an invalid JSON response") from exc
    if not isinstance(value, dict):
        raise PenetrationProtocolError("Penetration hint response must be an object")
    return value


def _fact_type(fact_id: str, description: str) -> str:
    if fact_id == "origin":
        return "origin"
    if fact_id == "goal":
        return "goal"
    return fallback_assessment(description)["type"]


def live_graph_approvals(detail: dict[str, Any], state: Any,
                         approvals: list[dict] | None) -> list[dict]:
    project = detail.get('project')
    if (not state or getattr(getattr(state, 'status', None), 'value', None) != 'running'
            or not isinstance(project, dict) or project.get('status') != 'active'):
        return []
    intents = {item.get('id'): item for item in detail.get('intents', []) if isinstance(item, dict)}
    return [record for record in approvals or []
            if record.get('status') == 'pending'
            and record.get('project_id') == project.get('id')
            and (intent := intents.get(record.get('intent_id')))
            and intent.get('execution_status') == 'running'
            and intent.get('worker') == record.get('worker')
            and intent.get('attempt_id') == record.get('attempt_id')
            and not intent.get('concluded_at') and not intent.get('to')]


def normalize_penetration_graph(detail: dict[str, Any], assessments: dict[str, Any] | None = None,
                                events: list[Any] | None = None, state: Any = None, approvals: list[dict] | None = None) -> dict[str, Any]:
    project = detail.get("project")
    facts = detail.get("facts", [])
    projected_facts = {f.get('id'): f for f in getattr(state, 'external_execution', {}).get('external_facts', [])
                       if isinstance(f, dict)}
    if isinstance(facts, list) and projected_facts:
        facts = [{**fact, 'items': projected_facts[fact['id']].get('items', fact.get('items', []))}
                 if isinstance(fact, dict) and fact.get('id') in projected_facts else fact for fact in facts]
    intents = detail.get("intents", [])
    hints = detail.get("hints", [])
    if not isinstance(project, dict) or not isinstance(facts, list) or not isinstance(intents, list):
        raise PenetrationProtocolError("Penetration project detail has an invalid shape")
    approvals = live_graph_approvals(detail, state, approvals)

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    fact_ids: set[str] = set()
    result_items: list[dict[str, Any]] = []
    from security_agent.schemas import Evidence
    evidence = {e.evidence_id: e for e in state.evidence} if state else {}
    for event in events or []:
        payload = getattr(event, "payload", {})
        binding = payload.get("blackboard", {}) if isinstance(payload, dict) else {}
        if (getattr(event, "event_type", "") in {"mcp.call.completed", "mcp.call.failed"}
                and binding.get("project_id") == project.get("id") and payload.get("call_id")
                and isinstance(payload.get("result"), dict)):
            evidence.setdefault(payload["call_id"], Evidence(evidence_id=payload["call_id"], source=payload.get("tool") or "MCP",
                summary="持久化 MCP 工具回执", metadata={"call_id": payload["call_id"], "result": payload["result"],
                                                         "intent_id": binding.get("intent_id"), "attempt_id": binding.get("attempt_id")}))

    for fact in facts:
        if not isinstance(fact, dict) or not isinstance(fact.get("id"), str):
            continue
        fact_id = fact["id"]
        description = str(fact.get("description", "")).strip() or fact_id
        title = str(fact.get("title") or "").strip() or (description[:100] if fact_id in {"origin", "goal"} else f"历史原文 · {fact_id}")
        items = fact.get("items") if isinstance(fact.get("items"), list) else []
        valid_items = []
        receipt = None
        if description.startswith("统一工作台步骤回执："):
            try:
                receipt = json.loads(description.split("：", 1)[1])
            except (ValueError, TypeError):
                pass
        if isinstance(receipt, dict):
            title = str(fact.get("title") or receipt.get("summary") or "执行结果包")[:120]
            if not items:
                items = [{"type": "observation", "title": title, "summary": str(receipt.get("summary") or ""),
                          "evidence_ids": receipt.get("evidence_ids", [])}]
        findings = {f.finding_id: f for f in state.findings} if state else {}
        verification = next((d for d in reversed(state.decisions)
                             if d.decision in {"verification_passed", "verification_failed"}), None) if state else None
        for index, original in enumerate(items):
            if not isinstance(original, dict):
                continue
            item = dict(original)
            iid = str(item.get("id") or index + 1)
            item["id"] = iid if iid.startswith(f"{fact_id}:") else f"{fact_id}:{iid}"
            base_id = item["id"]
            counter = index + 1
            while any(old["id"] == item["id"] for old in valid_items):
                item["id"] = f"{base_id}:{counter}"
                counter += 1
            refs = item.get("evidence_ids") or []
            item["evidence_ids"] = [ref for ref in refs if isinstance(ref, str)] if isinstance(refs, list) else []
            item["verification_status"] = ("pending" if item["evidence_ids"] else "insufficient") if item.get("verification_status") in {"confirmed", "ruled_out"} else item.get("verification_status")
            finding = findings.get(item.get("finding_id"))
            if state and getattr(state, 'external_execution', {}).get('blackboard', {}).get('planning_mode') == 'workbench':
                finding = next((f for f in state.findings if f.raw.get('fact_id') == fact_id
                                and (f.raw.get('item_id') == iid or f.raw.get('source_finding_id') == item.get('finding_id')
                                     and item.get('finding_id'))), None)
            if finding:
                refs = finding.evidence_ids
                item["evidence_ids"] = refs
                valid = bool(refs) and all(ref in evidence for ref in refs)
                passed = verification and verification.decision == "verification_passed" and set(refs).issubset(verification.evidence_ids)
                if getattr(state, "external_execution", {}).get("blackboard", {}).get("planning_mode") == "workbench":
                    passed = any(d.decision == "finding_verification_passed"
                                 and f"finding:{finding.finding_id}" in d.policy_ids
                                 and bool(d.evidence_ids) and set(d.evidence_ids).issubset(refs) for d in state.decisions)
                item["verification_status"] = "confirmed" if valid and passed else "pending" if valid else "insufficient"
                if state and getattr(state, 'external_execution', {}).get('blackboard', {}).get('planning_mode') == 'workbench':
                    item['verification_status'] = ('ruled_out' if finding.raw.get('verification_status') == 'excluded'
                                                   else finding.raw.get('verification_status', item['verification_status']))
            elif item.get("type") == "finding":
                item["verification_status"] = item.get("verification_status") or ("pending" if item["evidence_ids"] else "insufficient")
            item["evidence"] = [evidence[ref].model_dump(mode="json") for ref in item["evidence_ids"] if ref in evidence]
            item["provenance"] = "工具证据" if item["evidence"] else "证据引用待核对" if item["evidence_ids"] else "Worker 报告"
            valid_items.append(item)
        result_items.extend({"fact_id": fact_id, **item} for item in valid_items)
        cached = (assessments or {}).get(fact_id)
        digest = hashlib.sha256((ASSESSMENT_VERSION + description).encode()).hexdigest()
        assessment = (cached if isinstance(cached, dict) and cached.get("digest") == digest
                      else fallback_assessment(description))
        node_type = _fact_type(fact_id, description) if fact_id in {"origin", "goal"} else "fact"
        fact_ids.add(fact_id)
        nodes.append(
            {
                "id": f"fact:{fact_id}",
                "raw_id": fact_id,
                "type": node_type,
                "label": title,
                "title": title,
                "description": description,
                "status": "completed" if fact_id not in {"origin", "goal"} else "known",
                "items": valid_items,
                "summary": str(receipt.get("summary") or title) if isinstance(receipt, dict) else title,
                "item_count": len(valid_items),
                "legacy": not bool(fact.get("title") or valid_items) and fact_id not in {"origin", "goal"},
                "ai_generated": fact_id not in {"origin", "goal"},
                "creator": "AI Worker" if fact_id not in {"origin", "goal"} else "operator",
                **({"severity": assessment["severity"], "assessment_rule": assessment["rule"],
                    "assessment_reason": assessment["reason"]} if fact_id not in {"origin", "goal"} else {}),
            }
        )

    for intent in intents:
        if not isinstance(intent, dict) or not isinstance(intent.get("id"), str):
            continue
        intent_id = intent["id"]
        source_ids = [item for item in intent.get("from", []) if isinstance(item, str)]
        target_id = intent.get("to") if isinstance(intent.get("to"), str) else None
        worker = intent.get("worker") if isinstance(intent.get("worker"), str) else None
        if worker and worker.strip():
            worker = worker.strip()
        concluded = bool(intent.get("concluded_at") or target_id)
        # The project completion endpoint stores the final report summary as a
        # goal intent. It is a concluded result, so expose it as a conclusion
        # node instead of presenting a report as an unfulfilled reasoning step.
        is_conclusion = (target_id == "goal" and concluded
                         and str(intent.get("creator", "")).startswith("unified-workbench:"))
        node_type = "conclusion" if is_conclusion else ("hypothesis" if not concluded and not worker else "intent")
        status = intent.get("execution_status") or ("completed" if concluded else "running" if worker else "waiting")
        if concluded and status not in {"failed", "cancelled", "timeout"}:
            status = "completed"
        description = str(intent.get("description", "")).strip() or intent_id
        creator = "报告摘要" if is_conclusion else str(intent.get("creator", "AI Worker"))
        nodes.append(
            {
                "id": f"intent:{intent_id}",
                "raw_id": intent_id,
                "type": node_type,
                "label": description,
                "title": str(intent.get("title") or description),
                "description": description,
                "status": status,
                "ai_generated": not is_conclusion,
                "creator": creator,
                "worker": worker,
                "tool_name": intent.get("tool_name"),
                "attempt_id": intent.get("attempt_id"),
                "step_id": intent.get("step_id"),
                "depends_on": intent.get("depends_on") or [],
                "required_outputs": intent.get("required_outputs") or {},
                "validated_outputs": intent.get("validated_outputs") or [],
                "blocked_reasons": intent.get("blocked_reasons") or [],
                "source_relation": intent.get("source_relation", "evidence"),
                "source_ids": source_ids,
                "source_links": [{"fact_id": fid, "relation": intent.get("source_relations", {}).get(fid, intent.get("source_relation", "evidence"))} for fid in source_ids],
                "success_criteria": intent.get("success_criteria"),
                "verification_target": intent.get("verification_target"),
                "decision_id": intent.get("decision_id"),
                "decision_summary": intent.get("decision_summary"),
                "created_at": intent.get("created_at"),
                "concluded_at": intent.get("concluded_at"),
            }
        )
        for source_id in source_ids:
            if source_id not in fact_ids:
                continue
            edges.append(
                {
                    "id": f"edge:{source_id}:{intent_id}",
                    "source": f"fact:{source_id}",
                    "target": f"intent:{intent_id}",
                    "type": "hypothesis" if node_type == "hypothesis" else "intent-chain",
                    "label": {"process": "流程衔接", "unknown": "来源不明"}.get(intent.get("source_relations", {}).get(source_id, intent.get("source_relation")), "引用事实"),
                    "status": status,
                    "relation": intent.get("source_relations", {}).get(source_id, intent.get("source_relation", "evidence")),
                }
            )
        if target_id and target_id in fact_ids:
            edges.append(
                {
                    "id": f"edge:{intent_id}:{target_id}",
                    "source": f"intent:{intent_id}",
                    "target": f"fact:{target_id}",
                    "type": "produces",
                    "label": "产出" if target_id != "goal" else "证明",
                    "status": "completed",
                }
            )

    origin_exists = "origin" in fact_ids
    for hint in hints if isinstance(hints, list) else []:
        if not isinstance(hint, dict) or not isinstance(hint.get("id"), str):
            continue
        hint_id = hint["id"]
        content = str(hint.get("content", "")).strip() or hint_id
        nodes.append(
            {
                "id": f"hint:{hint_id}",
                "raw_id": hint_id,
                "type": "hint",
                "label": content,
                "description": content,
                "status": "known",
                "ai_generated": False,
                "creator": str(hint.get("creator", "operator")),
                "created_at": hint.get("created_at"),
            }
        )
        if origin_exists:
            edges.append(
                {
                    "id": f"edge:origin:{hint_id}",
                    "source": "fact:origin",
                    "target": f"hint:{hint_id}",
                    "type": "hint",
                    "label": "提示",
                    "status": "known",
                }
            )

    activity: dict[str, list[dict[str, Any]]] = {}
    for event in events or []:
        event_type = getattr(event, "event_type", None)
        payload = getattr(event, "payload", None)
        if not isinstance(payload, dict) or not event_type or not event_type.startswith(("tool.", "mcp.call.", "runtime.", "blackboard.intent.")):
            continue
        binding = payload.get("blackboard") if isinstance(payload.get("blackboard"), dict) else payload
        if binding.get("project_id") != project.get("id"):
            continue
        intent_id = binding.get("intent_id")
        if not isinstance(intent_id, str):
            continue
        activity.setdefault(intent_id, []).append({"event_type": event_type, "tool": payload.get("tool"),
            "call_id": payload.get("call_id"), "attempt_id": binding.get("attempt_id"),
            "phase": payload.get("phase"), "status": payload.get("status"),
            "timestamp": payload.get("timestamp") or str(getattr(event, "timestamp", "")),
            "fact_id": payload.get("fact_id"), "evidence_ids": payload.get("evidence_ids", [])})
    for node in nodes:
        if node["type"] not in {"intent", "hypothesis", "conclusion"}:
            continue
        history = activity.get(node["raw_id"], [])
        node["execution_history"] = history
        current_history = [item for item in history if item.get("attempt_id") == node.get("attempt_id")]
        pending = {}
        for item in current_history:
            kind = item["event_type"]
            key = item.get("call_id") or item.get("tool")
            if kind in {"mcp.call.started", "tool.started"}:
                pending[key] = item
            elif kind.startswith(("mcp.call.", "tool.")):
                pending.pop(key, None)
        if pending and node["status"] in {"running", "exploring"}:
            node["current_tool"] = list(pending.values())[-1].get("tool")
        stages = [item for item in current_history if item.get("phase")]
        node["phase"] = stages[-1]["phase"] if stages else None
        node["latest_activity"] = history[-1]["timestamp"] if history else node.get("concluded_at") or node.get("created_at")

    attempts = {node["raw_id"]: node.get("attempt_id") for node in nodes if node["type"] in {"intent", "hypothesis", "conclusion"}}
    pending_intents = {item.get("intent_id") for item in approvals or [] if item.get("status") == "pending"
                       and item.get("project_id") == project.get("id")
                       and item.get("attempt_id") == attempts.get(item.get("intent_id"))}
    if state and state.pending_approval:
        board = state.external_execution.get("blackboard", {})
        if board.get("project_id") == project.get("id") and board.get("attempt_id") == attempts.get(board.get("intent_id")):
            pending_intents.add(board.get("intent_id"))
    for node in nodes:
        if node.get("raw_id") in pending_intents and node["type"] in {"intent", "hypothesis"} and node["status"] not in {"completed", "failed", "cancelled", "timeout"}:
            node["status"] = "approval"
            node.pop("current_tool", None)
    status_by_id = {node["id"]: node["status"] for node in nodes}
    for edge in edges:
        if edge["target"].startswith("intent:"):
            edge["status"] = status_by_id.get(edge["target"], edge["status"])

    counts: dict[str, int] = {}
    for node in nodes:
        counts[node["type"]] = counts.get(node["type"], 0) + 1

    return {
        "schema_version": "1.1",
        "source": "penetration",
        "available": True,
        "linked": True,
        "project_id": project.get("id"),
        "project": project,
        "nodes": nodes,
        "edges": edges,
        "result_items": result_items,
        "budget": state.budget.model_dump(mode="json") if getattr(state, "budget", None) else None,
        "planning": [{"decision_id": getattr(event, "payload", {}).get("decision_id"),
                      "summary": getattr(event, "payload", {}).get("summary"),
                      "stop_reason": getattr(event, "payload", {}).get("stop_reason"),
                      "trigger": getattr(event, "payload", {}).get("trigger"),
                      "timestamp": str(getattr(event, "timestamp", ""))}
                     for event in events or [] if getattr(event, "event_type", "") == "planning.decision"],
        "execution": [{"intent_id": node["raw_id"], "status": node["status"], "worker": node.get("worker"),
                       "tool_name": node.get("tool_name"), "current_tool": node.get("current_tool"), "phase": node.get("phase"), "latest_activity": node.get("latest_activity"), "attempt_id": node.get("attempt_id")}
                      for node in nodes if node["type"] in {"intent", "hypothesis", "conclusion"}],
        "counts": counts,
        "fetched_at": datetime.now(UTC).isoformat(),
    }
