from types import SimpleNamespace

from security_agent.penetration_integration import normalize_penetration_graph
from security_agent.schemas import DecisionRecord, Evidence, Finding, RunStatus


def detail():
    return {"project": {"id": "p", "status": "active"}, "facts": [
        {"id": "origin", "description": "known"},
        {"id": "f1", "description": "claimed confirmed vulnerability", "title": "结果", "items": [
            {"id": "one", "type": "finding", "title": "SQL 注入候选", "finding_id": "finding", "evidence_ids": ["e1"], "verification_status": "confirmed"}]}],
        "intents": [{"id": "i1", "from": ["origin"], "to": None, "description": "验证注入", "worker": "shared", "attempt_id": "new", "execution_status": "running"},
                    {"id": "i2", "from": ["origin"], "to": "f1", "description": "其他分支", "worker": "shared", "attempt_id": "other", "execution_status": "failed", "concluded_at": "now"}]}


def event(kind, intent, attempt, call):
    return SimpleNamespace(event_type=kind, timestamp="now", payload={"tool": "http_probe", "call_id": call,
        "blackboard": {"project_id": "p", "intent_id": intent, "attempt_id": attempt}})


def test_parallel_worker_attempts_and_finished_tools_do_not_cross():
    events = [event("mcp.call.started", "i1", "old", "old-call"),
              event("mcp.call.started", "i2", "other", "other-call"),
              event("mcp.call.started", "i1", "new", "active-call")]
    graph = normalize_penetration_graph(detail(), events=events)
    nodes = {n["raw_id"]: n for n in graph["nodes"]}
    assert nodes["i1"]["current_tool"] == "http_probe"
    assert "current_tool" not in nodes["i2"]
    assert nodes["i2"]["status"] == "failed"
    events.append(event("mcp.call.completed", "i1", "new", "active-call"))
    nodes = {n["raw_id"]: n for n in normalize_penetration_graph(detail(), events=events)["nodes"]}
    assert "current_tool" not in nodes["i1"]
    assert len(nodes["i1"]["execution_history"]) == 3
    assert not any(n["type"] == "worker" for n in graph["nodes"])


def test_confirmation_requires_existing_verifier_and_valid_references():
    state = SimpleNamespace(evidence=[Evidence(evidence_id="e1", source="http_probe", summary="response")],
        findings=[Finding(finding_id="finding", rule_id="SQLI", path="login", title="注入", description="观察差异", evidence_ids=["e1"])], decisions=[], pending_approval=None)
    item = normalize_penetration_graph(detail(), state=state)["result_items"][0]
    assert item["verification_status"] == "pending"
    state.decisions.append(DecisionRecord(decision="verification_passed", rationale_summary="validated", evidence_ids=["e1"]))
    assert normalize_penetration_graph(detail(), state=state)["result_items"][0]["verification_status"] == "confirmed"
    state.evidence.clear()
    assert normalize_penetration_graph(detail(), state=state)["result_items"][0]["verification_status"] == "insufficient"
    assert normalize_penetration_graph(detail())["result_items"][0]["verification_status"] == "pending"


def test_pending_approval_and_mixed_source_relationships_are_explicit():
    data = detail()
    data["intents"][0]["from"] = ["origin", "f1"]
    data["intents"][0]["source_relations"] = {"origin": "process", "f1": "evidence"}
    state = SimpleNamespace(status=RunStatus.RUNNING, evidence=[], findings=[], decisions=[],
                            pending_approval=None, external_execution={})
    approval = {"intent_id": "i1", "attempt_id": "new", "project_id": "p",
                "worker": "shared", "status": "pending"}
    graph = normalize_penetration_graph(data, state=state, approvals=[approval])
    node = next(n for n in graph["nodes"] if n["raw_id"] == "i1")
    assert node["status"] == "approval"
    edges = [e for e in graph["edges"] if e["target"] == "intent:i1"]
    assert {e["relation"] for e in edges} == {"process", "evidence"}
    assert {e["label"] for e in edges} == {"流程衔接", "引用事实"}
    assert all(e["status"] == "approval" for e in edges)
    stale = normalize_penetration_graph(data, state=state,
                                        approvals=[{**approval, "attempt_id": "old"}])
    assert next(n for n in stale["nodes"] if n["raw_id"] == "i1")["status"] == "running"
    state.status = RunStatus.PARTIAL
    stopped = normalize_penetration_graph(data, state=state, approvals=[approval])
    assert next(n for n in stopped["nodes"] if n["raw_id"] == "i1")["status"] == "running"


def test_mcp_evidence_is_resolved_only_from_the_bound_project_receipt():
    data = detail()
    data['facts'][1]['items'][0]['evidence_ids'] = ['call-1']
    receipt = event('mcp.call.completed', 'i2', 'other', 'call-1')
    receipt.payload['result'] = {'content': [{'type': 'text', 'text': 'actual response'}]}
    item = normalize_penetration_graph(data, events=[receipt])['result_items'][0]
    assert item['provenance'] == '工具证据'
    assert item['evidence'][0]['metadata']['result'] == receipt.payload['result']
    assert item['verification_status'] != 'confirmed'
    receipt.payload['blackboard']['project_id'] = 'different-project'
    item = normalize_penetration_graph(data, events=[receipt])['result_items'][0]
    assert item['provenance'] == '证据引用待核对' and not item['evidence']


def test_new_finding_ids_survive_persistence_and_raw_json_has_a_readable_title():
    from security_agent.blackboard_coordinator import BlackboardCoordinator
    from security_agent.schemas import ToolResult, ToolStatus
    result = ToolResult(status=ToolStatus.SUCCESS, summary='{"logs": ["raw response"]}', data={'findings': [
        {'rule_id': 'SQLI', 'path': 'login', 'title': '注入候选', 'description': 'response difference', 'evidence_ids': ['e1']}]},
        evidence=[Evidence(evidence_id='e1', source='http_probe', summary='{"status":500}')])
    bundle = BlackboardCoordinator._structured_result(result)
    finding = next(item for item in bundle['items'] if item['type'] == 'finding')
    assert Finding.model_validate(result.data['findings'][0]).finding_id == finding['finding_id']
    assert BlackboardCoordinator._structured_result(ToolResult.model_validate_json(result.model_dump_json())) == bundle
    assert bundle['title'] == '执行结果包'
    assert bundle['items'][0]['title'] == 'http_probe · 工具观察'
