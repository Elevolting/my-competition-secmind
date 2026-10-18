import json

import httpx
import pytest

from security_agent.tsec_auto import (
    AutoOperator,
    WorkbenchClient,
    WorkbenchError,
    build_task_payload,
    harvest_flags,
)
from security_agent.tsec_benchmark import TSecError


class Platform:
    def __init__(self, count=3, flags=1):
        self.items = [
            {"unique_code": f"c-0{i}", "container_status": "stopped", "is_completed": False,
             "container_addr": [], "flag_count": flags, "correct_flag_count": 0,
             "description": f"题目 {i}"}
            for i in range(1, count + 1)
        ]
        self.calls = []
        self.start_error = None

    async def list_challenges(self):
        return [dict(item) for item in self.items]

    async def start(self, code):
        self.calls.append(("start", code))
        if self.start_error:
            raise self.start_error
        item = next(entry for entry in self.items if entry["unique_code"] == code)
        item["container_status"] = "available"
        item["container_addr"] = [f"10.0.0.{code[-1]}:80"]
        return {"unique_code": code, "container_addr": list(item["container_addr"])}

    async def submit(self, code, flag):
        self.calls.append(("submit", code, flag))
        item = next(entry for entry in self.items if entry["unique_code"] == code)
        if flag == "flag{right}":
            item["correct_flag_count"] += 1
            item["is_completed"] = item["correct_flag_count"] >= item["flag_count"]
            return {"correct": True, "awarded": 50, "correct_flag_count": item["correct_flag_count"],
                    "total_flag_count": item["flag_count"], "matched_flag_index": 0}
        return {"correct": False, "awarded": 0, "correct_flag_count": item["correct_flag_count"],
                "total_flag_count": item["flag_count"], "matched_flag_index": None}

    async def close(self, code):
        self.calls.append(("close", code))
        item = next(entry for entry in self.items if entry["unique_code"] == code)
        item["container_status"] = "stopped"
        item["container_addr"] = []
        return {"unique_code": code, "closed": True}


def workbench_transport(run_status="completed", report=None, graph=None):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/tasks" and request.method == "POST":
            return httpx.Response(202, json={"schema_version": "1.0", "run_id": "run-1", "status": "pending"})
        if path == "/api/v1/runs/run-1":
            return httpx.Response(200, json={"run_id": "run-1", "status": run_status})
        if path == "/api/v1/runs/run-1/report":
            if report is None:
                return httpx.Response(409, json={"detail": "Report is not available yet"})
            return httpx.Response(200, json=report)
        if path == "/api/v1/runs/run-1/penetration-graph":
            if graph is None:
                return httpx.Response(409, json={"detail": "Run is not routed to the penetration module"})
            return httpx.Response(200, json=graph)
        return httpx.Response(404, json={"detail": "Not Found"})

    return httpx.MockTransport(handler)


def test_harvest_flags_prefers_verified_evidence_and_skips_placeholders():
    report = {
        "verified_outputs": ["flag{right}"],
        "executive_summary": "已获取 flag{right}，示例 flag{example_value} 仅为格式说明。",
        "findings": [{"title": "确认漏洞", "description": "证据 ctf_demo{abc} 已复核", "raw": {}}],
        "evidence": [{"summary": "回显 flag{right}"}],
    }
    graph = {"nodes": [{"label": "flag{graph_value}", "description": "confirmed fact"}]}
    flags = harvest_flags(report, graph)
    assert flags == ["flag{right}"]


def test_harvest_flags_empty_when_no_evidence():
    assert harvest_flags(None, None) == []
    assert harvest_flags({"executive_summary": "尚未取得任何 flag"}, None) == []
    assert harvest_flags({"verified_outputs": [], "executive_summary": "flag{unverified}",
                          "findings": [{"description": "flag{candidate}"}],
                          "evidence": [{"summary": "flag{echoed_input}"}]},
                         {"nodes": [{"label": "flag{graph_claim}"}]}) == []


def test_build_task_payload_uses_container_addresses_as_scope():
    payload = build_task_payload({"unique_code": "c-01", "description": "SQL 注入"},
                                 autonomy_policy="automatic", addresses=["10.0.0.1:80"])
    assert payload["name"] == "TSec-c-01"
    assert payload["autonomy_policy"] == "automatic"
    assert "c-01" in payload["objective"] and "SQL 注入" in payload["objective"]
    assert "http://10.0.0.1:80" in payload["objective"]


def test_build_task_payload_authorizes_scoped_http_to_the_container():
    """Without a network policy the blackboard hides every network tool."""
    payload = build_task_payload({"unique_code": "c-01", "description": ""},
                                 autonomy_policy="automatic", addresses=["10.0.0.1:80"])
    assert payload["network_policy"] == "bounded_http"


def test_build_task_payload_accepts_an_explicit_network_policy():
    payload = build_task_payload({"unique_code": "c-01", "description": ""},
                                 autonomy_policy="automatic", addresses=["10.0.0.1:80"],
                                 network_policy="read_only_http")
    assert payload["network_policy"] == "read_only_http"


def test_build_task_payload_accepts_the_session_policy():
    payload = build_task_payload({"unique_code": "a-05"}, autonomy_policy="automatic",
                                 addresses=["10.0.166.0:80"], network_policy="session_http")
    assert payload["network_policy"] == "session_http"


def test_auto_operator_rejects_an_unknown_network_policy():
    operator = AutoOperator(Platform(), None, network_policy="none")
    assert operator.network_policy == "none"
    with pytest.raises(ValueError):
        AutoOperator(Platform(), None, network_policy="wide_open")


def test_bare_host_port_container_address_routes_to_penetration():
    from security_agent.fusion import classify_task

    payload = build_task_payload({"unique_code": "c-01", "description": ""},
                                 autonomy_policy="automatic", addresses=["10.0.186.160:10086"])
    assert payload["target_scope"] == ["http://10.0.186.160:10086"]
    routing = classify_task(payload["objective"], [], payload["target_scope"])
    assert routing["primary_type"] == "penetration"


def test_normalize_targets_keeps_scheme_and_drops_duplicates():
    from security_agent.tsec_auto import normalize_targets

    assert normalize_targets(["10.0.0.1:80", "http://10.0.0.1:80/", "", "https://a.b:443"]) == [
        "http://10.0.0.1:80", "https://a.b:443"]


async def test_run_submits_harvested_flags_and_releases_completed_container():
    platform = Platform(count=1)
    report = {"verified_outputs": ["flag{right}"], "executive_summary": "已获取 flag{right}"}
    workbench = WorkbenchClient("http://workbench", transport=workbench_transport(report=report))
    operator = AutoOperator(platform, workbench, poll_interval=0.01, solve_timeout=5)

    outcomes = await operator.run(["c-01"])

    assert [row.status for row in outcomes] == ["completed"]
    assert outcomes[0].run_id == "run-1"
    assert outcomes[0].flags_found == ["flag{right}"]
    assert outcomes[0].container_addr == ["10.0.0.1:80"]
    assert outcomes[0].submissions[0]["status"] == "correct"
    assert platform.calls == [("start", "c-01"), ("submit", "c-01", "flag{right}"), ("close", "c-01")]


async def test_run_reports_no_flag_without_submitting():
    platform = Platform(count=1)
    report = {"verified_outputs": [], "executive_summary": "本次执行未获取到 flag"}
    workbench = WorkbenchClient("http://workbench", transport=workbench_transport(report=report))
    operator = AutoOperator(platform, workbench, poll_interval=0.01, solve_timeout=5)

    outcomes = await operator.run(["c-01"])

    assert [row.status for row in outcomes] == ["no_flag"]
    assert [call[0] for call in platform.calls] == ["start"]


async def test_unknown_flag_leaves_container_for_manual_work():
    platform = Platform(count=1)
    report = {"verified_outputs": ["flag{wrong}"], "executive_summary": "flag{wrong}"}
    workbench = WorkbenchClient("http://workbench", transport=workbench_transport(report=report))
    operator = AutoOperator(platform, workbench, poll_interval=0.01, solve_timeout=5)

    outcomes = await operator.run(["c-01"])

    assert [row.status for row in outcomes] == ["incomplete"]
    assert outcomes[0].submissions[0]["status"] == "incorrect"
    assert ("close", "c-01") not in platform.calls


async def test_second_wave_runs_after_completed_container_is_released():
    platform = Platform(count=4)
    report = {"verified_outputs": ["flag{right}"], "executive_summary": "flag{right}"}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/tasks" and request.method == "POST":
            body = json.loads(request.content.decode())
            return httpx.Response(202, json={"run_id": f"run-{body['name']}", "status": "pending"})
        if path.startswith("/api/v1/runs/") and path.endswith("/report"):
            return httpx.Response(200, json=report)
        if path == "/api/v1/runs/run-TSec-c-01":
            return httpx.Response(200, json={"run_id": "run-TSec-c-01", "status": "completed"})
        if path == "/api/v1/runs/run-TSec-c-02":
            return httpx.Response(200, json={"run_id": "run-TSec-c-02", "status": "completed"})
        if path == "/api/v1/runs/run-TSec-c-03":
            return httpx.Response(200, json={"run_id": "run-TSec-c-03", "status": "completed"})
        if path == "/api/v1/runs/run-TSec-c-04":
            return httpx.Response(200, json={"run_id": "run-TSec-c-04", "status": "completed"})
        return httpx.Response(409, json={"detail": "Run is not routed to the penetration module"})

    workbench = WorkbenchClient("http://workbench", transport=httpx.MockTransport(handler))
    operator = AutoOperator(platform, workbench, poll_interval=0.01, solve_timeout=5)

    outcomes = await operator.run(["c-01", "c-02", "c-03", "c-04"])

    assert [row.status for row in outcomes] == ["completed"] * 4
    assert len([call for call in platform.calls if call[0] == "start"]) == 4


async def test_capacity_cap_defers_remaining_without_starting():
    platform = Platform(count=4)
    for item in platform.items[:3]:
        item["container_status"] = "available"
        item["container_addr"] = ["10.0.0.9:80"]
    report = {"verified_outputs": ["flag{right}"], "executive_summary": "flag{right}"}
    workbench = WorkbenchClient("http://workbench", transport=workbench_transport(report=report))
    operator = AutoOperator(platform, workbench, poll_interval=0.01, solve_timeout=5)

    outcomes = await operator.run(["c-04"], include_completed=True)

    assert [row.status for row in outcomes] == ["not_attempted"]
    assert not any(call[0] == "start" for call in platform.calls)


async def test_existing_container_reuses_slot_without_new_start():
    platform = Platform(count=3)
    platform.items[1]["container_status"] = "available"
    platform.items[1]["container_addr"] = ["10.0.0.9:80"]
    report = {"verified_outputs": ["flag{right}"], "executive_summary": "flag{right}"}
    workbench = WorkbenchClient("http://workbench", transport=workbench_transport(report=report))
    operator = AutoOperator(platform, workbench, poll_interval=0.01, solve_timeout=5)

    outcomes = await operator.run(["c-01", "c-02", "c-03"])

    assert [row.status for row in outcomes] == ["completed"] * 3
    started = [call[1] for call in platform.calls if call[0] == "start"]
    assert started == ["c-01", "c-03"]


async def test_uncertain_submit_is_not_retried():
    platform = Platform(count=1)
    report = {"verified_outputs": ["flag{right}"], "executive_summary": "flag{right}"}

    async def submit(code, flag):
        platform.calls.append(("submit", code, flag))
        raise TSecError(503, "platform_unavailable", "timeout")

    platform.submit = submit
    workbench = WorkbenchClient("http://workbench", transport=workbench_transport(report=report))
    operator = AutoOperator(platform, workbench, poll_interval=0.01, solve_timeout=5)

    outcomes = await operator.run(["c-01"])

    assert len([call for call in platform.calls if call[0] == "submit"]) == 1
    assert outcomes[0].submissions[0]["status"] == "error"
    assert ("close", "c-01") not in platform.calls


async def test_workbench_errors_are_surfaced_and_container_is_kept():
    platform = Platform(count=1)
    workbench = WorkbenchClient("http://workbench", transport=workbench_transport(run_status="failed"))
    operator = AutoOperator(platform, workbench, poll_interval=0.01, solve_timeout=5)

    outcomes = await operator.run(["c-01"])

    assert [row.status for row in outcomes] == ["no_flag"]
    assert ("close", "c-01") not in platform.calls


async def test_workbench_client_raises_on_error_response():
    transport = httpx.MockTransport(lambda request: httpx.Response(409, json={"detail": "Run not found"}))
    client = WorkbenchClient("http://workbench", transport=transport)
    with pytest.raises(WorkbenchError) as excinfo:
        await client.create_task({"objective": "x"})
    assert excinfo.value.status_code == 409


async def test_run_rejects_unknown_codes_before_any_platform_call():
    platform = Platform(count=1)
    workbench = WorkbenchClient("http://workbench", transport=workbench_transport())
    operator = AutoOperator(platform, workbench, poll_interval=0.01, solve_timeout=5)
    with pytest.raises(ValueError, match="不存在题目"):
        await operator.run(["c-99"])
    assert platform.calls == []
