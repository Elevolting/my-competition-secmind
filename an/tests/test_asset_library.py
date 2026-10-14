from __future__ import annotations

import httpx
import pytest
from sqlalchemy import event

from security_agent.api import create_app
from security_agent.asset_library import AssetLibrary, asset_identity, scope_display
from security_agent.schemas import AgentState, Finding, TaskRequest, ToolResult, ToolStatus


async def test_assets_deduplicate_across_runs_without_merging_scope_or_coverage(settings):
    app = create_app(settings)
    ledger = app.state.service.ledger
    first = AgentState(run_id="asset-run-one", task=TaskRequest(
        objective="Inspect login", target_scope=["https://lab.test/app"]),
        observations=[ToolResult(status=ToolStatus.SUCCESS, data={"call_id": "probe-1", "coverage": {
            "endpoints": ["https://lab.test/app/login?session=secret-value"]}})],
        findings=[Finding(finding_id="finding-1", rule_id="TEST", path="https://lab.test/app/login",
                          title="Login issue", description="Observed")])
    second = AgentState(run_id="asset-run-two", task=TaskRequest(
        objective="Inspect login separately", target_scope=["https://lab.test/app/login?token=second-secret"]),
        observations=[ToolResult(status=ToolStatus.ERROR, data={"coverage": {
            "endpoints": ["https://lab.test/app/login"]}})])
    ledger.save_state(first)
    ledger.save_state(second)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        listing = await client.get("/api/v1/assets", params={"kind": "endpoint", "search": "login"})
        assert listing.status_code == 200, listing.text
        assert listing.json()["total"] == 1
        asset = listing.json()["assets"][0]
        assert asset["label"] == "https://lab.test/app/login"
        assert asset["run_count"] == 2
        assert asset["observed_run_count"] == 1
        assert asset["finding_count"] == 1
        detail = await client.get(f"/api/v1/assets/{asset['asset_id']}")
        assert detail.status_code == 200, detail.text
        runs = {item["run_id"]: item for item in detail.json()["runs"]}
        assert runs["asset-run-one"]["coverage"] == "observed"
        assert runs["asset-run-one"]["finding_ids"] == ["finding-1"]
        assert runs["asset-run-two"]["coverage"] == "unobserved"
        assert runs["asset-run-one"]["scope_hash"] != runs["asset-run-two"]["scope_hash"]
        assert runs["asset-run-one"]["scope_display"] == ["https://lab.test/app"]
        assert runs["asset-run-two"]["scope_display"] == ["https://lab.test/app/login"]
        assert "secret" not in str(detail.json())
        again = await client.get("/api/v1/assets", params={"kind": "endpoint", "search": "login"})
        assert again.json() == listing.json()
        only_first = await client.get("/api/v1/assets", params={"run_id": "asset-run-one", "coverage": "observed"})
        assert any(item["asset_id"] == asset["asset_id"] for item in only_first.json()["assets"])
        assert (await client.get("/api/v1/assets/missing")).status_code == 404


@pytest.mark.parametrize(("kind", "value", "expected"), [
    ("endpoint", "HTTPS://Lab.Test:443/app?token=secret#fragment", "https://lab.test/app"),
    ("service", "http://LAB.test:80/app?key=value", "http://lab.test"),
    ("endpoint", "https://[2001:db8::1]:8443/", "https://[2001:db8::1]:8443/"),
    ("ip", "2001:0db8::1", "2001:db8::1"),
    ("domain", "LAB.test.", "lab.test"),
    ("endpoint", "https://user:password@lab.test/app", None),
    ("endpoint", "https://@lab.test/app", None),
    ("endpoint", "https://lab.test:0/app", None),
    ("endpoint", "file:///private/file", None),
    ("endpoint", "https://bad host/app", None),
    ("domain", "bad/path.test", None),
    ("artifact", "sample.txt", None),
])
def test_asset_identity_is_canonical_and_drops_query_values(kind, value, expected):
    assert asset_identity(kind, value) == expected


def test_scope_display_preserves_non_url_ranges_without_exposing_query_secrets():
    assert scope_display(["lab.test", "192.0.2.0/24", "127.0.0.1:8001", "uploaded-source",
                          "https://lab.test/app?api_key=hidden", "token=hidden"]) == [
        "lab.test", "192.0.2.0/24", "127.0.0.1:8001", "uploaded-source",
        "https://lab.test/app", "token=[REDACTED]",
    ]


def test_success_history_survives_later_failures_and_library_recreation(settings):
    app = create_app(settings)
    library = app.state.asset_library
    state = AgentState(run_id="history", task=TaskRequest(
        objective="Inspect fixture", target_scope=["https://lab.test/app"]), observations=[
            ToolResult(status=ToolStatus.SUCCESS, data={"call_id": "proof-1", "coverage": {
                "endpoints": ["https://lab.test/app/login?a=one", "https://lab.test/app/login?a=two"]}})])
    library.sync_run(state)
    asset = library.list(kind="endpoint", query="login")["assets"][0]
    original = library.detail(asset["asset_id"])
    library.sync_run(state)
    assert library.detail(asset["asset_id"]) == original
    later = state.model_copy(deep=True)
    later.observations = [ToolResult(status=ToolStatus.ERROR, data={"coverage": {
        "endpoints": ["https://lab.test/app/failed"]}})]
    library.sync_run(later)
    restored = AssetLibrary(library.ledger, library.operations)
    link = restored.detail(asset["asset_id"])["runs"][0]
    assert link["coverage"] == "observed"
    assert link["status"] == "discovered"
    assert link["first_seen"] == original["runs"][0]["first_seen"]
    assert link["first_seen"].endswith("+00:00")
    assert link["provenance"] == original["runs"][0]["provenance"]
    assert restored.list(query="failed")["total"] == 0
    assert restored.list(kind="endpoint", query="login")["total"] == 1


def test_invocations_and_failed_or_foreign_receipts_do_not_claim_coverage(settings):
    library = create_app(settings).state.asset_library
    state = AgentState(run_id="receipt-run", task=TaskRequest(
        objective="Inspect fixture", target_scope=["https://lab.test/app"]))
    library.sync_run(state, [
        {"run_id": state.run_id, "status": "completed", "call_id": "invoked",
         "arguments": {"url": "https://lab.test/app/login"}, "result": {}},
        {"run_id": state.run_id, "status": "failed", "call_id": "failed",
         "result": {"structuredContent": {"coverage": {"endpoints": ["https://lab.test/app/failed"]}}}},
        {"run_id": "foreign", "status": "completed", "call_id": "foreign",
         "result": {"structuredContent": {"coverage": {"endpoints": ["https://lab.test/app/foreign"]}}}},
        {"run_id": state.run_id, "status": "completed", "call_id": "observed",
         "result": {"structuredContent": {"coverage": {"endpoints": [
             "https://lab.test/app/observed", "https://elsewhere.test/outside"]}}}},
    ])
    invoked = library.list(query="login")["assets"][0]
    link = library.detail(invoked["asset_id"])["runs"][0]
    assert (link["status"], link["coverage"]) == ("invoked", "unobserved")
    assert library.list(kind="endpoint")["total"] == 3  # scope, invoked, observed
    assert library.list(query="outside")["total"] == 0
    assert library.list(query="failed")["total"] == 0
    assert library.list(query="foreign")["total"] == 0


def test_finding_upgrades_scoped_status_without_claiming_success(settings):
    library = create_app(settings).state.asset_library
    state = AgentState(run_id="scoped-finding", task=TaskRequest(
        objective="Inspect fixture", target_scope=["https://lab.test/app"]), findings=[
            Finding(finding_id="scope-finding", rule_id="TEST", path="https://lab.test/app",
                    title="Reference", description="Requires verification")])
    library.sync_run(state)
    asset = library.list(kind="endpoint")["assets"][0]
    link = library.detail(asset["asset_id"])["runs"][0]
    assert (link["status"], link["coverage"]) == ("referenced", "unobserved")
    assert set(link["sources"]) == {"scope", "finding"}
    assert link["finding_ids"] == ["scope-finding"]


async def test_finding_association_is_exact_task_scoped_and_not_coverage(settings):
    app = create_app(settings)
    for run_id in ("one", "two"):
        app.state.service.ledger.save_state(AgentState(run_id=run_id, task=TaskRequest(
            objective="Inspect fixture", target_scope=["https://lab.test/app"]), findings=[
                Finding(finding_id="same-local-id", rule_id="TEST", path="https://lab.test/app/login?token=hidden",
                        title="Login", description="A reference"),
                Finding(finding_id="outside", rule_id="TEST", path="https://other.test/app/login",
                        title="Outside", description="Outside scope"),
                Finding(finding_id="code-only", rule_id="TEST", path="src/auth.py",
                        title="Code", description="Non-network finding"),
            ]))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.get("/api/v1/assets", params={"kind": "endpoint", "search": "login"})
        asset = response.json()["assets"][0]
        assert asset["finding_count"] == 2
        assert asset["observed_run_count"] == 0
        assert (await client.get("/api/v1/assets", params={"search": "other.test"})).json()["total"] == 0
        detail = (await client.get(f"/api/v1/assets/{asset['asset_id']}")).json()
        assert all(run["finding_ids"] == ["same-local-id"] for run in detail["runs"])
        assert "hidden" not in str(detail)
        for params in ({"limit": 0}, {"offset": -1}, {"kind": "invalid"}, {"coverage": "tested"}):
            assert (await client.get("/api/v1/assets", params=params)).status_code == 422
        assert (await client.get("/api/v1/assets", params={"search": "%"})).json()["total"] == 0
        assert (await client.get("/api/v1/assets", params={"search": "_"})).json()["total"] == 0
        assert (await client.get("/api/v1/assets", params={"limit": 1, "offset": 100})).json()["assets"] == []
        filtered = await client.get("/api/v1/assets", params={"run_id": "one", "coverage": "observed"})
        assert filtered.json()["total"] == 0


def test_concurrent_sync_retries_autoflush_conflicts_and_keeps_each_task(settings):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier, local

    app = create_app(settings)
    original = app.state.asset_library
    libraries = [original, AssetLibrary(original.ledger, original.operations)]
    barrier = Barrier(2)
    thread = local()

    def rendezvous(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO global_assets") and not getattr(thread, "met", False):
            thread.met = True
            barrier.wait(timeout=10)

    states = [AgentState(run_id=f"concurrent-{index}", task=TaskRequest(
        objective="Inspect fixture", target_scope=["https://lab.test/app"])) for index in range(2)]
    event.listen(original.ledger.engine, "before_cursor_execute", rendezvous)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(library.sync_run, state)
                       for library, state in zip(libraries, states, strict=True)]
            for future in futures:
                future.result(timeout=20)
    finally:
        event.remove(original.ledger.engine, "before_cursor_execute", rendezvous)
    listing = original.list()
    assert listing["total"] == 3
    assert all(item["run_count"] == 2 for item in listing["assets"])
    for state in states:
        original.ledger.save_state(state)
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(original.sync_all) for _ in range(8)]
        for future in futures:
            future.result(timeout=20)
    assert original.list() == listing
