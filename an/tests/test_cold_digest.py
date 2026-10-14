from __future__ import annotations

from sqlalchemy import create_engine, inspect, select

from security_agent.cold_digest import (
    ColdDigestCoverRow,
    ColdDigestGenerationRow,
    ColdDigestRoundRow,
    ColdDigestRow,
    ColdDigestStore,
    DigestGeneration,
    block_signature,
    graph_from_projection,
    group_cold_blocks,
    hot_nodes,
    structural_cold_nodes,
)


def projection(nodes: list[dict], edges: list[tuple[str, str]]) -> dict:
    return {
        "nodes": nodes,
        "edges": [{"source": source, "target": target, "relation": "derived"} for source, target in edges],
    }


def node(node_id: str, kind: str = "fact", state: str = "completed", **extra) -> dict:
    return {"id": node_id, "type": kind, "status": state, "title": node_id, **extra}


def test_hot_set_keeps_live_intent_ancestors_and_children() -> None:
    graph = graph_from_projection(projection([
        node("root", "begin"),
        node("parent", "fact"),
        node("live", "intent", "running"),
        node("child", "fact"),
        node("cold", "fact"),
        node("unsettled", "fact", "open"),
        node("finding", "finding"),
        node("goal", "goal"),
        node("hint", "hint"),
        node("digest", "digest"),
    ], [("root", "parent"), ("parent", "live"), ("live", "child")]))

    hot = hot_nodes(graph)
    assert hot == {"live", "parent", "root", "child"}
    assert structural_cold_nodes(graph, hot) == {"cold"}


def test_grouping_is_deterministic_and_merges_sibling_singletons() -> None:
    graph = graph_from_projection(projection([
        node("anchor", "begin"), node("z", "fact"), node("a", "fact"), node("m", "fact"),
    ], [("anchor", "z"), ("anchor", "a"), ("anchor", "m")]))

    blocks = group_cold_blocks(graph, {"z", "a", "m"}, K=2)
    assert [block.member_ids for block in blocks] == [("a", "m", "z")]
    assert blocks[0].anchor_ids == ("anchor",)
    assert block_signature(blocks[0], {"a": 1, "m": 1, "z": 1}) == block_signature(
        blocks[0], {"z": 1, "a": 1, "m": 1}
    )


def test_deep_graph_and_cycle_do_not_recurse() -> None:
    nodes = [node("n0", "intent", "running")] + [node(f"n{i}") for i in range(1, 1200)]
    edges = [(f"n{i}", f"n{i + 1}") for i in range(1199)] + [("n1199", "n1")]
    graph = graph_from_projection(projection(nodes, edges))
    hot = hot_nodes(graph)
    assert hot == {"n0", "n1"}
    assert "n1199" in structural_cold_nodes(graph, hot)


def test_store_debounces_reuses_and_supersedes_digests() -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    store = ColdDigestStore(engine)
    base = projection([
        node("anchor", "begin", source_refs=["event:anchor"]),
        node("a", source_refs=["event:a"]),
        node("b", source_refs=["event:b"]),
    ], [("anchor", "a"), ("anchor", "b")])

    first = store.compact("run-1", base, R=2, K=2)
    assert first["round_no"] == 1 and first["digests"] == []
    second = store.compact("run-1", base, R=2, K=2)
    assert second["round_no"] == 2 and second["digests"] == []
    third = store.compact("run-1", base, R=2, K=2)
    active = [row for row in third["digests"] if row["status"] == "active"]
    assert len(active) == 1
    digest_id = active[0]["digest_id"]

    reused = store.compact("run-1", base, R=2, K=2)
    assert [row["digest_id"] for row in reused["digests"] if row["status"] == "active"] == [digest_id]

    changed = projection([
        node("anchor", "begin", source_refs=["event:anchor"]),
        node("a", title="changed", source_refs=["event:a"]),
        node("b", source_refs=["event:b"]),
    ], [("anchor", "a"), ("anchor", "b")])
    no_digest = store.compact("run-1", changed, R=2, K=2)
    assert not [row for row in no_digest["digests"] if row["status"] == "active"]
    still_cooling = store.compact("run-1", changed, R=2, K=2)
    assert not [row for row in still_cooling["digests"] if row["status"] == "active"]
    after_change = store.compact("run-1", changed, R=2, K=2)
    new_active = [row for row in after_change["digests"] if row["status"] == "active"]
    assert len(new_active) == 1 and new_active[0]["digest_id"] != digest_id
    assert new_active[0]["member_versions"] == [2, 1]
    assert new_active[0]["source_refs"] == ["event:a", "event:anchor", "event:b"]
    assert any(row["digest_id"] == digest_id and row["status"] == "superseded"
               for row in after_change["digests"])
    assert after_change["R"] == 2 and after_change["K"] == 2

    graph = store.project_graph("run-1", changed)
    digest_nodes = [item for item in graph["nodes"] if item.get("type") == "digest"]
    assert digest_nodes[0]["body"]
    assert {edge["relation"] for edge in graph["edges"] if edge["relation"] == "covers"} == {"covers"}

    with engine.connect() as connection:
        covers = connection.execute(select(ColdDigestCoverRow)).all()
        rows = connection.execute(select(ColdDigestRow)).all()
    assert len(covers) == 2
    assert sum(row.status == "active" for row in rows) == 1


def test_schema_migration_is_explicit_repeatable_and_upgrades_legacy_tables() -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    # Simulate a database produced by the old create_all-only prototype.
    from security_agent.cold_digest import Base

    Base.metadata.create_all(engine)
    ColdDigestStore(engine)
    tables = set(inspect(engine).get_table_names())
    assert {"cold_digest_schema", "cold_digest_rounds", "cold_digest_runs",
            "cold_digest_nodes", "cold_digests", "cold_digest_covers"} <= tables
    # Reopening the store must not create a second schema marker or fail.
    ColdDigestStore(engine)
    with engine.connect() as connection:
        rows = connection.exec_driver_sql("SELECT version FROM cold_digest_schema").all()
    assert rows == [(3,)]
    assert "cold_digest_generations" in tables


def test_round_identity_makes_planner_wakeup_replay_idempotent() -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    store = ColdDigestStore(engine)
    graph = projection([node("anchor", "begin"), node("a"), node("b")], [("anchor", "a"), ("anchor", "b")])

    first = store.compact("run-replay", graph, R=2, K=2, round_id="planner-42")
    replay = store.compact("run-replay", graph, R=2, K=2, round_id="planner-42")
    assert first["round_no"] == replay["round_no"] == 1
    assert replay["round_replayed"] is True
    with engine.connect() as connection:
        rounds = connection.execute(select(ColdDigestRoundRow)).all()
    assert [(row.run_id, row.round_key, row.round_no) for row in rounds] == [("run-replay", "planner-42", 1)]


def test_summary_generator_is_skipped_for_unchanged_active_signature() -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    store = ColdDigestStore(engine)
    graph = projection([node("anchor", "begin"), node("a"), node("b")], [("anchor", "a"), ("anchor", "b")])
    calls: list[str] = []

    def generate(block, nodes, **kwargs):
        calls.append(kwargs["signature"])
        return DigestGeneration("model summary", model_id="mock", usage={"input_tokens": 4, "output_tokens": 2})

    for index in range(3):
        store.compact("run-generator", graph, R=2, K=2, round_id=f"r-{index}", summary_generator=generate)
    store.compact("run-generator", graph, R=2, K=2, round_id="r-3", summary_generator=generate)
    assert len(calls) == 1
    snapshot = store.snapshot("run-generator")
    assert snapshot["generations"][0]["status"] == "generated"
    assert snapshot["generations"][0]["usage"] == {"input_tokens": 4, "output_tokens": 2}


def test_failed_or_empty_summary_keeps_source_nodes_and_records_status() -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    store = ColdDigestStore(engine)
    graph = projection([node("anchor", "begin"), node("a"), node("b")], [("anchor", "a"), ("anchor", "b")])

    def fail(block, nodes, **kwargs):
        raise TimeoutError("mock timeout")

    for index in range(3):
        result = store.compact("run-failure", graph, R=2, K=2, round_id=f"f-{index}", summary_generator=fail)
    assert result["digests"] == []
    assert result["generation_results"][-1]["status"] == "failed"
    assert "TimeoutError" in (result["generation_results"][-1]["error"] or "")
    assert result["nodes"]["a"]["content_version"] == 1
    assert result["nodes"]["b"]["content_version"] == 1
    with engine.connect() as connection:
        rows = connection.execute(select(ColdDigestGenerationRow)).all()
    assert len(rows) == 1 and rows[0].status == "failed"


def test_stale_summary_identity_cannot_create_digest() -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    store = ColdDigestStore(engine)
    graph = projection([node("anchor", "begin"), node("a"), node("b")], [("anchor", "a"), ("anchor", "b")])

    def stale(block, nodes, **kwargs):
        return DigestGeneration("late result", round_id="planner:old", signature=kwargs["signature"])

    for index in range(3):
        result = store.compact("run-stale", graph, R=2, K=2, round_id=f"s-{index}", summary_generator=stale)
    assert result["digests"] == []
    assert result["generation_results"][-1]["status"] == "failed"
    assert "stale" in (result["generation_results"][-1]["error"] or "")

