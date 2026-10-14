from __future__ import annotations

from sqlalchemy import create_engine, select

from security_agent.cold_digest import (
    ColdDigestCoverRow,
    ColdDigestRow,
    ColdDigestStore,
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

