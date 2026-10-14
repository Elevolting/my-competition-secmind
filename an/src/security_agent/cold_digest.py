"""Cold-node digest planning for the SecMind blackboard.

The module intentionally keeps the graph algorithm independent from the
blackboard transport and from model calls.  ARTEX's digest/covers layer is a
derived view: causal edges are the only edges used for hot/cold decisions.
The durable store records rounds, content versions, digest generations and
the active coverage set so a digest can be inspected or invalidated without
deleting the original facts and evidence.
"""
from __future__ import annotations

import hashlib
import json
import threading
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import uuid4

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint, create_engine, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from security_agent.ledger import Base, canonical_json

DEFAULT_R = 6
DEFAULT_K = 2
FOLDABLE_KINDS = frozenset({"fact", "intent"})
LIVE_STATES = frozenset({"open", "running", "paused"})
SETTLED_STATES = frozenset({
    "blocked", "cancelled", "completed", "exhausted", "failed", "known", "ruled_out", "stopped", "timeout",
})
DERIVED_RELATION = "covers"


class ColdDigestError(ValueError):
    """The graph or compaction parameters cannot be safely processed."""


@dataclass(frozen=True)
class DigestGeneration:
    """The bounded result of one digest summary attempt.

    ``body`` is deliberately kept separate from the durable digest row so an
    empty or failed model response can be recorded without hiding the source
    nodes or creating an unusable digest.
    """

    body: str
    status: str = "generated"
    model_id: str | None = None
    usage: dict[str, int] = field(default_factory=dict)
    error: str | None = None
    round_id: str | None = None
    signature: str | None = None
    generation: int | None = None


class DigestSummaryGenerator(Protocol):
    def __call__(
        self,
        block: DigestBlock,
        nodes: dict[str, GraphNode],
        *,
        run_id: str,
        round_id: str,
        signature: str,
    ) -> DigestGeneration | str: ...


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    kind: str
    state: str
    content_version: int = 1
    source_refs: tuple[str, ...] = ()
    payload: dict[str, Any] = field(default_factory=dict, compare=False)


@dataclass(frozen=True)
class GraphEdge:
    source: str
    relation: str
    target: str


@dataclass(frozen=True)
class DigestBlock:
    member_ids: tuple[str, ...]
    anchor_ids: tuple[str, ...]


@dataclass(frozen=True)
class ColdGraph:
    nodes: dict[str, GraphNode]
    children: dict[str, tuple[str, ...]]
    parents: dict[str, tuple[str, ...]]


class ColdDigestRunRow(Base):
    __tablename__ = "cold_digest_runs"

    run_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    round_no: Mapped[int] = mapped_column(Integer, default=0)
    compaction_R: Mapped[int] = mapped_column(Integer, default=DEFAULT_R)
    compaction_K: Mapped[int] = mapped_column(Integer, default=DEFAULT_K)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ColdDigestSchemaRow(Base):
    """Schema marker maintained by the explicit cold-digest migrator."""

    __tablename__ = "cold_digest_schema"

    schema_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ColdDigestRoundRow(Base):
    """One durable planner wakeup identity for a run."""

    __tablename__ = "cold_digest_rounds"

    run_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    round_key: Mapped[str] = mapped_column(String(200), primary_key=True)
    round_no: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ColdDigestNodeRow(Base):
    __tablename__ = "cold_digest_nodes"
    __table_args__ = (UniqueConstraint("run_id", "node_id", name="uq_cold_digest_node"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(128), index=True)
    node_id: Mapped[str] = mapped_column(String(512), index=True)
    kind: Mapped[str] = mapped_column(String(40))
    state: Mapped[str] = mapped_column(String(40))
    fingerprint: Mapped[str] = mapped_column(String(64))
    content_version: Mapped[int] = mapped_column(Integer, default=1)
    cold_since_round: Mapped[int | None] = mapped_column(Integer, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ColdDigestRow(Base):
    __tablename__ = "cold_digests"

    digest_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(128), index=True)
    signature: Mapped[str] = mapped_column(String(64), index=True)
    body: Mapped[str] = mapped_column(Text)
    member_ids_json: Mapped[str] = mapped_column(Text)
    anchor_ids_json: Mapped[str] = mapped_column(Text)
    member_versions_json: Mapped[str] = mapped_column(Text, default="[]")
    anchor_versions_json: Mapped[str] = mapped_column(Text, default="[]")
    source_refs_json: Mapped[str] = mapped_column(Text, default="[]")
    generation: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(20), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    invalidation_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    generation_status: Mapped[str] = mapped_column(String(30), default="generated")
    generation_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    generation_meta_json: Mapped[str] = mapped_column(Text, default="{}")


class ColdDigestGenerationRow(Base):
    """Durable status for every candidate summary generation attempt."""

    __tablename__ = "cold_digest_generations"
    __table_args__ = (UniqueConstraint("run_id", "round_no", "signature", name="uq_cold_digest_generation"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(128), index=True)
    round_no: Mapped[int] = mapped_column(Integer, index=True)
    round_id: Mapped[str] = mapped_column(String(200))
    signature: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(30))
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    model_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    usage_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ColdDigestCoverRow(Base):
    __tablename__ = "cold_digest_covers"
    __table_args__ = (UniqueConstraint("digest_id", "member_id", name="uq_cold_digest_cover"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    digest_id: Mapped[str] = mapped_column(String(36), index=True)
    run_id: Mapped[str] = mapped_column(String(128), index=True)
    member_id: Mapped[str] = mapped_column(String(512), index=True)


def _kind(node: dict[str, Any]) -> str:
    value = str(node.get("type") or node.get("kind") or "fact").strip().lower()
    return {
        "origin": "begin",
        "goal": "goal",
        "hypothesis": "intent",
        "conclusion": "intent",
        "result": "fact",
    }.get(value, value)


def _state(node: dict[str, Any], kind: str) -> str:
    value = str(node.get("state") or node.get("status") or "completed").strip().lower()
    if kind == "intent":
        return {
            "waiting": "open",
            "approval": "paused",
            "exploring": "running",
        }.get(value, value)
    return value


def _refs(node: dict[str, Any]) -> tuple[str, ...]:
    refs: list[str] = []
    for key in ("source_refs", "source_ids", "evidence_ids"):
        value = node.get(key)
        if isinstance(value, list):
            refs.extend(str(item) for item in value if isinstance(item, (str, int)))
    raw = node.get("raw_id")
    if isinstance(raw, str) and raw:
        refs.append(raw)
    return tuple(dict.fromkeys(refs))


def graph_from_projection(graph: dict[str, Any]) -> ColdGraph:
    """Convert the normalized blackboard projection to the algorithm view."""
    if not isinstance(graph, dict) or not isinstance(graph.get("nodes"), list):
        raise ColdDigestError("黑板图格式无效，无法计算冷节点")
    nodes: dict[str, GraphNode] = {}
    for raw in graph["nodes"]:
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str):
            continue
        node_id = raw["id"]
        kind = _kind(raw)
        if kind == "item":
            continue
        try:
            version = max(1, int(raw.get("content_version") or 1))
        except (TypeError, ValueError):
            version = 1
        nodes[node_id] = GraphNode(node_id, kind, _state(raw, kind), version, _refs(raw), dict(raw))
    children: dict[str, list[str]] = defaultdict(list)
    parents: dict[str, list[str]] = defaultdict(list)
    for raw in graph.get("edges", []):
        if not isinstance(raw, dict):
            continue
        source, target = raw.get("source"), raw.get("target")
        if not isinstance(source, str) or not isinstance(target, str) or source not in nodes or target not in nodes:
            continue
        relation = str(raw.get("relation") or raw.get("type") or "derived")
        if relation == DERIVED_RELATION:
            continue
        if target not in children[source]:
            children[source].append(target)
        if source not in parents[target]:
            parents[target].append(source)
    return ColdGraph(nodes, {key: tuple(value) for key, value in children.items()},
                     {key: tuple(value) for key, value in parents.items()})


def hot_nodes(graph: ColdGraph) -> set[str]:
    """Return live intents, their ancestors and their direct children."""
    hot: set[str] = set()
    stack = [node.node_id for node in graph.nodes.values()
             if node.kind == "intent" and node.state in LIVE_STATES]
    while stack:
        node_id = stack.pop()
        if node_id in hot:
            continue
        hot.add(node_id)
        stack.extend(graph.parents.get(node_id, ()))
    for node in graph.nodes.values():
        if node.kind == "intent" and node.state in LIVE_STATES:
            hot.update(graph.children.get(node.node_id, ()))
    return hot


def structural_cold_nodes(graph: ColdGraph, hot: set[str] | None = None) -> set[str]:
    hot = hot if hot is not None else hot_nodes(graph)
    return {node_id for node_id, node in graph.nodes.items()
            if node.kind in FOLDABLE_KINDS and node.state in SETTLED_STATES and node_id not in hot}


def compute_cold_stamps(
    structural_cold: set[str], previous: dict[str, int | None], round_no: int
) -> dict[str, int | None]:
    """Apply the first-cold-round rule and clear stamps for revived nodes."""
    if round_no < 1:
        raise ColdDigestError("round_no 必须从 1 开始")
    return {node_id: (previous.get(node_id) if previous.get(node_id) is not None else round_no)
            for node_id in structural_cold} | {
                node_id: None for node_id in previous if node_id not in structural_cold
            }


def eligible_cold_nodes(
    structural_cold: set[str], stamps: dict[str, int | None], round_no: int, R: int = DEFAULT_R
) -> set[str]:
    if R < 1:
        raise ColdDigestError("R 必须为正整数")
    eligible: set[str] = set()
    for node_id in structural_cold:
        stamp = stamps.get(node_id)
        if stamp is not None and round_no - stamp >= R:
            eligible.add(node_id)
    return eligible


class _UnionFind:
    def __init__(self, values: Iterable[str]) -> None:
        self.parent = {value: value for value in values}

    def find(self, value: str) -> str:
        while self.parent[value] != value:
            self.parent[value] = self.parent[self.parent[value]]
            value = self.parent[value]
        return value

    def union(self, left: str, right: str) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            self.parent[left_root] = right_root

    def components(self) -> list[list[str]]:
        groups: dict[str, list[str]] = defaultdict(list)
        for value in self.parent:
            groups[self.find(value)].append(value)
        return list(groups.values())


def group_cold_blocks(graph: ColdGraph, cold: set[str], K: int = DEFAULT_K) -> list[DigestBlock]:
    """Group adjacent cold nodes and rescue flat sibling singletons."""
    if K < 2:
        raise ColdDigestError("K 必须至少为 2")
    uf = _UnionFind(cold)
    for source in cold:
        for target in graph.children.get(source, ()):
            if target in cold:
                uf.union(source, target)
    components = uf.components()
    siblings: dict[str, list[str]] = defaultdict(list)
    for component in components:
        if len(component) != 1:
            continue
        member = component[0]
        for parent in graph.parents.get(member, ()):
            if graph.nodes.get(parent, GraphNode(parent, "", "")).kind != "digest":
                siblings[parent].append(member)
    for members in siblings.values():
        if len(members) > 1:
            for member in members[1:]:
                uf.union(members[0], member)
    blocks: list[DigestBlock] = []
    for members in uf.components():
        if len(members) < K:
            continue
        member_ids = tuple(sorted(members))
        member_set = set(member_ids)
        anchors = {
            parent
            for member in member_ids
            for parent in graph.parents.get(member, ())
            if parent not in member_set and graph.nodes.get(parent, GraphNode(parent, "", "")).kind != "digest"
        }
        blocks.append(DigestBlock(member_ids, tuple(sorted(anchors))))
    return sorted(blocks, key=lambda block: block.member_ids[0])


def block_signature(block: DigestBlock, versions: dict[str, int]) -> str:
    hasher = hashlib.sha256()
    for node_id in block.member_ids:
        hasher.update(f"m:{node_id}:{versions.get(node_id, 1)};".encode())
    for node_id in block.anchor_ids:
        hasher.update(f"a:{node_id}:{versions.get(node_id, 1)};".encode())
    return hasher.hexdigest()


def _node_fingerprint(node: GraphNode) -> str:
    # Exclude volatile UI fields and the version itself.  Content/status/source
    # changes are intentional invalidation inputs.
    payload = {key: value for key, value in node.payload.items()
               if key not in {"content_version", "latest_activity", "execution_history"}}
    return hashlib.sha256(
        canonical_json({"kind": node.kind, "state": node.state, "payload": payload}).encode()
    ).hexdigest()


def build_digest_body(block: DigestBlock, nodes: dict[str, GraphNode]) -> str:
    """Deterministic no-model fallback used by offline/API tests."""
    lines = [f"折叠摘要（{len(block.member_ids)} 条记录）"]
    for node_id in block.member_ids:
        node = nodes[node_id]
        payload = node.payload
        title = str(payload.get("title") or payload.get("label") or node_id).strip()
        summary = str(payload.get("summary") or payload.get("description") or "").strip()
        lines.append(f"- {node.kind} {title[:160]}" + (f"：{summary[:320]}" if summary else ""))
    if block.anchor_ids:
        lines.append("上下文锚点：" + "、".join(block.anchor_ids))
    return "\n".join(lines)


def _block_refs(block: DigestBlock, nodes: dict[str, GraphNode]) -> tuple[str, ...]:
    refs = {
        ref
        for node_id in (*block.member_ids, *block.anchor_ids)
        for ref in nodes[node_id].source_refs
    }
    return tuple(sorted(refs))


def _json_ids(value: str) -> tuple[str, ...]:
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return ()
    return tuple(str(item) for item in parsed) if isinstance(parsed, list) else ()


class ColdDigestStore:
    """Durable round, version and digest projection store."""

    def __init__(self, engine_or_url: Any) -> None:
        if isinstance(engine_or_url, str):
            self.engine = create_engine(
                engine_or_url,
                future=True,
                connect_args={"check_same_thread": False} if engine_or_url.startswith("sqlite") else {},
            )
        else:
            self.engine = engine_or_url
        from security_agent.cold_digest_migrations import ensure_cold_digest_schema

        ensure_cold_digest_schema(self.engine)
        self._locks: dict[str, threading.RLock] = {}
        self._locks_guard = threading.Lock()

    def _lock_for(self, run_id: str) -> threading.RLock:
        with self._locks_guard:
            return self._locks.setdefault(run_id, threading.RLock())

    def _rows(self, session: Session, run_id: str) -> dict[str, ColdDigestNodeRow]:
        return {row.node_id: row for row in session.scalars(
            select(ColdDigestNodeRow).where(ColdDigestNodeRow.run_id == run_id)
        ).all()}

    def compact(
        self,
        run_id: str,
        projection: dict[str, Any],
        *,
        R: int = DEFAULT_R,
        K: int = DEFAULT_K,
        round_id: str | None = None,
        summary_builder: Callable[[DigestBlock, dict[str, GraphNode]], str] | None = None,
        summary_generator: DigestSummaryGenerator | None = None,
    ) -> dict[str, Any]:
        if not isinstance(run_id, str) or not run_id.strip():
            raise ColdDigestError("run_id 不能为空")
        if R < 1 or K < 2:
            raise ColdDigestError("R 必须为正整数，K 必须至少为 2")
        if round_id is not None and (not isinstance(round_id, str) or not round_id.strip()):
            raise ColdDigestError("round_id 不能为空字符串")
        graph = graph_from_projection(projection)
        now = datetime.now(UTC)
        effective_round_id = (round_id.strip() if round_id is not None else None) or f"manual:{uuid4()}"
        replayed = False
        with self._lock_for(run_id), Session(self.engine) as session:
            prior_round = session.get(ColdDigestRoundRow, (run_id, effective_round_id))
            if prior_round is not None:
                replayed = True
                snapshot = self.snapshot(run_id)
                snapshot.update({"round_id": effective_round_id, "round_replayed": True})
                return snapshot

            run = session.execute(
                select(ColdDigestRunRow)
                .where(ColdDigestRunRow.run_id == run_id)
                .with_for_update()
            ).scalar_one_or_none()
            # A second process may have inserted the round while the row lock
            # was being acquired.  Recheck after locking the run row before
            # attempting the unique round insert.
            prior_round = session.get(ColdDigestRoundRow, (run_id, effective_round_id))
            if prior_round is not None:
                snapshot = self.snapshot(run_id)
                snapshot.update({"round_id": effective_round_id, "round_replayed": True})
                return snapshot
            if run is None:
                run = ColdDigestRunRow(
                    run_id=run_id,
                    round_no=0,
                    compaction_R=R,
                    compaction_K=K,
                    updated_at=now,
                )
                session.add(run)
                session.flush()
            else:
                run.compaction_R = R
                run.compaction_K = K
            run.round_no += 1
            run.updated_at = now
            round_no = run.round_no
            session.add(ColdDigestRoundRow(
                run_id=run_id,
                round_key=effective_round_id,
                round_no=round_no,
                created_at=now,
            ))
            previous_rows = self._rows(session, run_id)
            rows_by_id = dict(previous_rows)
            versions: dict[str, int] = {}
            stamps: dict[str, int | None] = {}
            for node in graph.nodes.values():
                fingerprint = _node_fingerprint(node)
                row = previous_rows.get(node.node_id)
                if row is None:
                    row = ColdDigestNodeRow(run_id=run_id, node_id=node.node_id, kind=node.kind,
                                            state=node.state, fingerprint=fingerprint, content_version=1,
                                            updated_at=now)
                    session.add(row)
                    rows_by_id[node.node_id] = row
                elif row.fingerprint != fingerprint:
                    row.content_version += 1
                    row.fingerprint = fingerprint
                    row.cold_since_round = None
                    row.kind, row.state = node.kind, node.state
                else:
                    row.kind, row.state = node.kind, node.state
                row.updated_at = now
                versions[node.node_id] = row.content_version
                stamps[node.node_id] = row.cold_since_round
            hot = hot_nodes(graph)
            structural = structural_cold_nodes(graph, hot)
            next_stamps = compute_cold_stamps(structural, stamps, round_no)
            for node_id, stamp in next_stamps.items():
                row = previous_rows.get(node_id)
                if row is None:
                    row = rows_by_id[node_id]
                row.cold_since_round = stamp
            eligible = eligible_cold_nodes(structural, next_stamps, round_no, R)
            blocks = group_cold_blocks(graph, eligible, K)
            active = session.scalars(select(ColdDigestRow).where(
                ColdDigestRow.run_id == run_id, ColdDigestRow.status == "active"
            ).order_by(ColdDigestRow.digest_id)).all()
            active_by_signature = {row.signature: row for row in active}
            used: set[str] = set()
            digest_rows: list[ColdDigestRow] = []
            next_generation = max((row.generation for row in session.scalars(
                select(ColdDigestRow).where(ColdDigestRow.run_id == run_id)
            ).all()), default=0) + 1
            if summary_builder is not None and summary_generator is not None:
                raise ColdDigestError("summary_builder 与 summary_generator 不能同时传入")
            builder = summary_builder
            generation_results: list[dict[str, Any]] = []
            for block in blocks:
                signature = block_signature(block, versions)
                existing = active_by_signature.get(signature)
                if (
                    existing is not None
                    and tuple(_json_ids(existing.member_ids_json)) == block.member_ids
                    and tuple(_json_ids(existing.anchor_ids_json)) == block.anchor_ids
                ):
                    digest = existing
                else:
                    generated = DigestGeneration(
                        body=build_digest_body(block, graph.nodes),
                        status="generated",
                    )
                    if summary_generator is not None:
                        try:
                            candidate = summary_generator(
                                block,
                                graph.nodes,
                                run_id=run_id,
                                round_id=effective_round_id,
                                signature=signature,
                            )
                            generated = candidate if isinstance(candidate, DigestGeneration) else DigestGeneration(
                                body=str(candidate),
                            )
                            if ((generated.round_id is not None and generated.round_id != effective_round_id)
                                    or (generated.signature is not None and generated.signature != signature)
                                    or (generated.generation is not None and generated.generation != next_generation)):
                                generated = DigestGeneration(
                                    body="",
                                    status="failed",
                                    error="stale digest generation identity",
                                    round_id=generated.round_id,
                                    signature=generated.signature,
                                    generation=generated.generation,
                                )
                        except Exception as exc:  # generator failures are durable but non-fatal
                            generated = DigestGeneration(
                                body="",
                                status="failed",
                                error=f"{type(exc).__name__}: {str(exc)[:400]}",
                            )
                    elif builder is not None:
                        try:
                            generated = DigestGeneration(body=str(builder(block, graph.nodes)))
                        except Exception as exc:
                            generated = DigestGeneration(
                                body="",
                                status="failed",
                                error=f"{type(exc).__name__}: {str(exc)[:400]}",
                            )
                    body = generated.body.strip()
                    status = generated.status if generated.status in {"generated", "empty", "failed"} else "failed"
                    if not body and status == "generated":
                        status = "empty"
                    generation_results.append({
                        "signature": signature,
                        "status": status,
                        "model_id": generated.model_id,
                        "usage": generated.usage,
                        "error": generated.error,
                    })
                    session.add(ColdDigestGenerationRow(
                        run_id=run_id,
                        round_no=round_no,
                        round_id=effective_round_id,
                        signature=signature,
                        status=status,
                        error=generated.error,
                        model_id=generated.model_id,
                        usage_json=canonical_json(generated.usage),
                        created_at=now,
                    ))
                    # A failed or empty summary never hides its source records.
                    if status != "generated" or not body:
                        continue
                    digest = ColdDigestRow(
                        digest_id=str(uuid4()), run_id=run_id, signature=signature,
                        body=body,
                        member_ids_json=canonical_json(list(block.member_ids)),
                        anchor_ids_json=canonical_json(list(block.anchor_ids)),
                        member_versions_json=canonical_json([versions[node_id] for node_id in block.member_ids]),
                        anchor_versions_json=canonical_json([versions.get(node_id, 1) for node_id in block.anchor_ids]),
                        source_refs_json=canonical_json(list(_block_refs(block, graph.nodes))),
                        generation=next_generation, status="active", created_at=now,
                        generation_status=status,
                        generation_error=generated.error,
                        generation_meta_json=canonical_json({
                            "model_id": generated.model_id,
                            "usage": generated.usage,
                        }),
                    )
                    next_generation += 1
                    session.add(digest)
                    session.flush()
                    for member_id in block.member_ids:
                        session.add(ColdDigestCoverRow(digest_id=digest.digest_id, run_id=run_id, member_id=member_id))
                used.add(digest.digest_id)
                digest_rows.append(digest)
            for old in active:
                if old.digest_id in used:
                    continue
                old.status = "superseded"
                old.superseded_at = now
                old.invalidation_reason = "active block changed or became hot"
                session.query(ColdDigestCoverRow).filter(ColdDigestCoverRow.digest_id == old.digest_id).delete()
            session.commit()
        snapshot = self.snapshot(run_id)
        snapshot.update({"round_id": effective_round_id, "round_replayed": replayed})
        if generation_results:
            snapshot["generation_results"] = generation_results
        return snapshot

    def snapshot(self, run_id: str) -> dict[str, Any]:
        with Session(self.engine) as session:
            run = session.get(ColdDigestRunRow, run_id)
            rows = session.scalars(select(ColdDigestRow).where(ColdDigestRow.run_id == run_id)
                                  .order_by(ColdDigestRow.generation, ColdDigestRow.digest_id)).all()
            nodes = self._rows(session, run_id)
            return {
                "schema_version": "1.0",
                "run_id": run_id,
                "round_no": run.round_no if run else 0,
                "R": run.compaction_R if run else DEFAULT_R,
                "K": run.compaction_K if run else DEFAULT_K,
                "rounds": [
                    {"round_id": row.round_key, "round_no": row.round_no, "created_at": row.created_at.isoformat()}
                    for row in session.scalars(
                        select(ColdDigestRoundRow)
                        .where(ColdDigestRoundRow.run_id == run_id)
                        .order_by(ColdDigestRoundRow.round_no)
                    ).all()
                ],
                "generations": [
                    {
                        "round_no": row.round_no,
                        "round_id": row.round_id,
                        "signature": row.signature,
                        "status": row.status,
                        "error": row.error,
                        "model_id": row.model_id,
                        "usage": json.loads(row.usage_json or "{}"),
                        "created_at": row.created_at.isoformat(),
                    }
                    for row in session.scalars(
                        select(ColdDigestGenerationRow)
                        .where(ColdDigestGenerationRow.run_id == run_id)
                        .order_by(ColdDigestGenerationRow.round_no, ColdDigestGenerationRow.id)
                    ).all()
                ],
                "nodes": {
                    key: {"content_version": row.content_version, "cold_since_round": row.cold_since_round,
                          "kind": row.kind, "state": row.state}
                    for key, row in nodes.items()
                },
                "digests": [self._digest_json(row, session) for row in rows],
            }

    @staticmethod
    def _digest_json(row: ColdDigestRow, session: Session) -> dict[str, Any]:
        members = list(_json_ids(row.member_ids_json))
        anchors = list(_json_ids(row.anchor_ids_json))
        return {"digest_id": row.digest_id, "status": row.status, "signature": row.signature,
                "body": row.body, "member_ids": members, "anchor_ids": anchors,
                "member_versions": list(json.loads(row.member_versions_json or "[]")),
                "anchor_versions": list(json.loads(row.anchor_versions_json or "[]")),
                "source_refs": list(json.loads(row.source_refs_json or "[]")),
                "generation": row.generation, "created_at": row.created_at.isoformat(),
                "superseded_at": row.superseded_at.isoformat() if row.superseded_at else None,
                "invalidation_reason": row.invalidation_reason,
                "generation_status": row.generation_status,
                "generation_error": row.generation_error,
                "generation_meta": json.loads(row.generation_meta_json or "{}"),
                }

    def project_graph(self, run_id: str, projection: dict[str, Any]) -> dict[str, Any]:
        result = json.loads(json.dumps(projection, ensure_ascii=False))
        with Session(self.engine) as session:
            active = session.scalars(select(ColdDigestRow).where(
                ColdDigestRow.run_id == run_id, ColdDigestRow.status == "active"
            ).order_by(ColdDigestRow.generation, ColdDigestRow.digest_id)).all()
            node_rows = self._rows(session, run_id)
            covered: dict[str, str] = {}
            for row in active:
                for member_id in _json_ids(row.member_ids_json):
                    covered.setdefault(member_id, row.digest_id)
                result.setdefault("nodes", []).append({
                    "id": f"digest:{row.digest_id}", "raw_id": row.digest_id, "type": "digest",
                    "title": f"摘要 #{row.generation}", "label": f"摘要 #{row.generation}",
                    "body": row.body, "description": row.body, "summary": row.body, "status": "active",
                    "digest_id": row.digest_id, "signature": row.signature,
                    "member_ids": list(_json_ids(row.member_ids_json)),
                    "anchor_ids": list(_json_ids(row.anchor_ids_json)),
                    "member_versions": list(json.loads(row.member_versions_json or "[]")),
                    "anchor_versions": list(json.loads(row.anchor_versions_json or "[]")),
                    "source_refs": list(json.loads(row.source_refs_json or "[]")),
                    "generation": row.generation, "created_at": row.created_at.isoformat(),
                })
                for member_id in _json_ids(row.member_ids_json):
                    result.setdefault("edges", []).append({
                        "id": f"covers:{row.digest_id}:{member_id}",
                        "source": f"digest:{row.digest_id}", "target": member_id,
                        "type": "covers", "relation": DERIVED_RELATION, "status": "active",
                    })
            for node in result.get("nodes", []):
                if isinstance(node, dict) and isinstance(node.get("id"), str):
                    node_row = node_rows.get(node["id"])
                    if node_row:
                        node["content_version"] = node_row.content_version
                        node["cold_since_round"] = node_row.cold_since_round
                        if node["id"] in covered:
                            node["covered_by_digest"] = covered[node["id"]]
            result["cold_digest"] = self.snapshot(run_id)
            result["digest_covered_nodes"] = covered
        return result
