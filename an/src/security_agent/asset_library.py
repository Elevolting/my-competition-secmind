"""Cross-run asset identities with task-scoped provenance and coverage."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import threading
from collections import defaultdict
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import DateTime, ForeignKey, String, Text, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from security_agent.asset_graph import project_asset_graph
from security_agent.ledger import Base, canonical_json
from security_agent.mcp_scope import validate_target_scope
from security_agent.trace_redaction import redact_trace

NETWORK_KINDS = frozenset({"domain", "ip", "service", "endpoint"})
STATUS_RANK = {"scoped": 0, "referenced": 1, "invoked": 2, "discovered": 3}


class AssetRow(Base):
    __tablename__ = "global_assets"

    asset_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    kind: Mapped[str] = mapped_column(String(20), index=True)
    identity: Mapped[str] = mapped_column(Text)
    label: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RunAssetRow(Base):
    __tablename__ = "run_asset_observations"

    run_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("global_assets.asset_id"), primary_key=True)
    status: Mapped[str] = mapped_column(String(20))
    coverage: Mapped[str] = mapped_column(String(20))
    sources_json: Mapped[str] = mapped_column(Text)
    provenance_json: Mapped[str] = mapped_column(Text)
    finding_ids_json: Mapped[str] = mapped_column(Text)
    scope_hash: Mapped[str] = mapped_column(String(64))
    scope_display_json: Mapped[str] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AssetSyncRow(Base):
    __tablename__ = "run_asset_sync"

    run_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    snapshot_sha256: Mapped[str] = mapped_column(String(64))
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


def asset_identity(kind: str, value: str) -> str | None:
    if kind not in NETWORK_KINDS or not isinstance(value, str):
        return None
    if kind in {"domain", "ip"}:
        raw = value.strip().rstrip(".").lower()
        if not raw:
            return None
        try:
            if kind == "ip":
                return str(ipaddress.ip_address(raw))
            domain = raw.encode("idna").decode("ascii")
            if len(domain) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                        for label in domain.split(".")):
                return None
            return domain
        except (ValueError, UnicodeError):
            return None
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
        if (parsed.scheme.lower() not in {"http", "https"} or not host
                or parsed.username is not None or parsed.password is not None or port == 0):
            return None
        host = asset_identity("ip" if ":" in host else "domain", host)
        if host is None:
            return None
        if ":" in host:
            host = f"[{host}]"
        default_port = 443 if parsed.scheme.lower() == "https" else 80
        netloc = host + (f":{port}" if port and port != default_port else "")
        path = parsed.path or "/"
        if not path.startswith("/"):
            return None
        return urlunsplit((parsed.scheme.lower(), netloc, path if kind == "endpoint" else "", "", ""))
    except (ValueError, UnicodeError):
        return None


def scope_display(values: list[str]) -> list[str]:
    display = []
    for value in values:
        if not isinstance(value, str):
            continue
        if "://" in value:
            try:
                kind = "endpoint" if urlsplit(value).path not in {"", "/"} else "service"
                sanitized = asset_identity(kind, value)
            except ValueError:
                sanitized = None
        else:
            # Preserve domain, IP/CIDR, host:port and local input markers.  URL
            # query values are stripped above; named secrets are redacted below.
            sanitized = value.strip()
        display.append(str(redact_trace(sanitized or "[无效范围]")))
    return display


class AssetLibrary:
    def __init__(self, ledger, operations):
        self.ledger = ledger
        self.operations = operations
        self._sync_lock = threading.RLock()
        for table in (AssetRow.__table__, RunAssetRow.__table__, AssetSyncRow.__table__):
            table.create(ledger.engine, checkfirst=True)

    @staticmethod
    def _asset_id(kind: str, identity: str) -> str:
        return str(uuid5(NAMESPACE_URL, f"secmind-asset:{kind}:{identity}"))

    @staticmethod
    def _link(row: RunAssetRow) -> dict:
        def utc(value: datetime) -> str:
            return (value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)).isoformat()

        return {"run_id": row.run_id, "status": row.status, "coverage": row.coverage,
                "sources": json.loads(row.sources_json), "provenance": json.loads(row.provenance_json),
                "finding_ids": json.loads(row.finding_ids_json), "scope_hash": row.scope_hash,
                "scope_display": json.loads(row.scope_display_json),
                "first_seen": utc(row.first_seen), "last_seen": utc(row.last_seen)}

    def sync_run(self, state, receipts=()) -> None:
        receipts = tuple(receipts)
        with self._sync_lock:
            # A second process can insert the same global identity.  Retry the
            # whole transaction, including autoflush, with a fresh session.
            for attempt in range(3):
                try:
                    self._sync_run(state, receipts)
                    return
                except IntegrityError:
                    if attempt == 2:
                        raise

    def _sync_run(self, state, receipts) -> None:
        receipts = tuple(receipts)
        graph = project_asset_graph(state, receipts)
        scope_hash = hashlib.sha256(canonical_json(state.task.target_scope).encode()).hexdigest()
        display = scope_display(state.task.target_scope)
        findings = defaultdict(list)
        for finding in state.findings:
            try:
                parsed = urlsplit(finding.path)
                kind = "endpoint" if parsed.path not in {"", "/"} or parsed.query else "service"
                validate_target_scope("local-http-fetch", {"url": finding.path}, state.task.target_scope)
            except ValueError:
                continue
            identity = asset_identity(kind, finding.path)
            if identity:
                findings[(kind, identity)].append(finding.finding_id)
        grouped = {}
        for node in graph["nodes"]:
            identity = asset_identity(node["type"], node["label"])
            if identity is None:
                continue
            key = (node["type"], identity)
            if key not in grouped:
                grouped[key] = {"status": node["status"], "sources": [], "provenance": []}
            item = grouped[key]
            item["sources"] = sorted(set([*item["sources"], *node["sources"]]))
            item["provenance"].extend(redact_trace(node["provenance"]))
            item["status"] = max((item["status"], node["status"]), key=lambda value: STATUS_RANK.get(value, -1))
        for key, ids in findings.items():
            item = grouped.setdefault(key, {"status": "referenced", "sources": [], "provenance": []})
            item["status"] = max((item["status"], "referenced"), key=lambda value: STATUS_RANK.get(value, -1))
            item["sources"] = sorted(set([*item["sources"], "finding"]))
            item["provenance"].extend({"source": "finding", "ref": fid} for fid in ids)
        nodes = []
        for (kind, identity), item in sorted(grouped.items()):
            item["provenance"] = sorted(
                {canonical_json(p): p for p in item["provenance"]}.values(), key=canonical_json)
            nodes.append(({"type": kind, **item}, identity))
        finding_snapshot = sorted((kind, identity, sorted(ids)) for (kind, identity), ids in findings.items())
        fingerprint = hashlib.sha256(canonical_json({"nodes": nodes, "scope": scope_hash,
            "findings": finding_snapshot}).encode()).hexdigest()
        now = datetime.now(UTC)
        with Session(self.ledger.engine) as session:
            checkpoint = session.get(AssetSyncRow, state.run_id)
            if checkpoint is not None and checkpoint.snapshot_sha256 == fingerprint:
                return
            for node, identity in nodes:
                kind = node["type"]
                asset_id = self._asset_id(kind, identity)
                asset = session.get(AssetRow, asset_id)
                if asset is None:
                    asset = AssetRow(asset_id=asset_id, kind=kind, identity=identity,
                                     label=str(redact_trace(identity)), created_at=now)
                    session.add(asset)
                link = session.get(RunAssetRow, (state.run_id, asset_id))
                if link is None:
                    link = RunAssetRow(run_id=state.run_id, asset_id=asset_id, first_seen=now)
                    session.add(link)
                previous_sources = json.loads(link.sources_json) if link.sources_json else []
                previous_provenance = json.loads(link.provenance_json) if link.provenance_json else []
                link.sources_json = canonical_json(list(dict.fromkeys([*previous_sources, *node["sources"]])))
                provenance = [*previous_provenance, *node["provenance"]]
                link.provenance_json = canonical_json(
                    list({canonical_json(item): item for item in provenance}.values()))
                previous_findings = json.loads(link.finding_ids_json) if link.finding_ids_json else []
                link.finding_ids_json = canonical_json(sorted(set([*previous_findings,
                                                                   *findings[(kind, identity)]])))
                link.scope_hash, link.scope_display_json = scope_hash, canonical_json(display)
                link.status = max((link.status, node["status"]), key=lambda value: STATUS_RANK.get(value, -1))
                link.coverage = "observed" if "tool" in json.loads(link.sources_json) else "unobserved"
                link.last_seen = now
            if checkpoint is None:
                session.add(AssetSyncRow(run_id=state.run_id, snapshot_sha256=fingerprint, synced_at=now))
            else:
                checkpoint.snapshot_sha256, checkpoint.synced_at = fingerprint, now
            session.commit()

    def sync_all(self) -> None:
        with self._sync_lock:
            receipts = defaultdict(list)
            for _, receipt in self.operations.items("call:"):
                if isinstance(receipt, dict) and isinstance(receipt.get("run_id"), str):
                    receipts[receipt["run_id"]].append(receipt)
            for state in self.ledger.list_states(limit=None):
                self.sync_run(state, receipts[state.run_id])

    def list(self, *, query: str = "", kind: str | None = None, run_id: str | None = None,
             coverage: str | None = None, limit: int = 100, offset: int = 0) -> dict:
        with Session(self.ledger.engine) as session:
            statement = select(AssetRow)
            if query:
                literal = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                statement = statement.where(AssetRow.label.ilike(f"%{literal}%", escape="\\"))
            if kind:
                statement = statement.where(AssetRow.kind == kind)
            if run_id or coverage:
                statement = statement.join(RunAssetRow, RunAssetRow.asset_id == AssetRow.asset_id)
                if run_id:
                    statement = statement.where(RunAssetRow.run_id == run_id)
                if coverage:
                    statement = statement.where(RunAssetRow.coverage == coverage)
                statement = statement.distinct()
            total = session.scalar(select(func.count()).select_from(statement.subquery())) or 0
            rows = session.scalars(statement.order_by(AssetRow.kind, AssetRow.label)
                                   .offset(offset).limit(limit)).all()
            links_by_asset = defaultdict(list)
            if rows:
                for link in session.scalars(select(RunAssetRow).where(
                        RunAssetRow.asset_id.in_([row.asset_id for row in rows]))):
                    links_by_asset[link.asset_id].append(link)
            items = []
            for row in rows:
                links = links_by_asset[row.asset_id]
                items.append({"asset_id": row.asset_id, "kind": row.kind, "label": row.label,
                              "run_count": len(links),
                              "observed_run_count": sum(link.coverage == "observed" for link in links),
                              "finding_count": len({(link.run_id, fid) for link in links
                                                    for fid in json.loads(link.finding_ids_json)})})
            return {"schema_version": "1.0", "assets": items, "total": total}

    def detail(self, asset_id: str) -> dict:
        with Session(self.ledger.engine) as session:
            asset = session.get(AssetRow, asset_id)
            if asset is None:
                raise KeyError(asset_id)
            links = session.scalars(select(RunAssetRow).where(RunAssetRow.asset_id == asset_id)
                                    .order_by(RunAssetRow.last_seen.desc())).all()
            return {"schema_version": "1.0", "asset_id": asset.asset_id,
                    "kind": asset.kind, "label": asset.label,
                    "runs": [self._link(row) for row in links]}
