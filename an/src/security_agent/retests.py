"""Durable source snapshots and lifecycle records for focused retests."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from uuid import NAMESPACE_URL, uuid4, uuid5

from sqlalchemy import DateTime, String, Text, and_, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from security_agent.ingest import InputIngestor, sha256_file
from security_agent.ledger import Base, canonical_json
from security_agent.schemas import AgentState, AttachmentRef, RunStatus, TaskRequest, ToolStatus
from security_agent.trace_redaction import redact_trace

CONCLUSION_SECTIONS = frozenset({
    "executive_summary", "verified_outputs", "ruled_out_directions",
    "insufficient_evidence", "worker_reports", "limitations",
})
ACTIVE_STATUSES = frozenset({"pending", "dispatching", "running", "awaiting_result"})
DISPATCH_LEASE = timedelta(minutes=5)
SOURCE_STATUSES = frozenset({RunStatus.COMPLETED, RunStatus.PARTIAL, RunStatus.FAILED, RunStatus.DENIED})
RESULT_RULES = {
    "penetration": {"reproduced": {"proof"}, "fixed": {"trigger", "baseline", "conditions"}},
    "code_audit": {"reproduced": {"validation"}, "fixed": {"path_coverage", "validation"}},
    "reverse": {"supported": {"verification"}, "refuted": {"verification"}},
    "log_analysis": {"supported": {"verification", "material_scope"},
                     "refuted": {"verification", "material_scope"}},
    "incident_response": {"supported": {"verification", "material_scope"},
                          "refuted": {"verification", "material_scope"}},
}


def validate_retest_evidence(child: AgentState, evidence_ids: list[str], ledger) -> None:
    """Resolve each reference to current execution output, then check artifact hashes."""
    evidence = {item.evidence_id: item for item in child.evidence}
    produced = {item.evidence_id for result in child.observations if result.status == ToolStatus.SUCCESS
                for item in result.evidence}
    events = ledger.events(child.run_id, limit=1_000_000)
    for event in events:
        if event.event_type == "mcp.call.completed":
            call_id = event.payload.get("call_id")
            for item in child.evidence:
                receipt = item.metadata.get("receipt", {})
                if (call_id and (item.evidence_id == call_id or item.metadata.get("call_id") == call_id)
                        and (not receipt or receipt.get("status") == "completed")):
                    produced.add(item.evidence_id)
        elif event.event_type == "tool.completed":
            result = event.payload.get("result", {})
            if isinstance(result, dict) and result.get("status") == "success":
                produced.update(item.get("evidence_id") for item in result.get("evidence", [])
                                if isinstance(item, dict))
        elif event.event_type == "traffic.evidence.created":
            produced.add(event.payload.get("evidence_id"))
    workspace = Path(child.workspace).resolve() if child.workspace else None
    for eid in evidence_ids:
        item = evidence.get(eid)
        if item is None or eid not in produced:
            raise ValueError("证据没有本次成功执行的来源回执")
        if item.artifact_ref:
            if workspace is None:
                raise ValueError("本次证据工作区无效")
            candidate = Path(item.artifact_ref)
            path = candidate if candidate.is_absolute() else workspace / candidate
            if (path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(workspace.parent)
                    or not item.sha256 or sha256_file(path) != item.sha256):
                raise ValueError("本次证据文件缺失、越界或校验失败")


class RetestRow(Base):
    __tablename__ = "run_retests"

    retest_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source_run_id: Mapped[str] = mapped_column(String(100), index=True)
    source_kind: Mapped[str] = mapped_column(String(20))
    source_ref: Mapped[str] = mapped_column(Text)
    active_key: Mapped[str | None] = mapped_column(String(64), unique=True)
    child_run_id: Mapped[str] = mapped_column(String(36), unique=True)
    request_json: Mapped[str] = mapped_column(Text)
    snapshot_json: Mapped[str] = mapped_column(Text)
    snapshot_sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(30))
    verdict: Mapped[str | None] = mapped_column(String(30))
    summary: Mapped[str | None] = mapped_column(Text)
    evidence_json: Mapped[str] = mapped_column(Text, default="[]")
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


def source_snapshot(state: AgentState, kind: str, reference: str) -> dict:
    if state.status not in SOURCE_STATUSES or state.report is None:
        raise ValueError("来源任务尚未生成可复核的历史报告")
    if kind == "finding":
        item = next((finding for finding in state.findings if finding.finding_id == reference), None)
        if item is None:
            raise KeyError(reference)
        original = item.model_dump(mode="json")
        evidence_ids = set(item.evidence_ids)
    elif kind == "conclusion":
        try:
            section, offset, expected_hash = reference.split(":", 2)
            index = int(offset)
        except (ValueError, AttributeError) as exc:
            raise ValueError("报告结论引用无效") from exc
        if section not in CONCLUSION_SECTIONS or index < 0:
            raise ValueError("报告结论引用无效")
        values = ([state.report.executive_summary] if section == "executive_summary"
                  else getattr(state.report, section))
        if index >= len(values):
            raise KeyError(reference)
        value = values[index]
        digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()
        if expected_hash != digest:
            raise ValueError("报告结论已变化，请刷新后重新选择")
        original = {"section": section, "index": index, "text": value}
        evidence_ids = {item.evidence_id for item in state.report.evidence}
    else:
        raise ValueError("复核来源类型无效")
    evidence = [item.model_dump(mode="json") for item in state.evidence if item.evidence_id in evidence_ids]
    return redact_trace({
        "source_run_id": state.run_id, "source_kind": kind, "source_ref": reference,
        "module_route": state.module_route, "scenario": state.scenario.value,
        "original": original, "evidence": evidence,
        "target_scope": state.task.target_scope, "constraints": state.task.constraints,
        "network_policy": state.task.network_policy,
        "input_artifacts": [item.model_dump(mode="json") for item in state.input_artifacts],
        "report_generated_at": state.report.generated_at.isoformat(),
    })


def prepare_retest_task(source: AgentState, record: dict, settings, notes: str,
                        new_attachments: list[AttachmentRef]) -> TaskRequest:
    if source.module_route not in {*RESULT_RULES, "audit"}:
        raise ValueError("来源模块尚不支持独立复核")
    if source.task.network_policy == "scoped_file_post":
        raise ValueError("原任务的单次 POST 授权不能自动用于复核")
    attachments = []
    if source.input_artifacts:
        ingestor = InputIngestor(settings)
        workspace = ingestor._workspace_for_run(source.run_id)
        if not source.workspace or Path(source.workspace).resolve() != workspace:
            raise ValueError("原任务输入工作区无效")
        stage_root = settings.input_root / ".retests"
        if stage_root.exists() and (stage_root.is_symlink() or
                                    hasattr(stage_root, "is_junction") and stage_root.is_junction()):
            raise ValueError("复核材料暂存目录无效")
        stage_root.mkdir(parents=True, exist_ok=True)
        target = stage_root / record["retest_id"]
        if target.is_symlink() or (hasattr(target, "is_junction") and target.is_junction()):
            raise ValueError("复核材料暂存目录无效")
        staging = stage_root / ("." + record["retest_id"] + "." + uuid4().hex)
        try:
            if not target.exists():
                staging.mkdir()
            for item in source.input_artifacts:
                relative = PurePosixPath(item.relative_path)
                if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
                    raise ValueError("原任务材料路径无效")
                origin = workspace.joinpath(*relative.parts)
                if origin.is_symlink() or not origin.is_file() or not origin.resolve().is_relative_to(workspace):
                    raise ValueError("原任务材料缺失或路径无效")
                if origin.stat().st_size != item.size_bytes or sha256_file(origin) != item.sha256:
                    raise ValueError("原任务材料校验失败")
                if target.exists():
                    copied = target.joinpath(*relative.parts)
                    if copied.is_symlink() or not copied.is_file() or sha256_file(copied) != item.sha256:
                        raise ValueError("复核材料暂存校验失败")
                else:
                    copied = staging.joinpath(*relative.parts)
                    copied.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(origin, copied)
                    if sha256_file(copied) != item.sha256:
                        raise ValueError("复核材料复制校验失败")
            if not target.exists():
                os.replace(staging, target)
        finally:
            if staging.exists():
                shutil.rmtree(staging)
        attachments.append(AttachmentRef(ref=str(target)))
    for attachment in new_attachments:
        if Path(attachment.ref).name != attachment.ref:
            raise ValueError("复核新材料必须使用上传引用")
        upload = settings.upload_root / attachment.ref
        if upload.is_symlink() or not upload.is_file():
            raise ValueError("复核新材料不存在")
        attachments.append(attachment)
    original = record["snapshot"]["original"]
    title = original.get("title") or original.get("text") or "报告结论"
    focus = (f"发现 {record['source_ref']}：{title}" if record["source_kind"] == "finding"
             else f"报告结论：{title}")
    task = source.task.model_copy(deep=True)
    task.name = ("独立复核 · " + str(title))[:120]
    task.objective = (
        f"仅复核原任务 {source.run_id} 中的单一对象。{focus}\n"
        f"原任务目标：{source.task.objective}\n"
        "只针对原触发条件执行最小验证，采集本次证据及可比正常对照。"
        "不可把历史证据当作本次结果；无法满足证据门槛时说明原因。"
    )[:10_000]
    task.constraints = [*source.task.constraints,
        f"独立复核限定为 {record['source_kind']}:{record['source_ref']}；不得扩展原授权范围或全量重扫。"]
    if notes.strip():
        task.constraints.append("本次补充说明：" + str(redact_trace(notes.strip()))[:2000])
    task.attachments = attachments
    return TaskRequest.model_validate(task.model_dump(mode="json"))


class RetestStore:
    def __init__(self, ledger):
        self.ledger = ledger
        RetestRow.__table__.create(ledger.engine, checkfirst=True)

    @staticmethod
    def _public(row: RetestRow, *, with_snapshot: bool = False) -> dict:
        saved_evidence = json.loads(row.evidence_json)
        snapshot = json.loads(row.snapshot_json)
        result = {
            "retest_id": row.retest_id, "source_run_id": row.source_run_id,
            "source_kind": row.source_kind, "source_ref": row.source_ref,
            "child_run_id": row.child_run_id, "snapshot_sha256": row.snapshot_sha256,
            "status": row.status, "verdict": row.verdict, "summary": row.summary,
            "evidence_ids": saved_evidence.get("ids", []) if isinstance(saved_evidence, dict) else saved_evidence,
            "checks": saved_evidence.get("checks", {}) if isinstance(saved_evidence, dict) else {},
            "original_evidence_ids": [item["evidence_id"] for item in snapshot["evidence"]],
            "error": row.error,
            "created_at": row.created_at.isoformat(),
            "started_at": row.started_at.isoformat() if row.started_at else None,
            "finished_at": row.finished_at.isoformat() if row.finished_at else None,
        }
        if with_snapshot:
            result["snapshot"] = snapshot
        return result

    def reserve(self, state: AgentState, kind: str, reference: str,
                request_id: str, parameters: dict) -> tuple[dict, bool]:
        retest_id = str(uuid5(NAMESPACE_URL, f"retest:{state.run_id}:{request_id}"))
        child_run_id = str(uuid5(NAMESPACE_URL, f"retest-child:{retest_id}"))
        active_key = hashlib.sha256(canonical_json([state.run_id, kind, reference]).encode()).hexdigest()
        request_json = canonical_json(parameters)
        with Session(self.ledger.engine) as session:
            existing = session.get(RetestRow, retest_id)
            if existing is not None:
                if (existing.source_run_id, existing.source_kind, existing.source_ref, existing.request_json) != (
                    state.run_id, kind, reference, request_json
                ):
                    raise ValueError("复核请求编号已用于不同的来源或参数")
                return self._public(existing, with_snapshot=True), False
            active = session.scalar(select(RetestRow).where(RetestRow.active_key == active_key))
            if active is not None:
                return self._public(active, with_snapshot=True), False
            snapshot_json = canonical_json(source_snapshot(state, kind, reference))
            snapshot_hash = hashlib.sha256(snapshot_json.encode()).hexdigest()
            row = RetestRow(
                retest_id=retest_id, source_run_id=state.run_id, source_kind=kind, source_ref=reference,
                active_key=active_key, child_run_id=child_run_id, request_json=request_json,
                snapshot_json=snapshot_json, snapshot_sha256=snapshot_hash, status="pending",
                evidence_json="[]", created_at=datetime.now(UTC),
            )
            session.add(row)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                existing = session.get(RetestRow, retest_id)
                if existing is not None:
                    if (existing.source_run_id, existing.source_kind, existing.source_ref, existing.request_json) != (
                        state.run_id, kind, reference, request_json
                    ):
                        raise ValueError("复核请求编号已用于不同的来源或参数") from None
                    return self._public(existing, with_snapshot=True), False
                active = session.scalar(select(RetestRow).where(RetestRow.active_key == active_key))
                if active is None:
                    raise
                return self._public(active, with_snapshot=True), False
            return self._public(row, with_snapshot=True), True

    def get(self, source_run_id: str, retest_id: str) -> dict:
        with Session(self.ledger.engine) as session:
            row = session.get(RetestRow, retest_id)
            if row is None or row.source_run_id != source_run_id:
                raise KeyError(retest_id)
            return self._public(row, with_snapshot=True)

    def list(self, source_run_id: str) -> list[dict]:
        with Session(self.ledger.engine) as session:
            rows = session.scalars(select(RetestRow).where(RetestRow.source_run_id == source_run_id)
                                   .order_by(RetestRow.created_at.desc())).all()
            return [self._public(row) for row in rows]

    def dispatchable(self) -> list[dict]:
        cutoff = datetime.now(UTC) - DISPATCH_LEASE
        with Session(self.ledger.engine) as session:
            rows = session.scalars(select(RetestRow).where(or_(
                RetestRow.status == "pending",
                and_(RetestRow.status == "dispatching", RetestRow.started_at < cutoff),
            ))).all()
            return [self._public(row, with_snapshot=True) for row in rows]

    def dispatching(self) -> list[dict]:
        with Session(self.ledger.engine) as session:
            rows = session.scalars(select(RetestRow).where(RetestRow.status == "dispatching")).all()
            return [self._public(row) for row in rows]

    def claim_dispatch(self, retest_id: str) -> bool:
        now = datetime.now(UTC)
        with Session(self.ledger.engine) as session:
            result = session.execute(update(RetestRow).where(
                RetestRow.retest_id == retest_id,
                or_(RetestRow.status == "pending",
                    and_(RetestRow.status == "dispatching",
                         RetestRow.started_at < now - DISPATCH_LEASE)),
            ).values(status="dispatching", started_at=now))
            session.commit()
            return result.rowcount == 1

    def parameters(self, retest_id: str) -> dict:
        with Session(self.ledger.engine) as session:
            row = session.get(RetestRow, retest_id)
            if row is None:
                raise KeyError(retest_id)
            return json.loads(row.request_json)

    def set_status(self, retest_id: str, status: str, error: str | None = None) -> dict:
        if status not in {"running", "awaiting_result", "failed", "stopped"}:
            raise ValueError("复核状态无效")
        with Session(self.ledger.engine) as session:
            row = session.get(RetestRow, retest_id)
            if row is None:
                raise KeyError(retest_id)
            if row.status not in ACTIVE_STATUSES:
                return self._public(row)
            transitions = {
                "pending": {"running", "awaiting_result", "failed", "stopped"},
                "dispatching": {"running", "awaiting_result", "failed", "stopped"},
                "running": {"awaiting_result", "failed", "stopped"},
                "awaiting_result": {"failed", "stopped"},
            }
            if status == row.status:
                return self._public(row)
            if status not in transitions[row.status]:
                raise ValueError("复核状态不能回退")
            now = datetime.now(UTC)
            values = {"status": status, "error": error}
            if status == "running" and row.started_at is None:
                values["started_at"] = now
            if status in {"failed", "stopped"}:
                values.update(finished_at=now, active_key=None)
            changed = session.execute(update(RetestRow).where(
                RetestRow.retest_id == retest_id, RetestRow.status == row.status,
            ).values(**values))
            if changed.rowcount != 1:
                session.rollback()
                session.expire_all()
                latest = session.get(RetestRow, retest_id)
                if latest.status not in ACTIVE_STATUSES:
                    return self._public(latest)
                raise ValueError("复核状态已变化，请重试")
            session.commit()
            session.refresh(row)
            return self._public(row)

    def finish(self, source_run_id: str, retest_id: str, child: AgentState,
               verdict: str, summary: str, checks: dict[str, list[str]]) -> dict:
        with Session(self.ledger.engine) as session:
            row = session.get(RetestRow, retest_id)
            if row is None or row.source_run_id != source_run_id:
                raise KeyError(retest_id)
            if child.run_id != row.child_run_id or child.report is None or child.status not in {
                RunStatus.COMPLETED, RunStatus.PARTIAL,
            }:
                raise ValueError("复核子任务尚未生成可用报告")
            module = json.loads(row.snapshot_json)["module_route"]
            rules = RESULT_RULES.get("code_audit" if module == "audit" else module)
            if rules is None or verdict not in {*rules, "inconclusive"}:
                raise ValueError("复核结论与来源模块不匹配")
            if child.status == RunStatus.PARTIAL and verdict != "inconclusive":
                raise ValueError("子任务部分完成时只能登记无法确认")
            summary = str(redact_trace(summary.strip()))
            if not summary:
                raise ValueError("复核结论摘要不能为空")
            checks = {role: list(dict.fromkeys(ids)) for role, ids in checks.items() if ids}
            required = rules.get(verdict, set())
            if not required.issubset(checks):
                raise ValueError("有效结论缺少本次验证、前置条件或正常对照证据")
            if module == "penetration" and verdict == "fixed" and not (
                set(checks["trigger"]) - set(checks["baseline"])
                and set(checks["baseline"]) - set(checks["trigger"])
            ):
                raise ValueError("已修复结论须使用不同的触发检查和正常对照证据")
            evidence_ids = list(dict.fromkeys(eid for ids in checks.values() for eid in ids))
            current_evidence = {item.evidence_id: item for item in child.evidence}
            report_evidence = {item.evidence_id for item in child.report.evidence}
            if any(eid not in current_evidence or eid not in report_evidence for eid in evidence_ids):
                raise ValueError("复核证据必须属于本次子任务报告")
            if verdict != "inconclusive" and not evidence_ids:
                raise ValueError("有效结论必须关联本次证据")
            if row.status == "completed":
                if (row.verdict, row.summary, self._public(row)["checks"]) == (verdict, summary, checks):
                    return self._public(row)
                raise ValueError("复核结论已保存，不能改写")
            if row.status != "awaiting_result":
                raise ValueError("复核尚未进入结论登记阶段")
            validate_retest_evidence(child, evidence_ids, self.ledger)
            changed = session.execute(update(RetestRow).where(
                RetestRow.retest_id == retest_id, RetestRow.status == "awaiting_result",
            ).values(verdict=verdict, summary=summary,
                     evidence_json=canonical_json({"ids": evidence_ids, "checks": checks}),
                     status="completed", active_key=None, finished_at=datetime.now(UTC)))
            if changed.rowcount != 1:
                session.rollback()
                session.expire_all()
                latest = session.get(RetestRow, retest_id)
                if latest.status == "completed" and (
                    latest.verdict, latest.summary, self._public(latest)["checks"]
                ) == (verdict, summary, checks):
                    return self._public(latest)
                raise ValueError("复核结论已保存或复核状态已变化")
            session.commit()
            session.refresh(row)
            return self._public(row)
