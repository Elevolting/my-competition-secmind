from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, UniqueConstraint, create_engine, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Mapped, Session, mapped_column

from security_agent.ledger import Base, canonical_json, redact
from security_agent.schemas import RunStatus, ToolStatus


class ExperienceRow(Base):
    __tablename__ = "experiences"
    __table_args__ = (UniqueConstraint("source_type", "source_run_id", name="uq_experience_run_source"),)

    experience_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(240))
    summary: Mapped[str] = mapped_column(Text)
    module_route: Mapped[str] = mapped_column(String(80), index=True)
    experience_kind: Mapped[str] = mapped_column(String(40), index=True)
    vulnerability_type: Mapped[str | None] = mapped_column(String(160), nullable=True)
    source_type: Mapped[str] = mapped_column(String(20), index=True)
    source_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    source_title: Mapped[str] = mapped_column(String(240))
    verified: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    steps_json: Mapped[str] = mapped_column(Text, default="[]")
    tools_json: Mapped[str] = mapped_column(Text, default="[]")
    evidence_refs_json: Mapped[str] = mapped_column(Text, default="[]")
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    usage_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ExperienceDetailRow(Base):
    __tablename__ = "experience_details"
    experience_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    data_json: Mapped[str] = mapped_column(Text)


class ExperienceHistoryRow(Base):
    __tablename__ = "experience_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    experience_id: Mapped[str] = mapped_column(String(36), index=True)
    data_json: Mapped[str] = mapped_column(Text)


class ExperienceUseRow(Base):
    __tablename__ = "experience_uses"
    __table_args__ = (UniqueConstraint("experience_id", "run_id", "version", name="uq_experience_use"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    experience_id: Mapped[str] = mapped_column(String(36), index=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    version: Mapped[int] = mapped_column(Integer)
    data_json: Mapped[str] = mapped_column(Text)


class ExperienceStore:
    """Evidence-linked candidates, explicit review, ranked retrieval and durable usage."""
    import threading
    _lock = threading.RLock()

    def __init__(self, engine_or_url: Engine | str) -> None:
        if isinstance(engine_or_url, str):
            self.engine = create_engine(engine_or_url, future=True,
                connect_args={"check_same_thread": False} if engine_or_url.startswith("sqlite") else {})
        else:
            self.engine = engine_or_url
        Base.metadata.create_all(self.engine)
        # Old verified/confidence/usage fields represented hash-chain validity and
        # search counts. Preserve their original values in history, never promote them.
        with self._lock, Session(self.engine) as session:
            for row in session.scalars(select(ExperienceRow)).all():
                if session.get(ExperienceDetailRow, row.experience_id) is None:
                    original = self._base_dict(row)
                    detail = self._initial_detail()
                    detail.update(conditions=[row.summary], lessons=[], limitations=["旧版摘要，需重新提炼并审核"],
                        legacy_usage_count=row.usage_count, legacy_confidence=row.confidence)
                    session.add(ExperienceHistoryRow(experience_id=row.experience_id,
                        data_json=canonical_json({"action": "legacy_migration", "at": self._now(), "snapshot": original})))
                    row.verified = False
                    row.confidence = 0
                    row.usage_count = 0
                    session.add(ExperienceDetailRow(experience_id=row.experience_id, data_json=canonical_json(detail)))
            session.commit()

    @staticmethod
    def _now():
        return datetime.now(UTC).isoformat()

    @staticmethod
    def _initial_detail():
        return {"version": 1, "review_status": "draft", "conditions": [], "lessons": [], "limitations": [],
                "evidence": [], "source_fingerprint": None, "chain_valid": None,
                "extraction_method": "manual", "review_note": "", "deleted": False}

    def _detail(self, session, row):
        saved = session.get(ExperienceDetailRow, row.experience_id)
        return json.loads(saved.data_json) if saved else self._initial_detail()

    def _save_detail(self, session, row, detail):
        saved = session.get(ExperienceDetailRow, row.experience_id)
        if saved is None:
            session.add(ExperienceDetailRow(experience_id=row.experience_id, data_json=canonical_json(detail)))
        else:
            saved.data_json = canonical_json(detail)

    def _snapshot(self, session, row):
        result = {**self._base_dict(row), **self._detail(session, row)}
        result["verified"] = result["review_status"] == "approved"
        result["confidence"] = None
        return result

    def _history(self, session, row, action, note=""):
        session.add(ExperienceHistoryRow(experience_id=row.experience_id,
            data_json=canonical_json({"action": action, "note": note, "at": self._now(), "snapshot": self._snapshot(session, row)})))

    def list(self, *, module_route=None, source_type=None, limit=200, review_status=None, q=""):
        query = select(ExperienceRow).order_by(ExperienceRow.updated_at.desc(), ExperienceRow.experience_id.desc())
        if module_route:
            query = query.where(ExperienceRow.module_route == module_route)
        if source_type:
            query = query.where(ExperienceRow.source_type == source_type)
        with Session(self.engine) as session:
            records = [self._snapshot(session, row) for row in session.scalars(query).all()]
        records = [r for r in records if not r["deleted"] and (not review_status or r["review_status"] == review_status)]
        if q:
            terms = self._terms(q)
            records = [r for r in records if terms & self._terms(self.context(r))]
        return records if limit is None else records[:limit]

    def get(self, experience_id, *, include_deleted=False):
        with Session(self.engine) as session:
            row = session.get(ExperienceRow, experience_id)
            if row is None:
                return None
            result = self._snapshot(session, row)
            return result if include_deleted or not result["deleted"] else None

    def history(self, experience_id):
        with Session(self.engine) as session:
            rows = session.scalars(select(ExperienceHistoryRow).where(ExperienceHistoryRow.experience_id == experience_id)
                .order_by(ExperienceHistoryRow.id.desc()).limit(100)).all()
            return [json.loads(row.data_json) for row in rows]

    def create_manual(self, payload):
        safe = redact(payload.model_dump(mode="json"))
        now = datetime.now(UTC)
        row = ExperienceRow(experience_id=str(uuid4()), title=safe["title"].strip(), summary=safe["summary"].strip(),
            module_route=safe["module_route"], experience_kind=safe["experience_kind"],
            vulnerability_type=safe.get("vulnerability_type"), source_type="manual", source_run_id=None,
            source_title="人工填入", verified=False, confidence=0, content_hash=self._hash(safe),
            tags_json=canonical_json(self._clean_tags(safe.get("tags", []))),
            steps_json=canonical_json(safe.get("steps", [])), tools_json="[]", evidence_refs_json="[]",
            finding_count=0, usage_count=0, created_at=now, updated_at=now)
        detail = {**self._initial_detail(), "conditions": safe.get("conditions", []),
                  "lessons": safe.get("lessons", []), "limitations": safe.get("limitations", [])}
        with self._lock, Session(self.engine) as session:
            session.add(row); session.flush()
            self._save_detail(session, row, detail); session.flush()
            self._history(session, row, "created"); session.commit()
            return self._snapshot(session, row)

    def delete(self, experience_id):
        with self._lock, Session(self.engine) as session:
            row = session.get(ExperienceRow, experience_id)
            if row is None or self._detail(session, row)["deleted"]:
                return False
            self._history(session, row, "deleted")
            detail = self._detail(session, row)
            detail.update(deleted=True, review_status="retired", version=detail["version"] + 1)
            row.verified = False
            self._save_detail(session, row, detail); session.commit()
            return True

    def update(self, experience_id, content, expected_version, *, method="manual_edit", model=None):
        with self._lock, Session(self.engine) as session:
            row = session.get(ExperienceRow, experience_id)
            if row is None or self._detail(session, row)["deleted"]:
                raise KeyError(experience_id)
            detail = self._detail(session, row)
            if detail["version"] != expected_version:
                raise ValueError("版本已更新，请刷新后重试")
            self._history(session, row, "edited")
            safe = redact(content)
            for key in ("title", "summary", "vulnerability_type"):
                if key in safe:
                    setattr(row, key, safe[key])
            for key in ("conditions", "lessons", "limitations"):
                if key in safe:
                    detail[key] = safe[key]
            for key in ("steps", "tags"):
                if key in safe:
                    setattr(row, key + "_json", canonical_json(safe[key]))
            detail.update(version=detail["version"] + 1, review_status="draft", review_note="", extraction_method=method)
            if model:
                detail["model_receipt"] = model
            else:
                detail.pop("model_receipt", None)
            row.verified = False
            row.updated_at = datetime.now(UTC)
            row.content_hash = self._hash({"content": safe, "source": detail.get("source_fingerprint")})
            self._save_detail(session, row, detail); session.commit()
            return self._snapshot(session, row)

    def review(self, experience_id, decision, expected_version, note=""):
        if decision not in {"approve", "reject", "retire"}:
            raise ValueError("审核决策无效")
        with self._lock, Session(self.engine) as session:
            row = session.get(ExperienceRow, experience_id)
            if row is None or self._detail(session, row)["deleted"]:
                raise KeyError(experience_id)
            detail = self._detail(session, row)
            if detail["version"] != expected_version:
                raise ValueError("版本已更新，请刷新后重试")
            if decision == "approve":
                if not any(x.strip() for x in detail["conditions"]) or not any(x.strip() for x in detail["lessons"]):
                    raise ValueError("请先补充适用条件与可复用经验，再启用")
                if row.source_type == "run" and (not detail["chain_valid"] or not detail["evidence"]):
                    raise ValueError("来源账本无效或没有可追溯的观测，不能启用")
            self._history(session, row, "review:" + decision, note)
            detail.update(review_status={"approve": "approved", "reject": "rejected", "retire": "retired"}[decision],
                          version=detail["version"] + 1, review_note=note, reviewed_at=self._now())
            row.verified = decision == "approve"
            row.updated_at = datetime.now(UTC)
            self._save_detail(session, row, detail); session.commit()
            return self._snapshot(session, row)

    def capture_run(self, state, events, *, chain_valid):
        if state.status not in {RunStatus.COMPLETED, RunStatus.PARTIAL, RunStatus.FAILED, RunStatus.DENIED}:
            return None
        data, detail = self._extract_run(state, events, chain_valid=chain_valid)
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            row = session.scalar(select(ExperienceRow).where(ExperienceRow.source_type == "run", ExperienceRow.source_run_id == state.run_id))
            if row:
                old = self._detail(session, row)
                if old["deleted"]:
                    return None
                if old.get("source_fingerprint") == detail["source_fingerprint"]:
                    return self._snapshot(session, row)
                self._history(session, row, "source_updated")
                detail["version"] = old["version"] + 1
                if old.get("legacy_usage_count") is not None:
                    detail["legacy_usage_count"] = old["legacy_usage_count"]
                for key, value in data.items():
                    setattr(row, key, value)
            else:
                row = ExperienceRow(experience_id=str(uuid4()), source_type="run", source_run_id=state.run_id,
                    created_at=now, updated_at=now, usage_count=0, **data)
                session.add(row); session.flush()
            row.updated_at = now
            self._save_detail(session, row, detail); session.flush()
            self._history(session, row, "extracted"); session.commit()
            return self._snapshot(session, row)

    def backfill(self, ledger):
        created = updated = unchanged = skipped = 0
        for state in ledger.list_states(limit=None):
            with Session(self.engine) as session:
                row = session.scalar(select(ExperienceRow).where(ExperienceRow.source_type == "run", ExperienceRow.source_run_id == state.run_id))
                before = self._snapshot(session, row) if row else None
            result = self.capture_run(state, ledger.events(state.run_id, limit=1_000_000), chain_valid=ledger.verify(state.run_id))
            if result is None: skipped += 1
            elif before is None: created += 1
            elif before["version"] == result["version"]: unchanged += 1
            else: updated += 1
        return {"stored": created + updated, "created": created, "updated": updated, "unchanged": unchanged, "skipped": skipped}

    @staticmethod
    def _terms(text):
        import re
        terms = set(re.findall(r"[a-z0-9_]{2,}", text.lower()))
        for segment in re.findall(r"[\u4e00-\u9fff]+", text):
            terms.update(segment[i:i + 2] for i in range(len(segment) - 1))
        return terms - {"任务", "安全", "分析", "审计", "代码", "文件", "进行", "需要", "执行", "检查", "the", "and", "with", "code", "audit"}

    @staticmethod
    def context(record):
        return canonical_json({"experience_id": record["experience_id"], "version": record["version"],
            "title": record["title"], "summary": record["summary"], "conditions": record["conditions"],
            "lessons": record["lessons"], "steps": record["steps"], "limitations": record["limitations"],
            "tags": record["tags"], "source_run_id": record["source_run_id"], "evidence_refs": record["evidence_refs"]})

    def search(self, module_route, objective, *, top_k=5, exclude_run_id=None):
        import math
        query = self._terms(objective)
        if not query: return []
        records = [r for r in self.list(module_route=module_route, review_status="approved", limit=None)
                   if not exclude_run_id or r["source_run_id"] != exclude_run_id]
        docs = [self._terms(' '.join([r['title'], r['summary'], *r['tags'], *r['conditions'], *r['lessons']])) for r in records]
        frequencies = {t: sum(t in doc for doc in docs) for t in query}
        ranked = []
        for r, doc in zip(records, docs):
            matched = query & doc
            if not matched: continue
            weights = {t: math.log(1 + (len(docs) + 1) / (frequencies[t] + 1)) for t in query}
            score = sum(weights[t] for t in matched) / sum(weights.values())
            if score < 0.12: continue
            feedback = [u["feedback"]["verdict"] for u in self.uses(r["experience_id"])
                        if u.get("feedback") and u["version"] == r["version"]]
            helpful = feedback.count("helpful")
            unhelpful = feedback.count("not_helpful")
            adjustment = 1 + 0.15 * (helpful - unhelpful) / max(1, helpful + unhelpful)
            ranked.append({**r, "relevance_score": round(score, 4), "ranking_score": round(score * adjustment, 4),
                           "feedback_counts": {"helpful": helpful, "not_helpful": unhelpful}, "matched_terms": sorted(matched),
                           "retrieval_reason": "同模块已审核；词项匹配：" + "、".join(sorted(matched)[:12])})
        return sorted(ranked, key=lambda r: (-r["ranking_score"], r["experience_id"]))[:top_k]

    def record_use(self, run_id, hit, *, cited=False, model_id=None):
        version = int(hit.version)
        with self._lock, Session(self.engine) as session:
            row = session.get(ExperienceRow, hit.memory_id)
            if row is None: return None
            detail = self._detail(session, row)
            if (detail["deleted"] or detail["review_status"] != "approved"
                    or detail["version"] != version or not row.verified):
                return None
            existing = session.scalar(select(ExperienceUseRow).where(ExperienceUseRow.experience_id == hit.memory_id,
                ExperienceUseRow.run_id == run_id, ExperienceUseRow.version == version))
            if existing: return json.loads(existing.data_json)
            data = {"experience_id": hit.memory_id, "run_id": run_id, "version": version,
                    "at": self._now(), "stage": "planner", "model_id": model_id, "model_cited": cited,
                    "content_hash": self._hash(hit.content), "context_snapshot": hit.content,
                    "outcome": "pending", "feedback": None}
            session.add(ExperienceUseRow(experience_id=hit.memory_id, run_id=run_id, version=version, data_json=canonical_json(data)))
            row.usage_count += 1
            session.commit()
            return data

    def complete_uses(self, state):
        with self._lock, Session(self.engine) as session:
            rows = session.scalars(select(ExperienceUseRow).where(ExperienceUseRow.run_id == state.run_id)).all()
            for row in rows:
                data = json.loads(row.data_json)
                data.update(outcome=str(state.status), completed_at=self._now(), finding_count=len(state.findings),
                            evidence_count=len(state.evidence), last_error=state.last_error)
                row.data_json = canonical_json(data)
            session.commit()

    def uses(self, experience_id):
        with Session(self.engine) as session:
            return [json.loads(row.data_json) for row in session.scalars(select(ExperienceUseRow)
                .where(ExperienceUseRow.experience_id == experience_id).order_by(ExperienceUseRow.id.desc())).all()]

    def uses_for_run(self, run_id):
        with Session(self.engine) as session:
            return [json.loads(row.data_json) for row in session.scalars(select(ExperienceUseRow)
                .where(ExperienceUseRow.run_id == run_id).order_by(ExperienceUseRow.id)).all()]

    def feedback(self, experience_id, run_id, version, verdict, note):
        if verdict not in {"helpful", "not_helpful", "uncertain"}: raise ValueError("反馈类型无效")
        with self._lock, Session(self.engine) as session:
            row = session.scalar(select(ExperienceUseRow).where(ExperienceUseRow.experience_id == experience_id,
                ExperienceUseRow.run_id == run_id, ExperienceUseRow.version == version))
            if row is None: raise KeyError(run_id)
            data = json.loads(row.data_json)
            previous = data.get("feedback")
            data.setdefault("feedback_history", []).append(previous) if previous else None
            data["feedback"] = {"verdict": verdict, "note": note, "at": self._now()}
            row.data_json = canonical_json(data); session.commit()
            return data

    @classmethod
    def _extract_run(cls, state, events, *, chain_valid):
        # Only observed events and results become citations; planned steps remain labelled as plans.
        observed = [e for e in events if e.event_type in {"tool.completed", "observation.recorded", "run.failed", "guardrail.denied", "penetration.terminal"}]
        evidence = [{"ref": e.evidence_id, "source": e.source, "summary": e.summary,
            "artifact_ref": e.artifact_ref, "sha256": e.sha256} for e in state.evidence]
        evidence += [{"ref": e.event_id, "event_type": e.event_type, "sequence": e.sequence,
                      "summary": str(e.payload.get("summary") or e.payload.get("error") or e.payload.get("status") or e.event_type)[:1500]} for e in observed]
        refs = {e["ref"] for e in evidence}
        tools = list(dict.fromkeys(str(e.payload["tool"]) for e in events if e.event_type == "tool.completed" and e.payload.get("tool")))
        failures = [o for o in state.observations if o.status != ToolStatus.SUCCESS]
        external_ok = state.module_route != "penetration" or state.external_execution.get("objective_reached") is True
        success = state.status == RunStatus.COMPLETED and not failures and external_ok
        findings = [{"rule": f.rule_id, "title": f.title, "description": f.description[:2000],
                     "remediation": f.remediation, "evidence_ids": [ref for ref in f.evidence_ids if ref in refs]} for f in state.findings]
        lessons = []
        for f in findings[:20]:
            if f["evidence_ids"]:
                lessons.append(f"{f['rule']}：{f['title']}。{f['description']}" + (f" 建议：{f['remediation']}" if f["remediation"] else "") + f" [证据 {', '.join(f['evidence_ids'])}]")
        for failure in failures[:10]:
            lessons.append(f"工具观测 {failure.status}：{failure.error_code or ''} {failure.error_message or failure.summary}")
        if state.last_error:
            lessons.append("执行限制：" + state.last_error)
        if not lessons:
            lessons = ["实际观测：" + e["summary"] for e in evidence[:5]]
        kind = "success_pattern" if success else "failure_lesson"
        summary = (state.report.executive_summary if state.report else state.last_error or "任务未形成报告")[:4000]
        conditions = ["来源任务目标：" + state.task.objective[:2000], "适用模块：" + state.module_route]
        formats = sorted({a.media_type for a in state.input_artifacts})
        if formats: conditions.append("已观察到的输入类型：" + ", ".join(formats))
        steps = [f"观测 {e.sequence} / {e.event_type}：{str(e.payload.get('summary') or e.payload.get('tool') or e.payload.get('status') or '')[:1500]}" for e in observed[:25]]
        limitations = list(state.report.limitations if state.report else [])
        limitations += ["同类任务仍需核对授权、工具可用性与本次输入，历史结果不保证复现。"]
        if not evidence: limitations.append("缺少可追溯观测，不能审核启用。")
        if not chain_valid: limitations.append("来源账本哈希链校验失败。")
        if not external_ok: limitations.append("外部目标未被确认达成。")
        source = {"objective": state.task.objective, "status": str(state.status), "observations": [o.model_dump(mode="json") for o in state.observations],
                  "findings": findings, "evidence": evidence, "summary": summary, "last_error": state.last_error,
                  "external": state.external_execution, "chain_valid": chain_valid,
                  "limitations": limitations, "conditions": conditions}
        detail = {**cls._initial_detail(), "conditions": conditions, "lessons": lessons, "limitations": limitations,
                  "evidence": evidence, "source_fingerprint": cls._hash(source), "chain_valid": chain_valid,
                  "extraction_method": "evidence_rules_v2", "source_status": str(state.status)}
        data = {"title": ((state.task.name or state.module_route) + (" · 任务经验候选" if success else " · 失败教训候选"))[:240],
                "summary": summary, "module_route": {"audit": "code_audit", "reverse_triage": "reverse", "penetration_test": "penetration"}.get(state.module_route, state.module_route),
                "experience_kind": kind, "vulnerability_type": ','.join(dict.fromkeys(f.rule_id for f in state.findings))[:160] or None,
                "source_title": (state.task.name or state.task.objective)[:240], "verified": False, "confidence": 0,
                "content_hash": cls._hash({"detail": detail, "summary": summary}),
                "tags_json": canonical_json(cls._clean_tags([state.module_route, *[f.rule_id for f in state.findings]])),
                "steps_json": canonical_json(steps), "tools_json": canonical_json(tools),
                "evidence_refs_json": canonical_json([e["ref"] for e in evidence]), "finding_count": len(state.findings)}
        return redact(data), redact(detail)

    @staticmethod
    def _hash(value):
        return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()

    @staticmethod
    def _clean_tags(tags):
        return list(dict.fromkeys(str(tag).strip()[:80] for tag in tags if str(tag).strip()))[:20]

    @staticmethod
    def _base_dict(row):
        return {"experience_id": row.experience_id, "title": row.title, "summary": row.summary,
            "module_route": row.module_route, "experience_kind": row.experience_kind,
            "vulnerability_type": row.vulnerability_type, "source_type": row.source_type,
            "source_run_id": row.source_run_id, "source_title": row.source_title, "verified": row.verified,
            "confidence": row.confidence, "content_hash": row.content_hash,
            "tags": json.loads(row.tags_json), "steps": json.loads(row.steps_json),
            "tools": json.loads(row.tools_json), "evidence_refs": json.loads(row.evidence_refs_json),
            "finding_count": row.finding_count, "usage_count": row.usage_count,
            "created_at": row.created_at.replace(tzinfo=row.created_at.tzinfo or UTC).isoformat(),
            "updated_at": row.updated_at.replace(tzinfo=row.updated_at.tzinfo or UTC).isoformat()}
