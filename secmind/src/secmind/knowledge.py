from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, String, Text, create_engine, func, or_, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from secmind.schemas import KnowledgeHit


class KnowledgeBase(DeclarativeBase):
    pass


class KnowledgeDocumentRow(KnowledgeBase):
    __tablename__ = "knowledge_documents"

    memory_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    content: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(500), index=True)
    version: Mapped[str] = mapped_column(String(100))
    kind: Mapped[str] = mapped_column(String(30), index=True)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    trust_score: Mapped[float] = mapped_column(Float, default=0.5)
    content_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tombstoned: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class OfflineKnowledgeStore:
    """Deterministic offline retrieval baseline; retrieved text is always untrusted data."""

    def __init__(
        self,
        database_url: str | None = None,
        *,
        engine: Engine | None = None,
        initialize_schema: bool = True,
    ) -> None:
        self._owns_engine = engine is None
        if engine is None:
            if database_url is None:
                raise ValueError("database_url or engine is required")
            connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
            engine = create_engine(database_url, future=True, connect_args=connect_args)
        self.engine = engine
        if initialize_schema:
            KnowledgeBase.metadata.create_all(self.engine)

    def upsert(
        self,
        *,
        content: str,
        source: str,
        version: str,
        content_hash: str,
        kind: str = "knowledge",
        verified: bool,
        trust_score: float = 0.5,
    ) -> str:
        if kind == "episodic" and not verified:
            raise ValueError("episodic memory must be verified")
        with Session(self.engine) as session:
            existing = session.scalar(
                select(KnowledgeDocumentRow).where(KnowledgeDocumentRow.content_hash == content_hash)
            )
            if existing is not None:
                return existing.memory_id
            memory_id = str(uuid4())
            session.add(
                KnowledgeDocumentRow(
                    memory_id=memory_id,
                    content=content,
                    source=source,
                    version=version,
                    kind=kind,
                    verified=verified,
                    trust_score=max(0.0, min(1.0, trust_score)),
                    content_hash=content_hash,
                    created_at=datetime.now(UTC),
                )
            )
            session.commit()
            return memory_id

    def search(self, query: str, *, top_k: int = 5, kind: str | None = None) -> list[KnowledgeHit]:
        tokens = self._tokens(query)
        if not tokens or top_k <= 0:
            return []
        top_k = min(top_k, 100)
        now = datetime.now(UTC)
        statement = select(KnowledgeDocumentRow).where(KnowledgeDocumentRow.tombstoned.is_(False))
        if kind is not None:
            statement = statement.where(KnowledgeDocumentRow.kind == kind)
        # Keep ranking deterministic in Python, but let the database discard
        # obvious non-candidates first.  Non-ASCII tokens skip this portable
        # fallback because SQLite's lower() is ASCII-only; PostgreSQL FTS can
        # remain an optional deployment enhancement without changing results.
        ascii_tokens = sorted(token for token in tokens if token.isascii())
        if ascii_tokens and len(ascii_tokens) == len(tokens):
            lowered_content = func.lower(KnowledgeDocumentRow.content)
            statement = statement.where(
                or_(*(lowered_content.contains(token, autoescape=True) for token in ascii_tokens))
            )
        with Session(self.engine) as session:
            rows = session.scalars(statement).all()
        ranked: list[tuple[float, KnowledgeDocumentRow]] = []
        for row in rows:
            expires_at = row.expires_at
            if expires_at is not None and expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            if expires_at is not None and expires_at <= now:
                continue
            document_tokens = self._tokens(row.content)
            overlap = len(tokens & document_tokens) / max(1, len(tokens))
            score = overlap * row.trust_score
            if score > 0:
                ranked.append((score, row))
        ranked.sort(key=lambda item: (-item[0], item[1].memory_id))
        return [
            KnowledgeHit(
                memory_id=row.memory_id,
                content=row.content,
                source=row.source,
                version=row.version,
                confidence=score,
                metadata={"kind": row.kind, "trusted_as_instructions": False},
            )
            for score, row in ranked[:top_k]
        ]

    def close(self) -> None:
        if self._owns_engine:
            self.engine.dispose()

    @staticmethod
    def _tokens(value: str) -> set[str]:
        return {item.lower() for item in re.findall(r"[\w.-]{2,}", value, flags=re.UNICODE)}


def knowledge_metadata(hit: KnowledgeHit) -> dict[str, Any]:
    metadata = {
        "memory_id": hit.memory_id,
        "source": hit.source,
        "version": hit.version,
        "confidence": hit.confidence,
        "trusted_as_instructions": False,
    }
    for key in ("content_sha256", "corpus_digest", "license", "retrieval", "source_verified"):
        if key in hit.metadata:
            metadata[key] = hit.metadata[key]
    return metadata
