import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from secmind.knowledge import KnowledgeDocumentRow, OfflineKnowledgeStore, knowledge_metadata


def test_offline_knowledge_search_is_source_backed_and_deterministic(tmp_path) -> None:
    store = OfflineKnowledgeStore(f"sqlite:///{(tmp_path / 'knowledge.db').as_posix()}")
    content = "Bandit B602 detects subprocess shell execution in Python code."
    memory_id = store.upsert(
        content=content,
        source="rulebook",
        version="2026.1",
        content_hash=hashlib.sha256(content.encode()).hexdigest(),
        verified=True,
        trust_score=0.9,
    )
    hits = store.search("Python subprocess Bandit", top_k=3)
    assert [item.memory_id for item in hits] == [memory_id]
    assert hits[0].source == "rulebook"
    assert hits[0].metadata["trusted_as_instructions"] is False
    store.close()


def test_unverified_episodic_memory_is_rejected(tmp_path) -> None:
    store = OfflineKnowledgeStore(f"sqlite:///{(tmp_path / 'memory.db').as_posix()}")
    with pytest.raises(ValueError, match="verified"):
        store.upsert(
            content="unsafe memory",
            source="run",
            version="1",
            content_hash="a" * 64,
            kind="episodic",
            verified=False,
        )
    store.close()


def test_duplicate_upsert_clamps_trust_and_search_filters_kind(tmp_path) -> None:
    store = OfflineKnowledgeStore(f"sqlite:///{(tmp_path / 'filters.db').as_posix()}")
    content = "python dependency advisory"
    digest = hashlib.sha256(content.encode()).hexdigest()
    first = store.upsert(
        content=content,
        source="knowledge",
        version="1",
        content_hash=digest,
        kind="knowledge",
        verified=True,
        trust_score=5,
    )
    assert (
        store.upsert(
            content="ignored duplicate",
            source="other",
            version="2",
            content_hash=digest,
            verified=True,
        )
        == first
    )
    assert store.search("python", kind="episodic") == []
    hit = store.search("python dependency")[0]
    assert hit.confidence == 1
    assert knowledge_metadata(hit)["trusted_as_instructions"] is False
    assert store.search("!") == []
    store.close()


def test_search_excludes_expired_and_tombstoned_documents(tmp_path) -> None:
    store = OfflineKnowledgeStore(f"sqlite:///{(tmp_path / 'expiry.db').as_posix()}")
    expired_id = store.upsert(
        content="expired bandit rule",
        source="rules",
        version="1",
        content_hash="a" * 64,
        verified=True,
    )
    tombstoned_id = store.upsert(
        content="tombstoned bandit rule",
        source="rules",
        version="1",
        content_hash="b" * 64,
        verified=True,
    )
    live_id = store.upsert(
        content="live bandit rule",
        source="rules",
        version="1",
        content_hash="c" * 64,
        verified=True,
        trust_score=-1,
    )
    with Session(store.engine) as session:
        expired = session.scalar(select(KnowledgeDocumentRow).where(KnowledgeDocumentRow.memory_id == expired_id))
        tombstoned = session.scalar(select(KnowledgeDocumentRow).where(KnowledgeDocumentRow.memory_id == tombstoned_id))
        assert expired is not None and tombstoned is not None
        expired.expires_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=1)
        tombstoned.tombstoned = True
        session.commit()
    assert all(item.memory_id not in {expired_id, tombstoned_id, live_id} for item in store.search("bandit"))
    store.close()


def test_schema_initialization_can_be_disabled(tmp_path) -> None:
    store = OfflineKnowledgeStore(
        f"sqlite:///{(tmp_path / 'no-schema.db').as_posix()}",
        initialize_schema=False,
    )
    store.close()
