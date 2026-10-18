from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from secmind.hybrid_knowledge import GovernedQdrantSearch, HybridKnowledgeStore, PrecomputedQueryVectors
from secmind.knowledge import OfflineKnowledgeStore, knowledge_metadata
from secmind.schemas import KnowledgeHit


def _catalog(
    path: Path,
    query: str,
    documents: dict[str, dict[str, str]],
) -> tuple[PrecomputedQueryVectors, str]:
    query_digest = hashlib.sha256(" ".join(query.casefold().split()).encode()).hexdigest()
    corpus_digest = hashlib.sha256(
        json.dumps(documents, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    path.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "corpus_digest": corpus_digest,
                "vector_size": 2,
                "documents": documents,
                "queries": {query_digest: [0.25, 0.75]},
            }
        ),
        encoding="utf-8",
    )
    return PrecomputedQueryVectors(path, vector_size=2, corpus_digest=corpus_digest), corpus_digest


def test_governed_qdrant_uses_only_precomputed_queries_and_governed_hits(tmp_path: Path) -> None:
    content = "Parameterized queries prevent SQL injection."
    documents = {
        "accepted": {
            "content_sha256": hashlib.sha256(content.encode()).hexdigest(),
            "source": "C-group/advisories",
            "version": "2026-08-01",
            "license": "CC-BY-4.0",
        }
    }
    vectors, corpus_digest = _catalog(tmp_path / "queries.json", "SQL injection", documents)
    accepted = {
        "memory_id": "accepted",
        "content": content,
        "source": "C-group/advisories",
        "version": "2026-08-01",
        "kind": "knowledge",
        "metadata": {
            "corpus_digest": corpus_digest,
            "source_verified": True,
            "license": "CC-BY-4.0",
            "untrusted_nested": {"inflate": ["ignored"] * 1_000},
        },
    }
    stale = {
        **accepted,
        "memory_id": "stale",
        "metadata": {**accepted["metadata"], "corpus_digest": "b" * 64},
    }
    client = SimpleNamespace(
        query_points=lambda **_kwargs: SimpleNamespace(
            points=[
                SimpleNamespace(id="stale", score=0.99, payload=stale),
                SimpleNamespace(id="accepted", score=float("nan"), payload=accepted),
                SimpleNamespace(id="accepted", score=0.9, payload=accepted),
            ]
        )
    )
    search = GovernedQdrantSearch(
        url="http://unused",
        collection_name="knowledge",
        vectors=vectors,
        corpus_digest=corpus_digest,
        client=client,
    )

    hits = search.search("SQL   INJECTION", top_k=5, kind="knowledge")

    assert [hit.memory_id for hit in hits] == ["accepted"]
    assert hits[0].metadata["trusted_as_instructions"] is False
    assert knowledge_metadata(hits[0])["corpus_digest"] == corpus_digest
    assert knowledge_metadata(hits[0])["license"] == "CC-BY-4.0"
    assert "untrusted_nested" not in hits[0].metadata
    assert search.search("query absent from sealed catalog", top_k=5, kind=None) == []


def test_hybrid_search_falls_back_and_merges_deterministically(tmp_path: Path) -> None:
    offline = OfflineKnowledgeStore(f"sqlite:///{tmp_path / 'knowledge.db'}")
    offline.upsert(
        content="SQL injection guidance",
        source="offline",
        version="1",
        content_hash="c" * 64,
        verified=True,
        trust_score=0.8,
    )

    class Semantic:
        def search(self, query: str, *, top_k: int, kind: str | None) -> list[KnowledgeHit]:
            return [
                KnowledgeHit(
                    memory_id="semantic",
                    content="Additional governed guidance",
                    source="vector",
                    version="1",
                    confidence=0.9,
                    metadata={"trusted_as_instructions": False},
                )
            ]

    hybrid = HybridKnowledgeStore(offline, Semantic())  # type: ignore[arg-type]
    try:
        hits = hybrid.search("SQL injection", top_k=2)
        assert [hit.memory_id for hit in hits] == ["semantic", hits[1].memory_id]
        assert hits[1].source == "offline"
    finally:
        hybrid.close()


def test_hybrid_semantic_failure_returns_offline_results(tmp_path: Path) -> None:
    offline = OfflineKnowledgeStore(f"sqlite:///{tmp_path / 'fallback.db'}")
    offline.upsert(
        content="offline incident knowledge",
        source="offline",
        version="1",
        content_hash="d" * 64,
        verified=True,
    )

    class FailingSemantic:
        def search(self, query: str, *, top_k: int, kind: str | None) -> list[KnowledgeHit]:
            raise RuntimeError("qdrant unavailable")

    hybrid = HybridKnowledgeStore(offline, FailingSemantic())  # type: ignore[arg-type]
    try:
        assert [hit.source for hit in hybrid.search("incident knowledge")] == ["offline"]
    finally:
        hybrid.close()


def test_hybrid_cannot_overwrite_offline_record_by_claiming_its_id(tmp_path: Path) -> None:
    offline = OfflineKnowledgeStore(f"sqlite:///{tmp_path / 'collision.db'}")
    memory_id = offline.upsert(
        content="trusted offline content",
        source="offline",
        version="1",
        content_hash="e" * 64,
        verified=True,
    )

    class CollidingSemantic:
        def search(self, query: str, *, top_k: int, kind: str | None) -> list[KnowledgeHit]:
            return [
                KnowledgeHit(
                    memory_id=memory_id,
                    content="different vector content",
                    source="vector",
                    version="2",
                    confidence=1.0,
                )
            ]

    hybrid = HybridKnowledgeStore(offline, CollidingSemantic())  # type: ignore[arg-type]
    try:
        hits = hybrid.search("trusted offline", top_k=5)
        assert len(hits) == 1
        assert hits[0].content == "trusted offline content"
    finally:
        hybrid.close()
