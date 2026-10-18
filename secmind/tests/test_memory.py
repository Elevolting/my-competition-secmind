from __future__ import annotations

import pytest
from qdrant_client import QdrantClient

from secmind.memory import MemoryDocument, QdrantVectorStore


def test_qdrant_store_requires_verified_episodic_memory() -> None:
    store = QdrantVectorStore(
        url=":memory:",
        collection_name="test",
        vector_size=3,
        client=QdrantClient(":memory:"),
    )
    with pytest.raises(ValueError, match="verification"):
        store.upsert(
            MemoryDocument(
                content="unverified experience",
                source="run-1",
                version="1",
                kind="episodic",
            ),
            [1.0, 0.0, 0.0],
        )


def test_qdrant_store_upserts_searches_and_filters() -> None:
    store = QdrantVectorStore(
        url=":memory:",
        collection_name="test",
        vector_size=3,
        client=QdrantClient(":memory:"),
    )
    store.upsert(
        MemoryDocument(
            content="Bandit detects shell injection",
            source="ATT&CK",
            version="1",
            metadata={"topic": "code"},
        ),
        [1.0, 0.0, 0.0],
    )
    hits = store.search([1.0, 0.0, 0.0], filters={"source": "ATT&CK"}, top_k=2)
    assert len(hits) == 1
    assert hits[0].source == "ATT&CK"
    assert hits[0].confidence > 0
    with pytest.raises(ValueError, match="vector size"):
        store.search([1.0])
