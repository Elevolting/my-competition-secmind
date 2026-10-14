from __future__ import annotations

import hashlib
import json
import math
import re
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError
from pathlib import Path
from threading import Lock
from typing import Any

from secmind.knowledge import OfflineKnowledgeStore
from secmind.schemas import KnowledgeHit

_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_MAX_CATALOG_BYTES = 16 * 1024 * 1024
_MAX_CATALOG_ENTRIES = 10_000
_MAX_HIT_CONTENT_CHARS = 100_000


class PrecomputedQueryVectors:
    """Bounded, offline query-vector catalog.

    The catalog is generated outside the runtime by the C group.  SecMind never
    creates embeddings while serving an audit, so enabling hybrid retrieval
    cannot silently create a model-network dependency.
    """

    def __init__(self, path: Path, *, vector_size: int, corpus_digest: str) -> None:
        if not _SHA256.fullmatch(corpus_digest):
            raise ValueError("knowledge vector corpus digest must be a lowercase SHA-256")
        if vector_size < 1:
            raise ValueError("knowledge vector size must be positive")
        stat = path.stat()
        if stat.st_size > _MAX_CATALOG_BYTES:
            raise ValueError("precomputed query-vector catalog exceeds the size limit")
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("schema_version") != "1":
            raise ValueError("unsupported precomputed query-vector catalog")
        if raw.get("corpus_digest") != corpus_digest or raw.get("vector_size") != vector_size:
            raise ValueError("query-vector catalog identity does not match configuration")
        documents = raw.get("documents")
        if not isinstance(documents, dict) or len(documents) > _MAX_CATALOG_ENTRIES:
            raise ValueError("query-vector catalog has an invalid governed document map")
        canonical_documents: dict[str, dict[str, str]] = {}
        for memory_id, document in documents.items():
            if not isinstance(memory_id, str) or not memory_id or not isinstance(document, dict):
                raise ValueError("governed document entries must have stable string identifiers")
            normalized = {
                "content_sha256": str(document.get("content_sha256", "")),
                "source": str(document.get("source", "")),
                "version": str(document.get("version", "")),
                "license": str(document.get("license", "")),
            }
            if (
                not _SHA256.fullmatch(normalized["content_sha256"])
                or not normalized["source"].strip()
                or not normalized["version"].strip()
                or not normalized["license"].strip()
            ):
                raise ValueError("governed document metadata is incomplete")
            canonical_documents[memory_id] = normalized
        computed_corpus_digest = hashlib.sha256(
            json.dumps(
                canonical_documents,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        if computed_corpus_digest != corpus_digest:
            raise ValueError("governed document map does not match the configured corpus digest")
        queries = raw.get("queries")
        if not isinstance(queries, dict) or len(queries) > _MAX_CATALOG_ENTRIES:
            raise ValueError("query-vector catalog has an invalid query map")
        self._vectors: dict[str, tuple[float, ...]] = {}
        self._documents = canonical_documents
        for digest, value in queries.items():
            if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                raise ValueError("query-vector keys must be lowercase SHA-256 digests")
            if not isinstance(value, list) or len(value) != vector_size:
                raise ValueError("query vector has the wrong dimension")
            vector = tuple(float(item) for item in value)
            if not all(math.isfinite(item) for item in vector):
                raise ValueError("query vectors must contain only finite numbers")
            self._vectors[digest] = vector

    def resolve(self, query: str) -> list[float] | None:
        normalized = " ".join(query.casefold().split())
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        vector = self._vectors.get(digest)
        return list(vector) if vector is not None else None

    def document_is_governed(
        self,
        *,
        memory_id: str,
        content: str,
        source: str,
        version: str,
        license_name: str,
    ) -> bool:
        expected = self._documents.get(memory_id)
        if expected is None:
            return False
        return expected == {
            "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "source": source,
            "version": version,
            "license": license_name,
        }


class GovernedQdrantSearch:
    """Read-only Qdrant adapter that accepts only governed corpus records."""

    def __init__(
        self,
        *,
        url: str,
        collection_name: str,
        vectors: PrecomputedQueryVectors,
        corpus_digest: str,
        client: Any | None = None,
        request_timeout_seconds: float = 0.5,
    ) -> None:
        if not _SHA256.fullmatch(corpus_digest):
            raise ValueError("knowledge vector corpus digest must be a lowercase SHA-256")
        if client is None:
            try:
                from qdrant_client import QdrantClient  # type: ignore[import-not-found]
            except ImportError as exc:  # pragma: no cover - depends on optional extra
                raise RuntimeError("hybrid knowledge requires the qdrant optional dependency") from exc
            client = QdrantClient(
                url=url,
                timeout=max(1, min(5, math.ceil(request_timeout_seconds))),
            )
        self._client = client
        self._collection_name = collection_name
        self._vectors = vectors
        self._corpus_digest = corpus_digest

    def close(self) -> None:
        close = getattr(self._client, "close", None)
        if callable(close):
            close()

    def search(self, query: str, *, top_k: int, kind: str | None) -> list[KnowledgeHit]:
        vector = self._vectors.resolve(query)
        if vector is None:
            return []
        response = self._client.query_points(
            collection_name=self._collection_name,
            query=vector,
            limit=min(max(top_k * 2, top_k), 100),
            with_payload=True,
        )
        hits: list[KnowledgeHit] = []
        for point in getattr(response, "points", ()):
            payload = getattr(point, "payload", None)
            hit = self._validated_hit(payload, point, kind=kind)
            if hit is not None:
                hits.append(hit)
            if len(hits) >= top_k:
                break
        return hits

    def _validated_hit(self, payload: object, point: object, *, kind: str | None) -> KnowledgeHit | None:
        if not isinstance(payload, dict):
            return None
        metadata = payload.get("metadata")
        if not isinstance(metadata, dict):
            return None
        if (
            metadata.get("corpus_digest") != self._corpus_digest
            or metadata.get("source_verified") is not True
            or metadata.get("tombstoned") is True
        ):
            return None
        if kind is not None and payload.get("kind") != kind:
            return None
        content = payload.get("content")
        source = payload.get("source")
        version = payload.get("version")
        if (
            not isinstance(content, str)
            or not content.strip()
            or not isinstance(source, str)
            or not source.strip()
            or not isinstance(version, str)
            or not version.strip()
        ):
            return None
        if len(content) > _MAX_HIT_CONTENT_CHARS:
            return None
        memory_id = payload.get("memory_id")
        license_name = metadata.get("license")
        if (
            not isinstance(memory_id, str)
            or not isinstance(license_name, str)
            or str(getattr(point, "id", "")) != memory_id
            or not self._vectors.document_is_governed(
                memory_id=memory_id,
                content=content,
                source=source,
                version=version,
                license_name=license_name,
            )
        ):
            return None
        score = float(getattr(point, "score", 0.0))
        if not math.isfinite(score):
            return None
        score = max(0.0, min(1.0, score))
        return KnowledgeHit(
            memory_id=memory_id,
            content=content,
            source=source,
            version=version,
            confidence=score,
            metadata={
                "corpus_digest": self._corpus_digest,
                "source_verified": True,
                "license": license_name,
                "tombstoned": False,
                "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                "retrieval": "qdrant_read_only",
                "trusted_as_instructions": False,
            },
        )


class HybridKnowledgeStore(OfflineKnowledgeStore):
    """Offline-first retrieval with a bounded, read-only semantic candidate."""

    def __init__(
        self,
        offline: OfflineKnowledgeStore,
        semantic: GovernedQdrantSearch,
        *,
        timeout_seconds: float = 0.5,
    ) -> None:
        # This class intentionally subclasses the stable store interface while
        # delegating ownership; it must not create a second database engine.
        self._offline = offline
        self._semantic = semantic
        self.engine = offline.engine
        self._timeout_seconds = max(0.05, min(5.0, timeout_seconds))
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="secmind-qdrant")
        self._lock = Lock()
        self._inflight: Future[list[KnowledgeHit]] | None = None
        self._closed = False

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
        # Runtime writes remain in PostgreSQL.  Vector publication is an
        # independently governed, asynchronous C-group operation.
        return self._offline.upsert(
            content=content,
            source=source,
            version=version,
            content_hash=content_hash,
            kind=kind,
            verified=verified,
            trust_score=trust_score,
        )

    def search(self, query: str, *, top_k: int = 5, kind: str | None = None) -> list[KnowledgeHit]:
        offline_hits = self._offline.search(query, top_k=top_k, kind=kind)
        if top_k <= 0:
            return []
        with self._lock:
            if self._closed:
                return offline_hits
            if self._inflight is not None and not self._inflight.done():
                return offline_hits
            self._inflight = self._executor.submit(self._semantic.search, query, top_k=top_k, kind=kind)
            future = self._inflight
        try:
            semantic_hits = future.result(timeout=self._timeout_seconds)
        except TimeoutError:
            future.cancel()
            return offline_hits
        except Exception:
            future.cancel()
            return offline_hits
        finally:
            if future.done():
                with self._lock:
                    if self._inflight is future:
                        self._inflight = None
        merged: dict[str, KnowledgeHit] = {hit.memory_id: hit for hit in offline_hits}
        for hit in semantic_hits:
            current = merged.get(hit.memory_id)
            if current is not None and (current.content, current.source, current.version) != (
                hit.content,
                hit.source,
                hit.version,
            ):
                # A vector payload may not replace a PostgreSQL record merely
                # by claiming its identifier.
                continue
            if current is None or hit.confidence > current.confidence:
                merged[hit.memory_id] = hit
        return sorted(merged.values(), key=lambda item: (-item.confidence, item.memory_id))[: min(top_k, 100)]

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            inflight = self._inflight
        if inflight is not None:
            inflight.cancel()
        semantic_close = getattr(self._semantic, "close", None)
        if callable(semantic_close):
            semantic_close()
        self._executor.shutdown(wait=False, cancel_futures=True)
        self._offline.close()
