from __future__ import annotations

import hashlib
from pathlib import Path

from secmind.canonical_primary import _build_canonical_context_legacy as build_canonical_context
from secmind.context_expansion import build_semantic_context_plan
from secmind.repository_index import INDEX_FORMAT_VERSION, RepositoryFileEntry, RepositoryIndexDocument
from secmind.schemas import InputArtifact, Scenario, TaskRequest


def _entry(path: str, *, imports: list[str] | None = None, score: int = 0) -> RepositoryFileEntry:
    payload = path.encode()
    return RepositoryFileEntry(
        path=path,
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        media_type="text/plain",
        language="python",
        imports=imports or [],
        security_score=score,
        security_signals=["dangerous-api"] if score else [],
    )


def _document() -> RepositoryIndexDocument:
    files = [
        _entry("aaa/noise.py"),
        _entry("src/db.py"),
        _entry("src/handler.py", imports=["src.service"], score=100),
        _entry("src/service.py", imports=["src.db"]),
    ]
    return RepositoryIndexDocument(
        format_version=INDEX_FORMAT_VERSION,
        files=files,
        file_count=len(files),
        total_bytes=sum(item.size_bytes for item in files),
    )


def test_semantic_context_expands_two_hops_from_security_anchor() -> None:
    plan = build_semantic_context_plan(
        _document(),
        available_paths={"aaa/noise.py", "src/db.py", "src/handler.py", "src/service.py"},
    )

    assert plan.anchor_paths == ("src/handler.py",)
    assert plan.ordered_paths[:3] == ("src/handler.py", "src/service.py", "src/db.py")
    assert plan.ordered_paths[-1] == "aaa/noise.py"
    assert {(edge["source"], edge["target"]) for edge in plan.edges} == {
        ("src/handler.py", "src/service.py"),
        ("src/service.py", "src/db.py"),
    }


def test_canonical_context_binds_semantic_order_and_edges(tmp_path: Path) -> None:
    document = _document()
    artifacts: list[InputArtifact] = []
    for path in ("aaa/noise.py", "src/db.py", "src/handler.py", "src/service.py"):
        payload = (f"# {path}\n" + "x = 1\n" * 30).encode()
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        artifacts.append(
            InputArtifact(
                original_name=target.name,
                relative_path=path,
                sha256=hashlib.sha256(payload).hexdigest(),
                size_bytes=len(payload),
                media_type="text/x-python",
            )
        )

    contract, views = build_canonical_context(
        task_id="semantic-context",
        task=TaskRequest(objective="Audit the request flow for security defects"),
        scenario=Scenario.CODE_AUDIT,
        workspace=tmp_path,
        artifacts=artifacts,
        repository_index=document,
    )

    assert [view.path for view in views][:3] == ["src/handler.py", "src/service.py", "src/db.py"]
    assert contract.semantic_context_edges
    assert contract.context_sha256
