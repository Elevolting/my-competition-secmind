from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.canonical_primary import _build_canonical_context_legacy as build_canonical_context
from secmind.external_skills import ExternalSkillCatalog, SkillRuntime
from secmind.repository_index import (
    INDEX_FORMAT_VERSION,
    LEGACY_INDEX_FORMAT_VERSION,
    RepositoryIndexer,
    repository_index_metadata,
    repository_planning_view,
)
from secmind.schemas import InputArtifact, RepositoryIndexRef, Scenario, TaskRequest
from secmind.skill_registry import SkillRegistry
from secmind.source_triage import (
    MAX_TRIAGE_CONTENT_CHARS,
    source_triage_sort_key,
    triage_javascript_typescript,
    triage_source,
)


def _artifact(store: ContentAddressedArtifactStore, root: Path, relative: str, content: bytes) -> InputArtifact:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    stored = store.put(content, run_id="run-triage", media_type="text/plain")
    return InputArtifact(
        artifact_id=stored.artifact_id,
        original_name=target.name,
        relative_path=relative,
        sha256=stored.sha256,
        size_bytes=stored.size_bytes,
        media_type="text/plain",
    )


def test_repository_index_v2_persists_bounded_routing_metadata_and_loads_v1(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text(
        "from flask import request\nimport os\nos.system(request.args['command'])\n",
        encoding="utf-8",
    )
    (workspace / "README.md").write_text("documentation", encoding="utf-8")
    store = ContentAddressedArtifactStore(tmp_path / "artifacts")
    indexer = RepositoryIndexer(store)

    reference = indexer.build("run-v2", workspace)
    document = indexer.load(reference, run_id="run-v2")

    assert document.format_version == INDEX_FORMAT_VERSION
    app = next(item for item in document.files if item.path == "app.py")
    readme = next(item for item in document.files if item.path == "README.md")
    assert app.security_score > readme.security_score
    assert {"source:http-input", "sink:command"}.issubset(app.security_signals)
    assert len(app.security_signals) <= 16
    prompt_metadata = json.dumps(repository_index_metadata(document), sort_keys=True)
    assert "security_score" not in prompt_metadata
    assert "security_signals" not in prompt_metadata

    legacy_payload = document.model_dump(mode="json")
    legacy_payload["format_version"] = LEGACY_INDEX_FORMAT_VERSION
    for entry in legacy_payload["files"]:
        entry.pop("security_score")
        entry.pop("security_signals")
    legacy_bytes = json.dumps(
        legacy_payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    stored = store.put(legacy_bytes, run_id="run-v1")
    legacy_ref = RepositoryIndexRef(
        run_id="run-v1",
        artifact_id=stored.artifact_id,
        digest=stored.sha256,
        file_count=document.file_count,
        total_bytes=document.total_bytes,
        languages=sorted(document.languages),
        dependency_files=document.dependency_files,
    )

    loaded = indexer.load(legacy_ref, run_id="run-v1")

    assert loaded.format_version == LEGACY_INDEX_FORMAT_VERSION
    assert all(item.security_score == 0 and item.security_signals == [] for item in loaded.files)


def test_canonical_primary_uses_snapshot_ranking_without_workspace_reread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = ContentAddressedArtifactStore(tmp_path / "artifacts")
    safe = _artifact(store, workspace, "aaa_safe.py", b"value = 1\n")
    dangerous = _artifact(
        store,
        workspace,
        "zzz_logic.py",
        b"from flask import request\nimport os\nos.system(request.args['command'])\n",
    )
    artifacts = [safe, dangerous]
    indexer = RepositoryIndexer(store)
    reference = indexer.build("run-triage", workspace, artifacts)
    document = indexer.load(reference, run_id="run-triage")
    original_read_bytes = Path.read_bytes

    def deny_workspace_reads(path: Path) -> bytes:
        if path.resolve().is_relative_to(workspace.resolve()):
            raise AssertionError("canonical routing reread the mutable workspace")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", deny_workspace_reads)
    task = TaskRequest(objective="Audit the repository", autonomy_policy="automatic")
    _legacy_contract, legacy_views = build_canonical_context(
        task_id="legacy-order",
        task=task,
        scenario=Scenario.CODE_AUDIT,
        workspace=workspace,
        artifacts=artifacts,
        content_loader=store.read,
        max_context_bytes=256,
    )
    _contract, indexed_views = build_canonical_context(
        task_id="indexed-order",
        task=task,
        scenario=Scenario.CODE_AUDIT,
        workspace=workspace,
        artifacts=artifacts,
        content_loader=store.read,
        repository_index=document,
        max_context_bytes=256,
    )

    assert legacy_views[0].path == "aaa_safe.py"
    assert indexed_views[0].path == "zzz_logic.py"
    assert "os.system" in indexed_views[0].content


def test_source_triage_has_hard_content_and_path_bounds() -> None:
    after_window = "x" * MAX_TRIAGE_CONTENT_CHARS + "\nos.system(user_input)"
    result = triage_source(
        ".config/app.py",
        text=after_window,
        language="python",
        dependency_manifest=False,
        generated=False,
        test_file=False,
        vendor=False,
    )

    assert "sink:command" not in result.signals
    assert source_triage_sort_key(score=result.score, size_bytes=1, path=".config/app.py")[2] == ".config/app.py"
    with pytest.raises(ValueError, match="safe relative path"):
        triage_source(
            "../escape.py",
            text="",
            language="python",
            dependency_manifest=False,
            generated=False,
            test_file=False,
            vendor=False,
        )


def test_javascript_source_triage_tracks_import_aliases_and_request_destructuring() -> None:
    source = """
    const { readFile: load } = require('fs');
    router.get('/download', (request, response) => {
        const { params: { file } } = request;
        return load(file);
    });
    """

    analysis = triage_javascript_typescript(source)

    assert analysis.imports == ("fs",)
    assert "load=fs.readFile" in analysis.aliases
    assert "file=request.params.file" in analysis.aliases
    assert any(flow.kind == "path" and flow.source == "request.params.file" for flow in analysis.flows)


def test_javascript_source_triage_masks_comments_and_literals() -> None:
    source = """
    // child_process.exec(req.query.cmd)
    const example = "fs.readFile(req.params.file)";
    function safe(value) { return value; }
    """

    result = triage_source(
        "src/safe.ts",
        text=source,
        language="typescript",
        dependency_manifest=False,
        generated=False,
        test_file=False,
        vendor=False,
    )

    assert result.flows == ()
    assert "sink:command" not in result.signals
    assert "sink:file" not in result.signals


def test_repository_planning_view_retains_identity_and_routing_metadata_without_source(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "app.ts"
    content = "import { readFile as load } from 'fs';\nexport function run(req) { return load(req.params.file); }\n"
    source.write_text(content, encoding="utf-8")
    indexer = RepositoryIndexer(ContentAddressedArtifactStore(tmp_path / "artifacts"))
    document = indexer.load(indexer.build("unused", workspace), run_id="unused")

    view = repository_planning_view(document)
    entry = view["files"][0]
    serialized = json.dumps(view, sort_keys=True)

    assert entry["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert "fs" in entry["imports"]
    assert any(item.startswith("alias:") for item in entry["symbols"])
    assert "readFile as load" not in serialized
    assert len(view["planning_digest"]) == 64


def test_source_signals_only_reorder_signed_skills() -> None:
    signed = SkillRegistry.builtin()
    signed.discover()
    runtime = SkillRuntime(signed, ExternalSkillCatalog.builtin())
    baseline = runtime.select_run(
        objective="Audit the repository",
        scenario=Scenario.CODE_AUDIT,
        languages={"python"},
        capabilities={"sast"},
    )
    routed = runtime.select_run(
        objective="Audit the repository",
        scenario=Scenario.CODE_AUDIT,
        languages={"python"},
        capabilities={"sast"},
        source_signals={"source:route", "authz:check"},
    )

    assert baseline.signed[0].skill_id != "web-auth-review"
    assert routed.signed[0].skill_id == "web-auth-review"
    assert routed.external == baseline.external
