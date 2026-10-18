from __future__ import annotations

import hashlib
import time
from types import SimpleNamespace

import pytest

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.canonical_primary import (
    UniversalPrimaryAnswer,
    UniversalPrimaryReviewer,
    canonical_user_prompt,
)
from secmind.canonical_primary import (
    _build_canonical_context_legacy as build_canonical_context,
)
from secmind.context_expansion import (
    SemanticSliceBudget,
    SemanticSliceError,
    SemanticSliceQuery,
    expand_semantic_slice,
)
from secmind.llm import ModelCallMeta
from secmind.repository_index import INDEX_FORMAT_VERSION, RepositoryFileEntry, RepositoryIndexDocument
from secmind.schemas import InputArtifact, ModelUsage, Scenario, TaskRequest


def _manifest_and_blobs(
    files: dict[str, bytes],
) -> tuple[list[dict[str, object]], dict[str, bytes]]:
    manifest: list[dict[str, object]] = []
    blobs: dict[str, bytes] = {}
    for path, payload in files.items():
        digest = hashlib.sha256(payload).hexdigest()
        blobs[digest] = payload
        manifest.append(
            {
                "path": path,
                "sha256": digest,
                "size_bytes": len(payload),
                "media_type": "text/plain",
            }
        )
    return manifest, blobs


def _python_corpus() -> dict[str, bytes]:
    return {
        "app/runner.py": (b"import os\ndef execute(cmd):\n    os.system(cmd)\n"),
        "app/helper.py": (
            b"from .runner import execute\ndef normalize(value):\n    execute(value)\n    return value\n"
        ),
        "app/entry.py": (
            b"from .helper import normalize\n"
            b"def handle(request):\n"
            b"    raw = request.args.get('cmd')\n"
            b"    value = normalize(raw)\n"
            b"    return value\n"
        ),
    }


def test_python_cross_file_import_call_and_data_flow_recall_is_cas_bound() -> None:
    manifest, blobs = _manifest_and_blobs(_python_corpus())
    first = expand_semantic_slice(
        input_manifest=manifest,
        source_bytes=blobs,
        query=SemanticSliceQuery.sink("os.system"),
    )
    second = expand_semantic_slice(
        input_manifest=list(reversed(manifest)),
        source_bytes=blobs,
        query=SemanticSliceQuery.sink("os.system"),
    )

    assert first.digest == second.digest
    assert set(first.files) == set(_python_corpus())
    relations = {(edge.relation, edge.source_path, edge.target_path) for edge in first.edges}
    assert ("imports", "app/entry.py", "app/helper.py") in relations
    assert ("imports", "app/helper.py", "app/runner.py") in relations
    assert ("calls", "app/entry.py", "app/helper.py") in relations
    assert ("calls", "app/helper.py", "app/runner.py") in relations
    assert any(
        edge.relation == "data_flow" and edge.source_path == "app/entry.py" and edge.target_path == "app/runner.py"
        for edge in first.edges
    )
    assert first.coverage.source_count > 0
    assert first.coverage.sink_count == 1
    assert all(ref.cas_ref.startswith("cas://sha256/") for ref in first.source_refs)
    assert all(node.cas_ref.startswith("cas://sha256/") for node in first.nodes)


@pytest.mark.parametrize(
    ("files", "sink"),
    [
        (
            {
                "app/runner.js": (b"import { exec } from 'child_process';\nexport function run(cmd) { exec(cmd); }\n"),
                "app/helper.js": (
                    b"import { run } from './runner';\nexport function normalize(value) { return run(value); }\n"
                ),
                "app/entry.js": (
                    b"import { normalize } from './helper';\n"
                    b"export function handle(req) { const raw = req.query.cmd; "
                    b"const value = normalize(raw); return value; }\n"
                ),
            },
            "exec",
        ),
        (
            {
                "app/Runner.java": (
                    b"package app; import app.Helper; public class Runner { "
                    b"public void run(String cmd) { Runtime.getRuntime().exec(cmd); } }"
                ),
                "app/Helper.java": (
                    b"package app; import app.Runner; public class Helper { "
                    b"public void normalize(String value) { Runner r = new Runner(); "
                    b"r.run(value); } }"
                ),
                "app/Entry.java": (
                    b"package app; import app.Helper; public class Entry { "
                    b"public void handle(String request) { Helper h = new Helper(); "
                    b"h.normalize(request); } }"
                ),
            },
            "exec",
        ),
    ],
)
def test_js_ts_and_java_adapters_keep_cross_file_sink_paths(files: dict[str, bytes], sink: str) -> None:
    manifest, blobs = _manifest_and_blobs(files)
    result = expand_semantic_slice(
        input_manifest=manifest,
        source_bytes=blobs,
        query=SemanticSliceQuery.sink(sink),
    )

    assert result.coverage.sink_count == 1
    assert len(result.files) == 3
    assert any(edge.relation == "imports" for edge in result.edges)
    assert any(edge.relation == "calls" for edge in result.edges)
    assert any(edge.relation == "data_flow" for edge in result.edges)
    assert not any(item.code == "parse_error" for item in result.unresolved)


def test_java_servlet_semantic_expansion_is_bounded_and_keeps_methods() -> None:
    source = b"""package evaluation.subject;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class Subject extends HttpServlet {
    private static final long serialVersionUID = 1L;
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String[] values = request.getParameterValues("Subject");
        String param = values != null ? values[0] : "";
        String bar = doSomething(request, param);
        String fileName = org.example.Utils.TESTFILES_DIR + bar;
        java.io.FileOutputStream fos = new java.io.FileOutputStream(
                new java.io.FileInputStream(fileName).getFD());
        response.getWriter().println(fileName);
    }
    private static String doSomething(HttpServletRequest request, String param)
            throws Exception {
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add("safe");
        valuesList.add(param);
        valuesList.add("moresafe");
        valuesList.remove(0);
        return valuesList.get(1);
    }
}
"""
    manifest, blobs = _manifest_and_blobs({"subject.java": source})

    started = time.perf_counter()
    result = expand_semantic_slice(
        input_manifest=manifest,
        source_bytes=blobs,
        query=SemanticSliceQuery.task("read-only security audit"),
    )
    elapsed = time.perf_counter() - started

    assert elapsed < 2.0
    assert result.coverage.parsed_files == 1
    assert {node.name for node in result.nodes if node.kind == "symbol"} >= {
        "Subject",
        "doPost",
        "doSomething",
    }


def test_sanitized_negative_does_not_become_direct_sink_data_flow() -> None:
    files = {
        "app/unsafe.py": (
            b"import os\nimport shlex\n"
            b"def run(request):\n"
            b"    raw = request.args.get('cmd')\n"
            b"    safe = shlex.quote(raw)\n"
            b"    os.system(safe)\n"
        )
    }
    manifest, blobs = _manifest_and_blobs(files)
    result = expand_semantic_slice(
        input_manifest=manifest,
        source_bytes=blobs,
        query=SemanticSliceQuery.sink("os.system"),
    )
    sink_ids = {node.node_id for node in result.nodes if node.kind == "sink"}

    assert sink_ids
    assert any(edge.relation == "sanitized" for edge in result.edges)
    assert not any(edge.relation == "data_flow" and edge.target in sink_ids for edge in result.edges)


@pytest.mark.parametrize(
    "query",
    [SemanticSliceQuery.call("normalize"), SemanticSliceQuery.dataflow("raw")],
)
def test_symbol_call_and_dataflow_queries_keep_typed_graph_edges(query: SemanticSliceQuery) -> None:
    manifest, blobs = _manifest_and_blobs(_python_corpus())
    result = expand_semantic_slice(
        input_manifest=manifest,
        source_bytes=blobs,
        query=query,
    )

    assert result.query == query
    assert result.nodes
    assert any(edge.relation in {"calls", "data_flow"} for edge in result.edges)


def test_manifest_and_cas_are_strict_and_never_fall_back_to_workspace() -> None:
    payload = b"import os\nos.system(user_input)\n"
    manifest, _blobs = _manifest_and_blobs({"app/main.py": payload})
    missing = expand_semantic_slice(
        input_manifest=manifest,
        source_bytes={},
        query=SemanticSliceQuery.sink("os.system"),
    )

    assert missing.coverage.parsed_files == 0
    assert any(item.code == "cas_missing" for item in missing.unresolved)
    with pytest.raises(SemanticSliceError):
        expand_semantic_slice(
            input_manifest=[{**manifest[0], "path": "../main.py"}],
            source_bytes={},
            query=SemanticSliceQuery.task("audit"),
        )


def test_budget_truncation_and_query_factories_are_deterministic() -> None:
    manifest, blobs = _manifest_and_blobs(_python_corpus())
    budget = SemanticSliceBudget(max_files=1, max_nodes=64, max_edges=64)
    first = expand_semantic_slice(
        input_manifest=manifest,
        source_bytes=blobs,
        query=SemanticSliceQuery.task("command sink"),
        budget=budget,
    )
    second = expand_semantic_slice(
        input_manifest=manifest,
        source_bytes=blobs,
        query=SemanticSliceQuery.task("command sink"),
        budget=budget,
    )

    assert first.digest == second.digest
    assert first.coverage.parsed_files == 1
    assert first.truncated
    assert "files" in first.truncation_reasons
    assert SemanticSliceQuery.task("audit").kind == "task"
    assert SemanticSliceQuery.gap("missing binding").kind == "gap"
    assert SemanticSliceQuery.symbol("handle").kind == "symbol"
    assert SemanticSliceQuery.sink("os.system").kind == "sink"
    assert SemanticSliceQuery.call("normalize").kind == "call"
    assert SemanticSliceQuery.dataflow("raw").kind == "dataflow"
    assert SemanticSliceQuery.data_flow("raw").kind == "dataflow"


class _RecordingPrimaryGateway:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.settings = SimpleNamespace(max_input_tokens=20_000, model_timeout_seconds=30.0)

    async def structured(self, **kwargs: object):
        self.calls.append(kwargs)
        return (
            UniversalPrimaryAnswer(
                task_id="wrong-task-id",
                status="insufficient_evidence",
                limitations=["bounded integration fixture"],
            ),
            ModelCallMeta(
                model_id="mock-primary",
                prompt_version=str(kwargs["prompt_version"]),
                response_sha256="e" * 64,
                duration_ms=1,
                used_fallback=False,
                usage=ModelUsage(provider_requests=1, input_tokens=1, output_tokens=1),
            ),
        )


@pytest.mark.asyncio
async def test_canonical_primary_main_chain_uses_cas_semantic_slice_once(tmp_path) -> None:
    files = {
        "app/entry.py": (
            b"from .helper import normalize\n"
            b"def handle(request):\n"
            b"    raw = request.args.get('cmd')\n"
            b"    return normalize(raw)\n"
        ),
        "app/helper.py": (b"from .runner import execute\ndef normalize(value):\n    return execute(value)\n"),
        "app/runner.py": (b"import os\ndef execute(cmd):\n    os.system(cmd)\n"),
    }
    artifacts: list[InputArtifact] = []
    entries: list[RepositoryFileEntry] = []
    store = ContentAddressedArtifactStore(tmp_path / "cas")
    for path, payload in files.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        stored = store.put(payload, run_id="semantic-primary-run", media_type="text/x-python")
        digest = stored.sha256
        artifacts.append(
            InputArtifact(
                original_name=target.name,
                relative_path=path,
                sha256=digest,
                size_bytes=len(payload),
                media_type="text/x-python",
            )
        )
        entries.append(
            RepositoryFileEntry(
                path=path,
                size_bytes=len(payload),
                sha256=digest,
                media_type="text/x-python",
                language="python",
                dangerous_apis=["os.system"] if path.endswith("runner.py") else [],
                security_score=100 if path.endswith("runner.py") else 0,
            )
        )
    document = RepositoryIndexDocument(
        format_version=INDEX_FORMAT_VERSION,
        files=entries,
        file_count=len(entries),
        total_bytes=sum(item.size_bytes for item in entries),
    )

    contract, views = build_canonical_context(
        task_id="semantic-primary-chain",
        task=TaskRequest(objective="Audit the Python command flow", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        workspace=tmp_path,
        artifacts=artifacts,
        max_context_bytes=8_192,
        content_loader=store.read,
        repository_index=document,
    )

    assert contract.semantic_slice_digest
    assert contract.semantic_slice_bytes <= contract.semantic_slice_budget["max_bytes"]
    assert {edge["relation"] for edge in contract.semantic_context_edges} >= {"calls", "data_flow"}
    prompt = canonical_user_prompt(contract, views)
    assert "<DETERMINISTIC_SEMANTIC_SLICE_JSON>" in prompt
    assert "app/helper.py" in prompt and "os.system(cmd)" in prompt
    assert any("<SEMANTIC_NODE_JSON>" in view.content for view in views)

    reversed_contract, reversed_views = build_canonical_context(
        task_id="semantic-primary-chain",
        task=TaskRequest(objective="Audit the Python command flow", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        workspace=tmp_path,
        artifacts=list(reversed(artifacts)),
        max_context_bytes=8_192,
        content_loader=store.read,
        repository_index=document,
    )
    assert reversed_contract.context_sha256 == contract.context_sha256
    assert reversed_contract.semantic_slice_digest == contract.semantic_slice_digest
    assert canonical_user_prompt(reversed_contract, reversed_views) == prompt

    def missing_cas(_digest: str) -> bytes:
        raise KeyError("CAS object unavailable")

    unresolved_contract, unresolved_views = build_canonical_context(
        task_id="semantic-primary-cas-gap",
        task=TaskRequest(objective="Audit the Python command flow", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        workspace=tmp_path,
        artifacts=artifacts,
        max_context_bytes=8_192,
        content_loader=missing_cas,
        repository_index=document,
    )
    assert unresolved_views == []
    assert any(item["code"] == "cas_missing" for item in unresolved_contract.semantic_slice_unresolved)
    assert "cas_missing" in canonical_user_prompt(unresolved_contract, unresolved_views)

    gateway = _RecordingPrimaryGateway()
    result = await UniversalPrimaryReviewer(gateway).review(
        contract=contract,
        views=views,
        run_id="semantic-primary-run",
    )
    assert result.answer.task_id == "semantic-primary-chain"
    assert len(gateway.calls) == 1
    assert "app/helper.py" in str(gateway.calls[0]["user_prompt"])
