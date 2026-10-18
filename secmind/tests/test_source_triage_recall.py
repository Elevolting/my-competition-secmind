from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest


def _module() -> Any:
    path = Path("scripts/evaluate_source_triage_recall.py")
    spec = importlib.util.spec_from_file_location("evaluate_source_triage_recall", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


triage = _module()

SAFE = b"value = 1\n"
DANGEROUS = b"from flask import request\nimport os\nos.system(request.args['command'])\n"


def _input(root: Path, relative: str, content: bytes) -> dict[str, Any]:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return {
        "path": relative,
        "sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
        "media_type": "text/x-python",
    }


def _record(
    manifest_root: Path,
    *,
    task_id: str,
    case_name: str,
    vulnerable_paths: list[str] | None,
) -> dict[str, Any]:
    case = manifest_root / case_name
    case.mkdir()
    inputs = [
        _input(case, "aaa_safe.py", SAFE),
        _input(case, "zzz_logic.py", DANGEROUS),
    ]
    record: dict[str, Any] = {
        "task_id": task_id,
        "root": case_name,
        "objective": "Audit the repository",
        "inputs": inputs,
    }
    if vulnerable_paths is not None:
        record["metadata"] = {"vulnerable_paths": vulnerable_paths}
    return record


def test_manifest_comparison_is_stable_and_indexed_recall_improves(tmp_path: Path) -> None:
    record = _record(
        tmp_path,
        task_id="source-1",
        case_name="case",
        vulnerable_paths=["zzz_logic.py"],
    )
    manifest = tmp_path / "tasks.json"
    manifest.write_text(json.dumps({"tasks": [record]}), encoding="utf-8")
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"

    assert triage.main(["--manifest", str(manifest), "--k", "1", "--diagnostic", "--output", str(first)]) == 0
    assert triage.main(["--manifest", str(manifest), "--k", "1", "--diagnostic", "--output", str(second)]) == 0

    assert first.read_bytes() == second.read_bytes()
    result = json.loads(first.read_text(encoding="utf-8"))
    task = result["tasks"][0]
    assert task["legacy_top_k_paths"] == ["aaa_safe.py"]
    assert task["indexed_top_k_paths"] == ["zzz_logic.py"]
    assert task["legacy_hits"] == []
    assert task["indexed_hits"] == ["zzz_logic.py"]
    assert task["delta"] == 1.0
    assert result["aggregate"]["legacy_recall_at_k"] == 0.0
    assert result["aggregate"]["indexed_recall_at_k"] == 1.0
    assert result["aggregate"]["passed"] is True
    assert result["provenance"]["benchmark_commitment_sha256"]
    assert result["provenance"]["script_sha256"]


def test_exit_one_when_indexed_recall_regresses(tmp_path: Path) -> None:
    record = _record(
        tmp_path,
        task_id="source-regression",
        case_name="case",
        vulnerable_paths=["aaa_safe.py"],
    )
    manifest = tmp_path / "tasks.json"
    output = tmp_path / "result.json"
    manifest.write_text(json.dumps([record]), encoding="utf-8")

    assert triage.main(["--manifest", str(manifest), "--top-k", "1", "--diagnostic", "--output", str(output)]) == 1

    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["tasks"][0]["delta"] == -1.0
    assert result["aggregate"]["passed"] is False


def test_jsonl_supports_a_fixed_task_id_list_before_task_bound(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    first = _record(
        tmp_path,
        task_id="source-a",
        case_name="case-a",
        vulnerable_paths=["zzz_logic.py"],
    )
    second = _record(
        tmp_path,
        task_id="source-b",
        case_name="case-b",
        vulnerable_paths=["zzz_logic.py"],
    )
    manifest = tmp_path / "tasks.jsonl"
    manifest.write_text("\n".join(json.dumps(item) for item in (first, second)) + "\n", encoding="utf-8")
    output = tmp_path / "result.json"

    assert (
        triage.main(
            [
                "--manifest",
                str(manifest),
                "--task-ids",
                "source-b",
                "--max-tasks",
                "1",
                "--k",
                "1",
                "--diagnostic",
                "--output",
                str(output),
            ]
        )
        == 0
    )

    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["selection"] == {"mode": "explicit_task_ids", "task_ids": ["source-b"]}
    assert result["aggregate"]["task_count"] == 1

    assert triage.main(["--manifest", str(manifest), "--max-tasks", "1", "--k", "1", "--diagnostic"]) == 2
    assert "task limit exceeded" in capsys.readouterr().err


def test_public_dataset_layout_reads_ground_truth_from_case_metadata(tmp_path: Path) -> None:
    case = tmp_path / "cases" / "public-1"
    case.mkdir(parents=True)
    task = {
        "task_id": "public-1",
        "prompt": "Audit the repository",
        "inputs": [
            _input(case, "aaa_safe.py", SAFE),
            _input(case, "zzz_logic.py", DANGEROUS),
        ],
    }
    task_path = case / "task.json"
    task_path.write_text(json.dumps(task, sort_keys=True), encoding="utf-8")
    (case / "metadata.json").write_text(
        json.dumps({"expected_findings": [{"path": "zzz_logic.py", "cwe": "CWE-78"}]}),
        encoding="utf-8",
    )
    dataset = {
        "task_count": 1,
        "cases": [
            {
                "task_id": "public-1",
                "task_sha256": hashlib.sha256(task_path.read_bytes()).hexdigest(),
            }
        ],
    }
    (tmp_path / "dataset.json").write_text(json.dumps(dataset), encoding="utf-8")
    output = tmp_path / "result.json"

    assert triage.main(["--public-dir", str(tmp_path), "--k", "1", "--diagnostic", "--output", str(output)]) == 0

    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["tasks"][0]["ground_truth_paths"] == ["zzz_logic.py"]
    assert result["aggregate"]["file_count"] == 2
    assert result["aggregate"]["input_bytes"] == len(SAFE) + len(DANGEROUS)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda record: record["inputs"].append({"path": "AAA_SAFE.py"}), "duplicate input paths"),
        (lambda record: record["inputs"].__setitem__(0, {"path": "../escape.py"}), "traversal"),
        (lambda record: record.pop("metadata"), "missing vulnerable-path ground truth"),
        (
            lambda record: record["metadata"].__setitem__("vulnerable_paths", ["zzz_logic.py", "ZZZ_LOGIC.py"]),
            "duplicate ground-truth paths",
        ),
    ],
)
def test_rejects_unsafe_or_unscorable_metadata(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    mutation: Any,
    message: str,
) -> None:
    record = _record(
        tmp_path,
        task_id="invalid",
        case_name="case",
        vulnerable_paths=["zzz_logic.py"],
    )
    mutation(record)
    manifest = tmp_path / "tasks.json"
    manifest.write_text(json.dumps([record]), encoding="utf-8")

    assert triage.main(["--manifest", str(manifest), "--k", "1", "--diagnostic"]) == 2

    assert message in capsys.readouterr().err


def test_enforces_file_and_byte_limits(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    record = _record(
        tmp_path,
        task_id="bounded",
        case_name="case",
        vulnerable_paths=["zzz_logic.py"],
    )
    manifest = tmp_path / "tasks.json"
    manifest.write_text(json.dumps([record]), encoding="utf-8")

    assert triage.main(["--manifest", str(manifest), "--max-files", "1", "--k", "1", "--diagnostic"]) == 2
    assert "input file limit exceeded" in capsys.readouterr().err
    assert (
        triage.main(
            [
                "--manifest",
                str(manifest),
                "--max-bytes",
                str(len(SAFE) + len(DANGEROUS) - 1),
                "--k",
                "1",
                "--diagnostic",
            ]
        )
        == 2
    )
    assert "input byte limit exceeded" in capsys.readouterr().err


def test_datasetless_one_level_case_discovery_uses_real_fallback(tmp_path: Path) -> None:
    case = tmp_path / "one-level-case"
    case.mkdir()
    task = {
        "task_id": "fallback-case",
        "objective": "Audit the repository",
        "inputs": [_input(case, "zzz_logic.py", DANGEROUS)],
    }
    (case / "task.json").write_text(json.dumps(task), encoding="utf-8")
    (case / "metadata.json").write_text(
        json.dumps({"vulnerable_paths": ["zzz_logic.py"]}),
        encoding="utf-8",
    )

    tasks, _budget = triage.load_benchmark_directory(
        tmp_path,
        selected=None,
        limits=triage.Limits(max_tasks=10, max_files=10, max_bytes=10_000),
    )

    assert [item.task_id for item in tasks] == ["fallback-case"]


def test_macro_gain_cannot_hide_vulnerable_file_micro_recall_regression(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def artifact(path: str) -> Any:
        content = path.encode()
        return triage.InputArtifact(
            artifact_id=f"artifact-{path}",
            original_name=path,
            relative_path=path,
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
            media_type="text/plain",
        )

    a_vulnerable = [f"a_v{index}.py" for index in range(10)]
    a_safe = ["a_safe0.py", "a_safe1.py"]
    task_a = triage.BenchmarkTask(
        task_id="task-a",
        objective="audit",
        workspace=tmp_path,
        artifacts=tuple(artifact(path) for path in [*a_vulnerable, *a_safe]),
        vulnerable_paths=tuple(a_vulnerable),
    )
    task_b = triage.BenchmarkTask(
        task_id="task-b",
        objective="audit",
        workspace=tmp_path,
        artifacts=(artifact("b_v.py"), artifact("b_safe0.py"), artifact("b_safe1.py")),
        vulnerable_paths=("b_v.py",),
    )

    class FakeIndexer:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def build(self, *_args: Any, **_kwargs: Any) -> object:
            return object()

        def load(self, *_args: Any, **_kwargs: Any) -> Any:
            paths = [*a_vulnerable, *a_safe, "b_v.py", "b_safe0.py", "b_safe1.py"]
            return SimpleNamespace(
                format_version=triage.INDEX_FORMAT_VERSION,
                files=[SimpleNamespace(path=path) for path in paths],
            )

    legacy_order = {
        **{path: index for index, path in enumerate(a_vulnerable)},
        "a_safe0.py": 20,
        "a_safe1.py": 21,
        "b_safe0.py": 0,
        "b_safe1.py": 1,
        "b_v.py": 2,
    }
    indexed_order = {
        "a_safe0.py": 0,
        "a_safe1.py": 1,
        **{path: index + 2 for index, path in enumerate(a_vulnerable)},
        "b_v.py": 0,
        "b_safe0.py": 1,
        "b_safe1.py": 2,
    }
    monkeypatch.setattr(triage, "RepositoryIndexer", FakeIndexer)
    monkeypatch.setattr(triage, "_path_priority", lambda item, _objective: (legacy_order[item.relative_path], 0, ""))
    monkeypatch.setattr(
        triage,
        "_indexed_path_priority",
        lambda item, _objective, _entries: (indexed_order[item.relative_path], 0, ""),
    )

    result = triage.evaluate_tasks(
        [task_a, task_b],
        k=2,
        limits=triage.Limits(max_tasks=10, max_files=100, max_bytes=10_000),
        budget=triage.InputBudget(triage.Limits(max_tasks=10, max_files=100, max_bytes=10_000)),
        selected=("task-a", "task-b"),
        diagnostic=True,
    )

    assert result["aggregate"]["macro_passed"] is True
    assert result["aggregate"]["micro_passed"] is False
    assert result["aggregate"]["passed"] is False


def test_release_mode_rejects_arbitrary_k_and_trivial_single_task(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    record = _record(
        tmp_path,
        task_id="release-trivial",
        case_name="case",
        vulnerable_paths=["zzz_logic.py"],
    )
    manifest = tmp_path / "tasks.json"
    manifest.write_text(json.dumps([record]), encoding="utf-8")

    assert triage.main(["--manifest", str(manifest), "--task-id", "release-trivial", "--k", "1"]) == 2
    assert "release acceptance fixes k" in capsys.readouterr().err
    assert triage.main(["--manifest", str(manifest), "--task-id", "release-trivial", "--k", "10"]) == 2
    assert "requires at least" in capsys.readouterr().err
