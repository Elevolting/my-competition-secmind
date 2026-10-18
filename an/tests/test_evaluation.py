from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from security_agent.evaluation import BenchmarkCatalog, EvaluationError, EvaluationStore
from security_agent.schemas import EvaluationJob, EvaluationMode, EvaluationStatus


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _make_dataset(root: Path) -> tuple[Path, str]:
    task_id = "T3S-005EB93054"
    public = root / "01_public" / "S-Suite"
    case = public / "cases" / task_id
    input_root = case / "input"
    input_root.mkdir(parents=True)
    subject = input_root / "subject.py"
    subject.write_text("print('safe')\n", encoding="utf-8")
    input_manifest = {
        "schema_version": "3.0",
        "files": [{"path": subject.name, "size_bytes": subject.stat().st_size, "sha256": _sha256(subject)}],
    }
    (case / "input_manifest.json").write_text(json.dumps(input_manifest), encoding="utf-8")
    task = {
        "task_id": task_id,
        "suite": "S-Suite",
        "dataset_version": "3.0.0-2026.07",
        "prompt": "Audit the input and produce evidence-backed findings.",
        "difficulty": "easy",
        "primary_domain": "code_audit_and_patch",
        "input": {"root": "input"},
        "required_output": {"scoring_mode": "security_finding"},
    }
    (case / "task.json").write_text(json.dumps(task), encoding="utf-8")
    manifest = {
        "suite": "S-Suite",
        "dataset_version": "3.0.0-2026.07",
        "cases": [{"task_id": task_id, "difficulty": "easy", "primary_domain": "code_audit_and_patch"}],
    }
    (public / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return public, task_id


def test_catalog_lists_and_stages_only_registered_public_input(settings, tmp_path: Path) -> None:
    dataset, task_id = _make_dataset(tmp_path / "dataset")
    settings.benchmark_dataset_root = dataset
    settings.prepare_directories()
    catalog = BenchmarkCatalog(settings)

    tasks = catalog.list_tasks()
    assert [item.task_id for item in tasks] == [task_id]
    assert tasks[0].input_file_count == 1

    request, digest = catalog.prepare_task(task_id, "evaluation-1")
    assert request.attachments[0].ref == f"benchmark/evaluation-1/{task_id}"
    assert (settings.input_root / request.attachments[0].ref / "subject.py").is_file()
    assert digest == _sha256(dataset / "cases" / task_id / "input_manifest.json")
    assert not (settings.input_root / request.attachments[0].ref / "task.json").exists()


def test_catalog_rejects_modified_registered_input(settings, tmp_path: Path) -> None:
    dataset, task_id = _make_dataset(tmp_path / "dataset")
    settings.benchmark_dataset_root = dataset
    subject = dataset / "cases" / task_id / "input" / "subject.py"
    subject.write_text("print('tampered')\n", encoding="utf-8")

    with pytest.raises(EvaluationError, match="immutable manifest"):
        BenchmarkCatalog(settings).prepare_task(task_id, "evaluation-2")


def test_evaluation_store_public_job_does_not_contain_private_paths(settings, tmp_path: Path) -> None:
    settings.benchmark_private_root = tmp_path / "private-gold"
    store = EvaluationStore(settings.evaluation_root)
    job = EvaluationJob(
        evaluation_id="evaluation-3",
        mode=EvaluationMode.BENCHMARK,
        benchmark_task_id="T3S-005EB93054",
        dataset_version=settings.benchmark_dataset_version,
        status=EvaluationStatus.SCORED,
        task_score=88.0,
    )
    store.save(job)

    exported = store.load(job.evaluation_id).model_dump_json()
    assert "private-gold" not in exported
    assert "benchmark_private_root" not in exported
