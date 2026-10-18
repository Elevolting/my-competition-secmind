from __future__ import annotations

import json
from pathlib import Path

from secmind_dev.release_evaluation import (
    ArtifactRef,
    CandidateManifest,
    RunLedger,
    RunRecord,
    aggregate_paired_runs,
    build_candidate_manifest,
    paired_sign_test,
    randomized_blocks,
    release_report,
)


def _manifest() -> CandidateManifest:
    artifact = ArtifactRef("artifact", "dist/artifact", "a" * 64, 1, "1")
    return CandidateManifest(
        candidate_id="candidate",
        candidate_version="1",
        agent_git_sha="b" * 40,
        agent_tree_sha256="c" * 40,
        agent_git_dirty=False,
        agent_status_sha256="d" * 64,
        working_tree_sha256="e" * 64,
        wheel=ArtifactRef("wheel", "dist/a.whl", "f" * 64, 10, "1"),
        sdist=ArtifactRef("sdist", "dist/a.tar.gz", "1" * 64, 10, "1"),
        bridge=artifact,
        adapter=ArtifactRef("adapter", "adapter.py", "2" * 64, 10, "1"),
        profile="offline",
        effective_env={"SAFE_FLAG": "1", "API_KEY": "must-not-survive"},
        model_parameters={"temperature": 0},
        prompt_lineage={"compiler": "prompt-v1", "selection_digest": "3" * 64},
        scorer_sha256="4" * 64,
        task_set_sha256="5" * 64,
        dependency_sha256="6" * 64,
        lockfile_sha256="7" * 64,
    )


def _rows(manifest: CandidateManifest) -> list[RunRecord]:
    plan = randomized_blocks(["direct", "agent"], ["a", "b"], block_count=5, seed=11)
    result: list[RunRecord] = []
    for block in plan:
        for arm in ("direct", "agent"):
            for task_id in ("a", "b"):
                result.append(
                    RunRecord(
                        run_id=f"{arm}-{block.block}-{task_id}",
                        arm=arm,
                        block=block.block,
                        task_id=task_id,
                        domain="logs" if task_id == "a" else "code",
                        score=50 if arm == "direct" else 60,
                        correct=True,
                        manifest_digest=manifest.manifest_digest,
                        tool_accepted_delta_count=0 if arm == "direct" else 1,
                        eirs_accepted_delta_count=0 if arm == "direct" else 1,
                    )
                )
    return result


def test_manifest_is_secret_free_and_round_trips_exactly() -> None:
    manifest = _manifest()
    payload = manifest.to_dict()
    assert payload["effective_env"] == {"SAFE_FLAG": "1"}
    assert "must-not-survive" not in json.dumps(payload)
    restored = CandidateManifest.from_dict(payload)
    assert restored.manifest_digest == manifest.manifest_digest
    assert restored.to_dict() == manifest.to_dict()


def test_manifest_without_git_marks_provenance_unavailable(tmp_path: Path) -> None:
    manifest = build_candidate_manifest(tmp_path, candidate_id="source-only", candidate_version="1")
    assert manifest.agent_git_sha == "UNKNOWN"
    assert manifest.agent_tree_sha256 == "UNKNOWN"
    assert manifest.agent_status_sha256 == "UNKNOWN"
    assert manifest.working_tree_sha256 == "UNKNOWN"
    assert manifest.agent_git_dirty is True
    assert "agent_tree_dirty" in manifest.verify(require_artifacts=False)["blockers"]


def test_ledger_preserves_failure_and_verifies_hash_chain(tmp_path: Path) -> None:
    path = tmp_path / "runs.jsonl"
    ledger = RunLedger(path)
    ledger.append(RunRecord("ok", "direct", 1, "T1", score=10))
    ledger.record_failure(run_id="bad", arm="agent", block=1, task_id="T1", failure_type="timeout")
    assert ledger.verify()["valid"] is True
    assert [item.status for item in ledger.records] == ["SUCCESS", "FAILED"]
    loaded = RunLedger.load(path)
    assert loaded.verify()["event_count"] == 2
    assert loaded.records[-1].failure_type == "timeout"


def test_randomization_has_five_blocks_and_is_reproducible() -> None:
    first = randomized_blocks(["direct", "agent"], ["T1", "T2"], block_count=5, seed=99)
    second = randomized_blocks(["direct", "agent"], ["T1", "T2"], block_count=5, seed=99)
    assert first == second
    assert len({item.arm_order for item in first}) == 2
    assert all(set(item.task_order) == {"T1", "T2"} for item in first)


def test_itt_uses_fixed_denominator_for_missing_candidate_cell() -> None:
    manifest = _manifest()
    rows = _rows(manifest)
    rows.pop()
    summary = aggregate_paired_runs(
        rows,
        baseline_arm="direct",
        candidate_arm="agent",
        task_set=("a", "b"),
        task_domains={"a": "logs", "b": "code"},
        plan=randomized_blocks(["direct", "agent"], ["a", "b"], block_count=5, seed=11),
        candidate_manifest=manifest,
        bootstrap_iterations=100,
    )
    assert summary["itt"]["denominator"] == 10
    assert summary["itt"]["fixed_denominator"] is True
    assert summary["itt"]["missing_count"] == 1
    assert summary["itt"]["candidate"]["denominator"] == 10


def test_release_gate_passes_only_with_domain_and_tool_eirs_gain() -> None:
    manifest = _manifest()
    report = release_report(
        _rows(manifest),
        baseline_arm="direct",
        candidate_arm="agent",
        task_set=("a", "b"),
        task_domains={"a": "logs", "b": "code"},
        plan=randomized_blocks(["direct", "agent"], ["a", "b"], block_count=5, seed=11),
        candidate_manifest=manifest,
        bootstrap_iterations=100,
    )
    assert report["gate"]["status"] == "PASS"
    assert report["accepted_delta"]["tool"]["net_gain"] > 0
    assert report["accepted_delta"]["eirs"]["net_gain"] > 0


def test_sign_test_reports_ci_and_ties() -> None:
    result = paired_sign_test((1, 2, 0, -1, 0))
    assert result["n"] == 3
    assert result["positive"] == 2
    assert result["negative"] == 1
    assert result["ties"] == 2
    assert result["positive_fraction_ci95"][0] is not None
