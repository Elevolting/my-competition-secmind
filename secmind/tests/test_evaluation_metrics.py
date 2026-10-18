from __future__ import annotations

import json

import pytest

from secmind_dev.evaluation import (
    REQUIRED_RELEASE_TOOLS,
    BenchmarkDefinition,
    BenchmarkProfile,
    EvaluationError,
    ReplayCheck,
    RunEvaluation,
    ToolchainEvidence,
    build_evaluation_report,
    dataset_bundle_sha256,
)


def _run(
    case_id: str,
    *,
    repetition: int = 1,
    expected: frozenset[str] = frozenset(),
    found: frozenset[str] = frozenset(),
    findings: int = 0,
    linked: int = 0,
    ledger_valid: bool = True,
    replay: ReplayCheck = ReplayCheck.NOT_EVALUATED,
    backend: str = "host-subprocess-development",
    tools: tuple[str, ...] = (),
    high_expected: frozenset[str] = frozenset(),
    high_found: frozenset[str] = frozenset(),
    status: str = "completed",
) -> RunEvaluation:
    return RunEvaluation(
        case_id=case_id,
        repetition=repetition,
        status=status,
        expected_rule_ids=expected,
        found_rule_ids=found,
        finding_count=findings,
        findings_with_valid_evidence=linked,
        within_finding_limit=True,
        ledger_event_count=1,
        ledger_valid=ledger_valid,
        replay_check=replay,
        provider_requests=0,
        model_cost_units=0,
        execution_backend=backend,
        executed_tools=tools,
        expected_high_critical_rule_ids=high_expected,
        found_high_critical_rule_ids=high_found,
    )


def test_synthetic_report_separates_quality_metrics_and_never_claims_release_gate() -> None:
    definition = BenchmarkDefinition(
        profile=BenchmarkProfile.SYNTHETIC_SMOKE,
        dataset_id="synthetic:test",
        dataset_kind="synthetic-inline-single-file",
        declared_case_count=2,
        declared_repetitions=1,
        languages=("python",),
    )
    report = build_evaluation_report(
        definition,
        [
            _run(
                "mixed",
                expected=frozenset({"A", "B"}),
                found=frozenset({"A", "C"}),
                findings=2,
                linked=2,
                replay=ReplayCheck.VERIFIED,
            ),
            _run("safe", ledger_valid=False),
        ],
    )

    assert report["profile"] == "synthetic-smoke"
    assert report["coverage"] == {
        "expected_runs": 2,
        "observed_runs": 2,
        "observed_cases": 2,
        "duplicate_run_keys": [],
        "complete": True,
        "exact_40x3_executed": False,
    }
    assert report["metrics"] == {
        "process_success_rate": 0.0,
        "safe_terminal_rate": 0.0,
        "precision": 0.5,
        "recall": 0.5,
        "high_critical_recall": None,
        "finding_to_evidence_completeness": 1.0,
        "ledger_verification_rate": 0.5,
        "replay_verification_rate": 1.0,
    }
    assert report["release_gate_eligible"] is False
    assert "synthetic smoke is not a release benchmark" in report["release_gate_blockers"]
    assert any("must not be cited" in item for item in report["limitations"])


def test_partial_is_safe_smoke_convergence_but_not_release_completion() -> None:
    definition = BenchmarkDefinition(
        profile=BenchmarkProfile.SYNTHETIC_SMOKE,
        dataset_id="synthetic:partial",
        dataset_kind="synthetic-inline-single-file",
        declared_case_count=1,
        declared_repetitions=1,
        languages=("python",),
    )
    run = _run(
        "high-impact",
        status="partial",
        expected=frozenset({"HIGH"}),
        found=frozenset({"HIGH"}),
        findings=1,
        linked=1,
    )

    report = build_evaluation_report(definition, [run])

    assert run.functional_passed is False
    assert run.safely_converged is True
    assert report["counts"]["passed"] == 0
    assert report["counts"]["safely_converged"] == 1
    assert report["metrics"]["process_success_rate"] == 0.0
    assert report["metrics"]["safe_terminal_rate"] == 1.0
    assert report["release_gate_eligible"] is False


def test_undefined_evidence_and_replay_rates_are_null_not_invented_passes() -> None:
    definition = BenchmarkDefinition(
        profile=BenchmarkProfile.SYNTHETIC_SMOKE,
        dataset_id="synthetic:empty",
        dataset_kind="synthetic-inline-single-file",
        declared_case_count=1,
        declared_repetitions=3,
        languages=("python",),
    )
    report = build_evaluation_report(definition, [_run("only", repetition=1)])

    assert report["coverage"]["complete"] is False
    assert report["metrics"]["finding_to_evidence_completeness"] is None
    assert report["metrics"]["replay_verification_rate"] is None
    assert report["counts"]["replay_evaluated_runs"] == 0


def test_toolchain_evidence_rejects_tags_zero_digests_and_non_rootless_runner(tmp_path) -> None:
    valid_digest = "sha256:" + "a" * 64
    raw = {
        "platform": "linux/amd64",
        "runner_isolation": "dedicated-rootless",
        "images": {tool: valid_digest for tool in REQUIRED_RELEASE_TOOLS},
        "staging_image_digest": valid_digest,
        "semgrep_rule_bundle_digest": valid_digest,
        "osv_database_digest": valid_digest,
        "dataset_digest": valid_digest,
    }
    path = tmp_path / "toolchain.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert ToolchainEvidence.load(path).runner_isolation == "dedicated-rootless"

    raw["images"]["semgrep_sast"] = "semgrep:latest"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(EvaluationError, match="invalid SHA-256"):
        ToolchainEvidence.load(path)
    raw["images"]["semgrep_sast"] = valid_digest
    raw["runner_isolation"] = "main-docker-daemon"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(EvaluationError, match="dedicated rootless"):
        ToolchainEvidence.load(path)


def test_complete_tool_backed_matrix_can_become_candidate_only_with_all_evidence(tmp_path) -> None:
    digest = "sha256:" + "b" * 64
    evidence = ToolchainEvidence(
        platform="linux/amd64",
        runner_isolation="dedicated-rootless",
        images={tool: digest for tool in REQUIRED_RELEASE_TOOLS},
        staging_image_digest=digest,
        semgrep_rule_bundle_digest=digest,
        osv_database_digest=digest,
        dataset_digest=digest,
        source_path=str(tmp_path / "toolchain.json"),
    )
    evidence.validate()
    definition = BenchmarkDefinition(
        profile=BenchmarkProfile.TOOL_BACKED,
        dataset_id="real:test",
        dataset_kind="real-multifile-projects",
        declared_case_count=40,
        declared_repetitions=3,
        languages=("python", "typescript", "java"),
        required_tools=REQUIRED_RELEASE_TOOLS,
        toolchain_evidence=evidence,
    )
    runs = [
        _run(
            f"case-{case}",
            repetition=repetition,
            expected=frozenset({"HIGH-1"}),
            found=frozenset({"HIGH-1"}),
            findings=1,
            linked=1,
            replay=ReplayCheck.VERIFIED,
            backend="sandbox-runner",
            tools=tuple(sorted(REQUIRED_RELEASE_TOOLS)),
            high_expected=frozenset({"HIGH-1"}),
            high_found=frozenset({"HIGH-1"}),
        )
        for case in range(40)
        for repetition in range(1, 4)
    ]
    report = build_evaluation_report(definition, runs)

    assert report["coverage"]["exact_40x3_executed"] is True
    assert report["metrics"]["replay_verification_rate"] == 1.0
    assert report["release_gate_eligible"] is True
    assert report["release_gate_blockers"] == []


def test_duplicate_run_keys_and_inconsistent_counts_fail_closed() -> None:
    definition = BenchmarkDefinition(
        profile=BenchmarkProfile.SYNTHETIC_SMOKE,
        dataset_id="synthetic:duplicate",
        dataset_kind="synthetic-inline-single-file",
        declared_case_count=1,
        declared_repetitions=2,
        languages=("python",),
    )
    report = build_evaluation_report(definition, [_run("case"), _run("case")])
    assert report["coverage"]["complete"] is False
    assert report["coverage"]["duplicate_run_keys"] == [["case", 1]]

    with pytest.raises(EvaluationError, match="inconsistent"):
        RunEvaluation(
            case_id="bad",
            repetition=1,
            status="completed",
            expected_rule_ids=frozenset(),
            found_rule_ids=frozenset(),
            finding_count=0,
            findings_with_valid_evidence=1,
            within_finding_limit=True,
            ledger_event_count=1,
            ledger_valid=True,
            replay_check=ReplayCheck.NOT_EVALUATED,
            provider_requests=0,
            model_cost_units=0,
            execution_backend="unknown",
        )


def test_real_dataset_digest_binds_manifest_and_project_contents_and_rejects_escape(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    source = project / "app.py"
    source.write_text("print('first')\n", encoding="utf-8")
    manifest = tmp_path / "real-projects.json"
    manifest.write_text("[]\n", encoding="utf-8")
    first = dataset_bundle_sha256(manifest, ["project"])

    source.write_text("print('second')\n", encoding="utf-8")
    second = dataset_bundle_sha256(manifest, ["project"])
    assert first != second
    with pytest.raises(EvaluationError, match="escapes"):
        dataset_bundle_sha256(manifest, ["../outside"])
    with pytest.raises(EvaluationError, match="duplicate"):
        dataset_bundle_sha256(manifest, ["project", "project"])
