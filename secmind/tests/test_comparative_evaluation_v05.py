from __future__ import annotations

import pytest

from secmind_dev.comparative_evaluation import (
    ComparativeEvaluationError,
    ExperimentDefinition,
    ExperimentRun,
    evaluate_experiment,
)


def definition() -> ExperimentDefinition:
    return ExperimentDefinition(
        experiment_id="taskspec-vs-keyword",
        hypothesis="TaskSpec improves recall without unacceptable latency",
        dataset_digest="a" * 64,
        label_version="gold-v1",
        repetitions=3,
        minimum_cases=2,
        controlled_variables=("dataset", "hardware", "tool versions", "seed"),
    )


def run(variant: str, case: str, repetition: int, *, recall: float, latency: int, success: bool = True):
    return ExperimentRun(
        experiment_id="taskspec-vs-keyword",
        variant=variant,  # type: ignore[arg-type]
        case_id=case,
        repetition=repetition,
        success=success,
        precision=0.95,
        recall=recall,
        latency_ms=latency,
        operator_actions=2,
        artifact_digests=("b" * 64,),
    )


def test_complete_comparison_reports_statistics_deltas_and_failures() -> None:
    runs = []
    for case in ("a", "b"):
        for repetition in range(1, 4):
            runs.append(run("v0.4", case, repetition, recall=0.80, latency=100))
            runs.append(run("v0.5", case, repetition, recall=0.92, latency=110))
    report = evaluate_experiment(definition(), runs, minimum_recall_gain=0.08)
    assert report.complete is True
    assert report.comparable is True
    assert report.supported is True
    assert report.deltas["recall"] == pytest.approx(0.12)
    assert report.metrics["v0.5"]["latency_ms"]["p95"] == 110
    assert report.failures == ()


def test_incomplete_or_costed_experiment_cannot_support_claim() -> None:
    runs = [run("v0.4", "a", 1, recall=0.8, latency=100), run("v0.5", "b", 1, recall=0.9, latency=100)]
    report = evaluate_experiment(definition(), runs)
    assert report.supported is False
    assert "case/repetition matrix is incomplete" in report.blockers
    assert "baseline and candidate do not contain the same cases" in report.blockers


def test_negative_outcomes_are_retained_and_can_block_the_claim() -> None:
    runs = []
    for case in ("a", "b"):
        for repetition in range(1, 4):
            runs.append(run("v0.4", case, repetition, recall=0.80, latency=100))
            runs.append(run("v0.5", case, repetition, recall=0.92, latency=110, success=case != "b"))
    report = evaluate_experiment(definition(), runs, minimum_recall_gain=0.08)
    assert report.supported is False
    assert "candidate success rate exceeded" in " ".join(report.blockers)
    assert len(report.failures) == 3


def test_invalid_metrics_and_digests_fail_closed() -> None:
    with pytest.raises(ComparativeEvaluationError, match="dataset"):
        ExperimentDefinition("x", "hypothesis", "0" * 64, "v1")
    with pytest.raises(ComparativeEvaluationError, match="precision"):
        ExperimentRun("x", "v0.5", "case", 1, True, 1.1, 0.5, 1, 0)


def test_invalid_definitions_runs_thresholds_and_foreign_inputs_are_rejected() -> None:
    with pytest.raises(ComparativeEvaluationError, match="incomplete"):
        ExperimentDefinition("", "hypothesis", "a" * 64, "v1")
    with pytest.raises(ComparativeEvaluationError, match="three repetitions"):
        ExperimentDefinition("x", "hypothesis", "a" * 64, "v1", repetitions=2)
    with pytest.raises(ComparativeEvaluationError, match="identity"):
        ExperimentRun("", "v0.5", "case", 1, True, 1, 1, 1, 0)
    with pytest.raises(ComparativeEvaluationError, match="counters"):
        ExperimentRun("x", "v0.5", "case", 1, True, 1, 1, -1, 0)
    with pytest.raises(ComparativeEvaluationError, match="artifacts"):
        ExperimentRun("x", "v0.5", "case", 1, True, 1, 1, 1, 0, artifact_digests=("bad",))
    with pytest.raises(ComparativeEvaluationError, match="thresholds"):
        evaluate_experiment(definition(), [], maximum_latency_regression=-1)
    with pytest.raises(ComparativeEvaluationError, match="another experiment"):
        evaluate_experiment(definition(), [ExperimentRun("other", "v0.5", "case", 1, True, 1, 1, 1, 0)])


def test_offline_cost_missing_metrics_and_zero_baseline_are_reported() -> None:
    runs = []
    for case in ("a", "b"):
        for repetition in range(1, 4):
            runs.append(
                ExperimentRun(
                    "taskspec-vs-keyword",
                    "v0.4",
                    case,
                    repetition,
                    True,
                    None,
                    None,
                    0,
                    0,
                )
            )
            runs.append(
                ExperimentRun(
                    "taskspec-vs-keyword",
                    "v0.5",
                    case,
                    repetition,
                    True,
                    None,
                    None,
                    1,
                    0,
                    provider_requests=1 if case == "a" and repetition == 1 else 0,
                )
            )
    report = evaluate_experiment(definition(), runs)
    assert report.metrics["v0.4"]["precision"]["count"] == 0
    assert report.deltas["recall"] is None
    assert report.deltas["latency_ratio"] is None
    assert any("provider request" in item for item in report.blockers)
    assert report.model_dump()["report_format"] == "secmind-comparative-evaluation-v1"
