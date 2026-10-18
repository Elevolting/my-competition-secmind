"""Command line entry point for the v0.8.2 evaluation contracts."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import fields
from pathlib import Path
from typing import Any

from .v082_aggregate import (
    AggregationError,
    TaskScore,
    aggregate_scores,
    randomized_blocks,
)
from .v082_cas import CASError, CASStore, EvaluationSealStore
from .v082_contracts import (
    AgentReport,
    AttemptRecord,
    ContractError,
    FailureCapsule,
    InputManifest,
    QuarantineRecord,
    RunIdentity,
    build_run_identity,
    canonical_json,
)
from .v082_scorer import score_report


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        result = arguments.handler(arguments)
        if result is not None:
            _write_result(result, arguments.output)
        return 0
    except (AggregationError, CASError, ContractError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"v0.8.2 evaluation error: {exc}", file=sys.stderr)
        return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secmind-evaluation", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    plan = commands.add_parser("plan", help="create a reproducible randomized block plan")
    plan.add_argument("--arm", dest="arms", action="append", required=True)
    plan.add_argument("--task", dest="tasks", action="append", required=True)
    plan.add_argument("--blocks", type=int, default=5)
    plan.add_argument("--seed", type=int, default=0)
    plan.add_argument("--scheme", choices=("latin-square", "abba"), default="latin-square")
    plan.add_argument("--output", type=Path)
    plan.set_defaults(handler=_handle_plan)

    seal = commands.add_parser("seal", help="seal an AgentReport, evidence and input manifest")
    seal.add_argument("--report", type=Path, required=True)
    seal.add_argument("--manifest", type=Path, required=True)
    seal.add_argument("--cas-root", type=Path, required=True)
    seal.add_argument("--identity", type=Path)
    seal.add_argument("--candidate-id", default="candidate-v0.8.2")
    seal.add_argument("--candidate-version", default="0.8.2")
    seal.add_argument("--attempts", type=Path)
    seal.add_argument("--failure-capsules", type=Path)
    seal.add_argument("--quarantine", type=Path)
    seal.add_argument("--bridge-executions", type=Path)
    seal.add_argument("--output", type=Path)
    seal.set_defaults(handler=_handle_seal)

    verify = commands.add_parser("verify", help="verify a seal and all referenced CAS objects")
    verify.add_argument("--cas-root", type=Path, required=True)
    verify.add_argument("--seal", required=True)
    verify.add_argument("--output", type=Path)
    verify.set_defaults(handler=_handle_verify)

    aggregate = commands.add_parser("aggregate", help="aggregate all rounds and score views")
    aggregate.add_argument("--input", dest="inputs", type=Path, action="append", required=True)
    aggregate.add_argument("--capability-task", dest="capability_tasks", action="append", default=[])
    aggregate.add_argument("--engineering-task", dest="engineering_tasks", action="append", default=[])
    aggregate.add_argument("--blocks", type=int)
    aggregate.add_argument("--output", type=Path)
    aggregate.set_defaults(handler=_handle_aggregate)

    score = commands.add_parser("score", help="score one sealed AgentReport against expected findings")
    score.add_argument("--report", type=Path, required=True)
    score.add_argument("--manifest", type=Path, required=True)
    score.add_argument("--expected", type=Path)
    score.add_argument("--engineering-score", type=float)
    score.add_argument("--attempts", type=Path)
    score.add_argument("--round", dest="round_number", type=int, default=1)
    score.add_argument("--block", type=int)
    score.add_argument("--arm", default="unknown")
    score.add_argument("--output", type=Path)
    score.set_defaults(handler=_handle_score)
    return parser


def _handle_plan(arguments: argparse.Namespace) -> dict[str, Any]:
    plans = randomized_blocks(
        arguments.arms,
        arguments.tasks,
        block_count=arguments.blocks,
        seed=arguments.seed,
        scheme=arguments.scheme,
    )
    return {
        "schema_version": "secmind-randomization-v0.8.2",
        "seed": arguments.seed,
        "scheme": arguments.scheme,
        "blocks": [item.to_dict() for item in plans],
    }


def _handle_seal(arguments: argparse.Namespace) -> dict[str, Any]:
    report_raw = _read_json(arguments.report)
    manifest = InputManifest.from_dict(_read_json(arguments.manifest))
    report = AgentReport.from_dict(report_raw)
    identity = (
        _identity_from_file(arguments.identity)
        if arguments.identity
        else build_run_identity(
            candidate_id=arguments.candidate_id,
            candidate_version=arguments.candidate_version,
            input_manifest_digest=manifest.digest,
            profile="v0.8.2",
        )
    )
    attempts = _attempts(_read_json(arguments.attempts)) if arguments.attempts else ()
    failures = _failures(_read_json(arguments.failure_capsules)) if arguments.failure_capsules else ()
    quarantine = _quarantine(_read_json(arguments.quarantine)) if arguments.quarantine else ()
    bridge_executions = (
        _bridge_executions(_read_json(arguments.bridge_executions)) if arguments.bridge_executions else ()
    )
    sealed = EvaluationSealStore(CASStore(arguments.cas_root)).seal(
        identity=identity,
        report=report,
        input_manifest=manifest,
        attempts=attempts,
        failure_capsules=failures,
        quarantine=quarantine,
        bridge_executions=bridge_executions,
    )
    return sealed.to_dict()


def _handle_verify(arguments: argparse.Namespace) -> dict[str, Any]:
    return EvaluationSealStore(CASStore(arguments.cas_root)).verify(arguments.seal)


def _handle_aggregate(arguments: argparse.Namespace) -> dict[str, Any]:
    rows: list[TaskScore] = []
    for path in arguments.inputs:
        rows.extend(_score_rows(_read_json(path)))
    return aggregate_scores(
        rows,
        capability_task_ids=arguments.capability_tasks or None,
        engineering_task_ids=arguments.engineering_tasks or None,
        randomized_block_count=arguments.blocks,
    )


def _handle_score(arguments: argparse.Namespace) -> dict[str, Any]:
    report = AgentReport.from_dict(_read_json(arguments.report))
    manifest = InputManifest.from_dict(_read_json(arguments.manifest))
    expected_raw = _read_json(arguments.expected) if arguments.expected else []
    expected = expected_raw.get("findings", []) if isinstance(expected_raw, dict) else expected_raw
    attempts = _attempts(_read_json(arguments.attempts)) if arguments.attempts else ()
    return score_report(
        report,
        manifest,
        expected_findings=expected if isinstance(expected, list) else [],
        engineering_score=arguments.engineering_score,
        attempts=attempts,
        round_number=arguments.round_number,
        block=arguments.block,
        arm=arguments.arm,
    ).to_dict()


def _score_rows(
    raw: Any, *, default_arm: str = "unknown", default_round: int = 1, default_block: int | None = None
) -> list[TaskScore]:
    if isinstance(raw, list):
        return [
            TaskScore.from_mapping(item, arm=default_arm, round_number=default_round, block=default_block)
            for item in raw
            if isinstance(item, dict)
        ]
    if not isinstance(raw, dict):
        raise AggregationError("score input must be an object or list")
    if isinstance(raw.get("arms"), dict):
        rows: list[TaskScore] = []
        for arm, value in raw["arms"].items():
            rows.extend(
                _score_rows(value, default_arm=str(arm), default_round=default_round, default_block=default_block)
            )
        return rows
    for key in ("tasks", "rows", "scores", "results"):
        if isinstance(raw.get(key), list):
            return [
                TaskScore.from_mapping(
                    item,
                    arm=str(item.get("arm", raw.get("arm", default_arm))),
                    round_number=_int_or_default(item.get("round", raw.get("round")), default_round),
                    block=_optional_int(item.get("block", default_block)),
                )
                for item in raw[key]
                if isinstance(item, dict)
            ]
    if "task_id" in raw:
        return [TaskScore.from_mapping(raw, arm=default_arm, round_number=default_round, block=default_block)]
    raise AggregationError("score input has no tasks/rows/scores/results")


def _identity_from_file(path: Path) -> RunIdentity:
    raw = _read_json(path)
    if isinstance(raw, dict) and isinstance(raw.get("identity"), dict):
        raw = raw["identity"]
    if not isinstance(raw, dict):
        raise ContractError("identity must be an object")
    names = {item.name for item in fields(RunIdentity)}
    values = {key: value for key, value in raw.items() if key in names}
    return RunIdentity(**values)


def _int_or_default(value: Any, default: int) -> int:
    return default if value is None else int(value)


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


def _attempts(raw: Any) -> tuple[AttemptRecord, ...]:
    values = raw.get("attempts", []) if isinstance(raw, dict) else raw
    if not isinstance(values, list):
        raise ContractError("attempts must be a list")
    return tuple(AttemptRecord(**item) for item in values if isinstance(item, dict))


def _failures(raw: Any) -> tuple[FailureCapsule, ...]:
    values = raw.get("capsules", raw.get("failure_capsules", [])) if isinstance(raw, dict) else raw
    if not isinstance(values, list):
        raise ContractError("failure capsules must be a list")
    return tuple(FailureCapsule(**item) for item in values if isinstance(item, dict))


def _quarantine(raw: Any) -> tuple[QuarantineRecord, ...]:
    values = raw.get("records", raw.get("quarantine", [])) if isinstance(raw, dict) else raw
    if not isinstance(values, list):
        raise ContractError("quarantine records must be a list")
    return tuple(QuarantineRecord(**item) for item in values if isinstance(item, dict))


def _bridge_executions(raw: Any) -> tuple[dict[str, Any], ...]:
    values = raw.get("executions", []) if isinstance(raw, dict) else raw
    if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
        raise ContractError("bridge executions must be a list of objects")
    return tuple(dict(item) for item in values)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_result(value: Any, path: Path | None) -> None:
    payload = canonical_json(value) + b"\n"
    if path is None:
        sys.stdout.buffer.write(payload)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


__all__ = ["main"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
