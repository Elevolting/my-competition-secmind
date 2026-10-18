"""Build an exact candidate manifest or score a fully offline release gate.

Examples (PowerShell)::

    python scripts/evaluate_release_candidate.py manifest `
      --root . --candidate-id secmind-terra --candidate-version 0.8.6 `
      --wheel dist/secmind-0.8.6-py3-none-any.whl `
      --sdist dist/secmind-0.8.6.tar.gz --bridge scripts/bridge.py `
      --adapter scripts/adapter.json --scorer evaluation/scorer.json `
      --task-set evaluation/task-set.json --dependency-file uv.lock `
      --lockfile uv.lock --output evaluation/release/manifest.json

    python scripts/evaluate_release_candidate.py plan `
      --arm direct --arm agent --task T1 --task T2 --blocks 5 --seed 17 `
      --output evaluation/release/randomization.json

    python scripts/evaluate_release_candidate.py report `
      --manifest evaluation/release/manifest.json `
      --runs evaluation/release/runs.jsonl `
      --task-set evaluation/task-set.json --plan evaluation/release/randomization.json `
      --baseline-arm direct --candidate-arm agent `
      --output evaluation/release/report.json

The command never contacts a model provider.  Report mode writes the report
even when the gate fails, then exits with status 2 so CI cannot mistake a
failed evaluation for a successful release.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

# ``scripts/*.py`` is intentionally runnable from a source checkout where the
# package is not installed into the active interpreter.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from secmind_dev.release_evaluation import (  # noqa: E402
    MIN_RANDOMIZED_BLOCKS,
    CandidateManifest,
    RandomizedBlock,
    ReleaseEvaluationError,
    RunLedger,
    RunRecord,
    build_candidate_manifest,
    canonical_digest,
    randomized_blocks,
    release_report,
)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseEvaluationError(f"cannot read JSON: {path}: {exc}") from exc


def _write_json(value: Any, path: Path | None) -> None:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if path is None:
        sys.stdout.write(payload)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")


def _resolve(root: Path, value: str | None) -> Path | None:
    if value is None:
        return None
    path = Path(value)
    return path if path.is_absolute() else root / path


def _object(path: Path | None, *, default: Any = None) -> Any:
    return default if path is None else _read_json(path)


def _task_set(path: Path) -> tuple[tuple[str, ...], dict[str, str]]:
    raw = _read_json(path)
    if isinstance(raw, Mapping):
        values = raw.get("tasks", raw.get("cases", raw.get("task_set", [])))
    else:
        values = raw
    if not isinstance(values, list):
        raise ReleaseEvaluationError("task-set JSON must contain a list or {tasks: [...]}")
    task_ids: list[str] = []
    domains: dict[str, str] = {}
    for item in values:
        if isinstance(item, str):
            task_id = item
            domain = "unknown"
        elif isinstance(item, Mapping):
            task_id = str(item.get("task_id", item.get("id", item.get("case_id", ""))))
            domain = str(item.get("domain", item.get("primary_domain", "unknown")))
        else:
            raise ReleaseEvaluationError("task-set entries must be strings or objects")
        if not task_id:
            raise ReleaseEvaluationError("task-set entry has no task_id")
        if task_id in task_ids:
            raise ReleaseEvaluationError(f"task-set contains duplicate task: {task_id}")
        task_ids.append(task_id)
        domains[task_id] = domain
    if not task_ids:
        raise ReleaseEvaluationError("task-set is empty")
    return tuple(task_ids), domains


def _plan(path: Path | None) -> tuple[RandomizedBlock, ...] | None:
    if path is None:
        return None
    raw = _read_json(path)
    values = raw.get("blocks", raw) if isinstance(raw, Mapping) else raw
    if not isinstance(values, list):
        raise ReleaseEvaluationError("randomization JSON must contain a blocks list")
    result: list[RandomizedBlock] = []
    for item in values:
        if not isinstance(item, Mapping):
            raise ReleaseEvaluationError("randomization block must be an object")
        result.append(
            RandomizedBlock(
                block=int(item["block"]),
                seed=int(item.get("seed", 0)),
                arm_order=tuple(str(value) for value in item.get("arm_order", ())),
                task_order=tuple(str(value) for value in item.get("task_order", ())),
            )
        )
    return tuple(result)


def _runs(path: Path) -> tuple[RunRecord, ...]:
    # JSONL is the preferred exchange format because a process can flush each
    # failure before the next task starts.  JSON arrays and ledger envelopes
    # remain accepted for easy local inspection.
    text = path.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return ()
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        document = None
    try:
        first = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        if document is None:
            raise ReleaseEvaluationError(f"invalid run JSON: {path}") from exc
        first = document
    if isinstance(first, Mapping) and first.get("schema_version") == "secmind-run-ledger-v1":
        if isinstance(first.get("events"), list):
            return tuple(RunRecord.from_mapping(item["run"]) for item in first["events"] if isinstance(item, Mapping))
        # A single event per line is loaded through the hash-chain verifier.
        return RunLedger.load(path).records
    if len(lines) > 1 and document is None:
        values: Any = [json.loads(line) for line in lines]
    else:
        values = first
    if isinstance(values, Mapping):
        values = values.get("runs", values.get("rows", values.get("results", values)))
    if not isinstance(values, list):
        raise ReleaseEvaluationError("runs JSON must contain an array or {runs: [...]}")
    result: list[RunRecord] = []
    for item in values:
        if isinstance(item, Mapping) and isinstance(item.get("run"), Mapping):
            item = item["run"]
        if not isinstance(item, Mapping):
            raise ReleaseEvaluationError("run entries must be objects")
        result.append(RunRecord.from_mapping(item))
    return tuple(result)


def _manifest(arguments: argparse.Namespace) -> dict[str, Any]:
    root = Path(arguments.root).resolve()
    manifest = build_candidate_manifest(
        root,
        candidate_id=arguments.candidate_id,
        candidate_version=arguments.candidate_version,
        wheel_path=_resolve(root, arguments.wheel),
        sdist_path=_resolve(root, arguments.sdist),
        bridge_path=_resolve(root, arguments.bridge),
        bridge_version=arguments.bridge_version,
        adapter_path=_resolve(root, arguments.adapter),
        adapter_version=arguments.adapter_version,
        profile=arguments.profile,
        profile_config=_object(_resolve(root, arguments.profile_config), default={}),
        environment=_object(_resolve(root, arguments.environment), default=None),
        model_parameters=_object(_resolve(root, arguments.model_parameters), default={}),
        prompt_lineage=_object(_resolve(root, arguments.prompt_lineage), default={}),
        scorer=_resolve(root, arguments.scorer) or _object(_resolve(root, arguments.scorer_json), default=None),
        task_set=_resolve(root, arguments.task_set),
        dependency_files=tuple(_resolve(root, item) for item in arguments.dependency_file),
        lockfile=_resolve(root, arguments.lockfile),
    )
    return manifest.to_dict()


def _plan_command(arguments: argparse.Namespace) -> dict[str, Any]:
    plans = randomized_blocks(
        arguments.arm,
        arguments.task,
        block_count=arguments.blocks,
        seed=arguments.seed,
        scheme=arguments.scheme,
    )
    return {
        "schema_version": "secmind-randomization-v1",
        "seed": arguments.seed,
        "scheme": arguments.scheme,
        "arms": list(dict.fromkeys(arguments.arm)),
        "tasks": list(dict.fromkeys(arguments.task)),
        "blocks": [item.to_dict() for item in plans],
        "plan_digest": canonical_digest([item.to_dict() for item in plans]),
    }


def _report_command(arguments: argparse.Namespace) -> tuple[dict[str, Any], int]:
    manifest = CandidateManifest.from_dict(_read_json(arguments.manifest)) if arguments.manifest else None
    task_ids, domains = _task_set(arguments.task_set)
    plan = _plan(arguments.plan)
    report = release_report(
        _runs(arguments.runs),
        baseline_arm=arguments.baseline_arm,
        candidate_arm=arguments.candidate_arm,
        task_set=task_ids,
        task_domains=domains,
        candidate_manifest=manifest,
        plan=plan,
        bootstrap_iterations=arguments.bootstrap_draws,
        bootstrap_seed=arguments.seed,
        require_clean_tree=not arguments.allow_dirty,
        require_artifacts=not arguments.allow_missing_artifacts,
        require_offline=not arguments.allow_live,
        require_tool_net_gain=not arguments.no_tool_gain,
        require_eirs_net_gain=not arguments.no_eirs_gain,
    )
    return report, 0 if report["gate"]["passed"] else 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="evaluate_release_candidate")
    subcommands = parser.add_subparsers(dest="command", required=True)

    manifest = subcommands.add_parser("manifest", help="build an exact candidate manifest")
    manifest.add_argument("--root", type=Path, default=ROOT)
    manifest.add_argument("--candidate-id", required=True)
    manifest.add_argument("--candidate-version", required=True)
    manifest.add_argument("--wheel")
    manifest.add_argument("--sdist")
    manifest.add_argument("--bridge")
    manifest.add_argument("--bridge-version", default="UNKNOWN")
    manifest.add_argument("--adapter")
    manifest.add_argument("--adapter-version", default="UNKNOWN")
    manifest.add_argument("--profile", default="UNKNOWN")
    manifest.add_argument("--profile-config")
    manifest.add_argument("--environment", help="JSON object containing the effective environment")
    manifest.add_argument("--model-parameters", help="JSON object containing frozen model parameters")
    manifest.add_argument("--prompt-lineage", help="JSON prompt lineage record")
    manifest.add_argument("--scorer")
    manifest.add_argument("--scorer-json")
    manifest.add_argument("--task-set", required=True)
    manifest.add_argument("--dependency-file", action="append", default=[])
    manifest.add_argument("--lockfile")
    manifest.add_argument("--output", type=Path)
    manifest.set_defaults(handler=lambda args: (_manifest(args), 0))

    plan = subcommands.add_parser("plan", help="create a deterministic randomized block plan")
    plan.add_argument("--arm", action="append", required=True)
    plan.add_argument("--task", action="append", required=True)
    plan.add_argument("--blocks", type=int, default=MIN_RANDOMIZED_BLOCKS)
    plan.add_argument("--seed", type=int, default=0)
    plan.add_argument("--scheme", choices=("abba", "latin-square"), default="abba")
    plan.add_argument("--output", type=Path)
    plan.set_defaults(handler=lambda args: (_plan_command(args), 0))

    report = subcommands.add_parser("report", help="aggregate runs and enforce the release gate")
    report.add_argument("--manifest", type=Path)
    report.add_argument("--runs", type=Path, required=True)
    report.add_argument("--task-set", type=Path, required=True)
    report.add_argument("--plan", type=Path)
    report.add_argument("--baseline-arm", required=True)
    report.add_argument("--candidate-arm", required=True)
    report.add_argument("--bootstrap-draws", type=int, default=2000)
    report.add_argument("--seed", type=int, default=0)
    report.add_argument("--allow-dirty", action="store_true")
    report.add_argument("--allow-missing-artifacts", action="store_true")
    report.add_argument("--allow-live", action="store_true")
    report.add_argument("--no-tool-gain", action="store_true")
    report.add_argument("--no-eirs-gain", action="store_true")
    report.add_argument("--output", type=Path)
    report.set_defaults(handler=_report_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        value, status = arguments.handler(arguments)
        _write_json(value, arguments.output)
        return status
    except (OSError, ValueError, ReleaseEvaluationError, KeyError, TypeError) as exc:
        print(f"release evaluation error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
