"""Enforce precise release engineering gates used by CI.

The project keeps the policy in a small script that consumes machine-readable
evidence rather than the rounded human output of ``coverage report``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as ET  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]
GIT = shutil.which("git") or "git"
DEFAULT_TOTAL_FLOOR = Decimal("85.69")
DEFAULT_BRANCH_FLOOR = Decimal("75.28")
DEFAULT_CHANGED_LINES_FLOOR = Decimal("90")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


class GateFailure(ValueError):
    """Raised when an evidence payload does not satisfy its release gate."""


@dataclass(frozen=True)
class GateResult:
    passed: bool
    evidence: dict[str, Any]
    failures: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {"passed": self.passed, **self.evidence, "failures": list(self.failures)}


def _decimal(value: Any, *, label: str) -> Decimal:
    try:
        result = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise GateFailure(f"{label} is not a finite decimal: {value!r}") from exc
    if not result.is_finite():
        raise GateFailure(f"{label} is not finite: {value!r}")
    return result


def _display(value: Decimal) -> str:
    return format(value, ".6f")


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GateFailure(f"cannot read JSON evidence {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise GateFailure(f"JSON evidence {path} must contain an object")
    return payload


def _coverage_file_key(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _coverage_file(files: dict[str, Any], path: str) -> dict[str, Any] | None:
    normalized = _coverage_file_key(path)
    for key, value in files.items():
        if _coverage_file_key(str(key)) == normalized:
            return value if isinstance(value, dict) else None
    return None


def _source_changed_lines(diff: str) -> dict[str, set[int]]:
    """Return added executable candidates in ``src/secmind`` from a zero-context diff."""

    changed: dict[str, set[int]] = {}
    current: str | None = None
    new_line = 0
    for raw in diff.splitlines():
        if raw.startswith("diff --git "):
            current = None
            continue
        if raw.startswith("+++ b/"):
            candidate = raw.removeprefix("+++ b/")
            if candidate.startswith("src/secmind/") and candidate.endswith(".py"):
                current = candidate
                changed.setdefault(candidate, set())
            else:
                current = None
            continue
        match = _HUNK_RE.match(raw)
        if match:
            new_line = int(match.group(1))
            continue
        if current is None or new_line <= 0:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            # Coverage JSON lists executable lines. Non-empty comments are kept
            # as candidates and are removed below when they are absent from the
            # executable line set; this also handles a changed docstring.
            changed[current].add(new_line)
            new_line += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            continue
        else:
            new_line += 1
    return {path: lines for path, lines in changed.items() if lines}


def _git_diff(base_ref: str | None) -> str:
    candidates = [base_ref, os.getenv("GITHUB_BASE_SHA"), "origin/main"]
    for candidate in candidates:
        if not candidate or set(candidate) == {"0"}:
            continue
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", candidate):
            continue
        try:
            completed = subprocess.run(  # noqa: S603
                [GIT, "diff", "--no-ext-diff", "--unified=0", f"{candidate}...HEAD", "--", "src/secmind"],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except (OSError, subprocess.CalledProcessError):
            continue
        return completed.stdout
    return ""


def evaluate_changed_lines(
    coverage: dict[str, Any],
    *,
    diff: str,
    floor: Decimal = DEFAULT_CHANGED_LINES_FLOOR,
) -> GateResult:
    files = coverage.get("files")
    if not isinstance(files, dict):
        raise GateFailure("coverage JSON is missing its files object")
    changed = _source_changed_lines(diff)
    executed_total = 0
    executable_total = 0
    details: list[dict[str, Any]] = []
    for path, candidates in sorted(changed.items()):
        file_data = _coverage_file(files, path)
        if file_data is None:
            executable = sorted(candidates)
            executed: set[int] = set()
        else:
            listed_executed = {int(line) for line in file_data.get("executed_lines", [])}
            listed_missing = {int(line) for line in file_data.get("missing_lines", [])}
            executable_set = listed_executed | listed_missing
            # Coverage.py's executed/missing union is the authoritative set of
            # executable statement lines for the exact source revision.  A
            # non-empty physical line can still be a docstring, continuation,
            # decorator payload, import member, or closing delimiter; treating
            # all such lines as missed statements makes the gate path/formatter
            # dependent and can report more statements than coverage.py itself.
            executable = sorted(candidates & executable_set)
            executed = listed_executed
        covered = sorted(line for line in executable if line in executed)
        executable_total += len(executable)
        executed_total += len(covered)
        details.append(
            {
                "file": path,
                "changed_executable_lines": len(executable),
                "covered_lines": len(covered),
                "missing_lines": sorted(set(executable) - set(covered)),
            }
        )
    if executable_total == 0:
        percent = Decimal("100")
        status = "not_applicable"
    else:
        percent = Decimal(executed_total * 100) / Decimal(executable_total)
        status = "measured"
    failures = () if percent >= floor else (f"changed-line coverage {_display(percent)}% is below {_display(floor)}%",)
    return GateResult(
        passed=not failures,
        evidence={
            "changed_lines": {
                "status": status,
                "covered": executed_total,
                "total": executable_total,
                "percent": _display(percent),
                "floor": _display(floor),
                "files": details,
            }
        },
        failures=failures,
    )


def evaluate_coverage(
    coverage: dict[str, Any],
    *,
    diff: str,
    total_floor: Decimal = DEFAULT_TOTAL_FLOOR,
    branch_floor: Decimal = DEFAULT_BRANCH_FLOOR,
    changed_lines_floor: Decimal = DEFAULT_CHANGED_LINES_FLOOR,
) -> GateResult:
    totals = coverage.get("totals")
    if not isinstance(totals, dict):
        raise GateFailure("coverage JSON is missing its totals object")
    total = _decimal(totals.get("percent_covered"), label="total coverage")
    branch = _decimal(totals.get("percent_branches_covered"), label="branch coverage")
    changed_result = evaluate_changed_lines(coverage, diff=diff, floor=changed_lines_floor)
    failures = list(changed_result.failures)
    if total < total_floor:
        failures.append(f"total coverage {_display(total)}% is below {_display(total_floor)}%")
    if branch < branch_floor:
        failures.append(f"branch coverage {_display(branch)}% is below {_display(branch_floor)}%")
    return GateResult(
        passed=not failures,
        evidence={
            "coverage": {
                "total": _display(total),
                "branch": _display(branch),
                "total_floor": _display(total_floor),
                "branch_floor": _display(branch_floor),
                "covered_lines": totals.get("covered_lines"),
                "num_statements": totals.get("num_statements"),
                "covered_branches": totals.get("covered_branches"),
                "num_branches": totals.get("num_branches"),
            },
            **changed_result.evidence,
        },
        failures=tuple(failures),
    )


def _junit_counts(root: ET.Element) -> tuple[int, int, int, int]:
    suites = [root] if root.tag.endswith("testsuite") else list(root.iter("testsuite"))
    tests = failures = errors = skipped = 0
    for suite in suites:
        tests += int(suite.attrib.get("tests", "0"))
        failures += int(suite.attrib.get("failures", "0"))
        errors += int(suite.attrib.get("errors", "0"))
        skipped += int(suite.attrib.get("skipped", "0"))
    return tests, failures, errors, skipped


def evaluate_postgres_junit(path: Path) -> GateResult:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise GateFailure(f"cannot read PostgreSQL JUnit evidence {path}: {exc}") from exc
    tests, failures, errors, skipped = _junit_counts(root)
    executed = tests - skipped
    reasons: list[str] = []
    if executed <= 0:
        reasons.append(f"PostgreSQL integration executed count must be > 0 (tests={tests}, skipped={skipped})")
    if failures or errors:
        reasons.append(f"PostgreSQL integration has failures={failures}, errors={errors}")
    return GateResult(
        passed=not reasons,
        evidence={
            "postgres": {
                "tests": tests,
                "executed": executed,
                "skipped": skipped,
                "failures": failures,
                "errors": errors,
            }
        },
        failures=tuple(reasons),
    )


def evaluate_docker_snapshot(snapshot: dict[str, Any]) -> GateResult:
    health = snapshot.get("health")
    result = snapshot.get("result")
    resources = snapshot.get("resources")
    policy = snapshot.get("policy")
    failures: list[str] = []
    execution_plane = health.get("execution_plane", {}) if isinstance(health, dict) else {}
    if not isinstance(health, dict) or health.get("status") != "ready":
        failures.append("Runner health is not ready")
    if execution_plane.get("backend") != "docker" or execution_plane.get("daemon") != "ok":
        failures.append("Runner health did not prove the Docker execution plane")
    volume_limit_mode = execution_plane.get("volume_limit_mode")
    if volume_limit_mode not in {"local-tmpfs", "container-tmpfs", "preflight-fail-closed"}:
        failures.append("Runner health did not prove bounded output/volume storage")
    if not isinstance(result, dict) or result.get("status") != "success":
        failures.append("Runner invocation did not succeed")
    if not isinstance(result, dict) or result.get("cleanup_confirmed") is not True:
        failures.append("Runner invocation did not return positive cleanup confirmation")
    if not isinstance(resources, dict) or resources.get("resources") != []:
        failures.append("Runner resource API did not report an empty post-invocation resource set")
    if not isinstance(policy, dict):
        failures.append("Docker policy inspection is missing")
        policy = {}
    if policy.get("network") != "none":
        failures.append("Docker probe network mode is not none")
    if str(policy.get("user", "")).split(":", 1)[0] in {"", "0", "root"}:
        failures.append("Docker probe did not run as a non-root user")
    cap_drop = {str(item).upper() for item in policy.get("cap_drop", [])}
    if "ALL" not in cap_drop:
        failures.append("Docker probe did not drop all capabilities")
    if policy.get("cleanup_confirmed") is not True:
        failures.append("Docker probe cleanup was not positively confirmed")
    rootless = execution_plane.get("rootless")
    if not isinstance(rootless, bool):
        failures.append("Runner health did not declare rootless status")
        rootless = False
    dedicated_rootless = execution_plane.get("dedicated_rootless")
    if not isinstance(dedicated_rootless, bool):
        failures.append("Runner health did not declare dedicated-rootless daemon status")
        dedicated_rootless = False
    if rootless and dedicated_rootless:
        # A rootless claim is release evidence only when it comes from the
        # versioned real-daemon probe.  Keeping these checks here prevents a
        # hand-written snapshot from upgrading a rootful smoke into a
        # production-authentic qualification.
        if snapshot.get("schema_version") != "rootless-runner-evidence-v1":
            failures.append("rootless Runner evidence schema is missing or unsupported")
        daemon = snapshot.get("daemon")
        if not isinstance(daemon, dict) or daemon.get("rootless") is not True:
            failures.append("rootless Runner evidence did not attest the daemon security mode")
        security_options = daemon.get("security_options", []) if isinstance(daemon, dict) else []
        if not any("rootless" in str(option).lower() for option in security_options):
            failures.append("rootless Runner evidence lacks a rootless Docker security option")
        images = snapshot.get("images")
        if not isinstance(images, dict) or not {"staging", "bandit", "cancel"} <= set(images):
            failures.append("rootless Runner evidence is missing immutable scenario images")
        else:
            for image_name in ("staging", "bandit", "cancel"):
                image = str(images[image_name])
                digest = image.rsplit("@sha256:", maxsplit=1)[-1].removeprefix("sha256:")
                if len(digest) != 64 or not re.fullmatch(r"[0-9a-fA-F]{64}", digest) or digest.lower() == "0" * 64:
                    failures.append(f"rootless Runner image {image_name} is not a non-zero immutable digest")
        scenarios = snapshot.get("scenarios")
        cleanup = snapshot.get("cleanup")
        if not isinstance(scenarios, dict) or not {"success", "cancel", "stale_fence"} <= set(scenarios):
            failures.append("rootless Runner evidence is missing success/cancel/stale-fence scenarios")
        if not isinstance(cleanup, dict) or any(
            cleanup.get(name) is not True
            for name in (
                "success_confirmed",
                "cancel_confirmed",
                "stale_fence_removed",
                "latest_fence_preserved",
                "stale_fence_final_resources_empty",
            )
        ):
            failures.append("rootless Runner evidence did not positively confirm every cleanup obligation")
    return GateResult(
        passed=not failures,
        evidence={
            "docker": {
                "runner_backend": execution_plane.get("backend"),
                "runner_rootless": rootless,
                "dedicated_rootless": dedicated_rootless,
                "volume_limit_mode": volume_limit_mode,
                "production_auth_equivalent": bool(rootless and dedicated_rootless),
                "qualification": (
                    "dedicated rootless Runner evidence is production-authentic"
                    if rootless and dedicated_rootless
                    else "non-rootless CI Docker is an execution smoke only and is not production authentication"
                ),
                "policy": policy,
                "resources_after_invocation": resources.get("resources") if isinstance(resources, dict) else None,
            }
        },
        failures=tuple(failures),
    )


def _write_output(path: Path | None, result: GateResult) -> None:
    payload = result.as_dict()
    rendered = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if path is not None:
        path.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


def _coverage_command(arguments: argparse.Namespace) -> GateResult:
    payload = load_json(Path(arguments.coverage_json))
    return evaluate_coverage(
        payload,
        diff=_git_diff(arguments.base_ref),
        total_floor=_decimal(arguments.total_floor, label="total floor"),
        branch_floor=_decimal(arguments.branch_floor, label="branch floor"),
        changed_lines_floor=_decimal(arguments.changed_lines_floor, label="changed-lines floor"),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    coverage = subparsers.add_parser("coverage", help="check precise total, branch, and changed-line coverage")
    coverage.add_argument("--coverage-json", required=True)
    coverage.add_argument("--base-ref", default=None)
    coverage.add_argument("--total-floor", default=str(DEFAULT_TOTAL_FLOOR))
    coverage.add_argument("--branch-floor", default=str(DEFAULT_BRANCH_FLOOR))
    coverage.add_argument("--changed-lines-floor", default=str(DEFAULT_CHANGED_LINES_FLOOR))
    coverage.add_argument("--output", type=Path)

    postgres = subparsers.add_parser("postgres", help="require at least one executed PostgreSQL integration test")
    postgres.add_argument("--junitxml", required=True, type=Path)
    postgres.add_argument("--output", type=Path)

    docker = subparsers.add_parser("docker", help="check Runner API, isolation policy, and cleanup evidence")
    docker.add_argument("--snapshot", required=True, type=Path)
    docker.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    try:
        if arguments.command == "coverage":
            result = _coverage_command(arguments)
        elif arguments.command == "postgres":
            result = evaluate_postgres_junit(arguments.junitxml)
        else:
            result = evaluate_docker_snapshot(load_json(arguments.snapshot))
    except GateFailure as exc:
        print(f"Engineering gate input failed: {exc}", file=sys.stderr)
        return 2
    _write_output(arguments.output, result)
    if not result.passed:
        print("Engineering gate failed:", file=sys.stderr)
        for failure in result.failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
