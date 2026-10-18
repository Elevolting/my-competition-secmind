from __future__ import annotations

import importlib.util
import sys
from decimal import Decimal
from pathlib import Path

_GATE_SPEC = importlib.util.spec_from_file_location(
    "engineering_gate",
    Path(__file__).parents[1] / "scripts" / "check_engineering_gate.py",
)
assert _GATE_SPEC is not None and _GATE_SPEC.loader is not None
gate = importlib.util.module_from_spec(_GATE_SPEC)
sys.modules[_GATE_SPEC.name] = gate
_GATE_SPEC.loader.exec_module(gate)

DEFAULT_BRANCH_FLOOR = gate.DEFAULT_BRANCH_FLOOR
DEFAULT_CHANGED_LINES_FLOOR = gate.DEFAULT_CHANGED_LINES_FLOOR
DEFAULT_TOTAL_FLOOR = gate.DEFAULT_TOTAL_FLOOR


def _coverage(total: str = "85.69", branch: str = "75.28") -> dict[str, object]:
    return {
        "totals": {
            "percent_covered": total,
            "percent_branches_covered": branch,
            "covered_lines": 8569,
            "num_statements": 10000,
            "covered_branches": 7528,
            "num_branches": 10000,
        },
        "files": {},
    }


def test_coverage_uses_exact_total_and_branch_floors() -> None:
    result = gate.evaluate_coverage(
        _coverage(),
        diff="",
        total_floor=DEFAULT_TOTAL_FLOOR,
        branch_floor=DEFAULT_BRANCH_FLOOR,
        changed_lines_floor=DEFAULT_CHANGED_LINES_FLOOR,
    )

    assert result.passed
    assert result.evidence["coverage"]["total"] == "85.690000"
    assert result.evidence["coverage"]["branch"] == "75.280000"


def test_coverage_rejects_values_just_below_exact_floors() -> None:
    total_result = gate.evaluate_coverage(
        _coverage(total="85.689999"),
        diff="",
    )
    branch_result = gate.evaluate_coverage(
        _coverage(branch="75.279999"),
        diff="",
    )

    assert not total_result.passed
    assert not branch_result.passed
    assert any("total coverage" in failure for failure in total_result.failures)
    assert any("branch coverage" in failure for failure in branch_result.failures)


def test_changed_line_gate_counts_only_executable_added_lines(monkeypatch, tmp_path) -> None:
    source = tmp_path / "src" / "secmind" / "new_gate_target.py"
    source.parent.mkdir(parents=True)
    source.write_text("value = 1\n# comment\nother = 2\n", encoding="utf-8")
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    diff = """\
diff --git a/src/secmind/new_gate_target.py b/src/secmind/new_gate_target.py
--- /dev/null
+++ b/src/secmind/new_gate_target.py
@@ -0,0 +1,3 @@
+value = 1
+# comment
+other = 2
"""
    result = gate.evaluate_changed_lines(
        {
            "files": {
                "src/secmind/new_gate_target.py": {
                    "executed_lines": [1],
                    "missing_lines": [3],
                }
            }
        },
        diff=diff,
        floor=Decimal("50"),
    )

    assert result.passed
    assert result.evidence["changed_lines"]["covered"] == 1
    assert result.evidence["changed_lines"]["total"] == 2
    assert result.evidence["changed_lines"]["percent"] == "50.000000"


def test_changed_line_gate_uses_coverage_statement_map_for_multiline_syntax() -> None:
    diff = """\
diff --git a/src/secmind/new_gate_target.py b/src/secmind/new_gate_target.py
--- /dev/null
+++ b/src/secmind/new_gate_target.py
@@ -0,0 +1,8 @@
+\"\"\"Module documentation is not an executable statement.\"\"\"
+
+VALUES = (
+    \"first\",
+    \"second\",
+)
+
+RESULT = len(VALUES)
"""

    result = gate.evaluate_changed_lines(
        {
            "files": {
                "src/secmind/new_gate_target.py": {
                    "executed_lines": [3],
                    "missing_lines": [8],
                }
            }
        },
        diff=diff,
        floor=Decimal("50"),
    )

    assert result.passed
    assert result.evidence["changed_lines"]["covered"] == 1
    assert result.evidence["changed_lines"]["total"] == 2


def test_postgres_gate_requires_nonzero_executed_tests(tmp_path) -> None:
    passing = tmp_path / "postgres-pass.xml"
    passing.write_text(
        '<testsuites tests="2" failures="0" errors="0" skipped="1">'
        '<testsuite tests="2" failures="0" errors="0" skipped="1" />'
        "</testsuites>",
        encoding="utf-8",
    )
    skipped = tmp_path / "postgres-skipped.xml"
    skipped.write_text(
        '<testsuite tests="1" failures="0" errors="0" skipped="1" />',
        encoding="utf-8",
    )

    assert gate.evaluate_postgres_junit(passing).passed
    failed = gate.evaluate_postgres_junit(skipped)
    assert not failed.passed
    assert any("executed count must be > 0" in reason for reason in failed.failures)


def _docker_snapshot() -> dict[str, object]:
    return {
        "health": {
            "status": "ready",
            "execution_plane": {
                "backend": "docker",
                "daemon": "ok",
                "rootless": False,
                "dedicated_rootless": False,
                "volume_limit_mode": "local-tmpfs",
            },
        },
        "result": {"status": "success", "cleanup_confirmed": True},
        "resources": {"resources": []},
        "policy": {
            "network": "none",
            "user": "65532:65532",
            "cap_drop": ["ALL"],
            "cleanup_confirmed": True,
        },
    }


def test_docker_gate_checks_runner_policy_and_qualifies_non_rootless() -> None:
    result = gate.evaluate_docker_snapshot(_docker_snapshot())

    assert result.passed
    docker = result.evidence["docker"]
    assert docker["runner_rootless"] is False
    assert docker["production_auth_equivalent"] is False
    assert "not production authentication" in docker["qualification"]


def test_docker_gate_rejects_network_or_cleanup_regressions() -> None:
    snapshot = _docker_snapshot()
    snapshot["policy"] = {
        "network": "bridge",
        "user": "0:0",
        "cap_drop": [],
        "cleanup_confirmed": False,
    }

    result = gate.evaluate_docker_snapshot(snapshot)

    assert not result.passed
    assert len(result.failures) == 4
