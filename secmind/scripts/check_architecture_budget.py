"""Fail CI when known SecMind coordination hot spots grow without extraction.

The orchestrator budget is deliberately a *downward* gate.  It is measured
against the current v0.8.6 refactoring boundary, not a permissive historical
ceiling: the graph facade must stay at or below 5,810 lines, expose no
oversized function, and keep its direct dependency fan-out bounded.  Runtime
collaborators may depend on their own modules; the graph boundary should only
depend on the stable orchestration dependency facade.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "secmind"
MODULE_LINE_LIMITS = {
    "orchestrator.py": 5_810,
    "tools.py": 2_900,
    "llm.py": 2_350,
    "schemas.py": 1_700,
}
ORCHESTRATOR_DIRECT_IMPORT_LIMIT = 65
ORCHESTRATOR_CLASS_LINE_LIMIT = 5_000
ORCHESTRATOR_METHOD_LIMIT = 93
FUNCTION_LINE_LIMIT = 450
LEGACY_FUNCTION_LIMITS = {
    ("llm.py", "structured"): 460,
    ("orchestrator.py", "_canonical_primary"): 520,
}


def _line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def _oversized_functions(path: Path) -> list[tuple[str, int, int]]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    oversized: list[tuple[str, int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.end_lineno is None:
            continue
        length = node.end_lineno - node.lineno + 1
        limit = LEGACY_FUNCTION_LIMITS.get((path.name, node.name), FUNCTION_LINE_LIMIT)
        if length > limit:
            oversized.append((node.name, length, limit))
    return sorted(oversized, key=lambda item: (-item[1], item[0]))


def _direct_secmind_imports(path: Path) -> list[str]:
    """Return unique first-party modules imported directly by ``path``.

    Counting modules rather than imported symbols makes the metric reflect
    architectural coupling.  Re-exporting collaborators through one focused
    facade therefore lowers fan-out without hiding additional graph edges in
    a string-based allowlist.
    """

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("secmind"):
            modules.add(node.module)
        elif isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names if alias.name.startswith("secmind"))
    return sorted(modules)


def _class_metrics(path: Path, class_name: str) -> tuple[int, int] | None:
    """Return ``(class_lines, method_count)`` for one coordinator class."""

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name and node.end_lineno is not None:
            methods = sum(isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) for item in node.body)
            return node.end_lineno - node.lineno + 1, methods
    return None


def evaluate() -> dict[str, Any]:
    """Return architecture observations and failures as serializable evidence."""

    errors: list[str] = []
    modules: list[dict[str, Any]] = []
    for name, limit in MODULE_LINE_LIMITS.items():
        path = SOURCE / name
        observed = _line_count(path)
        modules.append({"file": f"src/secmind/{name}", "lines": observed, "limit": limit})
        if observed > limit:
            errors.append(f"{name}: {observed} lines exceeds incremental architecture budget {limit}")
    orchestrator = SOURCE / "orchestrator.py"
    direct_imports = _direct_secmind_imports(orchestrator)
    if len(direct_imports) > ORCHESTRATOR_DIRECT_IMPORT_LIMIT:
        errors.append(
            "orchestrator.py: "
            f"{len(direct_imports)} direct secmind modules exceeds fan-out budget "
            f"{ORCHESTRATOR_DIRECT_IMPORT_LIMIT}"
        )
    class_metrics = _class_metrics(orchestrator, "SecMindOrchestrator")
    if class_metrics is None:
        errors.append("orchestrator.py: SecMindOrchestrator class is missing")
        class_lines, class_methods = 0, 0
    else:
        class_lines, class_methods = class_metrics
        if class_lines > ORCHESTRATOR_CLASS_LINE_LIMIT:
            errors.append(
                "orchestrator.py: "
                f"SecMindOrchestrator has {class_lines} lines, exceeds class budget "
                f"{ORCHESTRATOR_CLASS_LINE_LIMIT}"
            )
        if class_methods > ORCHESTRATOR_METHOD_LIMIT:
            errors.append(
                "orchestrator.py: "
                f"SecMindOrchestrator has {class_methods} methods, exceeds class budget "
                f"{ORCHESTRATOR_METHOD_LIMIT}"
            )
    functions: list[dict[str, Any]] = []
    for path in sorted(SOURCE.rglob("*.py")):
        for function, length, limit in _oversized_functions(path):
            functions.append(
                {
                    "file": path.relative_to(ROOT).as_posix(),
                    "function": function,
                    "lines": length,
                    "limit": limit,
                }
            )
            errors.append(
                f"{path.relative_to(ROOT).as_posix()}::{function}: {length} lines exceeds function budget {limit}"
            )
    return {
        "gate": "architecture-budget",
        "passed": not errors,
        "modules": modules,
        "orchestrator_direct_imports": direct_imports,
        "orchestrator_direct_import_count": len(direct_imports),
        "orchestrator_direct_import_limit": ORCHESTRATOR_DIRECT_IMPORT_LIMIT,
        "orchestrator_class_lines": class_lines,
        "orchestrator_class_line_limit": ORCHESTRATOR_CLASS_LINE_LIMIT,
        "orchestrator_class_methods": class_methods,
        "orchestrator_class_method_limit": ORCHESTRATOR_METHOD_LIMIT,
        "oversized_functions": functions,
        "failures": errors,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="write machine-readable gate evidence to this file")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    evidence = evaluate()
    rendered = json.dumps(evidence, ensure_ascii=False, indent=2) + "\n"
    if arguments.output is not None:
        arguments.output.write_text(rendered, encoding="utf-8")
    if not evidence["passed"]:
        print("Architecture budget failed:")
        print("\n".join(f"- {item}" for item in evidence["failures"]))
        return 1
    print("Architecture budget passed; v0.8.6 hot-spot and orchestrator fan-out budgets are satisfied.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
