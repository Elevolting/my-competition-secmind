from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SCRIPT = Path(__file__).parents[1] / "scripts" / "check_architecture_budget.py"
_SPEC = importlib.util.spec_from_file_location("check_architecture_budget", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
gate = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = gate
_SPEC.loader.exec_module(gate)


def test_architecture_gate_writes_fail_closed_machine_evidence(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "src" / "secmind"
    source.mkdir(parents=True)
    (source / "orchestrator.py").write_text("def oversized():\n    return True\n", encoding="utf-8")
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    monkeypatch.setattr(gate, "SOURCE", source)
    monkeypatch.setattr(gate, "MODULE_LINE_LIMITS", {"orchestrator.py": 1})
    monkeypatch.setattr(gate, "FUNCTION_LINE_LIMIT", 1)
    monkeypatch.setattr(gate, "LEGACY_FUNCTION_LIMITS", {})

    evidence_path = tmp_path / "architecture-gate.json"
    assert gate.main(["--output", str(evidence_path)]) == 1

    payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert payload["gate"] == "architecture-budget"
    assert payload["passed"] is False
    assert payload["oversized_functions"][0]["function"] == "oversized"
    assert payload["failures"]


def test_architecture_gate_enforces_orchestrator_dependency_fanout(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "src" / "secmind"
    source.mkdir(parents=True)
    (source / "orchestrator.py").write_text(
        "from secmind.alpha import Alpha\nfrom secmind.beta import Beta\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    monkeypatch.setattr(gate, "SOURCE", source)
    monkeypatch.setattr(gate, "MODULE_LINE_LIMITS", {"orchestrator.py": 10})
    monkeypatch.setattr(gate, "ORCHESTRATOR_DIRECT_IMPORT_LIMIT", 1)
    monkeypatch.setattr(gate, "FUNCTION_LINE_LIMIT", 450)
    monkeypatch.setattr(gate, "LEGACY_FUNCTION_LIMITS", {})

    evidence = gate.evaluate()

    assert evidence["passed"] is False
    assert evidence["orchestrator_direct_import_count"] == 2
    assert any("fan-out budget" in item for item in evidence["failures"])
