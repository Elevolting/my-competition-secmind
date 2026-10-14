from __future__ import annotations

import hashlib
from pathlib import Path

from secmind.schemas import InputArtifact, PlanStep, RiskLevel, ToolHealth
from secmind.tool_affinity import route_tools_by_affinity
from secmind.tools import default_registry


def _artifact(root: Path, content: bytes, name: str = "app.py") -> InputArtifact:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return InputArtifact(
        artifact_id="input",
        original_name=target.name,
        relative_path=name,
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        media_type="text/x-python",
    )


def _steps() -> list[PlanStep]:
    return [
        PlanStep(
            step_id="inventory",
            objective="inventory",
            agent_role="scout",
            capability="inventory",
            tool_candidates=["project_inventory"],
            inputs={"target": "."},
            success_criteria=["done"],
            risk_hint=RiskLevel.R0,
        ),
        PlanStep(
            step_id="sast",
            objective="sast",
            agent_role="sast_specialist",
            capability="sast",
            dependencies=["inventory"],
            tool_candidates=["bandit_python_audit", "python_taint_audit"],
            inputs={"target": "."},
            success_criteria=["done"],
            risk_hint=RiskLevel.R1,
        ),
        PlanStep(
            step_id="secrets",
            objective="secrets",
            agent_role="secret_specialist",
            capability="secret_scan",
            dependencies=["inventory"],
            tool_candidates=["secret_pattern_scan"],
            inputs={"target": "."},
            success_criteria=["done"],
            risk_hint=RiskLevel.R1,
        ),
    ]


def _route(root: Path, artifact: InputArtifact):
    registry = default_registry()
    return route_tools_by_affinity(
        workspace=root,
        artifacts=[artifact],
        steps=_steps(),
        manifests={item.name: item for item in registry.manifests()},
    )


def test_command_sink_keeps_deep_secret_scan_reachable_without_a_lexical_gate(tmp_path: Path) -> None:
    result = _route(tmp_path, _artifact(tmp_path, b"def run(value):\n    return os.system(value)\n"))

    tools = {name for step in result.steps for name in step.tool_candidates}
    assert tools == {
        "project_inventory",
        "bandit_python_audit",
        "python_taint_audit",
        "secret_pattern_scan",
    }
    assert "command" in result.signals
    assert result.scores["secret_pattern_scan"] == 15  # noqa: S105
    assert "secret_pattern_scan" not in result.reasons  # noqa: S105


def test_safe_python_keeps_broad_sast_and_runs_redacted_secret_scan(tmp_path: Path) -> None:
    result = _route(tmp_path, _artifact(tmp_path, b"def add(left, right):\n    return left + right\n"))

    tools = {name for step in result.steps for name in step.tool_candidates}
    assert tools == {"project_inventory", "bandit_python_audit", "secret_pattern_scan"}
    assert result.reasons == {
        "python_taint_audit": "low_signal_affinity",
    }


def test_secret_signal_activates_redacted_secret_skill_tool_path(tmp_path: Path) -> None:
    result = _route(tmp_path, _artifact(tmp_path, b"api_key = 'development-placeholder-value'\n"))

    tools = {name for step in result.steps for name in step.tool_candidates}
    assert "secret_pattern_scan" in tools
    assert result.scores["secret_pattern_scan"] == 90


def test_client_secret_signal_activates_redacted_secret_skill_tool_path(tmp_path: Path) -> None:
    result = _route(tmp_path, _artifact(tmp_path, b"client_secret = 'client-secret-value-12345'\n"))

    tools = {name for step in result.steps for name in step.tool_candidates}
    assert "secret_material" in result.signals
    assert "secret_pattern_scan" in tools
    assert result.scores["secret_pattern_scan"] == 90


def test_secret_candidate_filename_keeps_secret_scanner_reachable(tmp_path: Path) -> None:
    result = _route(tmp_path, _artifact(tmp_path, b"value = build_secret_from_parts()\n", ".env"))

    tools = {name for step in result.steps for name in step.tool_candidates}
    assert "secret_candidate" in result.signals
    assert "secret_pattern_scan" in tools
    assert result.scores["secret_pattern_scan"] == 90


def test_dependency_manifest_keeps_available_sca_route_reachable(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path, b'{"lockfileVersion": 3}\n', "pnpm-lock.yaml")
    manifests = {item.name: item for item in default_registry().manifests()}
    manifests["syft_sbom"] = manifests["syft_sbom"].model_copy(update={"health_status": ToolHealth.HEALTHY})
    step = PlanStep(
        step_id="sbom",
        objective="dependency inventory",
        agent_role="dependency_specialist",
        capability="sbom",
        tool_candidates=["syft_sbom"],
        inputs={"target": "."},
        success_criteria=["done"],
        risk_hint=RiskLevel.R1,
    )

    result = route_tools_by_affinity(
        workspace=tmp_path,
        artifacts=[artifact],
        steps=[step],
        manifests=manifests,
    )

    assert "dependency_manifest" in result.signals
    assert result.steps[0].tool_candidates == ["syft_sbom"]
    assert result.scores["syft_sbom"] == 90


def test_java_sensitive_weak_digest_signal_selects_semantic_sast_after_quick_deferral(
    tmp_path: Path,
) -> None:
    source = b"""
    class PasswordStore {
        byte[] hashPassword(String password) throws Exception {
            return MessageDigest.getInstance("MD5").digest(password.getBytes());
        }
    }
    """
    artifact = _artifact(tmp_path, source, "PasswordStore.java")
    step = PlanStep(
        step_id="sast",
        objective="sast",
        agent_role="sast_specialist",
        capability="sast",
        tool_candidates=["bandit_python_audit", "java_semantic_sast", "python_taint_audit"],
        inputs={"target": "."},
        success_criteria=["done"],
        risk_hint=RiskLevel.R1,
        context_requirements={"tool_candidate_limit": 1},
    )
    registry = default_registry()

    result = route_tools_by_affinity(
        workspace=tmp_path,
        artifacts=[artifact],
        steps=[step],
        manifests={item.name: item for item in registry.manifests()},
    )

    assert result.signals == ("java_sensitive_weak_digest",)
    assert result.steps[0].tool_candidates == ["java_semantic_sast"]
    assert result.scores["java_semantic_sast"] == 100


def test_java_output_flow_preserves_camel_case_before_semantic_affinity(tmp_path: Path) -> None:
    source = b"""
    class LegacyStore {
        void checksum(byte[] input) throws Exception {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(input);
            byte[] result = md.digest();
            String passwordFile = "passwordFile.txt";
            FileWriter fw = new FileWriter(passwordFile, true);
            fw.write(result);
        }
    }
    """
    artifact = _artifact(tmp_path, source, "LegacyStore.java")
    step = PlanStep(
        step_id="sast",
        objective="sast",
        agent_role="sast_specialist",
        capability="sast",
        tool_candidates=["semgrep_sast", "java_semantic_sast"],
        inputs={"target": "."},
        success_criteria=["done"],
        risk_hint=RiskLevel.R1,
        context_requirements={"tool_candidate_limit": 1},
    )
    registry = default_registry()

    result = route_tools_by_affinity(
        workspace=tmp_path,
        artifacts=[artifact],
        steps=[step],
        manifests={item.name: item for item in registry.manifests()},
    )

    assert result.signals == ("java_sensitive_weak_digest",)
    assert result.scores["java_semantic_sast"] == 100
    assert result.steps[0].tool_candidates == ["java_semantic_sast"]


def test_java_semantic_scanner_is_not_removed_by_absent_shallow_signal(tmp_path: Path) -> None:
    source = b"""
    class DirectoryLookup {
        void search(HttpServletRequest request) throws Exception {
            String value = request.getParameter("uid");
            String filter = "(uid=" + value + ")";
            DirContext context = manager.getDirContext();
            context.search("ou=users", filter, controls);
        }
    }
    """
    artifact = _artifact(tmp_path, source, "DirectoryLookup.java")
    step = PlanStep(
        step_id="sast",
        objective="sast",
        agent_role="sast_specialist",
        capability="sast",
        tool_candidates=["semgrep_sast", "java_semantic_sast"],
        inputs={"target": "."},
        success_criteria=["done"],
        risk_hint=RiskLevel.R1,
        context_requirements={"tool_candidate_limit": 2},
    )
    registry = default_registry()

    result = route_tools_by_affinity(
        workspace=tmp_path,
        artifacts=[artifact],
        steps=[step],
        manifests={item.name: item for item in registry.manifests()},
    )

    assert result.steps[0].tool_candidates == ["java_semantic_sast"]
    assert result.scores["java_semantic_sast"] == 75
    assert result.reasons["semgrep_sast"] in {"language_incompatible", "tool_unavailable"}


def test_sast_affinity_keeps_three_complementary_independent_scanners(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path, b"def run(value):\n    return os.system(value)\n")
    base = default_registry().manifests()
    broad = next(item for item in base if item.name == "bandit_python_audit")
    flow = broad.model_copy(
        update={
            "name": "scanner-flow",
            "description": "Independent source-to-sink SAST scanner.",
            "evidence_types": ["sast_flow"],
        }
    )
    reviewed = broad.model_copy(
        update={
            "name": "scanner-reviewed",
            "description": "Independent reviewed rule bundle SAST scanner.",
            "evidence_types": ["sast_finding"],
        }
    )
    manifests = {item.name: item for item in base}
    manifests.update(
        {
            "scanner-broad": broad.model_copy(update={"name": "scanner-broad"}),
            flow.name: flow,
            reviewed.name: reviewed,
        }
    )
    step = PlanStep(
        step_id="sast",
        objective="sast",
        agent_role="sast_specialist",
        capability="sast",
        tool_candidates=["scanner-reviewed", "scanner-broad", "scanner-flow"],
        inputs={"target": "."},
        success_criteria=["done"],
        risk_hint=RiskLevel.R1,
    )

    result = route_tools_by_affinity(
        workspace=tmp_path,
        artifacts=[artifact],
        steps=[step],
        manifests=manifests,
    )

    selected = result.steps[0].tool_candidates
    assert set(selected) == {"scanner-broad", "scanner-flow", "scanner-reviewed"}
    assert len(selected) == 3
    assert all(result.steps[0].context_requirements["tool_coverage"][name] for name in selected)
