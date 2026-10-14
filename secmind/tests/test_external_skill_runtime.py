from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from secmind.api import create_app
from secmind.config import Settings
from secmind.external_skills import ExternalSkillCatalog, SkillRunSelection, SkillRuntime
from secmind.schemas import PlanStep, RiskLevel, Scenario
from secmind.skill_registry import SkillRegistry


def _runtime() -> SkillRuntime:
    signed = SkillRegistry.builtin()
    signed.discover()
    return SkillRuntime(signed, ExternalSkillCatalog.builtin())


def test_pinned_external_catalog_is_metadata_only_and_provenance_complete() -> None:
    catalog = ExternalSkillCatalog.builtin()
    cards = catalog.catalog()

    assert len(cards) == catalog.source.selected_count == 273
    assert catalog.source.commit == "673da1f3b0b7be34ffc9624ef3858fe45f1c3bed"
    assert catalog.source.bodies_included is False
    assert catalog.source.scripts_allowed is False
    assert all(card.source_path == f"skills/{card.skill_id}/SKILL.md" for card in cards)
    assert all(len(card.source_sha256) == 64 for card in cards)
    assert all(card.integration_mode != "C-tool-adapter" for card in cards if card.risk_class in {"R2", "R3"})


def test_external_selection_proactively_matches_the_approved_toolchain() -> None:
    catalog = ExternalSkillCatalog.builtin()
    selected = catalog.select(
        objective="Audit Python source, secrets and dependencies.",
        capabilities={"inventory", "sast", "secret_scan", "sbom", "dependency_audit"},
        languages={"python"},
    )

    assert [item.skill_id for item in selected] == [
        "integrating-sast-into-github-actions-pipeline",
        "implementing-secret-scanning-with-gitleaks",
        "analyzing-sbom-for-supply-chain-vulnerabilities",
    ]
    assert all(item.maximum_risk <= RiskLevel.R1 for item in selected)
    assert [
        item.skill_id
        for item in catalog.select(
            objective="Review serverless function injection.",
            capabilities={"sast"},
            languages={"python"},
        )
    ] == ["detecting-serverless-function-injection"]


def test_every_low_risk_tagged_external_skill_is_explicitly_reachable() -> None:
    catalog = ExternalSkillCatalog.builtin()
    eligible = [card for card in catalog.catalog() if card.maximum_risk <= RiskLevel.R1 and card.capability_tags]

    assert len(eligible) == 27
    for card in eligible:
        selected = catalog.select(
            objective=card.skill_id,
            capabilities=set(card.capability_tags),
            maximum_risk=RiskLevel.R1,
        )
        assert card.skill_id in {item.skill_id for item in selected}


def test_runtime_binds_signed_skills_and_external_cards_before_plan_sealing() -> None:
    runtime = _runtime()
    selection = runtime.select_run(
        objective="Audit Python source, secrets and dependencies.",
        scenario=Scenario.CODE_AUDIT,
        languages={"python"},
        capabilities={"inventory", "sast", "secret_scan", "sbom", "dependency_audit"},
    )
    steps = [
        PlanStep(
            step_id="scan-sast",
            objective="Collect SAST evidence.",
            agent_role="sast_specialist",
            capability="sast",
            tool_candidates=["bandit"],
            success_criteria=["evidence is immutable"],
        ),
        PlanStep(
            step_id="scan-secrets",
            objective="Collect redacted secret evidence.",
            agent_role="secret_specialist",
            capability="secret_scan",
            tool_candidates=["gitleaks"],
            success_criteria=["evidence is redacted"],
        ),
    ]

    bound = runtime.bind_steps(steps, selection)

    assert 1 <= len(bound[0].skill_ids) <= 3
    assert bound[1].skill_ids == ["secret-exposure-review"]
    assert bound[0].context_requirements["external_skill_card_ids"]
    assert bound[1].context_requirements["external_skill_card_ids"] == ["implementing-secret-scanning-with-gitleaks"]
    binding = runtime.compile_binding(bound[1].skill_ids[0])
    assert binding.signer == "secmind-platform-v1"
    assert binding.required_capabilities == ["secret_scan"]
    assert runtime.validate_plan(bound, selection) == []
    assert runtime.validate_plan(
        [bound[0].model_copy(update={"skill_ids": ["unselected-skill"]})],
        selection,
    ) == ["Step scan-sast references an unselected skill: unselected-skill"]


def test_runtime_rejects_an_executable_step_without_a_signed_skill() -> None:
    runtime = _runtime()
    step = PlanStep(
        step_id="unknown",
        objective="Attempt an unsupported capability.",
        agent_role="executor",
        capability="host_shell",
        tool_candidates=["host-shell"],
        success_criteria=["never executes"],
    )

    with pytest.raises(ValueError, match="no signed skill"):
        runtime.bind_steps([step], SkillRunSelection(signed=(), external=()))


def test_external_catalog_api_is_paginated_and_never_returns_bodies(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 'skills.db').as_posix()}",
        input_root=tmp_path / "inputs",
        upload_root=tmp_path / "uploads",
        run_root=tmp_path / "runs",
        artifact_root=tmp_path / "artifacts",
        unsafe_development_tools=True,
    )
    with TestClient(create_app(settings), base_url="http://127.0.0.1") as client:
        response = client.get("/api/v1/skills/external?offset=0&limit=2")

    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 2
    assert payload["total"] == 273
    assert payload["has_more"] is True
    assert payload["bodies_included"] is False
    assert payload["scripts_allowed"] is False
