from __future__ import annotations

import pytest

from secmind.agent_profiles import BUILTIN_AGENT_PROFILES, AgentProfileError, AgentProfileRegistry
from secmind.skill_registry import SkillRegistry


def _builtin_manifests():
    registry = SkillRegistry.builtin()
    catalog = registry.discover()
    return [registry.load(item.skill_id).manifest for item in catalog]


def test_builtin_profiles_are_bounded_and_accept_builtin_skills() -> None:
    profiles = AgentProfileRegistry()
    manifests = _builtin_manifests()
    for skill in manifests:
        profiles.validate_skill(skill)

    assert all(item.max_turns <= 3 and item.max_tool_calls <= 3 for item in profiles.catalog())


def test_dynamic_profile_selection_is_limited_to_three_and_capability_scoped() -> None:
    profiles = AgentProfileRegistry()
    skills = [item for item in _builtin_manifests() if item.skill_id == "supply-chain-audit"]
    selected = profiles.select(
        skills,
        requested_capabilities={"sbom", "dependency_audit"},
        maximum_workers=3,
    )

    assert [item.profile_id for item in selected] == ["dependency-investigator"]
    assert set(selected[0].allowed_capabilities) == {"sbom", "dependency_audit"}


def test_invalid_parallel_worker_limit_is_rejected() -> None:
    with pytest.raises(AgentProfileError, match="between one and three"):
        AgentProfileRegistry().select([], requested_capabilities=set(), maximum_workers=4)


def test_registry_rejects_duplicate_unbounded_and_unknown_profiles() -> None:
    profile = BUILTIN_AGENT_PROFILES[0]
    with pytest.raises(AgentProfileError, match="duplicate"):
        AgentProfileRegistry([profile, profile])
    with pytest.raises(AgentProfileError, match="bounded"):
        AgentProfileRegistry([profile.model_copy(update={"max_turns": 4})])
    with pytest.raises(KeyError):
        AgentProfileRegistry().get("missing")
    selected = AgentProfileRegistry().select([], requested_capabilities=set(), maximum_workers=2)
    assert len(selected) == 2
    assert AgentProfileRegistry().select([], requested_capabilities={"unknown"}) == []
    incompatible_skill = _builtin_manifests()[0].model_copy(
        update={"skill_id": "unknown-skill", "allowed_agent_profiles": ["repository-scout"]}
    )
    assert AgentProfileRegistry().select([incompatible_skill], requested_capabilities=set()) == []


def test_skill_validation_rejects_unknown_disallowed_and_missing_capabilities() -> None:
    registry = AgentProfileRegistry()
    skill = _builtin_manifests()[0]
    with pytest.raises(AgentProfileError, match="unknown agent profile"):
        registry.validate_skill(skill.model_copy(update={"allowed_agent_profiles": ["missing"]}))
    with pytest.raises(AgentProfileError, match="does not allow"):
        registry.validate_skill(
            skill.model_copy(update={"allowed_agent_profiles": ["sast-investigator"], "skill_id": "project-inventory"})
        )
    with pytest.raises(AgentProfileError, match="lacks capabilities"):
        registry.validate_skill(
            skill.model_copy(
                update={
                    "allowed_agent_profiles": ["repository-scout"],
                    "skill_id": "project-inventory",
                    "required_capabilities": ["sast"],
                }
            )
        )
