from __future__ import annotations

from collections.abc import Iterable

from secmind.schemas import AgentProfile, AuditSkillManifest


class AgentProfileError(ValueError):
    pass


BUILTIN_AGENT_PROFILES = (
    AgentProfile(
        profile_id="repository-scout",
        purpose="Build a bounded repository map and identify relevant audit surfaces.",
        allowed_capabilities=["inventory"],
        allowed_skills=["project-inventory"],
        model_role="worker",
        reasoning_effort="low",
        max_turns=1,
        max_tool_calls=1,
    ),
    AgentProfile(
        profile_id="sast-investigator",
        purpose="Investigate static-analysis and injection evidence in a bounded workspace slice.",
        allowed_capabilities=["sast"],
        allowed_skills=["python-security-audit", "web-auth-review", "injection-dataflow-review"],
        model_role="planner",
        reasoning_effort="medium",
        max_turns=3,
        max_tool_calls=3,
        can_propose_replan=True,
    ),
    AgentProfile(
        profile_id="secret-reviewer",
        purpose="Review redacted credential-candidate evidence without materializing secret values.",
        allowed_capabilities=["secret_scan"],
        allowed_skills=["secret-exposure-review"],
        model_role="worker",
        reasoning_effort="low",
        max_turns=2,
        max_tool_calls=2,
    ),
    AgentProfile(
        profile_id="dependency-investigator",
        purpose="Generate an SBOM and match dependencies against approved offline advisories.",
        allowed_capabilities=["sbom", "dependency_audit"],
        allowed_skills=["supply-chain-audit"],
        model_role="worker",
        reasoning_effort="medium",
        max_turns=3,
        max_tool_calls=2,
    ),
    AgentProfile(
        profile_id="evidence-verifier",
        purpose="Skeptically verify claims against immutable evidence and outcome contracts.",
        allowed_capabilities=[],
        allowed_skills=[
            "python-security-audit",
            "secret-exposure-review",
            "supply-chain-audit",
            "web-auth-review",
            "injection-dataflow-review",
        ],
        model_role="planner",
        reasoning_effort="high",
        max_turns=2,
        max_tool_calls=0,
    ),
)


class AgentProfileRegistry:
    """Trusted profile catalog; profiles constrain workers rather than granting tools."""

    def __init__(self, profiles: Iterable[AgentProfile] = BUILTIN_AGENT_PROFILES) -> None:
        self._profiles: dict[str, AgentProfile] = {}
        for profile in profiles:
            if profile.profile_id in self._profiles:
                raise AgentProfileError(f"duplicate agent profile: {profile.profile_id}")
            if profile.max_turns > 3 or profile.max_tool_calls > 3:
                raise AgentProfileError("agent profiles must remain bounded to three turns and tool calls")
            self._profiles[profile.profile_id] = profile.model_copy(deep=True)

    def catalog(self) -> list[AgentProfile]:
        return [self._profiles[key].model_copy(deep=True) for key in sorted(self._profiles)]

    def get(self, profile_id: str) -> AgentProfile:
        try:
            return self._profiles[profile_id].model_copy(deep=True)
        except KeyError as exc:
            raise KeyError(profile_id) from exc

    def select(
        self,
        skills: Iterable[AuditSkillManifest],
        *,
        requested_capabilities: set[str],
        maximum_workers: int = 3,
    ) -> list[AgentProfile]:
        if not 1 <= maximum_workers <= 3:
            raise AgentProfileError("dynamic worker count must be between one and three")
        selected_skills = {skill.skill_id: skill for skill in skills}
        allowed_profile_ids = {
            profile_id for skill in selected_skills.values() for profile_id in skill.allowed_agent_profiles
        }
        ranked: list[tuple[tuple[int, int, str], AgentProfile]] = []
        for profile in self._profiles.values():
            if allowed_profile_ids and profile.profile_id not in allowed_profile_ids:
                continue
            supported_skills = set(profile.allowed_skills).intersection(selected_skills)
            supported_capabilities = set(profile.allowed_capabilities).intersection(requested_capabilities)
            if requested_capabilities and not supported_capabilities:
                continue
            if selected_skills and not supported_skills:
                continue
            ranked.append(
                (
                    (-len(supported_capabilities), -len(supported_skills), profile.profile_id),
                    profile,
                )
            )
        selected = sorted(ranked, key=lambda pair: pair[0])[:maximum_workers]
        return [profile.model_copy(deep=True) for _, profile in selected]

    def validate_skill(self, skill: AuditSkillManifest) -> None:
        for profile_id in skill.allowed_agent_profiles:
            profile = self._profiles.get(profile_id)
            if profile is None:
                raise AgentProfileError(f"skill references unknown agent profile: {profile_id}")
            if skill.skill_id not in profile.allowed_skills:
                raise AgentProfileError(f"profile {profile_id} does not allow skill {skill.skill_id}")
            if not set(skill.required_capabilities).issubset(set(profile.allowed_capabilities)):
                raise AgentProfileError(f"profile {profile_id} lacks capabilities required by {skill.skill_id}")
