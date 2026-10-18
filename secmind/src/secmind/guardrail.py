from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from secmind.schemas import RiskLevel, ToolManifest


class GuardrailAction(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass(frozen=True)
class GuardrailDecision:
    action: GuardrailAction
    risk_level: RiskLevel
    policy_ids: tuple[str, ...]
    reason: str


class Guardrail:
    """Rules-first policy engine. Model output can never lower a manifest risk level."""

    BLOCKED_TERMS = {
        "credential_theft",
        "persistence",
        "destructive",
        "ransomware",
        "wipe_disk",
        "disable_security",
    }

    def evaluate(
        self,
        manifest: ToolManifest,
        parameters: dict[str, Any],
        autonomy_policy: str,
    ) -> GuardrailDecision:
        serialized = str(parameters).lower()
        permissions = {item.lower() for item in manifest.permissions}
        effective_risk = max(manifest.risk_level, manifest.platform_risk or RiskLevel.R0)
        if manifest.requires_network or manifest.execution.network_policy != "none":
            effective_risk = max(effective_risk, RiskLevel.R2)
        if permissions & {"workspace:write", "host:write", "state:modify", "network:egress"}:
            effective_risk = max(effective_risk, RiskLevel.R2)
        prohibited_capability = permissions & {
            "credentials:read",
            "host:privileged",
            "persistence:write",
            "security:disable",
        }
        if (
            effective_risk >= RiskLevel.R3
            or prohibited_capability
            or any(term in serialized for term in self.BLOCKED_TERMS)
        ):
            return GuardrailDecision(
                GuardrailAction.DENY,
                RiskLevel.R3,
                ("POL-R3-DENY",),
                "Destructive, credential, persistence, or out-of-scope actions are prohibited.",
            )
        if autonomy_policy == "approval_all" or effective_risk == RiskLevel.R2:
            return GuardrailDecision(
                GuardrailAction.REQUIRE_APPROVAL,
                max(effective_risk, RiskLevel.R2),
                ("POL-R2-HITL",),
                "The operation requires explicit operator approval.",
            )
        return GuardrailDecision(
            GuardrailAction.ALLOW,
            effective_risk,
            ("POL-R0-R1-AUTO",),
            "Read-only operation is allowed inside the controlled workspace.",
        )
