from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from security_agent.schemas import RiskLevel, ToolManifest


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
        if manifest.risk_level >= RiskLevel.R3 or any(term in serialized for term in self.BLOCKED_TERMS):
            if autonomy_policy == "automatic_r3":
                return GuardrailDecision(
                    GuardrailAction.ALLOW,
                    RiskLevel.R3,
                    ("POL-R3-AUTO",),
                    "操作人已选择自动执行 R3 操作；工作区、授权范围和工具参数校验仍然生效。",
                )
            return GuardrailDecision(
                GuardrailAction.REQUIRE_APPROVAL,
                RiskLevel.R3,
                ("POL-R3-HITL",),
                "高风险操作可能修改或删除数据、访问凭据或建立持久访问，必须由操作人核对目标和参数后逐次批准。",
            )
        # ``automatic`` skips R2 approvals; ``automatic_r3`` skips both R2 and
        # R3 approvals. ``graded`` preserves risk-based review and
        # ``approval_all`` always pauses.
        if autonomy_policy == "approval_all" or (
            manifest.risk_level == RiskLevel.R2
            and autonomy_policy not in {"automatic", "automatic_r3"}
        ):
            return GuardrailDecision(
                GuardrailAction.REQUIRE_APPROVAL,
                max(manifest.risk_level, RiskLevel.R2),
                ("POL-R2-HITL",),
                "The operation requires explicit operator approval.",
            )
        return GuardrailDecision(
            GuardrailAction.ALLOW,
            manifest.risk_level,
            ("POL-R2-AUTO",) if manifest.risk_level == RiskLevel.R2 else ("POL-R0-R1-AUTO",),
            ("操作人已选择自动执行 R2 操作；授权范围和工具参数校验仍然生效。"
             if manifest.risk_level == RiskLevel.R2 else "允许在受控工作区内执行只读操作。"),
        )


def autonomy_policy_skips_approval(risk_level: RiskLevel, autonomy_policy: str) -> bool:
    """Whether the task's explicit autonomy setting skips this risk-tier gate."""
    if autonomy_policy == "automatic_r3":
        return risk_level <= RiskLevel.R3
    if autonomy_policy == "automatic":
        return risk_level <= RiskLevel.R2
    return False
