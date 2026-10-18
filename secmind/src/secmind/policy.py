from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

from secmind.ledger import canonical_json
from secmind.schemas import (
    CapabilityGrant,
    DataSensitivity,
    PolicyAction,
    PolicyDecision,
    PolicyInput,
    RiskLevel,
    ToolManifest,
)


class PolicyError(ValueError):
    pass


PROHIBITED_PERMISSIONS = {
    "credentials:read",
    "host:privileged",
    "persistence:write",
    "security:disable",
}
ELEVATED_PERMISSIONS = {"workspace:write", "host:write", "state:modify", "network:egress"}


def manifest_digest(manifest: ToolManifest) -> str:
    return hashlib.sha256(canonical_json(manifest.model_dump(mode="json")).encode()).hexdigest()


def policy_input_digest(value: PolicyInput) -> str:
    return hashlib.sha256(canonical_json(value.model_dump(mode="json")).encode()).hexdigest()


def _normalise_scope(value: str) -> str:
    cleaned = value.replace("\\", "/").strip()
    if "\x00" in cleaned or any(ord(char) < 32 for char in cleaned):
        raise PolicyError("resource contains a prohibited control character")
    return str(PurePosixPath(cleaned))


def resource_in_scope(resource: str, target_scope: list[str]) -> bool:
    if not target_scope:
        return False
    candidate = _normalise_scope(resource)
    for raw_scope in target_scope:
        scope = _normalise_scope(raw_scope)
        if scope in {".", "*"}:
            return True
        if candidate == scope or candidate.startswith(scope.rstrip("/") + "/"):
            return True
    return False


class PolicyDecisionPoint:
    """Deterministic policy decision point; model output cannot authorize actions."""

    def __init__(self, *, policy_version: str = "pdp-v1.3") -> None:
        self.policy_version = policy_version

    def evaluate(self, value: PolicyInput, manifest: ToolManifest) -> PolicyDecision:
        digest = policy_input_digest(value)
        policies: list[str] = ["POLICY-PDP-1.3"]
        effective_risk = max(manifest.risk_level, manifest.platform_risk or RiskLevel.R0)
        permissions = {permission.lower() for permission in manifest.permissions}
        if value.tool_manifest_digest != manifest_digest(manifest):
            return self._decision(
                PolicyAction.DENY,
                RiskLevel.R3,
                policies + ["MANIFEST-DIGEST-MISMATCH"],
                "The tool manifest digest does not match the platform-approved manifest.",
                digest,
            )
        if permissions & PROHIBITED_PERMISSIONS or effective_risk >= RiskLevel.R3:
            return self._decision(
                PolicyAction.DENY,
                RiskLevel.R3,
                policies + ["POL-R3-DENY"],
                "The requested capability is permanently prohibited.",
                digest,
            )
        if not resource_in_scope(value.resource, value.target_scope):
            return self._decision(
                PolicyAction.DENY,
                RiskLevel.R3,
                policies + ["TARGET-SCOPE-DENY"],
                "The requested resource is outside the immutable task scope.",
                digest,
            )
        approved_capabilities = set(manifest.capability_tags) | permissions
        if not set(value.requested_capabilities).issubset(approved_capabilities):
            return self._decision(
                PolicyAction.DENY,
                RiskLevel.R3,
                policies + ["CAPABILITY-ESCALATION-DENY"],
                "The request exceeds the platform-approved tool capabilities.",
                digest,
            )
        if (
            manifest.requires_network
            or manifest.execution.network_policy != "none"
            or permissions & ELEVATED_PERMISSIONS
            or value.network_policy != "none"
            or value.data_classification in {DataSensitivity.SECRET, DataSensitivity.CREDENTIAL_CANDIDATE}
        ):
            effective_risk = max(effective_risk, RiskLevel.R2)
        if "approval_all" in value.task_constraints:
            effective_risk = max(effective_risk, RiskLevel.R2)
        valid_grant = self.select_grant(value, manifest) if effective_risk == RiskLevel.R2 else None
        if effective_risk == RiskLevel.R2 and valid_grant is None:
            return self._decision(
                PolicyAction.REQUIRE_APPROVAL,
                effective_risk,
                policies + ["POL-R2-GRANT"],
                "The operation requires a current capability grant bound to this input.",
                digest,
            )
        return self._decision(
            PolicyAction.ALLOW,
            effective_risk,
            policies + (["POL-R2-GRANT-VALID"] if valid_grant else ["POL-R0-R1-AUTO"]),
            "The request is within the approved scope and technical capability boundary.",
            digest,
            grant=valid_grant,
        )

    @staticmethod
    def select_grant(value: PolicyInput, manifest: ToolManifest) -> CapabilityGrant | None:
        now = datetime.now(UTC)
        for grant in sorted(value.current_grants, key=lambda item: item.grant_id):
            expires_at = grant.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            expected_parameters = grant.parameter_constraints.get("parameters_hash")
            if (
                grant.run_id == value.run_id
                and grant.revoked_at is None
                and expires_at > now
                and grant.uses < grant.max_uses
                and value.action in grant.allowed_actions
                and manifest.name in grant.allowed_tools
                and (not grant.target_scope or resource_in_scope(value.resource, grant.target_scope))
                and expected_parameters == value.parameters_hash
                and (not grant.network_constraints or value.network_policy in grant.network_constraints)
            ):
                return grant
        return None

    @staticmethod
    def _decision(
        action: PolicyAction,
        risk: RiskLevel,
        policy_ids: list[str],
        reason: str,
        input_hash: str,
        *,
        grant: CapabilityGrant | None = None,
        constrained_parameters: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        decision_material = {
            "action": action.value,
            "risk": int(risk),
            "policy_ids": policy_ids,
            "reason": reason,
            "input_hash": input_hash,
            "grant_id": None if grant is None else grant.grant_id,
        }
        decision_id = hashlib.sha256(canonical_json(decision_material).encode()).hexdigest()[:36]
        return PolicyDecision(
            decision_id=decision_id,
            action=action,
            effective_risk=risk,
            policy_ids=policy_ids,
            reason_summary=reason,
            constrained_parameters=constrained_parameters or {},
            capability_grant=grant,
            decision_input_hash=input_hash,
        )
