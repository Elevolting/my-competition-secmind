from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from secmind.execution import parameters_hash
from secmind.policy import PolicyDecisionPoint, manifest_digest
from secmind.schemas import (
    CapabilityGrant,
    PolicyAction,
    PolicyInput,
    RiskLevel,
    Scenario,
    ToolExecutionPolicy,
    ToolManifest,
)


def _manifest(*, risk: RiskLevel = RiskLevel.R1, permissions: list[str] | None = None) -> ToolManifest:
    return ToolManifest(
        name="audit-tool",
        version="1",
        description="test",
        scenarios=[Scenario.CODE_AUDIT],
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        risk_level=risk,
        permissions=permissions or ["workspace:read"],
        capability_tags=["sast"],
        execution=ToolExecutionPolicy(),
    )


def _input(manifest: ToolManifest, **updates: Any) -> PolicyInput:
    values: dict[str, Any] = {
        "policy_version": "pdp-v1.3",
        "actor": "worker",
        "run_id": "run",
        "step_id": "step",
        "action": "execute",
        "resource": "repo/src/app.py",
        "target_scope": ["repo"],
        "tool_manifest_digest": manifest_digest(manifest),
        "parameters_hash": hashlib.sha256(b"args").hexdigest(),
        "requested_capabilities": ["sast"],
        "fence": 1,
    }
    values.update(updates)
    return PolicyInput(**values)


def test_pdp_allows_scoped_read_only_and_rejects_scope_or_digest_mismatch() -> None:
    manifest = _manifest()
    pdp = PolicyDecisionPoint()
    assert pdp.evaluate(_input(manifest), manifest).action == PolicyAction.ALLOW
    assert pdp.evaluate(_input(manifest, resource="other/app.py"), manifest).action == PolicyAction.DENY
    assert pdp.evaluate(_input(manifest, tool_manifest_digest="0" * 64), manifest).action == PolicyAction.DENY


def test_pdp_requires_bound_unexpired_grant_for_r2() -> None:
    manifest = _manifest(risk=RiskLevel.R2, permissions=["workspace:read", "network:egress"])
    value = _input(manifest, requested_capabilities=["sast", "network:egress"])
    pdp = PolicyDecisionPoint()
    assert pdp.evaluate(value, manifest).action == PolicyAction.REQUIRE_APPROVAL
    grant = CapabilityGrant(
        run_id=value.run_id,
        actor="operator",
        allowed_actions=["execute"],
        allowed_tools=[manifest.name],
        target_scope=value.target_scope,
        parameter_constraints={"parameters_hash": value.parameters_hash},
        max_uses=1,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        grant_digest=hashlib.sha256(b"grant").hexdigest(),
    )
    allowed = pdp.evaluate(value.model_copy(update={"current_grants": [grant]}), manifest)
    assert allowed.action == PolicyAction.ALLOW
    assert allowed.capability_grant is not None
    expired = grant.model_copy(update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)})
    assert (
        pdp.evaluate(value.model_copy(update={"current_grants": [expired]}), manifest).action
        == PolicyAction.REQUIRE_APPROVAL
    )
    wrong_parameters = grant.model_copy(
        update={"parameter_constraints": {"parameters_hash": parameters_hash({"other": True})}}
    )
    assert (
        pdp.evaluate(value.model_copy(update={"current_grants": [wrong_parameters]}), manifest).action
        == PolicyAction.REQUIRE_APPROVAL
    )


def test_r3_is_never_approvable() -> None:
    manifest = _manifest(risk=RiskLevel.R3, permissions=["host:privileged"])
    assert PolicyDecisionPoint().evaluate(_input(manifest), manifest).action == PolicyAction.DENY
