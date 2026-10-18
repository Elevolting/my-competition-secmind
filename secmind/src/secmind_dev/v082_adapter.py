"""Versioned adapter profiles and sealed execution for the v0.8.2 Bridge.

The adapter is deliberately thin: it constructs a canonical request, lets the
Bridge own process execution, converts the selected JSON into an
``AgentReport``, and hands every outcome to the CAS seal store.  The legacy
v0.8.1 profiles are kept as explicit comparison arms so a report cannot call a
timing/model change an A/B experiment without recording which profile ran.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .v082_bridge import BridgeConfig, BridgeInvocation, BridgeRun, ProcessBridge
from .v082_cas import EvaluationSealStore
from .v082_contracts import (
    AgentReport,
    ContractError,
    FailureCapsule,
    InputManifest,
    QuarantineRecord,
    RunIdentity,
    SealedEvaluation,
    build_run_identity,
    canonical_digest,
    canonical_json,
)


class AdapterError(ValueError):
    """Raised when a profile or adapter request is not reproducible."""


@dataclass(frozen=True, slots=True)
class AdapterProfile:
    profile_id: str
    workers: int
    primary_timeout_seconds: float
    logical_budget_seconds: float
    max_attempts: int
    model_profile: str
    model_id: str
    reasoning_effort: str
    thinking_enabled: bool
    max_output_tokens: int
    fallback_model_id: str | None = None
    transport_mode: str = "separated_connect_read_idle"
    feature_flags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.profile_id or not self.model_profile or not self.model_id:
            raise AdapterError("profile_id, model_profile and model_id are required")
        if self.workers < 1 or self.primary_timeout_seconds <= 0 or self.logical_budget_seconds <= 0:
            raise AdapterError("profile budget and worker values must be positive")
        if self.max_attempts not in {1, 2, 3}:
            raise AdapterError("profile max_attempts must be 1, 2 or 3")
        if self.max_output_tokens < 1:
            raise AdapterError("max_output_tokens must be positive")

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    @property
    def bridge_max_attempts(self) -> int:
        # v0.8.2 permits one primary and one true fallback.  The legacy A
        # profile records its historical retry budget but is clamped at the
        # process boundary rather than silently pretending retries are a
        # fallback experiment.
        return min(self.max_attempts, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "workers": self.workers,
            "primary_timeout_seconds": self.primary_timeout_seconds,
            "logical_budget_seconds": self.logical_budget_seconds,
            "max_attempts": self.max_attempts,
            "model_profile": self.model_profile,
            "model_id": self.model_id,
            "reasoning_effort": self.reasoning_effort,
            "thinking_enabled": self.thinking_enabled,
            "max_output_tokens": self.max_output_tokens,
            "fallback_model_id": self.fallback_model_id,
            "transport_mode": self.transport_mode,
            "feature_flags": list(self.feature_flags),
            "profile_digest": self.digest,
        }


V081_A = AdapterProfile(
    profile_id="v0.8.1-A",
    workers=6,
    primary_timeout_seconds=45.0,
    logical_budget_seconds=45.0,
    max_attempts=3,
    model_profile="ae65c0f-fixed",
    model_id="deepseek-v4-flash",
    reasoning_effort="high",
    thinking_enabled=True,
    max_output_tokens=8_192,
    transport_mode="fixed_outer_deadline",
    feature_flags=("legacy_outer_45s_deadline", "legacy_same_payload_retry_budget"),
)

V081_B = AdapterProfile(
    profile_id="v0.8.1-B",
    workers=6,
    primary_timeout_seconds=180.0,
    logical_budget_seconds=180.0,
    max_attempts=2,
    model_profile="ae65c0f-read-idle",
    model_id="deepseek-v4-flash",
    reasoning_effort="high",
    thinking_enabled=True,
    max_output_tokens=8_192,
    fallback_model_id="deepseek-v4-flash",
    feature_flags=("separated_read_idle", "true_fallback_request"),
)

V082_DEFAULT = AdapterProfile(
    profile_id="v0.8.2-default",
    workers=6,
    primary_timeout_seconds=180.0,
    logical_budget_seconds=180.0,
    max_attempts=2,
    model_profile="v0.8.2-full-flags",
    model_id="deepseek-v4-flash",
    reasoning_effort="high",
    thinking_enabled=True,
    max_output_tokens=16_000,
    fallback_model_id="deepseek-v4-flash",
    feature_flags=(
        "separated_connect_pool_write_read_idle",
        "typed_attempt_capsule",
        "full_evidence_contract",
        "success_conditional_metrics",
    ),
)

PROFILES: dict[str, AdapterProfile] = {item.profile_id: item for item in (V081_A, V081_B, V082_DEFAULT)}


def get_profile(profile_id: str) -> AdapterProfile:
    try:
        return PROFILES[profile_id]
    except KeyError as exc:
        raise AdapterError(f"unknown adapter profile: {profile_id}") from exc


def compare_profiles(left: AdapterProfile, right: AdapterProfile) -> dict[str, Any]:
    """Return an explicit A/B diff suitable for a provenance envelope."""

    left_values = left.to_dict()
    right_values = right.to_dict()
    fields = []
    for name in sorted(set(left_values) | set(right_values)):
        if name == "profile_digest":
            continue
        if left_values.get(name) == right_values.get(name):
            state = "CONTROLLED"
        else:
            state = "CHANGED"
        fields.append({"field": name, "left": left_values.get(name), "right": right_values.get(name), "status": state})
    return {
        "schema_version": "secmind-adapter-ab-v0.8.2",
        "left": left.profile_id,
        "right": right.profile_id,
        "changed_fields": [item["field"] for item in fields if item["status"] == "CHANGED"],
        "fields": fields,
    }


@dataclass(frozen=True, slots=True)
class AdapterRun:
    profile: AdapterProfile
    bridge_run: BridgeRun
    report: AgentReport
    seal: SealedEvaluation

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "secmind-adapter-run-v0.8.2",
            "profile": self.profile.to_dict(),
            "bridge": self.bridge_run.to_dict(),
            "report": self.report.to_dict(),
            "seal": self.seal.to_dict(),
        }


@dataclass(slots=True)
class V082Adapter:
    """Run one task through the versioned Bridge and seal the outcome."""

    command: tuple[str, ...]
    profile: AdapterProfile = V082_DEFAULT
    cas_store: Any = None
    agent_root: Path | None = None
    lockfile_path: Path | None = None
    prompt: object = None
    schema: object = None
    rules: object = None
    adapter_path: Path = field(default_factory=lambda: Path(__file__).resolve())

    def __post_init__(self) -> None:
        if not self.command or any(not isinstance(value, str) or not value for value in self.command):
            raise AdapterError("adapter command must be a non-empty argument array")
        if not isinstance(self.profile, AdapterProfile):
            raise AdapterError("profile must be an AdapterProfile")

    def bridge_config(self, *, working_directory: Path | None = None) -> BridgeConfig:
        return BridgeConfig(
            timeout_seconds=self.profile.primary_timeout_seconds,
            max_attempts=self.profile.bridge_max_attempts,
            working_directory=working_directory,
        )

    def build_invocations(
        self,
        *,
        task_id: str,
        input_manifest: InputManifest,
        prompt: object,
        run_id: str | None = None,
    ) -> tuple[BridgeInvocation, ...]:
        base: dict[str, Any] = {
            "schema_version": "secmind-adapter-request-v0.8.2",
            "task_id": task_id,
            "run_id": run_id or f"{task_id}-{self.profile.profile_id}",
            "input_manifest": input_manifest.to_dict(),
            "prompt": prompt,
            "profile": self.profile.to_dict(),
            "budget": {
                "logical_budget_seconds": self.profile.logical_budget_seconds,
                "provider_request_cap": 24,
            },
        }
        primary = BridgeInvocation(
            command=self.command,
            request={**base, "attempt_type": "primary", "model_id": self.profile.model_id},
            attempt_type="primary",
            model_profile=self.profile.model_profile,
        )
        invocations = [primary]
        if self.profile.fallback_model_id:
            fallback_request = {
                **base,
                "attempt_type": "fallback",
                "model_id": self.profile.fallback_model_id,
                "fallback_for_request_digest": primary.request_digest,
                "fallback": True,
            }
            invocations.append(
                BridgeInvocation(
                    command=self.command,
                    request=fallback_request,
                    attempt_type="fallback",
                    model_profile=f"{self.profile.model_profile}:fallback",
                )
            )
        return tuple(invocations)

    def run(
        self,
        *,
        task_id: str,
        input_manifest: InputManifest,
        prompt: object,
        run_id: str | None = None,
        working_directory: Path | None = None,
        quarantine: Sequence[QuarantineRecord] = (),
        identity: RunIdentity | None = None,
    ) -> AdapterRun:
        from .v082_cas import CASStore

        effective_run_id = run_id or f"{task_id}-{self.profile.profile_id}"
        cas = self.cas_store if self.cas_store is not None else CASStore(Path(".secmind-v082-cas"))
        bridge = ProcessBridge(self.bridge_config(working_directory=working_directory), cas=cas)
        invocations = self.build_invocations(
            task_id=task_id,
            input_manifest=input_manifest,
            prompt=prompt,
            run_id=effective_run_id,
        )
        bridge_run = bridge.run_with_fallback(invocations)
        attempts = bridge_run.attempts
        failures = tuple(item.failure_capsule for item in bridge_run.executions if item.failure_capsule is not None)
        selected = bridge_run.selected_result
        if selected is None:
            report = AgentReport(
                task_id=task_id,
                run_id=effective_run_id,
                status=bridge_run.status,
                summary="Bridge did not produce a scoreable AgentReport",
            )
        else:
            try:
                report = AgentReport.from_dict(selected, default_task_id=task_id, default_run_id=effective_run_id)
            except ContractError as exc:
                report = AgentReport(
                    task_id=task_id,
                    run_id=effective_run_id,
                    status="PARTIAL",
                    summary="adapter report failed the v0.8.2 schema contract",
                    run_proof={"schema_error": str(exc)},
                )
                last = attempts[-1] if attempts else None
                if last is not None:
                    failures = (
                        *failures,
                        FailureCapsule(
                            task_id=task_id,
                            status="PARTIAL",
                            final_error_type="schema",
                            stage="adapter_schema",
                            retryable=False,
                            request_digest=last.request_digest,
                            attempt_ordinals=tuple(item.attempt_ordinal for item in attempts),
                            stdout_sha256=last.stdout_sha256,
                            stderr_sha256=last.stderr_sha256,
                            message="adapter JSON did not satisfy AgentReport contract",
                        ),
                    )
        run_identity = identity or build_run_identity(
            candidate_id=self.profile.profile_id,
            candidate_version="0.8.2",
            agent_root=self.agent_root,
            bridge_path=Path(__file__).with_name("v082_bridge.py").resolve(),
            adapter_path=self.adapter_path,
            lockfile_path=self.lockfile_path,
            workers=self.profile.workers,
            model_profile=self.profile.model_profile,
            model_id=self.profile.model_id,
            model_parameters={
                "reasoning_effort": self.profile.reasoning_effort,
                "thinking_enabled": self.profile.thinking_enabled,
                "max_output_tokens": self.profile.max_output_tokens,
                "transport_mode": self.profile.transport_mode,
            },
            prompt=prompt,
            schema="secmind-evaluation-v0.8.2",
            rules=self.rules,
            input_manifest_digest=input_manifest.digest,
            profile=self.profile.profile_id,
        )
        store = EvaluationSealStore(cas)
        seal = store.seal(
            identity=run_identity,
            report=report,
            input_manifest=input_manifest,
            attempts=attempts,
            failure_capsules=failures,
            quarantine=quarantine,
            bridge_executions=tuple(item.to_dict() for item in bridge_run.executions),
        )
        return AdapterRun(profile=self.profile, bridge_run=bridge_run, report=report, seal=seal)


def write_adapter_snapshot(path: Path, profile: AdapterProfile, *, bridge: BridgeConfig | None = None) -> Path:
    bridge_payload = None
    if bridge is not None:
        bridge_payload = {
            "digest": bridge.digest,
            "timeout_seconds": bridge.timeout_seconds,
            "max_stdout_bytes": bridge.max_stdout_bytes,
            "max_stderr_bytes": bridge.max_stderr_bytes,
            "max_attempts": bridge.max_attempts,
            "kill_grace_seconds": bridge.kill_grace_seconds,
            "inherit_environment": bridge.inherit_environment,
            "pass_environment": list(bridge.pass_environment),
            "fixed_environment": dict(sorted(bridge.fixed_environment.items())),
            "working_directory": str(bridge.working_directory) if bridge.working_directory else None,
        }
    payload: dict[str, Any] = {
        "schema_version": "secmind-adapter-snapshot-v0.8.2",
        "profile": profile.to_dict(),
        "profile_digest": profile.digest,
        "bridge": bridge_payload,
    }
    # Keep this snapshot JSON-only and deterministic; the full config is
    # included so the digest can be independently recomputed.
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(payload))
    return path


__all__ = [
    "AdapterError",
    "AdapterProfile",
    "AdapterRun",
    "PROFILES",
    "V081_A",
    "V081_B",
    "V082_DEFAULT",
    "V082Adapter",
    "compare_profiles",
    "get_profile",
    "write_adapter_snapshot",
]
