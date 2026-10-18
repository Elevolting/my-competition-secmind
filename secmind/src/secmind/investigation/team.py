"""Pure domain logic for bounded, evidence-driven investigation teams.

This module deliberately owns no durable mutable state.  Registries are immutable
catalog views and every mailbox/thread transition accepts a serializable snapshot
and returns a new one.  A PostgreSQL adapter can therefore wrap each operation in
CAS/fence checks without having to reverse-engineer process-local state.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, ClassVar, Literal, TypeVar
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secmind.investigation.contracts import (
    AgentProfileV2,
    AgentThreadRef,
    AgentWorkContract,
    CollaborationMessage,
    ContextCapsule,
    MessageKind,
    MessageReceipt,
    PlanContract,
    SkillBinding,
    StrategyLevel,
    TeamMember,
    TeamPlan,
    canonical_content_digest,
    seal_contract,
)
from secmind.schemas import PlanStep, RiskLevel

SHA256_PATTERN = r"^[a-f0-9]{64}$"
COORDINATOR_ROLE = "coordinator"
BROADCAST_ROLE = "broadcast"


class TeamDomainError(ValueError):
    """Base class for deterministic domain rejections."""


class RegistryError(TeamDomainError):
    """A declarative catalog is inconsistent or has been tampered with."""


class TeamFormationError(TeamDomainError):
    """The accepted plan cannot be covered by the approved agent catalog."""


class WorkContractError(TeamDomainError):
    """A work contract would broaden the accepted plan or agent authority."""


class MailboxError(TeamDomainError):
    """Base class for typed mailbox failures."""


class MailboxAuthorizationError(MailboxError):
    """An actor attempted a route or transition it does not own."""


class MailboxConflict(MailboxError):
    """A dedupe key, lease, fence, or transition conflicts with stored state."""


class MailboxBackpressure(MailboxError):
    """The bounded mailbox cannot accept another active message."""


class ContinuationError(TeamDomainError):
    """A bounded thread transition is invalid."""


class ContinuationConflict(ContinuationError):
    """A thread CAS version, fence, attempt, or patch digest is stale."""


class ContinuationLimitError(ContinuationError):
    """The configured attempt or continuation bound has been reached."""


ModelT = TypeVar("ModelT", bound=BaseModel)


def _copy_model(value: ModelT) -> ModelT:
    return value.model_copy(deep=True)


def _catalog_digest(payload: Mapping[str, Any]) -> str:
    return canonical_content_digest(dict(payload))


class AgentRegistry:
    """Immutable, verified view of approved agent profiles.

    ``profile_id`` is the authority identifier used by work contracts, so two
    versions of the same ID cannot coexist in one catalog snapshot.
    """

    def __init__(self, profiles: Iterable[AgentProfileV2]) -> None:
        indexed: dict[str, AgentProfileV2] = {}
        for supplied in profiles:
            profile = _copy_model(supplied)
            if profile.profile_id in indexed:
                raise RegistryError(f"duplicate agent profile: {profile.profile_id}")
            if canonical_content_digest(profile) != profile.content_digest:
                raise RegistryError(f"agent profile digest mismatch: {profile.profile_id}")
            if set(profile.allowed_action_kinds) & set(profile.forbidden_action_kinds):
                raise RegistryError(f"agent profile has allowed/forbidden action overlap: {profile.profile_id}")
            indexed[profile.profile_id] = profile
        if not indexed:
            raise RegistryError("agent registry cannot be empty")
        self._profiles = tuple(indexed[key] for key in sorted(indexed))
        self._by_id = {profile.profile_id: profile for profile in self._profiles}
        self._digest = _catalog_digest({"profiles": [profile.model_dump(mode="json") for profile in self._profiles]})

    @property
    def catalog_digest(self) -> str:
        return self._digest

    def list(self) -> tuple[AgentProfileV2, ...]:
        return tuple(_copy_model(profile) for profile in self._profiles)

    def get(self, profile_id: str) -> AgentProfileV2:
        try:
            return _copy_model(self._by_id[profile_id])
        except KeyError as exc:
            raise RegistryError(f"unknown agent profile: {profile_id}") from exc

    def select(self, *, role: str, capability: str, risk: RiskLevel) -> AgentProfileV2:
        candidates = [
            profile
            for profile in self._profiles
            if profile.role == role
            and capability in profile.allowed_capabilities
            and int(risk) <= int(profile.maximum_risk)
        ]
        if not candidates:
            raise RegistryError(f"no approved profile for role={role!r}, capability={capability!r}, risk={risk.name}")
        return _copy_model(candidates[0])


class SkillRegistry:
    """Immutable bindings between signed skills and compatible profiles."""

    def __init__(self, bindings: Iterable[SkillBinding], agents: AgentRegistry | None = None) -> None:
        indexed: dict[str, SkillBinding] = {}
        for supplied in bindings:
            binding = _copy_model(supplied)
            if binding.skill_id in indexed:
                raise RegistryError(f"duplicate skill binding: {binding.skill_id}")
            if len(set(binding.compatible_profiles)) != len(binding.compatible_profiles):
                raise RegistryError(f"skill contains duplicate compatible profiles: {binding.skill_id}")
            if agents is not None:
                for profile_id in binding.compatible_profiles:
                    profile = agents.get(profile_id)
                    missing = set(binding.required_capabilities) - set(profile.allowed_capabilities)
                    if missing:
                        raise RegistryError(
                            f"skill {binding.skill_id} requires unsupported capabilities "
                            f"for {profile_id}: {sorted(missing)}"
                        )
            indexed[binding.skill_id] = binding
        self._bindings = tuple(indexed[key] for key in sorted(indexed))
        self._by_id = {binding.skill_id: binding for binding in self._bindings}
        self._digest = _catalog_digest({"skills": [binding.model_dump(mode="json") for binding in self._bindings]})

    @property
    def catalog_digest(self) -> str:
        return self._digest

    def list(self) -> tuple[SkillBinding, ...]:
        return tuple(_copy_model(binding) for binding in self._bindings)

    def get(self, skill_id: str) -> SkillBinding:
        try:
            return _copy_model(self._by_id[skill_id])
        except KeyError as exc:
            raise RegistryError(f"unknown skill binding: {skill_id}") from exc

    def for_profile(self, profile_id: str, *, capability: str | None = None) -> tuple[SkillBinding, ...]:
        return tuple(
            _copy_model(binding)
            for binding in self._bindings
            if profile_id in binding.compatible_profiles
            and (capability is None or not binding.required_capabilities or capability in binding.required_capabilities)
        )


class TeamFormer:
    """Compile accepted plan steps into a deterministic, bounded team plan."""

    def __init__(
        self,
        agents: AgentRegistry,
        skills: SkillRegistry,
        *,
        max_members: int = 4,
        max_parallel_specialists: int = 3,
    ) -> None:
        if not 1 <= max_members <= 4:
            raise ValueError("max_members must be between 1 and 4")
        if not 1 <= max_parallel_specialists <= 4:
            raise ValueError("max_parallel_specialists must be between 1 and 4")
        self.agents = agents
        self.skills = skills
        self.max_members = max_members
        self.max_parallel_specialists = max_parallel_specialists
        self.catalog_digest = _catalog_digest(
            {"agent_catalog": agents.catalog_digest, "skill_catalog": skills.catalog_digest}
        )

    def form(
        self,
        plan_contract: PlanContract,
        steps: Sequence[PlanStep],
        *,
        strategy: StrategyLevel = StrategyLevel.BALANCED,
        rationale_summary: str = "Deterministic least-authority team compiled from the accepted plan.",
        team_plan_id: str | None = None,
    ) -> TeamPlan:
        if plan_contract.catalog_digest != self.catalog_digest:
            raise TeamFormationError("plan catalog digest does not match the active agent/skill catalog")
        if not steps:
            raise TeamFormationError("team formation requires at least one step")
        step_ids = [step.step_id for step in steps]
        if len(step_ids) != len(set(step_ids)):
            raise TeamFormationError("plan contains duplicate step IDs")

        grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
        for step in sorted(steps, key=lambda value: value.step_id):
            if step.capability not in plan_contract.allowed_capabilities:
                raise TeamFormationError(f"step capability is outside the plan contract: {step.step_id}")
            try:
                profile = self.agents.select(
                    role=step.agent_role,
                    capability=step.capability,
                    risk=step.risk_hint,
                )
            except RegistryError as exc:
                raise TeamFormationError(str(exc)) from exc
            selected_skills: list[str] = []
            for skill_id in sorted(set(step.skill_ids)):
                try:
                    binding = self.skills.get(skill_id)
                except RegistryError as exc:
                    raise TeamFormationError(str(exc)) from exc
                if profile.profile_id not in binding.compatible_profiles:
                    raise TeamFormationError(f"skill {skill_id} is not compatible with profile {profile.profile_id}")
                if not set(binding.required_capabilities).issubset(profile.allowed_capabilities):
                    raise TeamFormationError(f"skill {skill_id} exceeds profile {profile.profile_id} capabilities")
                selected_skills.append(skill_id)

            key = (profile.profile_id, step.capability, step.concurrency_key)
            entry = grouped.setdefault(
                key,
                {
                    "step_ids": [],
                    "skill_ids": set(),
                    "budget_units": 0,
                    "purposes": [],
                },
            )
            entry["step_ids"].append(step.step_id)
            entry["skill_ids"].update(selected_skills)
            entry["budget_units"] += self._budget_units(step)
            entry["purposes"].append(step.objective)

        if len(grouped) > self.max_members:
            raise TeamFormationError(f"plan requires {len(grouped)} members; configured maximum is {self.max_members}")

        members = [
            TeamMember(
                profile_id=profile_id,
                capability=capability,
                step_ids=sorted(entry["step_ids"]),
                skill_ids=sorted(entry["skill_ids"]),
                concurrency_key=concurrency_key,
                budget_units=entry["budget_units"],
                purpose="; ".join(entry["purposes"]),
            )
            for (profile_id, capability, concurrency_key), entry in sorted(grouped.items())
        ]
        return seal_contract(
            TeamPlan,
            team_plan_id=team_plan_id or str(uuid4()),
            run_id=plan_contract.run_id,
            plan_contract_id=plan_contract.contract_id,
            strategy=strategy,
            members=members,
            max_parallel_specialists=min(self.max_parallel_specialists, len(members)),
            uncovered_obligations=[],
            rationale_summary=rationale_summary,
        )

    @staticmethod
    def _budget_units(step: PlanStep) -> int:
        weighted = (
            step.estimated_tool_calls * 5
            + step.estimated_model_calls * 3
            + step.estimated_tokens / 1000
            + step.estimated_cost_units
        )
        return max(1, math.ceil(weighted))


class WorkContractCompiler:
    """Narrow a plan step into an executable least-authority work contract."""

    def __init__(self, agents: AgentRegistry, skills: SkillRegistry) -> None:
        self.agents = agents
        self.skills = skills

    def compile(
        self,
        *,
        plan_contract: PlanContract,
        team_plan: TeamPlan,
        step: PlanStep,
        immutable_scope: Sequence[str],
        budget_reservation_id: str,
        transition_id: str,
        run_fence: int,
        step_fence: int,
        attempt: int = 1,
        step_generation: int = 0,
        required_evidence_types: Sequence[str] | None = None,
        stop_conditions: Sequence[str] | None = None,
        allowed_input_refs: Sequence[str] = (),
        dependency_refs: Sequence[str] | None = None,
        contract_id: str | None = None,
        delegation_id: str | None = None,
    ) -> AgentWorkContract:
        if team_plan.run_id != plan_contract.run_id or team_plan.plan_contract_id != plan_contract.contract_id:
            raise WorkContractError("team plan is not bound to the accepted plan contract")
        if not immutable_scope:
            raise WorkContractError("immutable scope cannot be empty")
        if attempt > step.max_attempts:
            raise WorkContractError("attempt exceeds the plan step maximum")

        matching_members = [member for member in team_plan.members if step.step_id in member.step_ids]
        if len(matching_members) != 1:
            raise WorkContractError(f"step must have exactly one team assignment: {step.step_id}")
        member = matching_members[0]
        profile = self.agents.get(member.profile_id)
        if profile.role != step.agent_role or member.capability != step.capability:
            raise WorkContractError("team assignment does not match the plan step role/capability")
        if int(step.risk_hint) > int(profile.maximum_risk):
            raise WorkContractError("plan step risk exceeds the selected profile")

        allowed_tools = self._allowed_tools(plan_contract, step)
        if not set(step.tool_candidates).issubset(allowed_tools):
            denied = sorted(set(step.tool_candidates) - allowed_tools)
            raise WorkContractError(f"step requests unapproved tools: {denied}")
        bindings: list[SkillBinding] = []
        for skill_id in sorted(set(step.skill_ids)):
            binding = self.skills.get(skill_id)
            if skill_id not in member.skill_ids or profile.profile_id not in binding.compatible_profiles:
                raise WorkContractError(f"skill is not authorized by the team assignment: {skill_id}")
            bindings.append(binding)

        outcome_contract_id = step.outcome_contract_id
        if outcome_contract_id is None and len(plan_contract.outcome_contract_ids) == 1:
            outcome_contract_id = plan_contract.outcome_contract_ids[0]
        if outcome_contract_id is None or outcome_contract_id not in plan_contract.outcome_contract_ids:
            raise WorkContractError("step has no approved outcome contract")

        evidence_types = list(required_evidence_types or step.output_contract.get("required_evidence_types", []))
        if not evidence_types:
            raise WorkContractError("work contract requires at least one evidence type")
        success_criteria = list(step.success_criteria)
        if not success_criteria:
            raise WorkContractError("work contract requires explicit success criteria")
        stops = list(stop_conditions or [*success_criteria, "budget exhausted", "authority boundary reached"])
        action_kinds = sorted(set(profile.allowed_action_kinds) - set(profile.forbidden_action_kinds))
        if not action_kinds:
            raise WorkContractError("selected profile has no effective allowed action kinds")

        return seal_contract(
            AgentWorkContract,
            contract_id=contract_id or str(uuid4()),
            run_id=plan_contract.run_id,
            step_id=step.step_id,
            profile_id=profile.profile_id,
            plan_revision=plan_contract.revision,
            step_generation=step_generation,
            delegation_id=delegation_id or str(uuid4()),
            attempt=attempt,
            task=step.objective,
            goal=step.objective,
            stop_conditions=stops,
            required_evidence_types=evidence_types,
            capability=step.capability,
            immutable_scope=list(immutable_scope),
            allowed_input_refs=list(allowed_input_refs),
            dependency_refs=list(dependency_refs if dependency_refs is not None else step.dependencies),
            allowed_action_kinds=action_kinds,
            allowed_tool_sets=sorted(set(step.tool_candidates)),
            skill_bindings=bindings,
            success_criteria=success_criteria,
            failure_policy=step.failure_policy.value,
            budget_reservation_id=budget_reservation_id,
            outcome_contract_id=outcome_contract_id,
            run_fence=run_fence,
            step_fence=step_fence,
            transition_id=transition_id,
        )

    @staticmethod
    def _allowed_tools(plan_contract: PlanContract, step: PlanStep) -> set[str]:
        for key in (step.step_id, step.capability, "*"):
            if key in plan_contract.allowed_tool_sets:
                return set(plan_contract.allowed_tool_sets[key])
        return set()


def compile_work_contract(
    agents: AgentRegistry,
    skills: SkillRegistry,
    **values: Any,
) -> AgentWorkContract:
    """Functional facade suitable for dependency-injected coordinator code."""

    return WorkContractCompiler(agents, skills).compile(**values)


class MailboxModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)

    schema_version: Literal["1.5"] = "1.5"


class MailboxActor(MailboxModel):
    run_id: str
    actor_id: str
    profile_id: str
    role: str
    delegation_id: str | None = None
    thread_id: str | None = None
    attempt: int = Field(default=1, ge=1)
    is_lead: bool = False


class TypedMessagePayload(MailboxModel):
    """Base for versioned message data; it never carries policy authority."""

    schema_id: ClassVar[str]


class HypothesisProposedPayload(TypedMessagePayload):
    schema_id = "hypothesis.proposed@1"
    hypothesis_id: str
    statement: str
    subject_ref: str | None = None


class EvidenceNeedProposedPayload(TypedMessagePayload):
    schema_id = "evidence.need_proposed@1"
    proposal_id: str
    requested_evidence_types: tuple[str, ...] = Field(min_length=1)
    reason: str


class EvidenceRequestedPayload(TypedMessagePayload):
    schema_id = "evidence.requested@1"
    request_id: str
    requested_evidence_types: tuple[str, ...] = Field(min_length=1)


class EvidenceSuppliedPayload(TypedMessagePayload):
    schema_id = "evidence.supplied@1"
    request_id: str
    evidence_ids: tuple[str, ...] = Field(min_length=1)


class CritiqueIssuedPayload(TypedMessagePayload):
    schema_id = "critique.issued@1"
    critique_id: str
    target_id: str
    verdict: str


class ContradictionDetectedPayload(TypedMessagePayload):
    schema_id = "contradiction.detected@1"
    subject_ref: str
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    summary: str


class ReplanProposedPayload(TypedMessagePayload):
    schema_id = "replan.proposed@1"
    proposal_id: str
    reason: str
    affected_step_ids: tuple[str, ...] = Field(min_length=1)


class DeliverableSubmittedPayload(TypedMessagePayload):
    schema_id = "deliverable.submitted@1"
    result_id: str
    evidence_ids: tuple[str, ...] = Field(default_factory=tuple)
    artifact_ids: tuple[str, ...] = Field(default_factory=tuple)


class VerificationCompletedPayload(TypedMessagePayload):
    schema_id = "verification.completed@1"
    receipt_id: str
    verdict: str
    evidence_ids: tuple[str, ...] = Field(default_factory=tuple)


DEFAULT_PAYLOAD_TYPES: dict[MessageKind, type[TypedMessagePayload]] = {
    MessageKind.HYPOTHESIS_PROPOSED: HypothesisProposedPayload,
    MessageKind.EVIDENCE_NEED_PROPOSED: EvidenceNeedProposedPayload,
    MessageKind.EVIDENCE_REQUESTED: EvidenceRequestedPayload,
    MessageKind.EVIDENCE_SUPPLIED: EvidenceSuppliedPayload,
    MessageKind.CRITIQUE_ISSUED: CritiqueIssuedPayload,
    MessageKind.CONTRADICTION_DETECTED: ContradictionDetectedPayload,
    MessageKind.REPLAN_PROPOSED: ReplanProposedPayload,
    MessageKind.DELIVERABLE_SUBMITTED: DeliverableSubmittedPayload,
    MessageKind.VERIFICATION_COMPLETED: VerificationCompletedPayload,
}


class DedupeRecord(MailboxModel):
    dedupe_key: str
    message_id: str
    payload_digest: str = Field(pattern=SHA256_PATTERN)


class MailboxSnapshot(MailboxModel):
    run_id: str
    version: int = Field(default=1, ge=1)
    messages: tuple[CollaborationMessage, ...] = Field(default_factory=tuple)
    receipts: tuple[MessageReceipt, ...] = Field(default_factory=tuple)
    dedupe_records: tuple[DedupeRecord, ...] = Field(default_factory=tuple)

    @model_validator(mode="after")
    def validate_unique_ids(self) -> MailboxSnapshot:
        message_ids = [message.message_id for message in self.messages]
        if len(message_ids) != len(set(message_ids)):
            raise ValueError("mailbox contains duplicate message IDs")
        receipt_ids = [receipt.message_id for receipt in self.receipts]
        if len(receipt_ids) != len(set(receipt_ids)):
            raise ValueError("mailbox contains duplicate receipts")
        dedupe_keys = [record.dedupe_key for record in self.dedupe_records]
        if len(dedupe_keys) != len(set(dedupe_keys)):
            raise ValueError("mailbox contains duplicate dedupe keys")
        return self


class MailboxMutation(MailboxModel):
    snapshot: MailboxSnapshot
    message: CollaborationMessage | None = None
    receipt: MessageReceipt | None = None
    idempotent: bool = False


class PeerMessageData(MailboxModel):
    """Projection presented to consumers: peer payload is always untrusted data."""

    authority: Literal["peer_data"] = "peer_data"
    trusted: Literal[False] = False
    policy_patch: None = None
    message_id: str
    kind: MessageKind
    sender_profile_id: str
    payload: dict[str, Any]


_FORBIDDEN_POLICY_KEYS = {
    "allowed_action_kinds",
    "allowed_tools",
    "approval",
    "guardrail",
    "model_id",
    "policy",
    "policy_patch",
    "scope_override",
    "system_prompt",
}


class TypedMailbox:
    """Bounded typed mailbox with coordinator-only consumption.

    The instance contains configuration only.  Persist ``MailboxSnapshot`` and
    compare its ``version`` in the database transaction that applies a mutation.
    """

    def __init__(
        self,
        *,
        capacity: int = 128,
        max_payload_bytes: int = 64 * 1024,
        payload_types: Mapping[MessageKind, type[TypedMessagePayload]] | None = None,
    ) -> None:
        if capacity < 1:
            raise ValueError("capacity must be positive")
        if max_payload_bytes < 256:
            raise ValueError("max_payload_bytes must be at least 256")
        self.capacity = capacity
        self.max_payload_bytes = max_payload_bytes
        self.payload_types = dict(payload_types or DEFAULT_PAYLOAD_TYPES)

    @staticmethod
    def empty(run_id: str) -> MailboxSnapshot:
        return MailboxSnapshot(run_id=run_id)

    def build_message(
        self,
        *,
        actor: MailboxActor,
        kind: MessageKind,
        payload: TypedMessagePayload | Mapping[str, Any],
        recipient_role: str = COORDINATOR_ROLE,
        resolved_recipient_id: str | None = None,
        correlation_id: str,
        contract_digest: str,
        transition_id: str,
        run_fence: int,
        dedupe_key: str,
        expires_at: datetime,
        plan_revision: int = 0,
        step_generation: int = 0,
        causation_id: str | None = None,
        message_id: str | None = None,
        created_at: datetime | None = None,
    ) -> CollaborationMessage:
        payload_type = self._payload_type(kind)
        typed = payload_type.model_validate(payload)
        payload_data = typed.model_dump(mode="json")
        self._reject_policy_fields(payload_data)
        payload_digest = canonical_content_digest(payload_data)
        return CollaborationMessage(
            message_id=message_id or str(uuid4()),
            run_id=actor.run_id,
            sender_profile_id=actor.profile_id,
            sender_delegation_id=actor.delegation_id or actor.actor_id,
            sender_thread_id=actor.thread_id or actor.actor_id,
            sender_attempt=actor.attempt,
            recipient_role=recipient_role,
            resolved_recipient_id=resolved_recipient_id,
            kind=kind,
            correlation_id=correlation_id,
            causation_id=causation_id,
            plan_revision=plan_revision,
            step_generation=step_generation,
            contract_digest=contract_digest,
            transition_id=transition_id,
            run_fence=run_fence,
            payload_schema=payload_type.schema_id,
            payload=payload_data,
            payload_digest=payload_digest,
            dedupe_key=dedupe_key,
            created_at=created_at or datetime.now(UTC),
            expires_at=expires_at,
        )

    def publish(
        self,
        snapshot: MailboxSnapshot,
        actor: MailboxActor,
        message: CollaborationMessage,
    ) -> MailboxMutation:
        self._same_run(snapshot.run_id, actor.run_id, message.run_id)
        if message.sender_profile_id != actor.profile_id:
            raise MailboxAuthorizationError("actor does not own the message sender profile")
        if actor.thread_id is not None and message.sender_thread_id != actor.thread_id:
            raise MailboxAuthorizationError("actor does not own the message sender thread")
        if message.recipient_role == BROADCAST_ROLE:
            if not actor.is_lead:
                raise MailboxAuthorizationError("only the lead may publish a broadcast")
        elif message.recipient_role != COORDINATOR_ROLE:
            raise MailboxAuthorizationError("peer-to-peer delivery is forbidden; route through the coordinator")
        self._validate_payload(message)

        existing = next(
            (record for record in snapshot.dedupe_records if record.dedupe_key == message.dedupe_key),
            None,
        )
        if existing is not None:
            if existing.payload_digest != message.payload_digest:
                raise MailboxConflict("dedupe key was reused with different payload")
            stored = next(item for item in snapshot.messages if item.message_id == existing.message_id)
            return MailboxMutation(snapshot=_copy_model(snapshot), message=_copy_model(stored), idempotent=True)
        if self._active_count(snapshot, message.created_at) >= self.capacity:
            raise MailboxBackpressure("mailbox capacity reached")

        updated = snapshot.model_copy(
            update={
                "version": snapshot.version + 1,
                "messages": (*snapshot.messages, _copy_model(message)),
                "dedupe_records": (
                    *snapshot.dedupe_records,
                    DedupeRecord(
                        dedupe_key=message.dedupe_key,
                        message_id=message.message_id,
                        payload_digest=message.payload_digest,
                    ),
                ),
            },
            deep=True,
        )
        return MailboxMutation(snapshot=updated, message=_copy_model(message))

    def reserve(
        self,
        snapshot: MailboxSnapshot,
        actor: MailboxActor,
        *,
        reservation_owner: str,
        lease_until: datetime,
        now: datetime | None = None,
    ) -> MailboxMutation:
        current = now or datetime.now(UTC)
        self._coordinator(snapshot, actor)
        if lease_until <= current:
            raise MailboxConflict("delivery lease must end in the future")
        receipts = {receipt.message_id: receipt for receipt in snapshot.receipts}
        selected: CollaborationMessage | None = None
        previous: MessageReceipt | None = None
        for message in sorted(snapshot.messages, key=lambda item: (item.created_at, item.message_id)):
            if message.expires_at <= current:
                continue
            receipt = receipts.get(message.message_id)
            if receipt is None:
                selected = message
                break
            if receipt.transport_status == "acked" or receipt.processing_status == "failed_final":
                continue
            if receipt.processing_status == "failed_retryable" or receipt.lease_until <= current:
                selected = message
                previous = receipt
                break
        if selected is None:
            return MailboxMutation(snapshot=_copy_model(snapshot))

        receipt = MessageReceipt(
            message_id=selected.message_id,
            delivery_attempt=(previous.delivery_attempt + 1) if previous else 1,
            reservation_owner=reservation_owner,
            delivery_fence=(previous.delivery_fence + 1) if previous else 1,
            lease_until=lease_until,
            receipt_version=(previous.receipt_version + 1) if previous else 1,
            transport_status="reclaimed" if previous else "reserved",
            processing_status="processing",
        )
        new_receipts = tuple(item for item in snapshot.receipts if item.message_id != selected.message_id) + (receipt,)
        updated = snapshot.model_copy(
            update={"version": snapshot.version + 1, "receipts": new_receipts},
            deep=True,
        )
        return MailboxMutation(snapshot=updated, message=_copy_model(selected), receipt=receipt)

    def ack(
        self,
        snapshot: MailboxSnapshot,
        actor: MailboxActor,
        *,
        message_id: str,
        reservation_owner: str,
        delivery_fence: int,
        transition_id: str,
        now: datetime | None = None,
    ) -> MailboxMutation:
        self._coordinator(snapshot, actor)
        receipt = self._receipt(snapshot, message_id)
        if receipt.transport_status == "acked":
            if receipt.processed_transition_id != transition_id:
                raise MailboxConflict("message was acknowledged by a different transition")
            return MailboxMutation(snapshot=_copy_model(snapshot), receipt=_copy_model(receipt), idempotent=True)
        self._owns_receipt(receipt, reservation_owner, delivery_fence)
        updated_receipt = receipt.model_copy(
            update={
                "receipt_version": receipt.receipt_version + 1,
                "transport_status": "acked",
                "processing_status": "processed",
                "processed_transition_id": transition_id,
                "processed_at": now or datetime.now(UTC),
            },
        )
        updated = self._replace_receipt(snapshot, updated_receipt)
        return MailboxMutation(snapshot=updated, receipt=updated_receipt)

    def fail(
        self,
        snapshot: MailboxSnapshot,
        actor: MailboxActor,
        *,
        message_id: str,
        reservation_owner: str,
        delivery_fence: int,
        retryable: bool,
        transition_id: str,
        now: datetime | None = None,
    ) -> MailboxMutation:
        self._coordinator(snapshot, actor)
        receipt = self._receipt(snapshot, message_id)
        self._owns_receipt(receipt, reservation_owner, delivery_fence)
        updated_receipt = receipt.model_copy(
            update={
                "receipt_version": receipt.receipt_version + 1,
                "transport_status": "delivered",
                "processing_status": "failed_retryable" if retryable else "failed_final",
                "processed_transition_id": transition_id,
                "processed_at": now or datetime.now(UTC),
            },
        )
        updated = self._replace_receipt(snapshot, updated_receipt)
        return MailboxMutation(snapshot=updated, receipt=updated_receipt)

    def as_peer_data(self, message: CollaborationMessage) -> PeerMessageData:
        self._validate_payload(message)
        return PeerMessageData(
            message_id=message.message_id,
            kind=message.kind,
            sender_profile_id=message.sender_profile_id,
            payload=dict(message.payload),
        )

    def _payload_type(self, kind: MessageKind) -> type[TypedMessagePayload]:
        try:
            return self.payload_types[kind]
        except KeyError as exc:
            raise MailboxError(f"no payload type registered for message kind: {kind}") from exc

    def _validate_payload(self, message: CollaborationMessage) -> None:
        payload_type = self._payload_type(message.kind)
        if message.payload_schema != payload_type.schema_id:
            raise MailboxError("message payload schema does not match its kind")
        typed = payload_type.model_validate(message.payload)
        normalized = typed.model_dump(mode="json")
        self._reject_policy_fields(normalized)
        if canonical_content_digest(normalized) != message.payload_digest:
            raise MailboxConflict("message payload digest mismatch")
        encoded = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        if len(encoded) > self.max_payload_bytes:
            raise MailboxBackpressure("message payload exceeds the configured byte limit")

    @classmethod
    def _reject_policy_fields(cls, value: Any) -> None:
        if isinstance(value, Mapping):
            forbidden = _FORBIDDEN_POLICY_KEYS & set(value)
            if forbidden:
                raise MailboxAuthorizationError(f"peer payload contains policy-shaped fields: {sorted(forbidden)}")
            for nested in value.values():
                cls._reject_policy_fields(nested)
        elif isinstance(value, (list, tuple)):
            for nested in value:
                cls._reject_policy_fields(nested)

    @staticmethod
    def _same_run(*run_ids: str) -> None:
        if len(set(run_ids)) != 1:
            raise MailboxAuthorizationError("cross-run mailbox operation rejected")

    @staticmethod
    def _coordinator(snapshot: MailboxSnapshot, actor: MailboxActor) -> None:
        TypedMailbox._same_run(snapshot.run_id, actor.run_id)
        if actor.role != COORDINATOR_ROLE:
            raise MailboxAuthorizationError("only the coordinator may reserve or consume messages")

    @staticmethod
    def _receipt(snapshot: MailboxSnapshot, message_id: str) -> MessageReceipt:
        try:
            return next(receipt for receipt in snapshot.receipts if receipt.message_id == message_id)
        except StopIteration as exc:
            raise MailboxConflict(f"message has no active receipt: {message_id}") from exc

    @staticmethod
    def _owns_receipt(receipt: MessageReceipt, owner: str, fence: int) -> None:
        if receipt.reservation_owner != owner or receipt.delivery_fence != fence:
            raise MailboxConflict("stale or foreign mailbox receipt")

    @staticmethod
    def _replace_receipt(snapshot: MailboxSnapshot, receipt: MessageReceipt) -> MailboxSnapshot:
        receipts = tuple(item for item in snapshot.receipts if item.message_id != receipt.message_id) + (receipt,)
        return snapshot.model_copy(
            update={"version": snapshot.version + 1, "receipts": receipts},
            deep=True,
        )

    @staticmethod
    def _active_count(snapshot: MailboxSnapshot, now: datetime) -> int:
        receipts = {receipt.message_id: receipt for receipt in snapshot.receipts}
        return sum(
            1
            for message in snapshot.messages
            if message.expires_at > now
            and (
                message.message_id not in receipts
                or (
                    receipts[message.message_id].transport_status != "acked"
                    and receipts[message.message_id].processing_status != "failed_final"
                )
            )
        )


MessageMailbox = TypedMailbox


class AttemptStatus(StrEnum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED_RETRYABLE = "failed_retryable"
    FAILED_FINAL = "failed_final"


class ContinuationStatus(StrEnum):
    IDLE = "idle"
    ACTIVE = "active"
    COMPLETED = "completed"
    ATTEMPTS_EXHAUSTED = "attempts_exhausted"
    CONTINUATIONS_EXHAUSTED = "continuations_exhausted"
    FAILED_FINAL = "failed_final"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class ThreadStateModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)

    schema_version: Literal["1.5"] = "1.5"


class AttemptRecord(ThreadStateModel):
    attempt_id: str
    attempt_number: int = Field(ge=1)
    continuation_generation: int = Field(ge=0)
    status: AttemptStatus
    started_at: datetime
    settled_at: datetime | None = None
    patch_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    error_code: str | None = None
    content_digest: str = Field(pattern=SHA256_PATTERN)


class ContinuationSnapshot(ThreadStateModel):
    thread: AgentThreadRef
    attempts: tuple[AttemptRecord, ...] = Field(default_factory=tuple)
    max_attempts: int = Field(default=3, ge=1, le=3)
    max_continuations: int = Field(default=2, ge=0, le=2)
    context_capsule_ids: tuple[str, ...] = Field(default_factory=tuple)
    status: ContinuationStatus = ContinuationStatus.IDLE
    state_version: int = Field(default=1, ge=1)
    content_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_thread_projection(self) -> ContinuationSnapshot:
        active = [attempt for attempt in self.attempts if attempt.status == AttemptStatus.RUNNING]
        if len(active) > 1:
            raise ValueError("continuation snapshot has multiple active attempts")
        if self.status == ContinuationStatus.ACTIVE and len(active) != 1:
            raise ValueError("active continuation snapshot requires one running attempt")
        if self.status != ContinuationStatus.ACTIVE and active:
            raise ValueError("non-active continuation snapshot cannot retain a running attempt")
        return self


class AttemptMutation(ThreadStateModel):
    snapshot: ContinuationSnapshot
    attempt: AttemptRecord | None = None
    idempotent: bool = False


def _seal_local(model_type: type[ModelT], **values: Any) -> ModelT:
    draft = model_type.model_validate({**values, "content_digest": "0" * 64})
    return draft.model_copy(update={"content_digest": canonical_content_digest(draft)})


class ContinuationMachine:
    """CAS/fence-friendly bounded attempt and continuation state machine."""

    def __init__(self, *, max_attempts: int = 3, max_continuations: int = 2) -> None:
        if not 1 <= max_attempts <= 3:
            raise ValueError("max_attempts must be between 1 and 3")
        if not 0 <= max_continuations <= 2:
            raise ValueError("max_continuations must be between 0 and 2")
        self.max_attempts = max_attempts
        self.max_continuations = max_continuations

    def create(
        self,
        *,
        run_id: str,
        root_step_id: str,
        profile_id: str,
        contract_digest: str,
        context_pack_digest: str,
        expected_last_patch_digest: str,
        run_fence: int,
        expires_at: datetime,
        thread_id: str | None = None,
    ) -> ContinuationSnapshot:
        if expires_at <= datetime.now(UTC):
            raise ContinuationError("thread expiry must be in the future")
        thread = seal_contract(
            AgentThreadRef,
            thread_id=thread_id or str(uuid4()),
            run_id=run_id,
            root_step_id=root_step_id,
            profile_id=profile_id,
            contract_digest=contract_digest,
            context_pack_digest=context_pack_digest,
            thread_version=1,
            continuation_generation=0,
            active_attempt_id=None,
            expected_last_patch_digest=expected_last_patch_digest,
            run_fence=run_fence,
            expires_at=expires_at,
            status="idle",
        )
        return _seal_local(
            ContinuationSnapshot,
            thread=thread,
            attempts=(),
            max_attempts=self.max_attempts,
            max_continuations=self.max_continuations,
            context_capsule_ids=(),
            status=ContinuationStatus.IDLE,
            state_version=1,
        )

    def begin_attempt(
        self,
        snapshot: ContinuationSnapshot,
        *,
        expected_state_version: int,
        expected_run_fence: int,
        attempt_id: str | None = None,
        now: datetime | None = None,
    ) -> AttemptMutation:
        current = now or datetime.now(UTC)
        self._cas(snapshot, expected_state_version, expected_run_fence)
        self._not_expired(snapshot, current)
        if snapshot.status != ContinuationStatus.IDLE:
            raise ContinuationError(f"cannot begin attempt from {snapshot.status}")
        generation_attempts = [
            attempt
            for attempt in snapshot.attempts
            if attempt.continuation_generation == snapshot.thread.continuation_generation
        ]
        if len(generation_attempts) >= snapshot.max_attempts:
            raise ContinuationLimitError("attempt limit reached for this continuation generation")
        record = _seal_local(
            AttemptRecord,
            attempt_id=attempt_id or str(uuid4()),
            attempt_number=len(generation_attempts) + 1,
            continuation_generation=snapshot.thread.continuation_generation,
            status=AttemptStatus.RUNNING,
            started_at=current,
            settled_at=None,
            patch_digest=None,
            error_code=None,
        )
        thread = self._update_thread(
            snapshot.thread,
            active_attempt_id=record.attempt_id,
            status="active",
        )
        updated = self._snapshot(
            snapshot,
            thread=thread,
            attempts=(*snapshot.attempts, record),
            status=ContinuationStatus.ACTIVE,
        )
        return AttemptMutation(snapshot=updated, attempt=record)

    def settle_attempt(
        self,
        snapshot: ContinuationSnapshot,
        *,
        attempt_id: str,
        expected_state_version: int,
        expected_run_fence: int,
        patch_digest: str,
        succeeded: bool,
        goal_complete: bool,
        retryable: bool,
        error_code: str | None = None,
        now: datetime | None = None,
    ) -> AttemptMutation:
        current = now or datetime.now(UTC)
        self._cas(snapshot, expected_state_version, expected_run_fence)
        active = next((attempt for attempt in snapshot.attempts if attempt.attempt_id == attempt_id), None)
        if active is None:
            if snapshot.status == ContinuationStatus.ACTIVE and snapshot.thread.active_attempt_id != attempt_id:
                raise ContinuationConflict("attempt is not the active fenced attempt")
            raise ContinuationConflict("active attempt record is missing")
        if active.status != AttemptStatus.RUNNING:
            if active.patch_digest == patch_digest:
                return AttemptMutation(snapshot=_copy_model(snapshot), attempt=_copy_model(active), idempotent=True)
            raise ContinuationConflict("attempt was already settled with a different patch")
        if snapshot.status != ContinuationStatus.ACTIVE or snapshot.thread.active_attempt_id != attempt_id:
            raise ContinuationConflict("attempt is not the active fenced attempt")

        if succeeded:
            attempt_status = AttemptStatus.SUCCEEDED
        elif retryable:
            attempt_status = AttemptStatus.FAILED_RETRYABLE
        else:
            attempt_status = AttemptStatus.FAILED_FINAL
        settled = _seal_local(
            AttemptRecord,
            attempt_id=active.attempt_id,
            attempt_number=active.attempt_number,
            continuation_generation=active.continuation_generation,
            status=attempt_status,
            started_at=active.started_at,
            settled_at=current,
            patch_digest=patch_digest,
            error_code=error_code,
        )
        attempts = tuple(settled if item.attempt_id == attempt_id else item for item in snapshot.attempts)
        generation_count = sum(
            item.continuation_generation == snapshot.thread.continuation_generation for item in attempts
        )
        if succeeded and goal_complete:
            status = ContinuationStatus.COMPLETED
            thread_status = "completed"
        elif not succeeded and not retryable:
            status = ContinuationStatus.FAILED_FINAL
            thread_status = "idle"
        elif generation_count < snapshot.max_attempts:
            status = ContinuationStatus.IDLE
            thread_status = "idle"
        elif snapshot.thread.continuation_generation >= snapshot.max_continuations:
            status = ContinuationStatus.CONTINUATIONS_EXHAUSTED
            thread_status = "idle"
        else:
            status = ContinuationStatus.ATTEMPTS_EXHAUSTED
            thread_status = "idle"
        thread = self._update_thread(
            snapshot.thread,
            active_attempt_id=None,
            expected_last_patch_digest=patch_digest,
            status=thread_status,
        )
        updated = self._snapshot(snapshot, thread=thread, attempts=attempts, status=status)
        return AttemptMutation(snapshot=updated, attempt=settled)

    def request_continuation(
        self,
        snapshot: ContinuationSnapshot,
        capsule: ContextCapsule,
        *,
        expected_state_version: int,
        expected_run_fence: int,
        expected_last_patch_digest: str,
        now: datetime | None = None,
    ) -> ContinuationSnapshot:
        current = now or datetime.now(UTC)
        self._cas(snapshot, expected_state_version, expected_run_fence)
        self._not_expired(snapshot, current)
        if snapshot.status not in {ContinuationStatus.IDLE, ContinuationStatus.ATTEMPTS_EXHAUSTED}:
            raise ContinuationError(f"cannot continue from {snapshot.status}")
        if snapshot.thread.continuation_generation >= snapshot.max_continuations:
            raise ContinuationLimitError("continuation limit reached")
        if expected_last_patch_digest != snapshot.thread.expected_last_patch_digest:
            raise ContinuationConflict("continuation is based on a stale patch")
        if capsule.run_id != snapshot.thread.run_id:
            raise ContinuationConflict("context capsule belongs to a different run")
        if capsule.current_contract_ref != snapshot.thread.contract_digest:
            raise ContinuationConflict("context capsule does not reference the active work contract")
        if canonical_content_digest(capsule) != capsule.content_digest:
            raise ContinuationConflict("context capsule digest mismatch")
        thread = self._update_thread(
            snapshot.thread,
            continuation_generation=snapshot.thread.continuation_generation + 1,
            context_pack_digest=capsule.content_digest,
            active_attempt_id=None,
            status="idle",
        )
        return self._snapshot(
            snapshot,
            thread=thread,
            context_capsule_ids=(*snapshot.context_capsule_ids, capsule.capsule_id),
            status=ContinuationStatus.IDLE,
        )

    def cancel(
        self,
        snapshot: ContinuationSnapshot,
        *,
        expected_state_version: int,
        expected_run_fence: int,
    ) -> ContinuationSnapshot:
        self._cas(snapshot, expected_state_version, expected_run_fence)
        if snapshot.status in {ContinuationStatus.COMPLETED, ContinuationStatus.CANCELLED}:
            return _copy_model(snapshot)
        if snapshot.status == ContinuationStatus.ACTIVE:
            raise ContinuationError("settle the active attempt before cancellation")
        thread = self._update_thread(snapshot.thread, active_attempt_id=None, status="cancelled")
        return self._snapshot(snapshot, thread=thread, status=ContinuationStatus.CANCELLED)

    def expire(
        self,
        snapshot: ContinuationSnapshot,
        *,
        expected_state_version: int,
        expected_run_fence: int,
        now: datetime | None = None,
    ) -> ContinuationSnapshot:
        current = now or datetime.now(UTC)
        self._cas(snapshot, expected_state_version, expected_run_fence)
        if current < snapshot.thread.expires_at:
            raise ContinuationError("thread has not expired")
        if snapshot.status == ContinuationStatus.ACTIVE:
            raise ContinuationError("active attempt must be fenced/recovered before expiry")
        thread = self._update_thread(snapshot.thread, active_attempt_id=None, status="expired")
        return self._snapshot(snapshot, thread=thread, status=ContinuationStatus.EXPIRED)

    @staticmethod
    def _cas(snapshot: ContinuationSnapshot, expected_version: int, expected_fence: int) -> None:
        if snapshot.state_version != expected_version:
            raise ContinuationConflict("stale continuation state version")
        if snapshot.thread.run_fence != expected_fence:
            raise ContinuationConflict("stale run fence")

    @staticmethod
    def _not_expired(snapshot: ContinuationSnapshot, now: datetime) -> None:
        if now >= snapshot.thread.expires_at:
            raise ContinuationError("thread has expired")

    @staticmethod
    def _update_thread(thread: AgentThreadRef, **updates: Any) -> AgentThreadRef:
        values = thread.model_dump(mode="python", exclude={"content_digest"})
        values.update(updates)
        values["thread_version"] = thread.thread_version + 1
        return seal_contract(AgentThreadRef, **values)

    @staticmethod
    def _snapshot(snapshot: ContinuationSnapshot, **updates: Any) -> ContinuationSnapshot:
        values = snapshot.model_dump(mode="python", exclude={"content_digest"})
        values.update(updates)
        values["state_version"] = snapshot.state_version + 1
        return _seal_local(ContinuationSnapshot, **values)


AttemptStateMachine = ContinuationMachine


__all__ = [
    "AgentRegistry",
    "AttemptMutation",
    "AttemptRecord",
    "AttemptStateMachine",
    "AttemptStatus",
    "BROADCAST_ROLE",
    "COORDINATOR_ROLE",
    "ContinuationConflict",
    "ContinuationError",
    "ContinuationLimitError",
    "ContinuationMachine",
    "ContinuationSnapshot",
    "ContinuationStatus",
    "DedupeRecord",
    "MailboxActor",
    "MailboxAuthorizationError",
    "MailboxBackpressure",
    "MailboxConflict",
    "MailboxError",
    "MailboxMutation",
    "MailboxSnapshot",
    "MessageMailbox",
    "PeerMessageData",
    "RegistryError",
    "SkillRegistry",
    "TeamDomainError",
    "TeamFormationError",
    "TeamFormer",
    "TypedMailbox",
    "TypedMessagePayload",
    "WorkContractCompiler",
    "WorkContractError",
    "compile_work_contract",
]
