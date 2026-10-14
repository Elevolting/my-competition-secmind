from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from collections.abc import Iterable

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from secmind.context_influence import work_item_context_fields
from secmind.schemas import (
    AgentState,
    DecisionRecord,
    DependencyBinding,
    EvidenceAssurance,
    FailurePolicy,
    Finding,
    PlanStep,
    RiskLevel,
    Scenario,
    StepPatch,
    StepRuntime,
    StepStatus,
    ToolHealth,
    ToolManifest,
    WorkItem,
)
from secmind.task_context import require_resolved_task_contract


class PlanValidationError(ValueError):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


class PlanValidator:
    """Validate an LLM plan as a bounded capability DAG before it can execute."""

    DEFAULT_ROLES = {
        "scout",
        "sast_specialist",
        "secret_specialist",
        "dependency_specialist",
        "executor",
    }

    def __init__(self, manifests: Iterable[ToolManifest], allowed_roles: set[str] | None = None) -> None:
        self.manifests = {manifest.name: manifest for manifest in manifests}
        self.allowed_roles = allowed_roles or self.DEFAULT_ROLES

    def validate(self, plan: list[PlanStep], scenario: Scenario, state: AgentState) -> list[str]:
        errors: list[str] = []
        identifiers = [step.step_id for step in plan]
        id_set = set(identifiers)
        if len(identifiers) != len(id_set):
            errors.append("Plan step identifiers must be unique")
        if len(plan) > state.budget.max_steps:
            errors.append("Plan exceeds step budget")

        tool_estimate = 0
        model_estimate = 0
        token_estimate = 0
        cost_estimate = 0.0
        for step in plan:
            if not step.step_id.strip():
                errors.append("Plan step identifiers must not be empty")
            if step.step_id in step.dependencies:
                errors.append(f"Step {step.step_id} cannot depend on itself")
            unknown_dependencies = sorted(set(step.dependencies) - id_set)
            if unknown_dependencies:
                errors.append(f"Unknown dependencies in {step.step_id}: {', '.join(unknown_dependencies)}")
            if step.agent_role not in self.allowed_roles:
                errors.append(f"Unsupported agent role in {step.step_id}: {step.agent_role}")
            if not step.success_criteria:
                errors.append(f"Step {step.step_id} must define success criteria")
            model_agent = step.context_requirements.get("execution_kind") == "model_agent"
            if not step.tool_candidates and not (
                model_agent and step.estimated_tool_calls == 0 and step.estimated_model_calls > 0
            ):
                errors.append(f"Step {step.step_id} has no executable tool or bounded model Agent")
            self._validate_dependency_bindings(step, plan, errors)
            for tool_name in step.tool_candidates:
                manifest = self.manifests.get(tool_name)
                if manifest is None:
                    errors.append(f"Unknown tool in {step.step_id}: {tool_name}")
                    continue
                if manifest.health_status == ToolHealth.UNAVAILABLE:
                    errors.append(f"Tool {tool_name} is unavailable")
                if scenario not in manifest.scenarios:
                    errors.append(f"Tool {tool_name} does not support scenario {scenario.value}")
                effective_risk = max(manifest.risk_level, manifest.platform_risk or RiskLevel.R0)
                if step.risk_hint < effective_risk:
                    errors.append(f"Step {step.step_id} understates risk for {tool_name}")
                if manifest.capability_tags and step.capability not in manifest.capability_tags:
                    errors.append(f"Tool {tool_name} does not provide capability {step.capability}")
            tool_estimate += step.estimated_tool_calls
            model_estimate += step.estimated_model_calls
            token_estimate += step.estimated_tokens
            cost_estimate += step.estimated_cost_units

        if tool_estimate > state.budget.max_tool_calls:
            errors.append("Plan exceeds tool-call budget")
        if model_estimate > state.budget.max_model_calls:
            errors.append("Plan exceeds model-call budget")
        if token_estimate > state.budget.max_input_tokens + state.budget.max_output_tokens:
            errors.append("Plan exceeds token budget")
        if cost_estimate > state.budget.max_cost_units:
            errors.append("Plan exceeds cost budget")
        if self._has_cycle(plan):
            errors.append("Plan dependencies contain a cycle")
        return errors

    @staticmethod
    def _validate_dependency_bindings(
        step: PlanStep,
        plan: list[PlanStep],
        errors: list[str],
    ) -> None:
        by_id = {item.step_id: item for item in plan}
        seen: set[tuple[str, str]] = set()
        output_names: set[str] = set()
        for binding in step.dependency_bindings:
            key = (binding.upstream_step_id, binding.output_name)
            if key in seen:
                errors.append(f"Duplicate dependency binding in {step.step_id}: {binding.output_name}")
            seen.add(key)
            if binding.output_name in output_names:
                errors.append(f"Dependency output names must be unique in {step.step_id}: {binding.output_name}")
            output_names.add(binding.output_name)
            if binding.upstream_step_id not in step.dependencies:
                errors.append(
                    f"Dependency binding in {step.step_id} references undeclared dependency {binding.upstream_step_id}"
                )
            if not binding.output_name.strip():
                errors.append(f"Dependency binding in {step.step_id} has an empty output name")
            if not binding.expected_media_type.strip():
                errors.append(f"Dependency binding in {step.step_id} has an empty media type")
            if binding.artifact_id is not None and not _is_sha256(binding.artifact_id):
                errors.append(f"Dependency binding in {step.step_id} has an invalid artifact id")
            try:
                Draft202012Validator.check_schema(binding.expected_schema)
            except SchemaError:
                errors.append(f"Dependency binding in {step.step_id} has an invalid JSON Schema")
            producer = by_id.get(binding.upstream_step_id)
            if producer is not None and producer.output_contract:
                declared = _declared_outputs(producer.output_contract)
                if declared is not None and binding.output_name not in declared:
                    errors.append(
                        f"Dependency binding in {step.step_id} references undeclared output "
                        f"{binding.output_name} from {producer.step_id}"
                    )

    @staticmethod
    def _has_cycle(plan: list[PlanStep]) -> bool:
        indegree = {step.step_id: len(set(step.dependencies)) for step in plan}
        outgoing: dict[str, set[str]] = defaultdict(set)
        for step in plan:
            for dependency in step.dependencies:
                outgoing[dependency].add(step.step_id)
        queue = deque(sorted(step_id for step_id, degree in indegree.items() if degree == 0))
        visited = 0
        while queue:
            current = queue.popleft()
            visited += 1
            for child in sorted(outgoing[current]):
                indegree[child] -= 1
                if indegree[child] == 0:
                    queue.append(child)
        return visited != len(plan)


class DagScheduler:
    def __init__(self, concurrency_limits: dict[str, int] | None = None) -> None:
        self.concurrency_limits = dict(concurrency_limits or {})
        if any(limit < 1 for limit in self.concurrency_limits.values()):
            raise ValueError("DAG concurrency limits must be positive")

    def initialize(self, state: AgentState) -> None:
        for step in state.plan:
            state.step_runtime.setdefault(step.step_id, StepRuntime(step_id=step.step_id))

    def ready_steps(self, state: AgentState) -> list[PlanStep]:
        self.initialize(state)
        by_id = {step.step_id: step for step in state.plan}
        active_by_key: dict[str, int] = defaultdict(int)
        for active_step in state.plan:
            if state.step_runtime[active_step.step_id].status == StepStatus.RUNNING:
                active_by_key[active_step.concurrency_key] += 1
        ready: list[PlanStep] = []
        for step in sorted(state.plan, key=lambda item: item.step_id):
            runtime = state.step_runtime[step.step_id]
            if runtime.status not in {StepStatus.PENDING, StepStatus.READY}:
                continue
            dependency_states = [state.step_runtime[item].status for item in step.dependencies]
            dependency_failed = any(
                status in {StepStatus.FAILED, StepStatus.SKIPPED, StepStatus.CANCELLED} for status in dependency_states
            )
            if dependency_failed:
                if step.failure_policy in {FailurePolicy.FAIL_FAST, FailurePolicy.SKIP_DEPENDENTS}:
                    runtime.status = StepStatus.SKIPPED
                    runtime.last_error = "A required dependency did not succeed"
                    continue
            dependencies_satisfied = all(status == StepStatus.SUCCEEDED for status in dependency_states)
            if step.failure_policy == FailurePolicy.CONTINUE and dependency_failed:
                dependencies_satisfied = all(
                    status in {StepStatus.SUCCEEDED, StepStatus.FAILED, StepStatus.SKIPPED, StepStatus.CANCELLED}
                    for status in dependency_states
                )
            if dependencies_satisfied:
                key_limit = self.concurrency_limits.get(step.concurrency_key)
                reserved = active_by_key[step.concurrency_key] + sum(
                    item.concurrency_key == step.concurrency_key for item in ready
                )
                if key_limit is not None and reserved >= key_limit:
                    continue
                runtime.status = StepStatus.READY
                ready.append(by_id[step.step_id])
        return ready[: state.budget.max_parallel_steps]

    @staticmethod
    def complete(state: AgentState) -> bool:
        terminal = {StepStatus.SUCCEEDED, StepStatus.FAILED, StepStatus.SKIPPED, StepStatus.CANCELLED}
        return bool(state.plan) and all(item.status in terminal for item in state.step_runtime.values())

    @staticmethod
    def resolve_step_bindings(state: AgentState, step: PlanStep) -> list[DependencyBinding]:
        resolved: list[DependencyBinding] = []
        for binding in step.dependency_bindings:
            runtime = state.step_runtime.get(binding.upstream_step_id)
            if runtime is None:
                raise PlanValidationError([f"Dependency binding references unknown step: {binding.upstream_step_id}"])
            artifact_ids = sorted(set(runtime.artifact_ids))
            artifact_id = binding.artifact_id
            if artifact_id is None:
                if len(artifact_ids) != 1:
                    raise PlanValidationError(
                        [
                            f"Dependency output {binding.output_name} from {binding.upstream_step_id} "
                            "cannot be resolved unambiguously"
                        ]
                    )
                artifact_id = artifact_ids[0]
            elif artifact_id not in artifact_ids:
                raise PlanValidationError(
                    [f"Dependency artifact {artifact_id} is not owned by completed step {binding.upstream_step_id}"]
                )
            resolved.append(binding.model_copy(update={"artifact_id": artifact_id}))
        return sorted(resolved, key=lambda item: (item.upstream_step_id, item.output_name))

    @staticmethod
    def build_work_item(state: AgentState, step: PlanStep) -> WorkItem:
        contract = require_resolved_task_contract(state)
        runtime = state.step_runtime[step.step_id]
        attempt = runtime.attempt + 1
        ticket_limits = [
            ticket.max_tool_calls for ticket in state.evidence_gap_tickets if ticket.step_id == step.step_id
        ]
        max_tool_calls = min(ticket_limits, default=3)
        dependency_bindings = DagScheduler.resolve_step_bindings(state, step)
        if dependency_bindings:
            dependency_refs = sorted(
                binding.artifact_id for binding in dependency_bindings if binding.artifact_id is not None
            )
        else:
            dependency_refs = sorted(
                artifact_id
                for dependency in step.dependencies
                for artifact_id in state.step_runtime[dependency].artifact_ids
            )
        profile_id = _agent_profile_id(step)
        matching_packs = [
            pack
            for pack in state.context_packs
            if pack.run_id == state.run_id and pack.step_id == step.step_id and pack.agent_profile == profile_id
        ]
        context_pack = matching_packs[-1] if matching_packs else None
        context_pack_id = context_pack.pack_id if context_pack is not None else None
        influence_payload = state.audit_coverage.get("context_influence", {})
        context_influence_digest = (
            str(influence_payload.get("context_digest"))
            if isinstance(influence_payload, dict) and influence_payload.get("context_digest")
            else None
        )
        context_fields = work_item_context_fields(
            context_pack=context_pack,
            context_influence_digest=context_influence_digest,
        )
        canonical = json.dumps(
            {
                "run_id": state.run_id,
                "step_id": step.step_id,
                "attempt": attempt,
                "inputs": step.inputs,
                "dependencies": dependency_refs,
                "dependency_bindings": [binding.model_dump(mode="json") for binding in dependency_bindings],
                "capability_candidates": step.tool_candidates,
                "skill_ids": step.skill_ids,
                "agent_profile": profile_id,
                "context_pack_id": context_pack_id,
                **context_fields,
                "outcome_contract_id": step.outcome_contract_id,
                "lease_fence": state.lease.fence,
                "max_tool_calls": max_tool_calls,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        transition_id = hashlib.sha256(canonical.encode()).hexdigest()
        runtime.status = StepStatus.RUNNING
        runtime.attempt = attempt
        runtime.transition_id = transition_id
        runtime.lease_fence = state.lease.fence
        return WorkItem(
            run_id=state.run_id,
            step_id=step.step_id,
            capability=step.capability,
            tool_name=step.tool_candidates[0],
            inputs=step.inputs,
            workspace_ref=state.workspace,
            autonomy_policy=contract.autonomy_policy,
            dependency_refs=dependency_refs,
            dependency_bindings=dependency_bindings,
            context_pack_id=context_pack_id,
            **context_fields,
            outcome_contract_id=step.outcome_contract_id,
            capability_candidates=step.tool_candidates,
            skill_ids=step.skill_ids,
            agent_profile=profile_id,
            transition_id=transition_id,
            lease_fence=state.lease.fence,
            lease_owner_id=state.lease.owner_id or "local-worker",
            attempt=attempt,
            max_tool_calls=max_tool_calls,
            budget_reservation=state.budget.model_copy(deep=True),
        )


class DeterministicReducer:
    """Merge isolated worker patches without depending on completion order."""

    @staticmethod
    def apply(state: AgentState, patches: Iterable[StepPatch]) -> AgentState:
        evidence_by_id = {item.evidence_id: item for item in state.evidence}
        finding_by_key = {DeterministicReducer.finding_fingerprint(item): item for item in state.findings}
        for patch in sorted(patches, key=lambda item: (item.step_id, item.transition_id)):
            if patch.transition_id in state.processed_transition_ids:
                continue
            runtime = state.step_runtime[patch.step_id]
            if runtime.transition_id != patch.transition_id:
                continue
            state.processed_transition_ids.add(patch.transition_id)
            runtime.status = patch.status
            runtime.run_fence = patch.run_fence
            runtime.step_fence = patch.step_fence
            runtime.actual_tool_calls = patch.actual_tool_calls
            runtime.tool_invocation_ids = sorted(set(patch.tool_invocation_ids))
            runtime.actual_tool_name = patch.actual_tool_name
            runtime.actual_tool_version = patch.actual_tool_version
            runtime.artifact_ids = sorted(set(runtime.artifact_ids) | set(patch.artifact_ids))
            runtime.last_error = patch.typed_error
            finding_evidence_ids = {evidence_id for finding in patch.findings for evidence_id in finding.evidence_ids}
            for evidence in patch.evidence:
                if evidence.evidence_id in finding_evidence_ids:
                    metadata = dict(evidence.metadata)
                    semantic = metadata.get("semantic_corroboration") is True or metadata.get("evidence_type") in {
                        "sast_flow",
                        "verified_data_flow",
                    }
                    metadata.setdefault(
                        "assurance_level",
                        (
                            EvidenceAssurance.SEMANTICALLY_CORROBORATED.value
                            if semantic
                            else EvidenceAssurance.INTEGRITY_VERIFIED.value
                        ),
                    )
                    evidence = evidence.model_copy(update={"metadata": metadata})
                evidence_by_id.setdefault(evidence.evidence_id, evidence)
            for finding in patch.findings:
                fingerprint = DeterministicReducer.finding_fingerprint(finding)
                existing = finding_by_key.get(fingerprint)
                if existing is None:
                    state.findings.append(finding)
                    finding_by_key[fingerprint] = finding
                else:
                    merged = DeterministicReducer._merge_findings(existing, finding, patch)
                    state.findings[state.findings.index(existing)] = merged
                    finding_by_key[fingerprint] = merged
            if patch.observation is not None:
                runtime.observation_indexes.append(len(state.observations))
                state.observations.append(patch.observation)
            state.decisions.append(
                DecisionRecord(
                    decision=f"step_{patch.status.value}",
                    rationale_summary=(
                        patch.decision_summary or patch.typed_error or "Worker patch reduced deterministically."
                    ),
                    evidence_ids=sorted(item.evidence_id for item in patch.evidence),
                    policy_ids=["DAG-REDUCER-V1"],
                    model_id="deterministic-reducer",
                )
            )
            step = next((item for item in state.plan if item.step_id == patch.step_id), None)
            if step is not None and step.skill_ids and patch.actual_tool_calls:
                external_ids = step.context_requirements.get("external_skill_card_ids", [])
                state.decisions.append(
                    DecisionRecord(
                        decision="skill_tool_invoked",
                        rationale_summary=(
                            f"Signed skills {', '.join(sorted(step.skill_ids))} actively guided "
                            f"{patch.actual_tool_name or step.tool_candidates[0]}; advisory cards "
                            f"{', '.join(sorted(str(item) for item in external_ids)) or 'none'} supplied L5 context."
                        ),
                        evidence_ids=sorted(item.evidence_id for item in patch.evidence),
                        policy_ids=["SIGNED-SKILL-BINDING-V1", "ATOMIC-TOOL-BROKER-V1"],
                        model_id="bounded-skill-worker",
                        confidence=1.0,
                    )
                )
            state.budget.usage.provider_requests += patch.usage.provider_requests
            state.budget.usage.input_tokens += patch.usage.input_tokens
            state.budget.usage.output_tokens += patch.usage.output_tokens
            state.budget.usage.cache_hit_input_tokens += patch.usage.cache_hit_input_tokens
            state.budget.usage.cache_miss_input_tokens += patch.usage.cache_miss_input_tokens
            state.budget.usage.cost_units += patch.usage.cost_units
        state.evidence = sorted(evidence_by_id.values(), key=lambda item: item.evidence_id)
        state.findings.sort(key=lambda item: DeterministicReducer.finding_fingerprint(item))
        return state

    @staticmethod
    def finding_fingerprint(finding: object) -> str:
        values = (
            str(getattr(finding, "rule_id", "")),
            str(getattr(finding, "path", "")),
            str(getattr(finding, "line", "")),
        )
        return hashlib.sha256("\x1f".join(values).encode()).hexdigest()

    @staticmethod
    def _merge_findings(existing: Finding, incoming: Finding, patch: StepPatch) -> Finding:
        severity_rank = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        confidence_rank = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
        existing_severity = str(getattr(existing, "severity", "UNKNOWN"))
        incoming_severity = str(getattr(incoming, "severity", "UNKNOWN"))
        existing_confidence = str(getattr(existing, "confidence", "UNKNOWN"))
        incoming_confidence = str(getattr(incoming, "confidence", "UNKNOWN"))
        raw = dict(getattr(existing, "raw", {}))
        tools = set(raw.get("corroborated_by_tools", []))
        native_rule_ids = set(raw.get("corroborating_native_rule_ids", []))
        for finding in (existing, incoming):
            finding_raw = getattr(finding, "raw", {})
            producer = finding_raw.get("tool_name")
            if isinstance(producer, str) and producer:
                tools.add(producer)
            for key in ("native_rule_id", "test_id", "check_id"):
                native_rule_id = finding_raw.get(key)
                if isinstance(native_rule_id, str) and native_rule_id:
                    native_rule_ids.add(native_rule_id)
            declared_native_ids = finding_raw.get("corroborating_native_rule_ids", [])
            if isinstance(declared_native_ids, list):
                native_rule_ids.update(item for item in declared_native_ids if isinstance(item, str) and item)
        if patch.actual_tool_name:
            tools.add(patch.actual_tool_name)
        raw["corroborated_by_tools"] = sorted(tools)
        if native_rule_ids:
            raw["corroborating_native_rule_ids"] = sorted(native_rule_ids)
        return existing.model_copy(
            update={
                "severity": max(
                    (existing_severity, incoming_severity),
                    key=lambda item: severity_rank.get(item, 0),
                ),
                "confidence": max(
                    (existing_confidence, incoming_confidence),
                    key=lambda item: confidence_rank.get(item, 0),
                ),
                "evidence_ids": sorted(
                    set(getattr(existing, "evidence_ids", [])) | set(getattr(incoming, "evidence_ids", []))
                ),
                "raw": raw,
            }
        )


def _is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(character in "0123456789abcdef" for character in lowered)


def _declared_outputs(contract: dict[str, object]) -> set[str] | None:
    properties = contract.get("properties")
    if isinstance(properties, dict):
        return {str(item) for item in properties}
    outputs = contract.get("outputs")
    if isinstance(outputs, dict):
        return {str(item) for item in outputs}
    if outputs is not None and isinstance(outputs, list):
        return {str(item) for item in outputs}
    return None


def _agent_profile_id(step: PlanStep) -> str:
    aliases = {
        "scout": "repository-scout",
        "sast_specialist": "sast-investigator",
        # This is a bounded agent profile identifier, not a credential.
        "secret_specialist": "secret-reviewer",  # nosec B105
        "dependency_specialist": "dependency-investigator",
    }
    return aliases.get(step.agent_role, step.agent_role)
