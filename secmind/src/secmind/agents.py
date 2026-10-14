from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from secmind.direct_anchor_pipeline import (
    CandidateStore,
    DeltaAction,
    DeltaDisposition,
    TypedDelta,
    evidence_semantic_checks,
)
from secmind.llm import QwenGateway
from secmind.model_policy import MODEL_CATALOG
from secmind.model_router import ModelTaskKind
from secmind.orchestration.obligation_runtime import clamp_run_status, current_obligation_set
from secmind.prompting.contracts import (
    ComplexityClass,
    PromptContext,
    PromptOutcome,
    PromptRole,
    RepositoryShape,
    canonical_digest,
)
from secmind.prompting.profiler import PromptContextProfiler
from secmind.prompting.service import PromptService
from secmind.schemas import (
    AgentReport,
    AgentState,
    ClaimStatus,
    DecisionRecord,
    PlanStep,
    RiskLevel,
    RunStatus,
    Scenario,
    ToolStatus,
)
from secmind.task_context import require_resolved_task_contract
from secmind.task_contract import (
    IndependenceProof,
    seal_independence_proof,
    validate_independence_proof,
)


class PlanOutput(BaseModel):
    steps: list[PlanStep]
    rationale_summary: str


class DeltaCriticDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["accepted", "rejected", "unresolved"] = "unresolved"
    rationale: str = ""
    conflict_delta_ids: list[str] = Field(default_factory=list)


class BaseAgent(ABC):
    """Base class for bounded specialist nodes controlled by the orchestrator."""

    name: str
    model_role: str = "worker"
    prompt_version: str = "v1"
    max_react_rounds: int = 3

    def __init__(self, gateway: QwenGateway, prompt_service: PromptService | None = None) -> None:
        self.gateway = gateway
        self.prompt_service = prompt_service

    @abstractmethod
    async def run(self, state: AgentState) -> AgentState:
        raise NotImplementedError


class TaskInterpreterAgent(BaseAgent):
    name = "task_interpreter"

    async def run(self, state: AgentState) -> AgentState:
        contract = require_resolved_task_contract(state)
        scenario = Scenario(contract.primary_scenario)
        state.scenario = scenario
        state.decisions.append(
            DecisionRecord(
                decision=f"scenario={scenario.value}",
                rationale_summary="Scenario projected from the sealed ResolvedTaskContract.",
                policy_ids=["ROUTE-RESOLVED-TASK-CONTRACT-V1"],
                model_id="deterministic-contract-router",
                prompt_version=self.prompt_version,
            )
        )
        return state


class PlannerAgent(BaseAgent):
    name = "planner"
    model_role = "planner"

    async def run(self, state: AgentState) -> AgentState:
        contract = require_resolved_task_contract(state)
        scenario = Scenario(contract.primary_scenario)
        state.scenario = scenario
        if scenario != Scenario.CODE_AUDIT:
            state.plan = []
            state.decisions.append(
                DecisionRecord(
                    decision="no_supported_plan",
                    rationale_summary="Only the code-audit scenario is enabled in the first executable baseline.",
                    policy_ids=["SCOPE-MVP-CODE-AUDIT"],
                    model_id="deterministic-planner",
                    prompt_version=self.prompt_version,
                )
            )
            return state
        default = PlanOutput(
            steps=[
                PlanStep(
                    step_id="audit-python-bandit",
                    objective="Scan the controlled workspace for Python security weaknesses.",
                    agent_role="sast_specialist",
                    capability="sast",
                    tool_candidates=["bandit_python_audit"],
                    inputs={"target": "."},
                    success_criteria=[
                        "Bandit returns a valid structured result",
                        "Every reported finding has an evidence reference",
                    ],
                    risk_hint=RiskLevel.R1,
                    max_attempts=2,
                )
            ],
            rationale_summary="Static, read-only analysis is the safest reproducible first strategy.",
        )
        if self.gateway.policy.network_enabled and state.budget.model_calls_used < state.budget.max_model_calls:
            prompt = (
                "Create a bounded code-audit plan. Only use the tool bandit_python_audit. "
                "Do not include hidden reasoning; provide a short rationale summary.\n"
                f"Objective: {contract.objective}\n"
                f"Inputs: {[item.relative_path for item in state.input_artifacts]}"
            )
            system_prompt = "You are SecMind Planner. Return only schema-valid JSON."
            prompt_artifact = None
            if self.prompt_service is not None:
                paths = sorted(item.relative_path.replace("\\", "/") for item in state.input_artifacts)
                languages = tuple(
                    sorted(
                        {
                            {
                                "py": "python",
                                "java": "java",
                                "js": "javascript",
                                "ts": "typescript",
                                "go": "go",
                                "php": "php",
                                "cs": "csharp",
                            }.get(path.rsplit(".", 1)[-1].casefold(), "unknown")
                            for path in paths
                        }
                    )
                )
                dependency_names = {
                    "pom.xml",
                    "build.gradle",
                    "build.gradle.kts",
                    "requirements.txt",
                    "pyproject.toml",
                    "package.json",
                    "package-lock.json",
                    "pnpm-lock.yaml",
                    "yarn.lock",
                    "go.mod",
                    "composer.json",
                    "packages.lock.json",
                }
                secret_names = {".env", ".env.local", ".npmrc", ".pypirc", "credentials.json"}
                basenames = {path.rsplit("/", 1)[-1].casefold() for path in paths}
                module_manifest_names = {
                    "pom.xml",
                    "build.gradle",
                    "build.gradle.kts",
                    "pyproject.toml",
                    "package.json",
                    "go.mod",
                    "composer.json",
                }
                module_roots = {
                    path.rsplit("/", 1)[0] if "/" in path else "."
                    for path in paths
                    if path.rsplit("/", 1)[-1].casefold() in module_manifest_names
                    or path.casefold().endswith((".csproj", ".sln"))
                }
                repository_shape = (
                    RepositoryShape.MONOREPO
                    if len(module_roots) >= 4
                    else RepositoryShape.MULTI_MODULE
                    if len(module_roots) >= 2
                    else RepositoryShape.SINGLE
                )
                tool_signals: list[str] = []
                if basenames.intersection(dependency_names):
                    tool_signals.append("dependency_manifest")
                if basenames.intersection(secret_names) or any("secret" in name for name in basenames):
                    tool_signals.append("secret_candidate")
                if len(set(languages) - {"unknown"}) > 1:
                    tool_signals.append("multi_language")
                complexity_class = (
                    ComplexityClass.HIGH
                    if len(paths) >= 500
                    else ComplexityClass.MEDIUM
                    if len(paths) >= 80
                    else ComplexityClass.LOW
                )
                evidence_gaps = () if paths else ("partial_input", "parser_coverage_zero")
                prompt_context = PromptContext.create(
                    run_id=state.run_id,
                    role=PromptRole.PLANNER,
                    phase="bounded_planning",
                    languages=languages or ("unknown",),
                    frameworks=(),
                    target_cwes=(),
                    capability_profile="code-audit-planning",
                    repository_shape=repository_shape,
                    evidence_gap_codes=evidence_gaps,
                    tool_signal_types=tuple(tool_signals),
                    parser_coverage=1 if state.input_artifacts else 0,
                    source_count=len(state.input_artifacts),
                    sink_count=0,
                    support_file_count=0,
                    complexity_class=complexity_class,
                    token_budget=max(256, min(16_384, state.budget.max_input_tokens)),
                    deadline_remaining_ms=state.budget.max_runtime_seconds * 1000,
                    trusted_feature_digest=canonical_digest(
                        [(item.relative_path, item.sha256) for item in state.input_artifacts]
                    ),
                    scope_digest=hashlib.sha256("\x1f".join(sorted(contract.authorized_scope)).encode()).hexdigest(),
                    output_schema_ref=PromptContextProfiler.output_schema_ref(PlanOutput),
                )
                preparation = await self.prompt_service.prepare(
                    context=prompt_context,
                    output_model=PlanOutput,
                    fixed_system_prompt=system_prompt,
                    fixed_prompt_version=self.prompt_version,
                    objective_summary=contract.objective,
                )
                prompt_artifact = preparation.artifact
            try:
                output, meta = await self.gateway.structured(
                    role=self.model_role,
                    task_kind=ModelTaskKind.PLANNING,
                    system_prompt=system_prompt,
                    user_prompt=prompt,
                    output_model=PlanOutput,
                    prompt_version=self.prompt_version,
                    run_id=state.run_id,
                    prompt_artifact=prompt_artifact,
                )
                if prompt_artifact is not None and self.prompt_service is not None:
                    self.prompt_service.record_outcome(
                        PromptOutcome(
                            artifact_id=prompt_artifact.artifact_id,
                            run_id=prompt_artifact.run_id,
                            model_receipt_id=meta.logical_call_id or meta.response_sha256,
                            schema_valid=True,
                            latency_ms=meta.duration_ms,
                            input_tokens=meta.usage.input_tokens,
                            output_tokens=meta.usage.output_tokens,
                            cost_units=meta.usage.cost_units,
                        )
                    )
                state.budget.model_calls_used += 1
                state.budget.usage.provider_requests += meta.usage.provider_requests
                state.budget.usage.input_tokens += meta.usage.input_tokens
                state.budget.usage.output_tokens += meta.usage.output_tokens
                state.budget.usage.cache_hit_input_tokens += meta.usage.cache_hit_input_tokens
                state.budget.usage.cache_miss_input_tokens += meta.usage.cache_miss_input_tokens
                default = output
                model_id = meta.model_id
                prompt_version = meta.prompt_version
            except Exception as exc:  # deterministic degradation is intentional
                model_id = "deterministic-planner-fallback"
                prompt_version = self.prompt_version
                state.last_error = f"Planner model degraded safely: {type(exc).__name__}"
        else:
            model_id = (
                "deterministic-planner-budget-fallback"
                if state.budget.model_calls_used >= state.budget.max_model_calls
                else "deterministic-planner"
            )
            prompt_version = self.prompt_version
        state.plan = default.steps
        state.decisions.append(
            DecisionRecord(
                decision="plan_created",
                rationale_summary=default.rationale_summary,
                policy_ids=["PLAN-BOUNDED-V1"],
                model_id=model_id,
                prompt_version=prompt_version,
            )
        )
        return state


class AnalystAgent(BaseAgent):
    name = "analyst"
    model_role = "planner"

    async def run(self, state: AgentState) -> AgentState:
        if not state.observations:
            return state
        successful = [item for item in state.observations if item.status == ToolStatus.SUCCESS]
        evidence_ids = sorted({item.evidence_id for result in successful for item in result.evidence})
        sources = sorted({item.source for result in successful for item in result.evidence})
        if not any(item.decision == "cross_tool_correlation" for item in state.decisions):
            cluster_count: int | None = None
            if state.audit_coverage.get("direct_anchor_pipeline") is True:
                store = CandidateStore.from_state(state)
                evidence_by_id = {item.evidence_id: item for item in state.evidence}
                for finding in state.findings:
                    if finding.raw.get("canonical_primary") is not True:
                        store.register(finding, evidence_by_id)
                clusters = store.correlate()
                store_digest = store.persist(state)
                cluster_count = len(clusters)
                state.audit_coverage["correlation"] = {
                    "stage": "before_gain_gate",
                    "cluster_count": cluster_count,
                    "candidate_count": len(store.records()),
                    "candidate_store_digest": store_digest,
                    "cluster_dimensions": [
                        "cwe_family",
                        "normalized_path",
                        "line_window",
                        "sink",
                        "dataflow",
                    ],
                }
            state.decisions.append(
                DecisionRecord(
                    decision="cross_tool_correlation",
                    rationale_summary=(
                        f"Correlated {len(state.findings)} finding(s) from {len(sources)} evidence source(s)"
                        + (f" into {cluster_count} semantic cluster(s)." if cluster_count is not None else ".")
                    ),
                    evidence_ids=evidence_ids,
                    policy_ids=(
                        ["EVIDENCE-CORRELATE-V1", "DIRECT-ANCHOR-CORRELATE-BEFORE-GATE-V1"]
                        if cluster_count is not None
                        else ["EVIDENCE-CORRELATE-V1"]
                    ),
                    model_id="deterministic-evidence-correlator",
                )
            )
        return state


class DeltaCriticAgent(BaseAgent):
    """Review non-Java correction conflicts without mutating the Anchor."""

    name = "delta_critic"
    model_role = "worker"
    prompt_version = "direct-delta-critic-v2"

    @staticmethod
    def _is_java(path: str | None) -> bool:
        return isinstance(path, str) and path.casefold().endswith((".java", ".kt"))

    @classmethod
    def _delta_finding(cls, delta: TypedDelta, primary_by_id: dict[str, Any]) -> Any | None:
        if delta.finding is not None:
            return delta.finding
        return primary_by_id.get(delta.target_finding_id or "")

    @classmethod
    def _conflict_delta_ids(
        cls,
        state: AgentState,
        deltas: tuple[TypedDelta, ...],
    ) -> tuple[list[str], list[str]]:
        primary = (
            list(state.published_baseline.findings)
            if state.published_baseline is not None
            else [item for item in state.findings if item.raw.get("canonical_primary") is True]
        )
        primary_by_id = {item.finding_id: item for item in primary}
        primary_ids = {
            str(item) for item in state.audit_coverage.get("primary_finding_ids", []) if isinstance(item, str)
        }
        primary_ids.update(primary_by_id)
        conflicts: set[str] = set()
        increments: list[str] = []
        by_target: dict[str, list[TypedDelta]] = {}
        for delta in deltas:
            finding = cls._delta_finding(delta, primary_by_id)
            if delta.target_finding_id:
                by_target.setdefault(delta.target_finding_id, []).append(delta)
            if delta.action == DeltaAction.ADD and delta.disposition == DeltaDisposition.ACCEPTED:
                increments.append(delta.delta_id)
            if finding is None or cls._is_java(getattr(finding, "path", None)):
                continue
            if delta.action == DeltaAction.CORRECT:
                conflicts.add(delta.delta_id)
            # A new candidate against an empty Primary is not, by itself, a
            # label conflict.  Sending every such candidate to the provider
            # created a costly shadow call whose answer could not affect
            # admission.  ADD deltas remain governed by deterministic
            # producer/specificity checks; the Critic is reserved for actual
            # non-Java corrections or overlapping deltas.
        for target_deltas in by_target.values():
            if len(target_deltas) < 2:
                continue
            non_java = [
                item
                for item in target_deltas
                if not cls._is_java(getattr(cls._delta_finding(item, primary_by_id), "path", None))
            ]
            if non_java:
                conflicts.update(item.delta_id for item in non_java)
        return sorted(conflicts), sorted(set(increments))

    @staticmethod
    def _input_payload(deltas: tuple[TypedDelta, ...], conflict_ids: list[str]) -> dict[str, Any]:
        conflict_set = set(conflict_ids)
        rows: list[dict[str, Any]] = []
        for delta in deltas:
            if delta.delta_id not in conflict_set:
                continue
            finding = delta.finding
            rows.append(
                {
                    "delta_id": delta.delta_id,
                    "action": delta.action.value,
                    "disposition": delta.disposition.value,
                    "target_finding_id": delta.target_finding_id,
                    "reason_code": delta.reason_code,
                    "evidence_ids": list(delta.evidence_ids),
                    "finding": (
                        None
                        if finding is None
                        else {
                            "finding_id": finding.finding_id,
                            "rule_id": finding.rule_id,
                            "path": finding.path,
                            "line": finding.line,
                            "severity": finding.severity,
                            "confidence": finding.confidence,
                            "title": finding.title,
                            "evidence_ids": list(finding.evidence_ids),
                        }
                    ),
                }
            )
        return {"conflicts": rows}

    @staticmethod
    def _account_usage(state: AgentState, meta: Any) -> None:
        usage = getattr(meta, "usage", None)
        if usage is None:
            return
        state.budget.usage.provider_requests += usage.provider_requests
        state.budget.usage.input_tokens += usage.input_tokens
        state.budget.usage.output_tokens += usage.output_tokens
        state.budget.usage.cache_hit_input_tokens += usage.cache_hit_input_tokens
        state.budget.usage.cache_miss_input_tokens += usage.cache_miss_input_tokens
        state.budget.usage.cost_units += usage.cost_units

    @staticmethod
    def _model_family(model_id: str | None) -> str | None:
        """Return a conservative family identity without changing model policy.

        The policy catalog remains the authority for whether a model may run.
        This projection is only used to describe whether two already-authorized
        calls came from the same model family.
        """

        if not isinstance(model_id, str) or not model_id.strip():
            return None
        normalized = model_id.strip().casefold()
        for prefix in ("qwen", "deepseek", "gpt", "claude", "gemini", "llama", "mistral"):
            if normalized == prefix or normalized.startswith(prefix + "-") or normalized.startswith(prefix + "/"):
                return prefix
        return normalized.split("-", 1)[0].split("/", 1)[0]

    @staticmethod
    def _text(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @classmethod
    def _primary_lineage(cls, state: AgentState, primary_route: dict[str, Any]) -> dict[str, str | None]:
        """Project the immutable Primary receipt into the proof's paired fields."""

        receipt = state.raw_primary_receipt

        def pick(route_key: str, receipt_key: str) -> str | None:
            route_value = cls._text(primary_route.get(route_key))
            if route_value is not None:
                return route_value
            return cls._text(getattr(receipt, receipt_key, None)) if receipt is not None else None

        model_id = pick("model_id", "model_id")
        provider = pick("provider", "provider")
        if provider is None and model_id is not None:
            catalog_entry = MODEL_CATALOG.get(model_id)
            provider = cls._text(getattr(catalog_entry, "provider", None))
        request_lineage = pick("request_sha256", "request_sha256")
        context_digest = pick("context_sha256", "context_sha256") or cls._text(
            state.audit_coverage.get("context_sha256")
        )
        input_slice_digest = cls._text(primary_route.get("input_slice_digest")) or cls._text(
            state.audit_coverage.get("primary_input_slice_digest")
        )
        # The immutable request digest is the safe fallback when the primary
        # does not expose a narrower slice.  It still prevents an unbound
        # mocked route from being called independent.
        input_slice_digest = input_slice_digest or request_lineage
        prompt_version = pick("prompt_version", "prompt_version")
        method_lineage = cls._text(primary_route.get("method_lineage"))
        if method_lineage is None:
            method_lineage = canonical_digest(
                {
                    "lane": primary_route.get("lane"),
                    "task_kind": primary_route.get("task_kind"),
                    "profile": primary_route.get("profile"),
                    "router_version": primary_route.get("router_version"),
                    "prompt_version": prompt_version,
                    "method_contract": "canonical-primary-v1",
                }
            )
        lineage_id = (
            cls._text(primary_route.get("lineage_id"))
            or cls._text(getattr(receipt, "receipt_id", None))
            or request_lineage
        )
        return {
            "provider": provider,
            "model_family": cls._model_family(model_id),
            "model_id": model_id,
            "request_lineage": request_lineage,
            "method_lineage": method_lineage,
            "input_slice_digest": input_slice_digest,
            "context_digest": context_digest,
            "lineage_id": lineage_id,
        }

    @classmethod
    def _build_independence_proof(
        cls,
        state: AgentState,
        *,
        primary_route: dict[str, Any],
        input_digest: str,
        system_prompt: str,
        meta: Any,
    ) -> tuple[IndependenceProof, tuple[str, ...]]:
        """Bind both calls, then classify the proof without trusting labels."""

        primary = cls._primary_lineage(state, primary_route)
        critic_model_id = cls._text(getattr(meta, "model_id", None))
        critic_provider = cls._text(getattr(meta, "provider", None))
        critic_request_lineage = cls._text(getattr(meta, "request_sha256", None))
        critic_lineage_id = cls._text(getattr(meta, "logical_call_id", None)) or critic_request_lineage
        critic_prompt_version = cls._text(getattr(meta, "prompt_version", None)) or cls.prompt_version
        critic_method_lineage = cls._text(getattr(meta, "method_lineage", None))
        if critic_method_lineage is None:
            critic_method_lineage = canonical_digest(
                {
                    "agent": cls.name,
                    "task_kind": ModelTaskKind.CRITIC_REVIEW.value,
                    "route_profile": cls._text(getattr(meta, "route_profile", None)) or "critic-bounded",
                    "prompt_version": critic_prompt_version,
                    "system_prompt": system_prompt,
                    "output_schema": DeltaCriticDecision.model_json_schema(),
                }
            )
        critic_context_digest = cls._text(getattr(meta, "context_digest", None)) or canonical_digest(
            {"scope": "non_java_conflicts_only", "input_digest": input_digest}
        )
        proof_values: dict[str, Any] = {
            "provider": critic_provider,
            "model_family": cls._model_family(critic_model_id),
            "model_id": critic_model_id,
            "method_family": "canonical-primary-vs-delta-critic",
            "primary_provider": primary["provider"],
            "critic_provider": critic_provider,
            "primary_model_family": primary["model_family"],
            "critic_model_family": cls._model_family(critic_model_id),
            "primary_model_id": primary["model_id"],
            "critic_model_id": critic_model_id,
            "primary_request_lineage": primary["request_lineage"],
            "critic_request_lineage": critic_request_lineage,
            "primary_method_lineage": primary["method_lineage"],
            "critic_method_lineage": critic_method_lineage,
            "primary_input_slice_digest": primary["input_slice_digest"],
            "critic_input_slice_digest": input_digest,
            "primary_context_digest": primary["context_digest"],
            "critic_context_digest": critic_context_digest,
            "context_digest": canonical_digest({"primary": primary["context_digest"], "critic": critic_context_digest}),
            "ancestor_digest": canonical_digest(
                {
                    "run_id": state.run_id,
                    "contract_digest": getattr(state.resolved_task_contract, "contract_digest", None),
                    "primary_lineage": primary["lineage_id"],
                    "critic_lineage": critic_lineage_id,
                }
            ),
            "compared_lineage_ids": [
                item
                for item in (
                    f"primary:{primary['lineage_id']}" if primary["lineage_id"] else None,
                    f"critic:{critic_lineage_id}" if critic_lineage_id else None,
                )
                if item is not None
            ],
            "independent": True,
            "reason_codes": [],
        }
        proof = seal_independence_proof(**proof_values)
        valid, reasons = validate_independence_proof(proof)
        if not valid:
            proof_values.update({"independent": False, "reason_codes": list(reasons)})
            proof = seal_independence_proof(**proof_values)
        return proof, reasons

    async def run(self, state: AgentState) -> AgentState:
        if state.audit_coverage.get("direct_anchor_pipeline") is not True:
            return state
        deltas = tuple(
            TypedDelta.model_validate(item)
            for item in state.audit_coverage.get("typed_deltas", [])
            if isinstance(item, dict)
        )
        conflicts, increments = self._conflict_delta_ids(state, deltas)
        input_payload = self._input_payload(deltas, conflicts)
        input_digest = hashlib.sha256(
            json.dumps(input_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        conflict_evidence_ids = sorted(
            {item for delta in deltas if delta.delta_id in conflicts for item in delta.evidence_ids}
        )
        coverage: dict[str, Any] = {
            "status": "skipped" if not conflicts else "pending",
            "route": ModelTaskKind.CRITIC_REVIEW.value + ":lightweight",
            "task_kind": ModelTaskKind.CRITIC_REVIEW.value,
            "profile": "critic-bounded",
            "scope": "non_java_conflicts_only",
            "input_delta_ids": [item.delta_id for item in deltas],
            "conflict_delta_ids": conflicts,
            "increment_delta_ids": increments,
            "input_digest": input_digest,
            "finding_mutation": False,
            "failure_policy": "shadow_fail_closed",
            "primary_route": state.audit_coverage.get("primary_route", {}),
        }
        if not conflicts:
            coverage["reason"] = "no_non_java_conflict"
            state.audit_coverage["delta_critic"] = coverage
            return state
        if state.budget.model_calls_used >= state.budget.max_model_calls:
            coverage.update({"status": "shadow", "reason": "model_budget_exhausted"})
            state.audit_coverage["delta_critic"] = coverage
            state.decisions.append(
                DecisionRecord(
                    decision="delta_critic_shadowed",
                    rationale_summary=(
                        "Independent Delta Critic was budget-blocked; the typed conflict stayed shadow-only."
                    ),
                    evidence_ids=conflict_evidence_ids,
                    policy_ids=["DELTA-CRITIC-TYPED-ONLY-V2", "FAIL-CLOSED-SHADOW-V1"],
                    model_id="independent-delta-critic-shadow",
                    prompt_version=self.prompt_version,
                    confidence=1.0,
                )
            )
            return state

        state.budget.model_calls_used += 1
        system_prompt = (
            "You are an independent bounded security Delta Critic. Review only the supplied non-Java typed conflicts. "
            "Return JSON matching the schema. You may classify the conflict, but you cannot mutate or delete "
            "the Anchor."
        )
        user_prompt = json.dumps(
            {
                "policy": "shadow_only_non_java_conflict_review",
                "input_digest": input_digest,
                **input_payload,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        try:
            output, meta = await self.gateway.structured(
                role=self.model_role,
                task_kind=ModelTaskKind.CRITIC_REVIEW,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                output_model=DeltaCriticDecision,
                prompt_version=self.prompt_version,
                run_id=state.run_id,
                durable_call_key=f"direct-delta-critic:{input_digest}",
            )
            self._account_usage(state, meta)
            output_payload = output.model_dump(mode="json")
            output_digest = hashlib.sha256(
                json.dumps(output_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            primary_route = state.audit_coverage.get("primary_route", {})
            if not isinstance(primary_route, dict):
                primary_route = {}
            independence_proof, proof_reasons = self._build_independence_proof(
                state,
                primary_route=primary_route,
                input_digest=input_digest,
                system_prompt=system_prompt,
                meta=meta,
            )
            route_is_independent, validated_reasons = validate_independence_proof(independence_proof)
            if not route_is_independent:
                proof_reasons = validated_reasons
            coverage.update(
                {
                    "status": "completed" if route_is_independent else "shadow",
                    "output": output_payload,
                    "output_digest": output_digest,
                    "model_id": getattr(meta, "model_id", ""),
                    "prompt_version": getattr(meta, "prompt_version", self.prompt_version),
                    "route_profile": getattr(meta, "route_profile", "critic-bounded"),
                    "route_lane": getattr(meta, "route_lane", "lightweight"),
                    "route_task_kind": getattr(meta, "route_task_kind", ModelTaskKind.CRITIC_REVIEW.value),
                    "route_is_independent": route_is_independent,
                    "independence_proof": independence_proof.model_dump(mode="json"),
                    "independence_reason": (
                        "different_provider_or_model_lineage"
                        if route_is_independent
                        else "critic_not_independent:" + ",".join(proof_reasons)
                    ),
                }
            )
            requested = set(conflicts)
            returned = set(output.conflict_delta_ids)
            coverage["authorized_delta_ids"] = (
                sorted(requested.intersection(returned)) if output.status == "accepted" else []
            )
            if not route_is_independent:
                coverage["authorized_delta_ids"] = []
                coverage["reason"] = "critic_not_independent"
            state.audit_coverage["delta_critic"] = coverage
            state.decisions.append(
                DecisionRecord(
                    decision=(
                        "independent_delta_critic_completed" if route_is_independent else "delta_critic_shadowed"
                    ),
                    rationale_summary=(
                        output.rationale
                        or (
                            "Independent Delta Critic reviewed the typed conflict in shadow."
                            if route_is_independent
                            else "Critic lineage was not independent; the typed conflict stayed shadow-only."
                        )
                    ),
                    evidence_ids=conflict_evidence_ids,
                    policy_ids=["DELTA-CRITIC-TYPED-ONLY-V2", "PRIMARY-NON-REGRESSION-V1"],
                    model_id=getattr(meta, "model_id", "independent-delta-critic"),
                    prompt_version=getattr(meta, "prompt_version", self.prompt_version),
                    confidence=1.0,
                )
            )
        except Exception as exc:  # deterministic failure isolation is intentional
            coverage.update({"status": "shadow", "reason": f"critic_failed_closed:{type(exc).__name__}"})
            state.audit_coverage["delta_critic"] = coverage
            state.decisions.append(
                DecisionRecord(
                    decision="delta_critic_shadowed",
                    rationale_summary=(
                        "Independent Delta Critic failed closed; the Anchor and typed deltas were preserved."
                    ),
                    evidence_ids=conflict_evidence_ids,
                    policy_ids=["DELTA-CRITIC-TYPED-ONLY-V2", "FAIL-CLOSED-SHADOW-V1"],
                    model_id="independent-delta-critic-shadow",
                    prompt_version=self.prompt_version,
                    confidence=1.0,
                )
            )
        return state


class VerifierAgent(BaseAgent):
    name = "verifier"
    model_role = "planner"

    async def run(self, state: AgentState) -> AgentState:
        orphaned = [finding.finding_id for finding in state.findings if not finding.evidence_ids]
        evidence_ids = {evidence.evidence_id for evidence in state.evidence}
        broken = [
            finding.finding_id
            for finding in state.findings
            if any(reference not in evidence_ids for reference in finding.evidence_ids)
        ]
        if orphaned or broken:
            state.last_error = "Verifier rejected findings with missing or broken evidence references"
            state.status = RunStatus.PARTIAL
            state.decisions.append(
                DecisionRecord(
                    decision="verification_failed",
                    rationale_summary=state.last_error,
                    policy_ids=["EVIDENCE-REQUIRED-V1"],
                    confidence=1,
                )
            )
        else:
            state.decisions.append(
                DecisionRecord(
                    decision="verification_passed",
                    rationale_summary="All normalized findings reference captured tool evidence.",
                    evidence_ids=sorted(evidence_ids),
                    policy_ids=["EVIDENCE-REQUIRED-V1"],
                    confidence=1,
                )
            )
        if state.audit_coverage.get("direct_anchor_pipeline") is True:
            delta_verification: dict[str, bool] = {}
            for raw_delta in state.audit_coverage.get("typed_deltas", []):
                if not isinstance(raw_delta, dict):
                    continue
                delta = TypedDelta.model_validate(raw_delta)
                if delta.finding is None:
                    continue
                checks = evidence_semantic_checks(delta.finding, {item.evidence_id: item for item in state.evidence})
                delta_verification[delta.finding.finding_id] = (
                    checks["evidence_complete"] and checks["semantic_assurance"]
                )
            state.audit_coverage["delta_verification"] = delta_verification
            state.decisions.append(
                DecisionRecord(
                    decision="delta_semantic_verification_completed",
                    rationale_summary=(
                        f"Verifier semantically checked {len(delta_verification)} typed delta(s); "
                        "no Anchor field was modified."
                    ),
                    policy_ids=["DELTA-SEMANTIC-VERIFIER-V1", "ANCHOR-IMMUTABLE-V1"],
                    model_id="deterministic-delta-verifier",
                    confidence=1.0,
                )
            )
        return state


class ReporterAgent(BaseAgent):
    name = "reporter"
    model_role = "planner"

    async def run(self, state: AgentState) -> AgentState:
        obligation_set = current_obligation_set(state)
        terminal_without_answer = state.status in {
            RunStatus.DENIED,
            RunStatus.FAILED,
            RunStatus.RECOVERY_REQUIRED,
            RunStatus.CANCELLED,
        }
        missing_obligation_authority = (
            obligation_set is None and state.resolved_task_contract is not None and not terminal_without_answer
        )
        if state.scenario != Scenario.CODE_AUDIT and state.report is not None:
            final_status = (
                clamp_run_status(obligation_set, state.status)
                if obligation_set is not None
                else (
                    state.status
                    if state.status
                    in {
                        RunStatus.DENIED,
                        RunStatus.FAILED,
                        RunStatus.RECOVERY_REQUIRED,
                        RunStatus.CANCELLED,
                    }
                    else RunStatus.PARTIAL
                )
            )
            scenario_limitations = sorted({*state.report.limitations, *state.completion_reasons})
            if missing_obligation_authority:
                scenario_limitations.append("The authoritative completion obligation set is absent or stale.")
            state.report = state.report.model_copy(
                update={
                    "status": final_status,
                    "decisions": state.decisions,
                    "evidence": state.evidence,
                    "limitations": scenario_limitations,
                    "coverage": dict(state.audit_coverage),
                    "claim_ids": sorted(
                        claim.claim_id for claim in state.claims if claim.status == ClaimStatus.VERIFIED
                    ),
                }
            )
            state.status = final_status
            return state
        tool_successful = any(item.status == ToolStatus.SUCCESS for item in state.observations)
        audit_successful = bool(state.audit_units) and all(
            item.final_verdict != "inconclusive" for item in state.audit_units
        )
        primary_successful = bool(state.audit_coverage.get("canonical_primary_completed"))
        successful = tool_successful or audit_successful or primary_successful
        if state.status in {
            RunStatus.DENIED,
            RunStatus.FAILED,
            RunStatus.RECOVERY_REQUIRED,
            RunStatus.PARTIAL,
            RunStatus.CANCELLED,
        }:
            final_status = state.status
        elif state.scenario != Scenario.CODE_AUDIT or not successful:
            final_status = RunStatus.PARTIAL
        else:
            final_status = RunStatus.COMPLETED
        if obligation_set is not None:
            final_status = clamp_run_status(obligation_set, final_status)
        elif state.resolved_task_contract is not None and final_status not in {
            RunStatus.DENIED,
            RunStatus.FAILED,
            RunStatus.RECOVERY_REQUIRED,
            RunStatus.CANCELLED,
        }:
            final_status = RunStatus.PARTIAL
        # CompletionGate reasons are part of the public, auditable explanation
        # for a fail-closed PARTIAL result. Dropping them made a correct bounded
        # stop look like an unexplained failure.
        limitations: list[str] = list(state.completion_reasons)
        if missing_obligation_authority:
            limitations.append("The authoritative completion obligation set is absent or stale.")
        if state.scenario != Scenario.CODE_AUDIT:
            limitations.append("The selected scenario is not enabled in the MVP tool chain.")
        if not state.input_artifacts:
            limitations.append("No input artifacts were supplied; the workspace may contain no analyzable code.")
        if state.last_error:
            limitations.append(state.last_error)
        if primary_successful:
            accepted_delta_count = sum(finding.raw.get("canonical_primary") is not True for finding in state.findings)
            summary = (
                f"Task-level Primary completed with {len(state.findings) - accepted_delta_count} baseline finding(s); "
                f"governed augmentation contributed {accepted_delta_count} accepted finding(s) and the report "
                f"preserves {len(state.evidence)} evidence record(s)."
            )
        elif audit_successful:
            summary = (
                f"Direct-first code audit covered {len(state.audit_units)} immutable unit(s), "
                f"reported {len(state.findings)} finding(s), and preserved "
                f"{len(state.evidence)} evidence record(s)."
            )
        elif successful:
            summary = (
                f"Code audit completed with {len(state.findings)} finding(s), "
                f"supported by {len(state.evidence)} evidence record(s)."
            )
        else:
            summary = "The task ended without a successful security-tool observation."
        state.status = final_status
        report_findings = state.findings
        if state.claims:
            verified_subjects = {claim.subject_ref for claim in state.claims if claim.status.value == "verified"}
            report_findings = [
                finding
                for finding in state.findings
                if finding.finding_id in verified_subjects or finding.raw.get("canonical_primary") is True
            ]
        state.report = AgentReport(
            run_id=state.run_id,
            status=final_status,
            executive_summary=summary,
            findings=report_findings,
            decisions=state.decisions,
            evidence=state.evidence,
            limitations=limitations,
            coverage=dict(state.audit_coverage),
            audit_kernel=state.audit_kernel,
            audit_units=state.audit_units,
            claim_ids=sorted(claim.claim_id for claim in state.claims if claim.status.value == "verified"),
        )
        return state
