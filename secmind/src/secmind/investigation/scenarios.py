"""Deterministic scenario adapters for v0.6 investigation planning.

Scenario compilation is intentionally pre-runtime: it produces a typed
``PlanProposal`` plus evidence-obligation templates.  It never changes run
state, writes findings, declares completion, or persists report/memory data.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secmind.investigation.contracts import PlanProposal, StrategyLevel, canonical_content_digest
from secmind.schemas import FailurePolicy, ModelUsage, PlanStep, RiskLevel, Scenario

SCENARIO_COMPILER_VERSION = "scenario-compiler-v0.6"
SHA256_PATTERN = r"^[a-f0-9]{64}$"


class ScenarioCompilationError(ValueError):
    """The requested scenario cannot be compiled within the safe adapter boundary."""


class UnsupportedScenarioError(ScenarioCompilationError):
    """No released static adapter exists for the requested scenario."""


class PenetrationScenarioRejected(ScenarioCompilationError):
    """Penetration workflows are outside the v0.6 release boundary."""


class ReleaseDisabledError(ScenarioCompilationError):
    """An unreleased adapter was requested in an executable mode."""


class ScenarioModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)

    schema_version: Literal["1.5"] = "1.5"


class ExecutionMode(StrEnum):
    STATIC = "static"
    DRY_RUN = "dry_run"


class ScenarioCompileRequest(ScenarioModel):
    run_id: str = Field(min_length=1)
    scenario: Scenario
    objective: str = Field(min_length=3)
    immutable_scope: tuple[str, ...] = Field(min_length=1)
    asset_refs: tuple[str, ...] = Field(default_factory=tuple)
    constraints: tuple[str, ...] = Field(default_factory=tuple)
    expected_outputs: tuple[str, ...] = Field(default_factory=lambda: ("evidence_backed_assessment",))
    strategy: StrategyLevel = StrategyLevel.BALANCED
    dry_run: bool = False


class CapabilityTemplate(ScenarioModel):
    template_id: str
    capability: str
    agent_role: str
    objective_template: str
    dependency_templates: tuple[str, ...] = Field(default_factory=tuple)
    tool_candidates: tuple[str, ...] = Field(default_factory=tuple)
    evidence_types: tuple[str, ...] = Field(min_length=1)
    success_criteria: tuple[str, ...] = Field(min_length=1)
    risk_hint: RiskLevel = RiskLevel.R0
    failure_policy: FailurePolicy = FailurePolicy.SKIP_DEPENDENTS
    concurrency_key: str = "workspace:read"
    max_attempts: int = Field(default=2, ge=1, le=3)
    estimated_tool_calls: int = Field(default=1, ge=0, le=20)
    estimated_model_calls: int = Field(default=0, ge=0, le=10)


class ObligationTemplate(ScenarioModel):
    obligation_id: str
    description: str
    applies_to_capabilities: tuple[str, ...] = Field(min_length=1)
    required_evidence_types: tuple[str, ...] = Field(min_length=1)
    minimum_evidence_count: int = Field(default=1, ge=1, le=20)
    requires_independent_verification: Literal[True] = True
    blocks_completion: Literal[True] = True


class ScenarioAdapter(ScenarioModel):
    adapter_id: str
    version: str = SCENARIO_COMPILER_VERSION
    scenario: Scenario
    execution_mode: ExecutionMode
    capability_templates: tuple[CapabilityTemplate, ...] = Field(min_length=1)
    obligations: tuple[ObligationTemplate, ...] = Field(min_length=1)
    requires_plan_contract: Literal[True] = True
    requires_verifier: Literal[True] = True
    requires_completion_receipt: Literal[True] = True
    release_enabled: bool = True
    content_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_adapter_graph_and_obligations(self) -> ScenarioAdapter:
        template_ids = [item.template_id for item in self.capability_templates]
        if len(template_ids) != len(set(template_ids)):
            raise ValueError("scenario adapter contains duplicate capability template IDs")
        known = set(template_ids)
        for item in self.capability_templates:
            unknown = set(item.dependency_templates) - known
            if unknown:
                raise ValueError(f"scenario adapter has unknown dependency templates: {sorted(unknown)}")
            if item.template_id in item.dependency_templates:
                raise ValueError("scenario capability template cannot depend on itself")
        capabilities = {item.capability for item in self.capability_templates}
        for obligation in self.obligations:
            unknown = set(obligation.applies_to_capabilities) - capabilities
            if unknown:
                raise ValueError(f"obligation references unknown capabilities: {sorted(unknown)}")
        if self.scenario == Scenario.INCIDENT_RESPONSE:
            if self.execution_mode != ExecutionMode.DRY_RUN or self.release_enabled:
                raise ValueError("incident-response adapter must remain release-disabled dry-run")
        elif self.execution_mode != ExecutionMode.STATIC:
            raise ValueError("released scenario adapters must be static")
        return self


class ScenarioCompilation(ScenarioModel):
    compilation_id: str
    compiler_version: str = SCENARIO_COMPILER_VERSION
    run_id: str
    scenario: Scenario
    execution_mode: ExecutionMode
    release_enabled: bool
    adapter_digest: str = Field(pattern=SHA256_PATTERN)
    capability_templates: tuple[CapabilityTemplate, ...] = Field(min_length=1)
    obligations: tuple[ObligationTemplate, ...] = Field(min_length=1)
    plan_proposal: PlanProposal
    requires_plan_contract: Literal[True] = True
    requires_verifier: Literal[True] = True
    requires_completion_receipt: Literal[True] = True
    content_digest: str = Field(pattern=SHA256_PATTERN)


def _stable_id(namespace: str, digest: str) -> str:
    return hashlib.sha256(f"{namespace}:{digest}".encode()).hexdigest()[:32]


def _deterministic_digest(value: Any, *, exclude_content_digest: bool = False) -> str:
    payload = ScenarioCompiler._json_value(value)
    if exclude_content_digest and isinstance(payload, dict):
        payload.pop("content_digest", None)
    return canonical_content_digest(payload)


def _seal_adapter(**values: Any) -> ScenarioAdapter:
    draft = ScenarioAdapter.model_validate({**values, "content_digest": "0" * 64})
    return draft.model_copy(update={"content_digest": canonical_content_digest(draft)})


def _capability(
    template_id: str,
    capability: str,
    agent_role: str,
    objective: str,
    evidence_types: Sequence[str],
    *,
    dependencies: Sequence[str] = (),
    tools: Sequence[str] = (),
    risk: RiskLevel = RiskLevel.R0,
    max_attempts: int = 2,
) -> CapabilityTemplate:
    return CapabilityTemplate(
        template_id=template_id,
        capability=capability,
        agent_role=agent_role,
        objective_template=objective,
        dependency_templates=tuple(dependencies),
        tool_candidates=tuple(tools),
        evidence_types=tuple(evidence_types),
        success_criteria=(
            f"{capability} output is schema-valid.",
            f"{capability} output references immutable evidence.",
        ),
        risk_hint=risk,
        max_attempts=max_attempts,
        estimated_tool_calls=1 if tools else 0,
    )


def _obligation(
    obligation_id: str,
    description: str,
    capabilities: Sequence[str],
    evidence_types: Sequence[str],
    *,
    minimum: int = 1,
) -> ObligationTemplate:
    return ObligationTemplate(
        obligation_id=obligation_id,
        description=description,
        applies_to_capabilities=tuple(capabilities),
        required_evidence_types=tuple(evidence_types),
        minimum_evidence_count=minimum,
    )


def _code_audit_adapter() -> ScenarioAdapter:
    capabilities = (
        _capability(
            "inventory",
            "project_inventory",
            "language_dependency_scout",
            "Inventory languages, manifests, and immutable source paths within scope.",
            ("project.inventory",),
            tools=("project-inventory",),
        ),
        _capability(
            "sast",
            "sast",
            "sast_specialist",
            "Perform static rule analysis over the inventoried source tree.",
            ("sast.finding", "sast.coverage"),
            dependencies=("inventory",),
            tools=("bandit", "semgrep"),
            risk=RiskLevel.R1,
        ),
        _capability(
            "secrets",
            "secret_scan",
            "secret_specialist",
            "Detect and fully redact credential candidates in immutable source content.",
            ("secret.redacted_candidate", "secret.coverage"),
            dependencies=("inventory",),
            tools=("gitleaks",),
            risk=RiskLevel.R1,
        ),
        _capability(
            "sbom",
            "sbom",
            "dependency_specialist",
            "Generate an offline software bill of materials from dependency manifests.",
            ("sbom.cyclonedx",),
            dependencies=("inventory",),
            tools=("syft",),
            risk=RiskLevel.R1,
        ),
        _capability(
            "dependencies",
            "dependency_audit",
            "dependency_specialist",
            "Match the generated SBOM against the pinned offline advisory database.",
            ("dependency.advisory_match", "dependency.database_version"),
            dependencies=("sbom",),
            tools=("osv-scanner",),
            risk=RiskLevel.R1,
        ),
        _capability(
            "correlate",
            "evidence_correlation",
            "correlator_analyst",
            "Deterministically correlate scanner observations without inventing findings.",
            ("correlation.record",),
            dependencies=("sast", "secrets", "dependencies"),
        ),
        _capability(
            "verify",
            "evidence_verification",
            "evidence_verifier",
            "Verify evidence integrity, coverage, contradictions, and obligation satisfaction.",
            ("verification.receipt",),
            dependencies=("correlate",),
        ),
    )
    obligations = (
        _obligation(
            "source-coverage",
            "Every in-scope supported source file is represented in scanner coverage evidence.",
            ("project_inventory", "sast", "secret_scan"),
            ("project.inventory", "sast.coverage", "secret.coverage"),
            minimum=3,
        ),
        _obligation(
            "dependency-provenance",
            "Dependency claims identify both the SBOM and pinned advisory database version.",
            ("sbom", "dependency_audit"),
            ("sbom.cyclonedx", "dependency.database_version"),
            minimum=2,
        ),
        _obligation(
            "code-audit-verification",
            "No code-audit conclusion is complete without independent evidence verification.",
            ("evidence_verification",),
            ("verification.receipt",),
        ),
    )
    return _seal_adapter(
        adapter_id="code-audit-static",
        scenario=Scenario.CODE_AUDIT,
        execution_mode=ExecutionMode.STATIC,
        capability_templates=capabilities,
        obligations=obligations,
        release_enabled=True,
    )


def _log_static_adapter() -> ScenarioAdapter:
    capabilities = (
        _capability(
            "inventory",
            "log_inventory",
            "log_scout",
            "Inventory immutable log sources, formats, clocks, and parse coverage.",
            ("log.inventory", "log.clock_metadata"),
            tools=("log-inventory",),
        ),
        _capability(
            "normalize",
            "log_normalization",
            "log_normalizer",
            "Normalize supplied log snapshots without tailing or modifying their sources.",
            ("log.normalized_event", "log.parse_diagnostic"),
            dependencies=("inventory",),
            tools=("log-normalizer",),
            risk=RiskLevel.R1,
        ),
        _capability(
            "detect",
            "static_log_detection",
            "detection_specialist",
            "Apply pinned offline detection rules to normalized events.",
            ("log.detection_match", "log.rule_bundle_version"),
            dependencies=("normalize",),
            tools=("sigma-offline",),
            risk=RiskLevel.R1,
        ),
        _capability(
            "timeline",
            "static_timeline",
            "timeline_specialist",
            "Build a deterministic timeline from supplied immutable events.",
            ("log.timeline", "log.clock_uncertainty"),
            dependencies=("normalize",),
            tools=("timeline-builder",),
            risk=RiskLevel.R1,
        ),
        _capability(
            "correlate",
            "evidence_correlation",
            "correlator_analyst",
            "Correlate detection matches and timeline events as candidate claims.",
            ("correlation.record",),
            dependencies=("detect", "timeline"),
        ),
        _capability(
            "verify",
            "evidence_verification",
            "evidence_verifier",
            "Verify log provenance, rule versions, clock caveats, and coverage.",
            ("verification.receipt",),
            dependencies=("correlate",),
        ),
    )
    obligations = (
        _obligation(
            "log-provenance",
            "Every normalized event preserves its immutable source and parser provenance.",
            ("log_inventory", "log_normalization"),
            ("log.inventory", "log.normalized_event"),
            minimum=2,
        ),
        _obligation(
            "time-uncertainty",
            "Timeline conclusions explicitly carry clock and ordering uncertainty.",
            ("static_timeline",),
            ("log.clock_uncertainty",),
        ),
        _obligation(
            "log-verification",
            "Static log conclusions require a verification receipt.",
            ("evidence_verification",),
            ("verification.receipt",),
        ),
    )
    return _seal_adapter(
        adapter_id="log-analysis-static",
        scenario=Scenario.LOG_ANALYSIS,
        execution_mode=ExecutionMode.STATIC,
        capability_templates=capabilities,
        obligations=obligations,
        release_enabled=True,
    )


def _api_static_adapter() -> ScenarioAdapter:
    capabilities = (
        _capability(
            "inventory",
            "api_inventory",
            "api_scout",
            "Inventory supplied OpenAPI, schema, policy, and server-code artifacts.",
            ("api.inventory",),
            tools=("openapi-inventory",),
        ),
        _capability(
            "schema",
            "api_schema_review",
            "api_schema_specialist",
            "Statically review API schemas and security declarations.",
            ("api.schema_issue", "api.operation_coverage"),
            dependencies=("inventory",),
            tools=("openapi-lint",),
            risk=RiskLevel.R1,
        ),
        _capability(
            "authorization",
            "api_authorization_review",
            "api_auth_specialist",
            "Review declared authorization boundaries and supplied implementation mappings.",
            ("api.authorization_observation",),
            dependencies=("inventory",),
            tools=("semgrep-api",),
            risk=RiskLevel.R1,
        ),
        _capability(
            "exposure",
            "api_data_exposure_review",
            "api_data_specialist",
            "Review schema fields and examples for static data-exposure risks.",
            ("api.exposure_observation",),
            dependencies=("inventory",),
            tools=("api-secret-redactor",),
            risk=RiskLevel.R1,
        ),
        _capability(
            "correlate",
            "evidence_correlation",
            "correlator_analyst",
            "Correlate static API observations by operation and immutable locator.",
            ("correlation.record",),
            dependencies=("schema", "authorization", "exposure"),
        ),
        _capability(
            "verify",
            "evidence_verification",
            "evidence_verifier",
            "Verify API operation coverage and evidence integrity without live requests.",
            ("verification.receipt",),
            dependencies=("correlate",),
        ),
    )
    obligations = (
        _obligation(
            "api-operation-coverage",
            "Every declared in-scope operation has static review coverage or an explicit gap.",
            ("api_inventory", "api_schema_review"),
            ("api.inventory", "api.operation_coverage"),
            minimum=2,
        ),
        _obligation(
            "api-no-live-claims",
            "Static API observations cannot be represented as live exploit confirmation.",
            ("api_authorization_review", "api_data_exposure_review"),
            ("api.authorization_observation", "api.exposure_observation"),
            minimum=2,
        ),
        _obligation(
            "api-verification",
            "Static API conclusions require independent verification.",
            ("evidence_verification",),
            ("verification.receipt",),
        ),
    )
    return _seal_adapter(
        adapter_id="api-assessment-static",
        scenario=Scenario.API_ASSESSMENT,
        execution_mode=ExecutionMode.STATIC,
        capability_templates=capabilities,
        obligations=obligations,
        release_enabled=True,
    )


def _incident_dry_run_adapter() -> ScenarioAdapter:
    capabilities = (
        _capability(
            "inventory",
            "incident_snapshot_inventory",
            "incident_scout",
            "Inventory supplied incident snapshots and declared assumptions.",
            ("incident.snapshot_inventory",),
            tools=("incident-snapshot-reader",),
        ),
        _capability(
            "timeline",
            "incident_timeline_dry_run",
            "timeline_specialist",
            "Simulate timeline construction from supplied snapshots only.",
            ("incident.simulated_timeline",),
            dependencies=("inventory",),
            tools=("timeline-builder",),
            risk=RiskLevel.R1,
            max_attempts=1,
        ),
        _capability(
            "containment",
            "containment_dry_run",
            "incident_response_specialist",
            "Produce non-executable containment options and predicted effects.",
            ("incident.containment_simulation",),
            dependencies=("timeline",),
            tools=("containment-simulator",),
            risk=RiskLevel.R1,
            max_attempts=1,
        ),
        _capability(
            "verify",
            "evidence_verification",
            "evidence_verifier",
            "Verify simulation provenance and ensure no response action was executed.",
            ("verification.receipt", "incident.no_action_attestation"),
            dependencies=("containment",),
            max_attempts=1,
        ),
    )
    obligations = (
        _obligation(
            "incident-no-action",
            "Dry-run compilation must attest that no containment or response action was released.",
            ("containment_dry_run", "evidence_verification"),
            ("incident.containment_simulation", "incident.no_action_attestation"),
            minimum=2,
        ),
        _obligation(
            "incident-verification",
            "Incident simulation remains incomplete without independent verification.",
            ("evidence_verification",),
            ("verification.receipt",),
        ),
    )
    return _seal_adapter(
        adapter_id="incident-response-dry-run",
        scenario=Scenario.INCIDENT_RESPONSE,
        execution_mode=ExecutionMode.DRY_RUN,
        capability_templates=capabilities,
        obligations=obligations,
        release_enabled=False,
    )


def _reverse_static_adapter() -> ScenarioAdapter:
    capabilities = (
        _capability(
            "triage",
            "static_file_triage",
            "reverse_scout",
            "Match complete, high-confidence behavior chains in immutable textual source without execution.",
            ("reverse.static_indicator", "reverse.scan_coverage"),
            max_attempts=1,
        ),
        _capability(
            "correlate",
            "evidence_correlation",
            "correlator_analyst",
            "Correlate static indicators into bounded behavior hypotheses.",
            ("correlation.record",),
            dependencies=("triage",),
            max_attempts=1,
        ),
        _capability(
            "verify",
            "evidence_verification",
            "evidence_verifier",
            "Verify manifest binding, source locators, and rule-bundle provenance.",
            ("verification.receipt",),
            dependencies=("correlate",),
            max_attempts=1,
        ),
    )
    obligations = (
        _obligation(
            "reverse-source-provenance",
            "Every static behavior is bound to an immutable source locator and pinned rule bundle.",
            ("static_file_triage", "evidence_correlation"),
            ("reverse.static_indicator", "correlation.record"),
            minimum=2,
        ),
        _obligation(
            "reverse-verification",
            "Static reverse conclusions require evidence verification and cannot claim execution.",
            ("evidence_verification",),
            ("verification.receipt",),
        ),
    )
    return _seal_adapter(
        adapter_id="reverse-triage-static",
        scenario=Scenario.REVERSE_TRIAGE,
        execution_mode=ExecutionMode.STATIC,
        capability_templates=capabilities,
        obligations=obligations,
        release_enabled=True,
    )


def default_scenario_adapters() -> tuple[ScenarioAdapter, ...]:
    """Return fresh immutable snapshots of the reviewed built-in adapters."""

    return (
        _api_static_adapter(),
        _code_audit_adapter(),
        _incident_dry_run_adapter(),
        _log_static_adapter(),
        _reverse_static_adapter(),
    )


class ScenarioCompiler:
    """Compile scenario input into the common v0.6 ``PlanProposal`` contract."""

    def __init__(self, adapters: Iterable[ScenarioAdapter] | None = None) -> None:
        indexed: dict[Scenario, ScenarioAdapter] = {}
        for supplied in adapters or default_scenario_adapters():
            adapter = supplied.model_copy(deep=True)
            if adapter.scenario in indexed:
                raise ScenarioCompilationError(f"duplicate scenario adapter: {adapter.scenario}")
            if not (
                adapter.requires_plan_contract and adapter.requires_verifier and adapter.requires_completion_receipt
            ):
                raise ScenarioCompilationError("scenario adapters cannot disable governance gates")
            if canonical_content_digest(adapter) != adapter.content_digest:
                raise ScenarioCompilationError(f"scenario adapter digest mismatch: {adapter.adapter_id}")
            indexed[adapter.scenario] = adapter
        self._adapters = {scenario: indexed[scenario] for scenario in sorted(indexed, key=lambda item: item.value)}
        catalog_payload = {
            "compiler_version": SCENARIO_COMPILER_VERSION,
            "adapters": [adapter.model_dump(mode="json") for adapter in self._adapters.values()],
        }
        self.catalog_digest = canonical_content_digest(catalog_payload)

    @property
    def supported_scenarios(self) -> tuple[Scenario, ...]:
        return tuple(self._adapters)

    def adapter_for(self, scenario: Scenario) -> ScenarioAdapter:
        if scenario == Scenario.PENETRATION_TEST:
            raise PenetrationScenarioRejected("penetration testing is rejected by the v0.6 scenario boundary")
        try:
            return self._adapters[scenario].model_copy(deep=True)
        except KeyError as exc:
            raise UnsupportedScenarioError(f"no static scenario adapter for: {scenario}") from exc

    def compile(self, request: ScenarioCompileRequest) -> ScenarioCompilation:
        adapter = self.adapter_for(request.scenario)
        if adapter.scenario == Scenario.INCIDENT_RESPONSE and not request.dry_run:
            raise ReleaseDisabledError("incident response is available only as an explicitly requested dry-run")
        if adapter.execution_mode == ExecutionMode.STATIC and request.dry_run:
            raise ScenarioCompilationError("dry_run is reserved for release-disabled scenario adapters")

        steps = self._compile_steps(adapter, request)
        proposal = self._compile_proposal(adapter, request, steps)
        payload: dict[str, Any] = {
            "compiler_version": SCENARIO_COMPILER_VERSION,
            "run_id": request.run_id,
            "scenario": request.scenario,
            "execution_mode": adapter.execution_mode,
            "release_enabled": adapter.release_enabled,
            "adapter_digest": adapter.content_digest,
            "capability_templates": adapter.capability_templates,
            "obligations": adapter.obligations,
            "plan_proposal": proposal,
            "requires_plan_contract": True,
            "requires_verifier": True,
            "requires_completion_receipt": True,
        }
        core_digest = canonical_content_digest({key: self._json_value(value) for key, value in payload.items()})
        payload["compilation_id"] = _stable_id("scenario-compilation", core_digest)
        draft = ScenarioCompilation.model_validate({**payload, "content_digest": "0" * 64})
        return draft.model_copy(update={"content_digest": _deterministic_digest(draft, exclude_content_digest=True)})

    def compile_code_audit(self, request: ScenarioCompileRequest) -> ScenarioCompilation:
        return self._compile_as(request, Scenario.CODE_AUDIT)

    def compile_log_static(self, request: ScenarioCompileRequest) -> ScenarioCompilation:
        return self._compile_as(request, Scenario.LOG_ANALYSIS)

    def compile_api_static(self, request: ScenarioCompileRequest) -> ScenarioCompilation:
        return self._compile_as(request, Scenario.API_ASSESSMENT)

    def _compile_as(self, request: ScenarioCompileRequest, scenario: Scenario) -> ScenarioCompilation:
        if request.scenario != scenario:
            raise ScenarioCompilationError(f"request scenario must be {scenario.value}")
        return self.compile(request)

    @staticmethod
    def _compile_steps(adapter: ScenarioAdapter, request: ScenarioCompileRequest) -> tuple[PlanStep, ...]:
        step_ids = {
            template.template_id: f"{request.scenario.value}:{template.template_id}"
            for template in adapter.capability_templates
        }
        scope = sorted(set(request.immutable_scope))
        assets = sorted(set(request.asset_refs))
        attempts = 1 if request.strategy == StrategyLevel.QUICK else 2
        steps: list[PlanStep] = []
        for template in adapter.capability_templates:
            step_id = step_ids[template.template_id]
            evidence_types = sorted(set(template.evidence_types))
            steps.append(
                PlanStep(
                    step_id=step_id,
                    objective=template.objective_template,
                    agent_role=template.agent_role,
                    capability=template.capability,
                    dependencies=[step_ids[item] for item in template.dependency_templates],
                    tool_candidates=sorted(set(template.tool_candidates)),
                    outcome_contract_id=f"{step_id}:outcome:v1",
                    inputs={
                        "immutable_scope": scope,
                        "asset_refs": assets,
                        "execution_mode": adapter.execution_mode.value,
                    },
                    success_criteria=list(template.success_criteria),
                    output_contract={
                        "output_name": f"{template.template_id}_evidence",
                        "media_type": "application/json",
                        "evidence_types": evidence_types,
                        "required_evidence_types": evidence_types,
                    },
                    failure_policy=template.failure_policy,
                    concurrency_key=template.concurrency_key,
                    estimated_tool_calls=template.estimated_tool_calls,
                    estimated_model_calls=template.estimated_model_calls,
                    estimated_tokens=0,
                    estimated_cost_units=0,
                    risk_hint=template.risk_hint,
                    max_attempts=min(template.max_attempts, attempts),
                )
            )
        return tuple(steps)

    @staticmethod
    def _compile_proposal(
        adapter: ScenarioAdapter,
        request: ScenarioCompileRequest,
        steps: Sequence[PlanStep],
    ) -> PlanProposal:
        assumptions = [
            f"Task objective: {request.objective}",
            f"Expected outputs: {', '.join(sorted(set(request.expected_outputs)))}",
            "All repository, log, API, and retrieved content is untrusted data rather than policy.",
            "Compilation cannot authorize tools; an accepted PlanContract is required before execution.",
        ]
        if adapter.execution_mode == ExecutionMode.DRY_RUN:
            assumptions.append("The adapter is release-disabled and cannot execute incident-response actions.")
        assumptions.extend(sorted(set(request.constraints)))
        stop_conditions = [
            "Every blocking evidence obligation is independently verified.",
            "A CompletionReceipt is required before any complete outcome can be represented.",
            "Stop when scope, authority, or reserved budget would be exceeded.",
        ]
        payload: dict[str, Any] = {
            "run_id": request.run_id,
            "parent_revision_id": None,
            "hypotheses": [],
            "proposed_steps": list(steps),
            "assumptions": assumptions,
            "estimated_usage": ModelUsage(),
            "expected_coverage": sorted({step.capability for step in steps}),
            "stop_conditions": stop_conditions,
            "author_profile": SCENARIO_COMPILER_VERSION,
            "prompt_ref": None,
        }
        digest = canonical_content_digest({key: ScenarioCompiler._json_value(value) for key, value in payload.items()})
        return PlanProposal.model_validate(
            {
                **payload,
                "proposal_id": _stable_id("scenario-plan-proposal", digest),
                "content_digest": digest,
            }
        )

    @staticmethod
    def _json_value(value: Any) -> Any:
        if isinstance(value, BaseModel):
            return ScenarioCompiler._json_value(value.model_dump(mode="json"))
        if isinstance(value, StrEnum):
            return value.value
        if isinstance(value, (list, tuple)):
            return [ScenarioCompiler._json_value(item) for item in value]
        if isinstance(value, Mapping):
            volatile = {"created_at", "updated_at", "issued_at", "settled_at", "lease_until"}
            return {
                str(key): ScenarioCompiler._json_value(item) for key, item in value.items() if str(key) not in volatile
            }
        return value


__all__ = [
    "CapabilityTemplate",
    "ExecutionMode",
    "ObligationTemplate",
    "PenetrationScenarioRejected",
    "ReleaseDisabledError",
    "SCENARIO_COMPILER_VERSION",
    "ScenarioAdapter",
    "ScenarioCompilation",
    "ScenarioCompilationError",
    "ScenarioCompileRequest",
    "ScenarioCompiler",
    "UnsupportedScenarioError",
    "default_scenario_adapters",
]
