from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from secmind.schemas import Claim, Evidence, OutcomeContract, PlanStep


class OutcomeContractError(ValueError):
    """An outcome contract is incomplete, unknown, or has been modified."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def stable_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def contract_payload(contract: OutcomeContract) -> dict[str, Any]:
    payload = contract.model_dump(mode="json")
    payload.pop("contract_id", None)
    payload.pop("contract_digest", None)
    return payload


class GradeStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"


@dataclass(frozen=True)
class GradeContext:
    contract: OutcomeContract
    claim: Claim
    evidence: tuple[Evidence, ...]
    evidence_types: frozenset[str]
    tool_versions: dict[str, str]
    coverage: dict[str, Any]
    integrity_valid: bool


@dataclass(frozen=True)
class GradeResult:
    grader_id: str
    status: GradeStatus
    reason: str
    requested_evidence_types: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return self.status == GradeStatus.PASSED


class Grader(Protocol):
    grader_id: str

    def grade(self, context: GradeContext) -> GradeResult: ...


class _EvidenceIntegrityGrader:
    grader_id = "evidence-integrity"

    def grade(self, context: GradeContext) -> GradeResult:
        if context.integrity_valid:
            return GradeResult(self.grader_id, GradeStatus.PASSED, "Evidence integrity checks passed.")
        return GradeResult(self.grader_id, GradeStatus.FAILED, "Evidence integrity checks failed.")


class _ClaimConfidenceGrader:
    grader_id = "claim-confidence"

    def grade(self, context: GradeContext) -> GradeResult:
        if context.claim.confidence >= context.contract.confidence_threshold:
            return GradeResult(self.grader_id, GradeStatus.PASSED, "Claim confidence meets the contract threshold.")
        return GradeResult(
            self.grader_id,
            GradeStatus.FAILED,
            "Claim confidence is below the contract threshold.",
        )


class _EvidenceTypesGrader:
    grader_id = "evidence-types"

    def grade(self, context: GradeContext) -> GradeResult:
        required = set(context.contract.required_evidence_types)
        missing = tuple(sorted(required - set(context.evidence_types)))
        if not missing:
            return GradeResult(self.grader_id, GradeStatus.PASSED, "Required evidence types are present.")
        return GradeResult(
            self.grader_id,
            GradeStatus.FAILED,
            f"Missing required evidence types: {', '.join(missing)}.",
            missing,
        )


class _ToolVersionsGrader:
    grader_id = "tool-versions"

    def grade(self, context: GradeContext) -> GradeResult:
        mismatches = [
            f"{tool}={context.tool_versions.get(tool, 'missing')} (required {required})"
            for tool, required in sorted(context.contract.required_tool_versions.items())
            if context.tool_versions.get(tool) != required
        ]
        if not mismatches:
            return GradeResult(self.grader_id, GradeStatus.PASSED, "Required tool versions are present.")
        return GradeResult(
            self.grader_id,
            GradeStatus.FAILED,
            f"Tool version requirements were not met: {'; '.join(mismatches)}.",
        )


def _coverage_satisfies(actual: Any, required: Any) -> bool:
    if isinstance(required, dict):
        return isinstance(actual, dict) and all(
            key in actual and _coverage_satisfies(actual[key], value) for key, value in required.items()
        )
    if isinstance(required, list):
        return isinstance(actual, (list, tuple, set, frozenset)) and set(required) <= set(actual)
    if isinstance(required, (int, float)) and not isinstance(required, bool):
        return isinstance(actual, (int, float)) and not isinstance(actual, bool) and actual >= required
    return actual == required


class _CoverageGrader:
    grader_id = "coverage"

    def grade(self, context: GradeContext) -> GradeResult:
        missing = [
            key
            for key, required in sorted(context.contract.required_coverage.items())
            if key not in context.coverage or not _coverage_satisfies(context.coverage[key], required)
        ]
        if not missing:
            return GradeResult(self.grader_id, GradeStatus.PASSED, "Coverage requirements are satisfied.")
        return GradeResult(
            self.grader_id,
            GradeStatus.FAILED,
            f"Coverage requirements were not met for: {', '.join(missing)}.",
        )


class GraderRegistry:
    """Closed registry of deterministic, platform-owned contract graders."""

    def __init__(self, graders: tuple[Grader, ...] | None = None) -> None:
        builtins: tuple[Grader, ...] = (
            _EvidenceIntegrityGrader(),
            _ClaimConfidenceGrader(),
            _EvidenceTypesGrader(),
            _ToolVersionsGrader(),
            _CoverageGrader(),
        )
        self._graders: dict[str, Grader] = {}
        for grader in graders or builtins:
            self.register(grader)

    def register(self, grader: Grader) -> None:
        if not grader.grader_id or grader.grader_id in self._graders:
            raise OutcomeContractError(f"Duplicate or empty grader id: {grader.grader_id!r}")
        self._graders[grader.grader_id] = grader

    def validate_contract(self, contract: OutcomeContract) -> None:
        expected = stable_digest(contract_payload(contract))
        if contract.contract_digest.lower() != expected:
            raise OutcomeContractError("Outcome contract digest does not match its canonical payload")
        if not contract.expected_claim_types:
            raise OutcomeContractError("Outcome contract must require at least one claim type")
        if not contract.grader_ids:
            raise OutcomeContractError("Outcome contract must select at least one grader")
        unknown = sorted(set(contract.grader_ids) - set(self._graders))
        if unknown:
            raise OutcomeContractError(f"Outcome contract references unknown graders: {', '.join(unknown)}")

    def grade(self, context: GradeContext) -> tuple[GradeResult, ...]:
        self.validate_contract(context.contract)
        return tuple(self._graders[grader_id].grade(context) for grader_id in context.contract.grader_ids)

    @property
    def grader_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._graders))


class OutcomeContractCompiler:
    """Compile a PlanStep into an immutable, reproducible acceptance contract."""

    VAGUE_SUCCESS_CRITERIA = {
        "done",
        "success",
        "successful",
        "tool completed",
        "tool execution succeeded",
        "工具成功",
        "工具执行成功",
    }

    def __init__(self, registry: GraderRegistry | None = None) -> None:
        self.registry = registry or GraderRegistry()

    def compile(
        self,
        step: PlanStep,
        *,
        expected_claim_types: list[str] | None = None,
        required_evidence_types: list[str] | None = None,
        required_tool_versions: dict[str, str] | None = None,
        required_coverage: dict[str, Any] | None = None,
        grader_ids: list[str] | None = None,
        confidence_threshold: float = 0.8,
        allow_partial: bool = True,
        partial_conditions: list[str] | None = None,
    ) -> OutcomeContract:
        self._validate_step(step)
        selected_claim_types = sorted(
            set(
                expected_claim_types
                or [
                    f"{step.capability}.coverage",
                    f"{step.capability}.finding",
                ]
            )
        )
        selected_evidence_types = sorted(set(required_evidence_types or []))
        selected_tool_versions = dict(sorted((required_tool_versions or {}).items()))
        selected_coverage = required_coverage or {}
        selected_graders = sorted(set(grader_ids or list(self.registry.grader_ids)))
        selected_partial_conditions = sorted(set(partial_conditions or []))
        payload = {
            "step_id": step.step_id,
            "expected_claim_types": selected_claim_types,
            "required_evidence_types": selected_evidence_types,
            "required_tool_versions": selected_tool_versions,
            "required_coverage": selected_coverage,
            "grader_ids": selected_graders,
            "confidence_threshold": confidence_threshold,
            "allow_partial": allow_partial,
            "partial_conditions": selected_partial_conditions,
        }
        digest = stable_digest(payload)
        contract = OutcomeContract(
            contract_id=f"outcome-{digest[:24]}",
            step_id=step.step_id,
            expected_claim_types=selected_claim_types,
            required_evidence_types=selected_evidence_types,
            required_tool_versions=selected_tool_versions,
            required_coverage=selected_coverage,
            grader_ids=selected_graders,
            confidence_threshold=confidence_threshold,
            allow_partial=allow_partial,
            partial_conditions=selected_partial_conditions,
            contract_digest=digest,
        )
        self.registry.validate_contract(contract)
        return contract

    def _validate_step(self, step: PlanStep) -> None:
        if not step.success_criteria:
            raise OutcomeContractError(f"Step {step.step_id} has no success criteria")
        normalized = {item.strip().casefold().rstrip(".") for item in step.success_criteria if item.strip()}
        if not normalized or normalized <= self.VAGUE_SUCCESS_CRITERIA:
            raise OutcomeContractError(f"Step {step.step_id} success criteria describe execution, not result quality")
