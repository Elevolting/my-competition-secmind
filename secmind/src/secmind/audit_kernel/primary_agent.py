from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from secmind.audit_kernel.pipeline import AuditKernelResult, JavaAuditKernel
from secmind.investigation.contracts import AgentWorkContract, canonical_content_digest
from secmind.live_source_review import SourceUnit


@dataclass(frozen=True, slots=True)
class PrimaryAuditWorkItem:
    """Least-authority input for the model-backed primary audit specialist."""

    contract: AgentWorkContract
    case_files: tuple[SourceUnit, ...]
    support_files: tuple[SourceUnit, ...]
    deadline_at: datetime
    max_model_calls: int
    mode: str
    authorized_scope: tuple[str, ...]


class PrimaryAuditAgent:
    """Formal Agent boundary around the Direct-quality Java audit kernel.

    The specialist receives neither ``AgentState`` nor database/tool handles.
    Its authority is the sealed work contract and immutable source snapshot.
    """

    def __init__(self, kernel: JavaAuditKernel) -> None:
        self._kernel = kernel

    async def run(self, item: PrimaryAuditWorkItem) -> AuditKernelResult:
        self._validate(item)
        return await self._kernel.run(
            run_id=item.contract.run_id,
            case_files=list(item.case_files),
            support_files=list(item.support_files),
            deadline_at=item.deadline_at,
            max_model_calls=item.max_model_calls,
            mode=item.mode,
            authorized_scope=item.authorized_scope,
        )

    @staticmethod
    def _validate(item: PrimaryAuditWorkItem) -> None:
        contract = item.contract
        if contract.content_digest != canonical_content_digest(contract, exclude={"content_digest"}):
            raise ValueError("primary audit work contract digest is invalid")
        if contract.step_id != "model-source-review" or contract.capability != "sast":
            raise ValueError("primary audit work is outside the approved specialist capability")
        if contract.profile_id != "sast-investigator":
            raise ValueError("primary audit work uses an unapproved agent profile")
        if contract.allowed_tool_sets:
            raise ValueError("primary audit Agent cannot invoke tools directly")
        if "review_immutable_source" not in contract.allowed_action_kinds:
            raise ValueError("primary audit work contract does not authorize source review")
        if not item.case_files:
            raise ValueError("primary audit requires at least one immutable source unit")
        if item.max_model_calls < 0:
            raise ValueError("primary audit model budget cannot be negative")


__all__ = ["PrimaryAuditAgent", "PrimaryAuditWorkItem"]
