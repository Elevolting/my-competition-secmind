"""Authoritative task-contract access at execution boundaries.

``TaskRequest`` is retained on :class:`~secmind.schemas.AgentState` for request
provenance, attachment discovery, and durable compatibility.  It is not an
execution authority.  Workflow, policy, projection, and memory code must read
operator intent from the sealed :class:`ResolvedTaskContract` instead.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from secmind.task_contract import ResolvedTaskContract

if TYPE_CHECKING:
    from secmind.schemas import AgentState


class ResolvedTaskContractRequired(RuntimeError):
    """Raised when an execution boundary has no valid sealed task contract."""


def require_resolved_task_contract(state: AgentState) -> ResolvedTaskContract:
    """Return the run-bound execution contract or fail closed.

    The extra reference checks prevent a valid contract from another run or
    TaskSpec revision being attached to the current state.  Pydantic already
    validates the contract's own content digest when the state is loaded.
    """

    contract = state.resolved_task_contract
    if contract is None:
        raise ResolvedTaskContractRequired("execution requires a sealed ResolvedTaskContract")
    if contract.run_id != state.run_id:
        raise ResolvedTaskContractRequired("resolved task contract belongs to a different run")
    task_spec_ref = state.task_spec_ref
    if task_spec_ref is not None and (
        contract.task_spec_id != task_spec_ref.task_spec_id
        or contract.task_spec_revision != task_spec_ref.revision
        or contract.task_spec_digest != task_spec_ref.content_digest
    ):
        raise ResolvedTaskContractRequired("resolved task contract does not match the durable TaskSpec reference")
    return contract


__all__ = ["ResolvedTaskContractRequired", "require_resolved_task_contract"]
