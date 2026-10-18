# Invalid Context Budget Repair

## Strategy Intent
Repair a negative, incomplete, or over-reserved context budget without changing the selected analysis strategy.

## Apply This Strategy When
- `invalid_context_budget` is declared and a trusted total token reservation is supplied.

## Do Not Use It To
- Increase the hard reservation.
- hide missing evidence by assigning zero output or evidence budget.
- Change template identity to avoid budgeting.

## Repair Procedure
1. Read the reserved total and current source/support/evidence/output allocations.
2. Set every component to a nonnegative integer and ensure their sum is within the reservation.
3. Reserve enough output for one complete structured result before distributing input.
4. Give primary source the largest share, then direct support, then typed evidence, adjusted to the declared gap.
5. Remove only unallocated excess; do not claim tokens were used when no context exists.
6. Preserve focus modules and analysis order unless a stage has no corresponding budget and must be explicitly limited.
7. Verify arithmetic deterministically.

## Preservation Standard
Budget repair changes allocation only. It cannot relax scope, evidence, or output requirements.

## Counterevidence and Failure Handling
If the trusted reservation is too small for a valid result, use an explicit token-pressure limitation rather than fabricating a feasible allocation.

## Confidence and Stopping Rules
Stop after one valid allocation. No iterative optimization is needed.

## Output Discipline
Return PromptPlan with a valid ContextBudget and unchanged template selection.
