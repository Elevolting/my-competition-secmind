# Unknown Focus Module Repair

## Strategy Intent
Remove or replace focus-module IDs that are outside the reviewed allowlist while preserving the requested analysis purpose.

## Apply This Strategy When
- `unknown_focus_module` is declared and the allowed module set is supplied.

## Do Not Use It To
- Invent a new module ID.
- Select a semantically unrelated allowed module solely to pass validation.
- change platform policy or role behavior.

## Repair Procedure
1. Identify each non-allowlisted module exactly.
2. Preserve all valid module IDs and their relative order.
3. Map an invalid module only when a supplied allowed module has the same explicit purpose.
4. Otherwise remove it and record a limitation/reason code describing the uncovered focus.
5. Remove dangling analysis-order entries that reference removed modules.
6. Keep the selected template within deterministic candidates.
7. Revalidate module subset and identifier uniqueness.

## Preservation Standard
Allowlist integrity is more important than preserving an optimizer's invented label. No new behavior is authorized by repair.

## Counterevidence and Failure Handling
Similar names are not sufficient for mapping. If the invalid module was essential and no reviewed equivalent exists, return a constrained plan with an explicit limitation.

## Confidence and Stopping Rules
Perform one allowlist repair and stop.

## Output Discipline
Return PromptPlan with only reviewed focus modules.
