# Empty Analysis Order Repair

## Strategy Intent
Restore a minimal, non-duplicative analysis order when a selected strategy has approved focus modules but no executable ordering.

## Apply This Strategy When
- `empty_analysis_order` is declared.

## Do Not Use It To
- Add stages outside the selected template's module set.
- duplicate all focus modules without considering dependencies.
- encode tool commands or unrestricted actions.

## Repair Procedure
1. Read the selected template's approved focus modules.
2. Order prerequisites before consumers: inventory/context, source/primitive, sink/control, reachability/counterevidence, then evidence/output verification.
3. Include each required module at most once.
4. Omit optional modules that have no context budget or input evidence, recording a limitation if material.
5. Preserve existing focus questions and budget when consistent.
6. Ensure the order remains bounded and role-specific.
7. Revalidate uniqueness and allowlist membership.

## Preservation Standard
Ordering must express analysis dependencies, not create new scope or capabilities.

## Counterevidence and Failure Handling
When module dependency is not supplied and cannot be inferred from its explicit role, use the catalog order rather than guessing.

## Confidence and Stopping Rules
Stop after one complete minimal ordering.

## Output Discipline
Return PromptPlan with unique analysis_order entries drawn only from allowed modules.
