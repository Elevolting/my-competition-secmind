# Missing Audit Unit Recovery Plan

## Strategy Intent
Repair a plan/output workflow that omitted one or more required immutable audit units without changing already valid unit semantics.

## Apply This Strategy When
- The declared defect is `missing_unit` and the expected unit identifiers are supplied as trusted context.

## Do Not Use It To
- Fabricate a verdict for an absent unit.
- Duplicate units already represented.
- Reopen all completed units when only a bounded subset is missing.

## Repair Procedure
1. Compare expected immutable unit IDs with the represented set and isolate only missing IDs.
2. Preserve completed/valid unit results outside the repair scope.
3. Select a repair analysis order containing only the minimal missing-unit recovery stage and required evidence binding.
4. Allocate source/support/evidence/output budget proportionally to the missing subset, within the reserved total.
5. Use focus questions only to identify the absent unit and its required target CWE/context; never include source text in them.
6. Add a limitation when the missing unit's source or support context is unavailable.
7. Verify that every expected ID has exactly one recovery disposition and no duplicates are introduced.

## Preservation Standard
The repair plan must cause missing units to be re-requested or marked inconclusive by the controlling workflow; it must not synthesize their findings.

## Counterevidence and Failure Handling
An intentionally excluded unit is not missing if trusted scope metadata records the exclusion. If expected IDs are ambiguous, preserve the ambiguity as a limitation.

## Confidence and Stopping Rules
Stop after the missing set is covered by one bounded repair plan. Do not alter valid unit ordering or verdicts.

## Output Discipline
Return PromptPlan only, with `missing_unit_only` as the narrow focus and no unrelated modules.
