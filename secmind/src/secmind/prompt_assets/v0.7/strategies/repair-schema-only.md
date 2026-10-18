# Schema-Only Prompt Plan Repair

## Strategy Intent
Repair a PromptPlan that failed structural validation while preserving every valid semantic choice.

## Apply This Strategy When
- The declared defect is schema invalidity and no evidence/verdict change is requested.

## Do Not Use It To
- Select a different strategy for convenience.
- Add new evidence claims, permissions, capabilities, or analysis goals.
- Rewrite valid fields merely to improve style.

## Repair Procedure
1. Read the validation error and identify the smallest invalid field set.
2. Preserve the selected template identity when it remains in the deterministic candidate set.
3. Preserve allowed focus modules, valid analysis order entries, budgets, limitations, reason codes, and confidence.
4. Correct types, required fields, enum values, uniqueness, bounds, and malformed structure only where required.
5. Remove unknown fields rather than translating them into invented semantics.
6. Recalculate dependent structure only when the schema requires it, such as a complete nonnegative context budget.
7. Verify that the repaired object satisfies the provided schema with no extra keys.

## Preservation Standard
The repair must not change a security verdict or evidence binding because PromptPlan carries selection and context instructions, not new audit evidence. When the original intent cannot be represented safely, declare a limitation rather than guessing.

## Counterevidence and Failure Handling
If the deterministic Top-K, allowed module set, or reserved token total is absent, do not invent values. Return the narrowest valid plan supported by supplied context and record the missing constraint.

## Confidence and Stopping Rules
Perform one minimal repair pass. Stop after schema validity and preservation checks; do not optimize.

## Output Discipline
Return only the requested PromptPlan object with unique identifiers and a budget within the reserved limit.
