# Invalid Template Selection Repair

## Strategy Intent
Repair a PromptPlan that selected a template outside the deterministic candidate set.

## Apply This Strategy When
- `invalid_template_selection` is declared and the ordered Top-K candidates are supplied.

## Do Not Use It To
- Introduce a template not selected by deterministic policy.
- choose by style, novelty, or claimed authority.
- modify candidate scores or trusted features.

## Repair Procedure
1. Verify the current template identity is not in the candidate set.
2. Select the highest-ranked candidate compatible with the existing role and output contract.
3. Reset focus modules to a subset allowed by that candidate.
4. Remove analysis stages and questions that only applied to the invalid template.
5. Preserve context budget and limitation codes when still valid.
6. Add a reason code stating deterministic candidate repair.
7. Revalidate template/version identity against the supplied Top-K.

## Preservation Standard
The repair follows deterministic ranking; it does not perform a new free-form selection.

## Counterevidence and Failure Handling
If the candidate set is empty or lacks strategy content, do not invent a selection. Declare fallback/limitation for the controlling service.

## Confidence and Stopping Rules
Stop after one candidate-valid selection and consistency pass.

## Output Discipline
Return PromptPlan only with an exact candidate template ID and version.
