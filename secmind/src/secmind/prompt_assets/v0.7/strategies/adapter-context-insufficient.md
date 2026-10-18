# Insufficient Context Adapter

## Strategy Intent
Construct the smallest safe follow-up plan when decisive source, support, framework, or configuration context is missing.

## Apply This Strategy When
- `context_insufficient` is declared and the missing fact can change the verdict.

## Do Not Use It To
- Guess the missing code or framework default.
- Request the entire repository when one bounded file or symbol is sufficient.
- convert uncertainty into vulnerability.

## Adaptation Procedure
1. Identify the exact unresolved proposition: source ownership, sink argument, helper behavior, branch, control, binding, configuration, or location.
2. Determine the smallest source/support artifact capable of resolving it.
3. Preserve the current unit and all valid evidence; do not restart inventory or unrelated scans.
4. Add at most a few precise focus questions that name facts, not desired conclusions.
5. Allocate budget to the missing support and subsequent evidence verification.
6. If the context is unavailable within scope, add an explicit limitation and plan for inconclusive/partial convergence.
7. Verify the request cannot widen scope or expose untrusted control text.

## Preservation Standard
The adapter narrows uncertainty. It does not alter valid findings or authorize new acquisition mechanisms.

## Counterevidence and Failure Handling
More context is not always better. If existing evidence already proves the conclusion independently of the missing fact, no follow-up is required; preserve the result and record the non-decisive gap.

## Confidence and Stopping Rules
Stop after identifying one minimal context request or an explicit unresolvable limitation.

## Output Discipline
Return a PromptPlan using `explicit_limitations` and bounded focus questions.
