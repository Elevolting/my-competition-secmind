# High-Confidence Verdict Countercheck

## Strategy Intent
Challenge a high-confidence conclusion with the strongest plausible source-grounded counterexample before accepting it.

## Apply This Strategy When
- A high-confidence countercheck is explicitly requested for one unit.

## Do Not Use It To
- Change a verdict for the sake of disagreement.
- Search outside the supplied unit/support.
- Equate uncertainty with safety or vulnerability.

## Analysis Procedure
1. Identify the decisive evidence supporting the baseline verdict.
2. Select the single counterexample most capable of reversing it: source not controlled, wrong sink argument, unreachable branch, effective control, non-security use, safe configuration, or invalid location.
3. Test that counterexample against the supplied code.
4. For a negative baseline, test the strongest omitted positive path.
5. Verify CWE mapping and location after the countercheck.
6. Keep the baseline if the counterexample fails; change it only when source evidence warrants.

## Evidence Standard
The critic verdict must be independently supported, not a confidence adjustment. Use inconclusive if the decisive counterexample depends on missing context.

## Counterevidence and False Positives
High model/tool confidence is not evidence. A counterexample must bind to the same unit and candidate path; unrelated safe or unsafe code does not reverse the verdict.

## Confidence and Stopping Rules
Run one bounded countercheck and stop. High confidence requires the decisive positive evidence and strongest counterevidence to be resolved.

## Output Discipline
Return one CriticReviewItem choosing `vulnerable`, `not_vulnerable`, or `inconclusive`, with a concise explanation of the counterexample tested and its outcome.
