# Incomplete Evidence Adjudication

## Strategy Intent
Decide whether the supplied evidence is sufficient for a positive or negative verdict when parser, tool, or context completeness is degraded.

## Apply This Strategy When
- Parser incomplete, tool incomplete, or context insufficient is declared.

## Do Not Use It To
- Fill missing code, configuration, tool output, or call edges with assumptions.
- Treat absence of a match in incomplete evidence as safety.
- Reject direct local evidence merely because unrelated coverage is incomplete.

## Analysis Procedure
1. Identify the exact evidence required by the target CWE.
2. Mark which required facts are supplied, contradicted, or missing.
3. Determine whether missing facts intersect the decisive candidate path.
4. Validate immutable source/tool bindings that remain available.
5. Assign vulnerable only if complete positive evidence survives the gap.
6. Assign not_vulnerable only if visible counterevidence positively refutes the candidate despite the gap.
7. Otherwise return inconclusive.

## Evidence Standard
Completeness is claim-specific. A missing unrelated module need not weaken a fully local primitive finding, while a missing sanitizer helper can prevent adjudication of an injection candidate.

## Counterevidence and False Positives
Tool timeout and parser failure are limitations, not findings. Partial source can still refute a candidate if it shows a constant or wrong argument, but cannot support broad absence claims.

## Confidence and Stopping Rules
Cap confidence according to the relationship between missing facts and decisive evidence. Stop at the supplied frontier.

## Output Discipline
Return one typed verdict and name the smallest missing fact that prevents a stronger conclusion.
