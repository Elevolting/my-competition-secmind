# Finding Location Binding Adjudication

## Strategy Intent
Verify that the claimed sink location binds to the immutable numbered source and represents the operation used by the verdict.

## Apply This Strategy When
- Location binding is unknown, stale, duplicated, or disputed.

## Do Not Use It To
- Select the nearest dangerous-looking line when the actual operation is elsewhere.
- Accept line numbers from raw tool output without checking source identity.
- Change CWE semantics unless location invalidates the underlying claim.

## Analysis Procedure
1. Verify unit identity, source digest context, and numbered-source line range.
2. Locate the exact call/configuration/operation claimed as the sink.
3. Distinguish construction lines, helper definitions, logging, and actual execution/use.
4. Confirm the value/primitive described by the verdict is present at that location.
5. Reconcile off-by-one, multiline, generated, and stale tool mappings using only supplied source.
6. If the cited location is wrong, determine whether another visible line preserves the same evidenced weakness or whether the claim collapses.

## Evidence Standard
Return vulnerable only with a valid source-bound operation and supported CWE. Return not_vulnerable if the alleged sink is absent/non-sensitive and no equivalent supplied sink exists. Use inconclusive when source revision or relevant lines are missing.

## Counterevidence and False Positives
A method declaration, string constant, or builder creation may not be the final sink. A line mismatch alone does not refute a real nearby operation, but the replacement line must be visible and semantically exact.

## Confidence and Stopping Rules
Stop after binding one unit and one operation. High confidence requires immutable source agreement and exact semantics.

## Output Discipline
Return one CriticReviewItem; mention the binding result without copying source content.
