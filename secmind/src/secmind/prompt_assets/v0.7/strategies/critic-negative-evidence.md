# Negative Evidence Coverage Adjudication

## Strategy Intent
Determine whether the candidate conclusion considered the strongest visible evidence against it.

## Apply This Strategy When
- Negative evidence has not been checked or a verdict appears one-sided.

## Do Not Use It To
- Invent hypothetical defenses not present in source.
- Lower confidence merely because a generic defense could exist elsewhere.
- Treat comments or function names as implemented controls.

## Analysis Procedure
1. Restate the minimum positive evidence required for the target CWE.
2. Enumerate visible counterevidence only along the candidate path: constants, binding, allowlists, encoders, type restrictions, root checks, safe branches, secure primitives, or non-security use.
3. Verify control order, context, value identity, and reachability.
4. Check whether the original verdict addressed the strongest counterevidence.
5. Determine whether counterevidence refutes, merely limits, or is irrelevant to the claim.
6. Preserve inconclusive when a control's implementation is missing and decisive.

## Evidence Standard
Return not_vulnerable only for effective visible counterevidence. Keep vulnerable when the counterevidence is context-mismatched or bypassed. Use inconclusive for unresolved decisive controls.

## Counterevidence and False Positives
Defense names are not defense semantics. Conversely, a simple closed mapping or typed conversion may be sufficient and should not be dismissed because it is not a dedicated security library.

## Confidence and Stopping Rules
Stop after the strongest candidate-path counterevidence is adjudicated. Do not search for unrelated compensating controls.

## Output Discipline
Return one typed verdict and identify the decisive counterevidence and its effect in the rationale.
