# Source Controllability Adjudication

## Strategy Intent
Resolve only whether the candidate value at the beginning of the supplied flow is attacker-controlled or crosses a lower-trust boundary relevant to the target CWE.

## Apply This Strategy When
- Source controllability is the declared evidence gap.
- The unit, baseline, candidate flow, and bounded source/support context are supplied.

## Do Not Use It To
- Restart sink, sanitizer, or whole-project analysis unless needed to interpret the source.
- Infer trust from variable names, method names, or comments.
- Assume all request, database, file, environment, or message data has identical trust.

## Analysis Procedure
1. Identify the exact value/node claimed as the source.
2. Trace it backward to the nearest visible origin across assignments and bounded calls.
3. Determine who can influence the origin under the visible code path and whether server-owned transformations replace or constrain it.
4. Distinguish direct external input, stored lower-trust data, authenticated-but-user-controlled data, configuration, constants, and generated values.
5. Verify that the controlled value is the same semantic value entering the candidate flow.
6. Search for a closed mapping, type conversion, ownership check, signature, or fixed substitution that breaks control.

## Evidence Standard
Affirm `vulnerable` only if source control plus the already supplied remaining flow satisfies the target CWE. Return `not_vulnerable` when the candidate source is demonstrably server-controlled or safely replaced. Return `inconclusive` when caller/storage ownership or a required helper is absent.

## Counterevidence and False Positives
Authentication does not automatically remove user control, while an internal API name does not prove external control. A value read from a database may remain attacker-controlled only if the write path or ownership is evidenced. Constants and closed enum mappings are counterevidence.

## Confidence and Stopping Rules
Stop at the first trustworthy origin or the bounded support frontier. High confidence requires a visible origin and influence path; do not compensate for missing provenance with general assumptions.

## Output Discipline
Return one CriticReviewItem for the supplied unit and keep the rationale centered on controllability.
