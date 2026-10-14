# Parser-Incomplete Conservative Review

## Strategy Intent
Adjudicate an audit unit when parsing, symbol extraction, or candidate-flow construction is incomplete while preventing false completeness.

## Apply This Strategy When
- Parser coverage is zero/incomplete or dynamic syntax could not be resolved.
- Numbered source remains available for bounded review.

## Do Not Use It To
- Treat parser failure as vulnerability evidence.
- Claim absence of a source/sink/guard from an incomplete parse.
- Reconstruct missing files or dynamic calls from imagination.

## Analysis Procedure
1. Identify which parser facts are reliable and which fields/edges are missing or degraded.
2. Review the numbered source directly for the target CWE's minimum semantic evidence.
3. Trace only visible assignments, calls, branches, constants, and configurations.
4. Treat reflection, generated code, macros/preprocessing, dynamic invocation, malformed regions, and missing support as explicit uncertainty.
5. Seek direct positive evidence that remains valid despite parser gaps, such as an insecure primitive configured on a visible reachable path.
6. Seek direct negative evidence, but do not infer safety from absent parser nodes.
7. Use `inconclusive` whenever a missing parse fact can materially reverse the verdict.

## Evidence Standard
`vulnerable` still requires the same source/sink or primitive/configuration evidence as a complete parse and an exact sink line. `not_vulnerable` requires visible counterevidence, not lack of a match. Parser limitations must be reported.

## Counterevidence and False Positives
Syntax recovery may associate the wrong call or line; verify against numbered source. A tool candidate without a visible semantic path remains unconfirmed. A malformed unrelated region need not lower confidence for a fully visible local primitive.

## Confidence and Stopping Rules
Cap confidence according to whether the missing parser facts intersect the decisive path. Stop at the supplied unit and return partial/inconclusive rather than attempting unbounded reconstruction.

## Output Discipline
Return one typed verdict per unit, include parser-related limitations, and never imply full-project coverage.
