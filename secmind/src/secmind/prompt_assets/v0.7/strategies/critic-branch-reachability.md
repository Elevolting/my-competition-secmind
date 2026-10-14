# Branch Reachability Adjudication

## Strategy Intent
Resolve whether the candidate vulnerable path can execute under a satisfiable set of conditions in the supplied code.

## Apply This Strategy When
- Reachability is explicitly unknown.
- The relevant conditions, assignments, and call path are bounded in the supplied unit/support.

## Do Not Use It To
- Assume a branch is reachable because it appears in source.
- Treat rare, admin-only, test-only, or error paths as unreachable without evidence.
- Expand into full symbolic execution beyond the candidate path.

## Analysis Procedure
1. List only the conditions guarding source acquisition, transformations, sink invocation, and any early return/exception.
2. Resolve constants, mutually exclusive predicates, null/type checks, feature/profile flags, and authorization predicates from supplied evidence.
3. Determine whether one feasible assignment permits the same candidate value to reach the sink.
4. Check exception handling, overwritten values, loops, and returns that terminate the path.
5. Distinguish deployment-unknown flags from demonstrably disabled code.
6. Seek a contradiction proving the path impossible or a concrete consistent path proving reachability.

## Evidence Standard
Return `vulnerable` only when a satisfiable reachable path completes the target weakness evidence. Return `not_vulnerable` when supplied conditions make the candidate path impossible or replace the value. Use `inconclusive` for external flags/callers required to decide reachability.

## Counterevidence and False Positives
An authorization check may restrict actors but still leave a vulnerability for authorized lower-privilege users. A test annotation or unreachable switch default can be decisive when visible. Unknown deployment configuration is uncertainty, not reachability proof.

## Confidence and Stopping Rules
Stop after the minimal candidate path conditions are adjudicated. High confidence requires a consistent condition set or a proven contradiction.

## Output Discipline
Return one typed critic verdict; summarize the decisive branch facts without exposing internal reasoning traces.
