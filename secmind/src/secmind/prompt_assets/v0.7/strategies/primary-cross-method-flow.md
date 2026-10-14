# Cross-Method Dataflow Continuity Review

## Strategy Intent
Resolve a candidate security path that crosses method parameters, returns, fields, callbacks, or helper transformations without inventing missing call edges.

## Apply This Strategy When
- Trusted metadata marks cross-method continuity as unknown.
- Primary and bounded support source contain enough declarations/call sites to attempt resolution.

## Do Not Use It To
- Re-audit unrelated weakness classes.
- Match values only by variable name or type.
- Assume dynamic dispatch targets, reflection, dependency injection, or callbacks without binding evidence.

## Analysis Procedure
1. Start from the known candidate source or sink and enumerate only the adjacent method boundary needed to resolve it.
2. Bind actual arguments to formal parameters by position/name and overload signature.
3. Track assignments, field writes/reads, returned values, wrappers, and transformations across the boundary.
4. Resolve overloads and receiver types from supplied code; mark ambiguous dispatch rather than choosing a convenient target.
5. Preserve branch conditions and sanitizers on both sides of the call.
6. Determine whether the same semantic value reaches the relevant sink argument or security primitive.
7. Seek breaks in continuity: constants, replacement values, validation, non-reachable callers, or unrelated instances.

## Evidence Standard
Return `vulnerable` only if the reconstructed cross-method chain completes the target weakness evidence required by the unit. Cite the target CWE and final sink line. Use `not_vulnerable` when supplied code proves the candidate value is replaced/constrained; use `inconclusive` for unresolved binding or missing implementation.

## Counterevidence and False Positives
Same names across methods are not dataflow. A sanitizer or fixed mapping in a helper can break the path. A return value ignored by the caller does not continue flow. Overload ambiguity caps confidence.

## Confidence and Stopping Rules
High confidence requires exact call-site binding and value continuity. Stop at the minimum method chain needed for the unit; do not expand into a whole-program review.

## Output Discipline
Return one typed verdict per unit with concise continuity/break evidence and explicit missing-edge limitations.
