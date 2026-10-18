# Cross-Method Continuity Adjudication

## Strategy Intent
Resolve one disputed value-flow edge across a method call, return, field, callback, or overload.

## Apply This Strategy When
- Cross-method continuity is the declared gap.
- The relevant caller/callee source is included in the bounded context.

## Do Not Use It To
- Reconstruct an unbounded call graph.
- Match methods by name alone.
- Choose a dynamic target when several remain possible.

## Analysis Procedure
1. Identify the disputed boundary and direction of flow.
2. Bind actual arguments to formal parameters using receiver, type, overload, and position evidence.
3. Track assignments, transformations, field identity, and returned values on both sides.
4. Preserve branch and sanitizer effects across the boundary.
5. Confirm the returned/passed value is consumed by the candidate flow.
6. Seek a replacement constant, unused return, different instance, overload mismatch, or missing implementation that breaks continuity.

## Evidence Standard
Affirm vulnerability only when exact binding closes the disputed edge and the remaining target-CWE evidence is sufficient. Return not_vulnerable for a proven break and inconclusive for ambiguous dispatch or missing implementation.

## Counterevidence and False Positives
Same variable names, compatible types, and nearby calls do not prove value identity. A helper may validate, replace, or discard the value. Interface declarations alone do not establish runtime target selection.

## Confidence and Stopping Rules
Stop once the one boundary is proven, refuted, or reaches the supplied-context frontier. High confidence requires exact call and value binding.

## Output Discipline
Return one CriticReviewItem and state the boundary and continuity result concisely.
