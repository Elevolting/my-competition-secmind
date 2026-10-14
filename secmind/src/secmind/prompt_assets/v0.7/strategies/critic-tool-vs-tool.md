# Tool-to-Tool Conflict Adjudication

## Strategy Intent
Resolve disagreement between normalized tool results by returning to immutable source and tool/rule metadata.

## Apply This Strategy When
- The conflict type is tool disagreement.
- Both tool findings, versions/rules, and source binding are supplied.

## Do Not Use It To
- Decide by majority, severity, brand, or number of matching rules.
- Merge distinct source locations or CWE semantics into one conflict.
- Invent tool configuration or rule intent.

## Analysis Procedure
1. Verify both results bind to the same source revision, location, and semantic operation.
2. Compare each rule's target condition, scope, severity mapping, and known blind spots from supplied metadata.
3. Reconstruct the minimum source semantics required by the target CWE.
4. Check source control, sink argument, reachability, controls, and security relevance as applicable.
5. Determine whether the tools disagree on presence, classification, severity, or only location.
6. Resolve from source evidence and preserve unresolved tool limitations.

## Evidence Standard
Return vulnerable only when source semantics satisfy the weakness; return not_vulnerable when both/one rule is refuted by visible code; return inconclusive when a missing rule/configuration fact is decisive.

## Counterevidence and False Positives
Duplicate rule families can disagree because of framework assumptions, generated code, line mapping, or different severity taxonomies. A conflict in severity does not necessarily change presence verdict.

## Confidence and Stopping Rules
Stop after the shared semantic claim is adjudicated. High confidence requires valid bindings and direct source evidence.

## Output Discipline
Return one CriticReviewItem and do not reproduce raw tool output.
