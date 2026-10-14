# Tool-Positive versus Primary-Negative Adjudication

## Strategy Intent
Adjudicate a deterministic tool candidate that conflicts with a primary `not_vulnerable` or inconclusive conclusion, without treating either source as automatically authoritative.

## Apply This Strategy When
- The conflict type is tool-positive/primary-negative.
- Tool rule metadata, candidate flow, primary verdict, and source evidence are supplied.

## Do Not Use It To
- Re-run the entire audit or create new tool findings.
- Accept a rule match as exploitability proof.
- Reject the tool solely because the primary model disagreed.

## Analysis Procedure
1. Verify that the tool location and rule still bind to the supplied immutable source.
2. Identify the semantic condition the rule approximates and what evidence it does not establish.
3. Compare the primary rationale against source, sink argument, reachability, controls, and target CWE.
4. Resolve the smallest disputed fact first, using bounded support only.
5. Search for false-positive patterns specific to the rule and for evidence omitted by the primary.
6. Choose the verdict supported by source semantics, not by vote or confidence score.

## Evidence Standard
Return vulnerable only when source evidence completes the weakness beyond the tool heuristic. Return not_vulnerable when a visible control or semantic mismatch refutes the rule. Return inconclusive when the conflict depends on missing context.

## Counterevidence and False Positives
Tool severity, count, or rule wording does not increase evidence by itself. Primary confidence is also not evidence. Stale line bindings, generated/test code, safe API arguments, and effective controls commonly explain tool positives.

## Confidence and Stopping Rules
Stop when the exact conflict fact is resolved. High confidence requires valid tool binding and independent source-semantic confirmation/refutation.

## Output Discipline
Return one CriticReviewItem with the adjudicated CWE and concise reason; do not summarize unrelated tool output.
