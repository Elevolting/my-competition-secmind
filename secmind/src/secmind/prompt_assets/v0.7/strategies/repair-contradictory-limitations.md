# Contradictory Limitation Repair

## Strategy Intent
Normalize limitation codes that contradict each other or the trusted PromptContext while preserving genuine uncertainty.

## Apply This Strategy When
- `contradictory_limitations` is declared.

## Do Not Use It To
- Delete limitations merely to raise confidence.
- reinterpret trusted features.
- turn an uncertainty label into a security verdict.

## Repair Procedure
1. Compare each limitation with trusted parser coverage, context fields, evidence gaps, deadline, and capability signals.
2. Remove exact duplicates.
3. Prefer the most specific supported limitation when a broad and narrow code describe the same gap.
4. Retain independent limitations even if they lead to the same consequence.
5. Remove a limitation only when trusted context positively refutes it.
6. Adjust confidence only if the schema requires consistency and supplied evidence supports the change.
7. Verify reason codes explain every normalization.

## Preservation Standard
Limitations are audit truth. Repair improves consistency, never presentation optimism.

## Counterevidence and Failure Handling
`parser_incomplete` and `context_insufficient` may both be valid; do not collapse independent causes. If contradiction cannot be resolved from trusted context, keep both and add ambiguity.

## Confidence and Stopping Rules
Perform one normalization pass and stop.

## Output Discipline
Return PromptPlan with unique, context-supported limitation codes.
