# Duplicate Identifier Repair

## Strategy Intent
Remove duplicate template, module, analysis-stage, reason, or limitation identifiers while preserving first-order semantics and stable ordering.

## Apply This Strategy When
- `duplicate_identifiers` is the declared structural defect.

## Do Not Use It To
- Merge identifiers that are merely similar.
- Rename canonical template or module IDs.
- Drop semantically distinct stages to reduce length.

## Repair Procedure
1. Identify duplicates by exact canonical value within each PromptPlan field.
2. Preserve the selected template identity unchanged.
3. Retain the first occurrence of repeated order-sensitive stages unless trusted context supplies a canonical order.
4. Deduplicate set-like focus modules, limitations, and reason codes without changing spelling.
5. If duplicate focus questions express the same fact differently, keep the shortest unambiguous version.
6. Verify all retained module IDs remain allowlisted and analysis order references remain valid.
7. Revalidate the full PromptPlan.

## Preservation Standard
Deduplication must not alter context budgets, confidence, or evidence meaning.

## Counterevidence and Failure Handling
Two stages with different IDs are not duplicates even if their prose overlaps. When order intent is ambiguous, preserve both and declare a limitation rather than guessing.

## Confidence and Stopping Rules
Perform one stable deduplication pass and stop.

## Output Discipline
Return only PromptPlan with unique identifiers and deterministic ordering.
