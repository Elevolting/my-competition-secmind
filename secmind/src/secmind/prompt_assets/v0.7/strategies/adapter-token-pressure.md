# Token Pressure Context Adapter

## Strategy Intent
Reallocate a PromptPlan under token pressure while retaining the evidence needed to decide the target unit.

## Apply This Strategy When
- `token_pressure` is declared and the existing context allocation exceeds or threatens the reserved budget.

## Do Not Use It To
- Lower the evidence standard.
- Remove source locations, immutable handles, decisive guards, or limitations.
- Expand model output to compensate for missing input.

## Adaptation Procedure
1. Preserve the selected reviewed template and only its allowed focus modules.
2. Reserve output tokens first for a complete schema-valid result.
3. Preserve the primary audit-unit slice containing source, sink/primitive, transformations, controls, and numbered location.
4. Rank support context by direct call/dataflow relevance and omit unrelated history, duplicate tool text, and narrative.
5. Replace large raw tool output with typed evidence handles and bounded summaries whose source digest remains available.
6. Shorten focus questions to one fact per question and remove questions already answered by trusted features.
7. Verify total source, support, evidence, and output allocations do not exceed the reserved budget.

## Preservation Standard
A compact context must still support vulnerable, not_vulnerable, or inconclusive. If it cannot support a decisive verdict, declare the limitation instead of retaining a biased positive-only slice.

## Counterevidence and Failure Handling
Do not discard sanitizers or safe branches because they appear less salient than sinks. Duplicate source excerpts can be removed only when one immutable reference remains.

## Confidence and Stopping Rules
Perform one deterministic compaction pass and stop when the budget fits. Do not repeatedly summarize summaries.

## Output Discipline
Return PromptPlan only, with explicit context budget and `context_compaction` analysis order.
