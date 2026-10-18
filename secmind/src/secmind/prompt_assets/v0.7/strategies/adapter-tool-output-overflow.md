# Tool Output Overflow Adapter

## Strategy Intent
Replace oversized raw tool output with the smallest typed evidence view needed for adjudication, while preserving full-artifact provenance outside the prompt.

## Apply This Strategy When
- `tool_output_overflow` is declared and raw scanner output exceeds context capacity.

## Do Not Use It To
- Drop errors, truncation markers, tool/rule versions, or artifact hashes.
- summarize multiple findings into an unverifiable narrative.
- expose raw secret candidates or logs.

## Adaptation Procedure
1. Preserve invocation ID, tool/version, rule/database digest, status, duration, truncation state, and full artifact handle.
2. Normalize only fields required for the target unit: rule, severity, path, line, message summary, candidate CWE, and evidence ID.
3. Deduplicate exact finding fingerprints while preserving contributing evidence handles.
4. Select only candidates relevant to current unit/CWE; retain counts for omitted candidates.
5. Include bounded stderr/error summaries separately from findings.
6. Allocate context to source-semantic verification rather than repeated raw output.
7. Verify every compacted item can be traced back to immutable full content.

## Preservation Standard
Compaction changes representation, not tool result status or evidence content.

## Counterevidence and Failure Handling
If truncation prevents reliable parsing, preserve the typed error and mark tool evidence incomplete. Do not infer absent findings from truncated output.

## Confidence and Stopping Rules
Stop after one deterministic normalization/selection pass.

## Output Discipline
Return PromptPlan with evidence-handle compaction stages and explicit overflow limitations.
