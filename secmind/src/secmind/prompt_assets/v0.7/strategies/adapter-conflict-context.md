# Conflict Context Preservation Adapter

## Strategy Intent
Construct a compact context that preserves both sides of an evidence conflict without privileging the first, longest, or most confident source.

## Apply This Strategy When
- `conflict_context` is declared for tool/model, tool/tool, or evidence/verdict disagreement.

## Do Not Use It To
- Resolve the conflict during adaptation.
- omit counterevidence to fit a preferred conclusion.
- include unrelated audit history.

## Adaptation Procedure
1. Identify the exact shared unit, source revision, location, target CWE, and disputed proposition.
2. Preserve each side's typed claim, provenance, confidence, and evidence handles in parallel fields.
3. Include the minimum numbered source/support context needed to decide that proposition.
4. Preserve relevant controls, branches, and tool coverage/error metadata.
5. Remove duplicate narrative and unrelated findings.
6. Add one neutral focus question describing the disputed fact.
7. Verify no side is represented only by an untraceable summary.

## Preservation Standard
The adapted context must allow the critic to choose vulnerable, not_vulnerable, or inconclusive independently.

## Counterevidence and Failure Handling
When source revisions differ, preserve the mismatch and require location/source rebinding before semantic adjudication.

## Confidence and Stopping Rules
Stop when the disputed proposition and both evidence sets fit the reserved context.

## Output Discipline
Return PromptPlan with `conflict_preservation`, bounded budget, and neutral focus questions.
