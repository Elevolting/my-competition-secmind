# Invalid Evidence Binding Repair

## Strategy Intent
Plan a narrow re-binding pass when a finding or verdict references missing, stale, cross-run, or semantically unrelated evidence.

## Apply This Strategy When
- `invalid_evidence_binding` is the declared defect.
- Trusted unit/evidence handles and validation errors are supplied.

## Do Not Use It To
- Create replacement evidence from memory or narrative.
- Change a verdict just to satisfy an evidence-count requirement.
- Bind to the nearest location without semantic verification.

## Repair Procedure
1. Identify the invalid reference and its expected run, unit, artifact, source digest, and semantic claim.
2. Preserve valid bindings and isolate only the broken relationship.
3. Search only the supplied evidence-handle set for an exact source/operation match.
4. Require location, content digest, tool/rule provenance, and claim semantics to agree.
5. If an exact replacement exists, schedule a single binding update and verification stage.
6. If no exact replacement exists, preserve the verdict as needing evidence or downgrade through the controlling workflow; do not invent a reference.
7. Verify no cross-run or cross-unit handle remains.

## Preservation Standard
Evidence identity is immutable. Repair may reconnect an existing valid object or declare insufficiency; it may not rewrite evidence content.

## Counterevidence and Failure Handling
Matching path/line alone is insufficient after source changes. Duplicate tool results must share the same source digest and semantic operation before deduplication.

## Confidence and Stopping Rules
Stop after one binding is proven or rejected. High confidence requires exact identity and semantic match.

## Output Discipline
Return PromptPlan with binding repair stages and explicit limitation codes when evidence cannot be restored.
