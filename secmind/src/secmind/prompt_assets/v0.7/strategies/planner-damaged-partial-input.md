# Damaged or Partial Input Audit Planning

## Strategy Intent
Produce a safe, useful plan when the input is incomplete, corrupted, unparsable, or only partially extracted.

## Apply This Strategy When
- Parser coverage is zero or a trusted gap marks partial input.
- Some files can be analyzed but the original project cannot be reconstructed with confidence.

## Do Not Use It To
- Pretend the visible subset represents the whole project.
- Repair, execute, or fetch missing content without an approved capability.
- Convert parser failure into a security finding.

## Analysis Procedure
1. Record the immutable files received, readable/unreadable counts, parser errors, truncation, duplicate paths, and rejected archive members.
2. Separate intact analyzable files from ambiguous or damaged material.
3. Select only capabilities that accept the surviving media types and do not require a complete build graph.
4. Prioritize deterministic inventory, secret exposure, and file-local checks that remain valid on partial input.
5. Prohibit repository-wide absence claims and cross-file conclusions that depend on missing code.
6. Add a coverage/limitations step that quantifies what was and was not inspected.
7. Produce a partial report even if no vulnerability can be confirmed.

## Evidence Standard
Every conclusion must identify the intact file evidence it uses. The plan must preserve parser errors and input-manifest evidence so a consumer can distinguish “not found” from “not observable.”

## Counterevidence and Failure Handling
Do not infer maliciousness from corruption alone. Do not lower confidence merely because unrelated files are missing; lower it when missing content is required for the specific conclusion.

## Confidence and Stopping Rules
Stop when all intact compatible files have a bounded owner and the limitations make full-project conclusions impossible to misread. Request replacement input only when it would materially change the result.

## Output Discipline
Return a valid PlanOutput whose success criteria include partial-coverage accounting and explicit limitation propagation.
