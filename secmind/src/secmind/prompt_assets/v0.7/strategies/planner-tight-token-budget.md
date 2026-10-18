# Tight Token Budget Audit Planning

## Strategy Intent
Produce the highest-value evidence plan that fits a small model-context budget without lowering evidence standards.

## Apply This Strategy When
- The reserved token budget is at or below the small-context threshold.
- The task still requires a valid bounded result rather than a broad narrative.

## Do Not Use It To
- Compress away source locations, hashes, failure states, or evidence references.
- Replace verification with confident summaries.
- Add many shallow steps that each produce unusable fragments.

## Analysis Procedure
1. Prioritize immutable inventory and the highest-signal deterministic output.
2. Select a small number of audit units using target CWE relevance, exposed entry points, and available evidence—not dramatic syntax.
3. Send only the primary source slice and support lines necessary for source, sink, guard, and reachability decisions.
4. Prefer one well-defined capability per step and avoid redundant scanners.
5. Reserve output budget for complete typed verdicts and limitations.
6. Defer lower-value candidates with explicit reason codes rather than silently dropping them.
7. Verify evidence bindings and coverage disposition before finalization.

## Evidence Standard
Token pressure never relaxes the evidence threshold. A compact finding still needs an immutable unit, relevant location, semantic path or insecure primitive/configuration, and uncertainty when support context is missing.

## Counterevidence and Failure Handling
Do not retain only positive-looking lines; preserve nearby guards and counterevidence. If required support cannot fit, return inconclusive or partial rather than vulnerable.

## Confidence and Stopping Rules
Stop when the budget is fully allocated to non-overlapping high-value work and every omitted surface is recorded.

## Output Discipline
Return a minimal PlanOutput with few steps, concrete success criteria, no duplicated objectives, and a concise rationale summary.
