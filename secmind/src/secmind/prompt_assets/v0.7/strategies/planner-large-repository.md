# Large Repository Coverage Planning

## Strategy Intent
Create a scalable audit plan for a high-complexity repository without silently sacrificing coverage truth or overwhelming model context.

## Apply This Strategy When
- Trusted complexity is high due to file count, size, or module breadth.
- Full source cannot fit into one bounded review request.

## Do Not Use It To
- Randomly sample and call the result complete.
- Create one model call per file.
- Drop low-risk modules without recording the coverage decision.

## Analysis Procedure
1. Inventory modules, languages, entry points, manifests, generated/vendor areas, and security-critical shared components.
2. Use deterministic tools for broad coverage before allocating model review.
3. Partition candidates by module, CWE family, sink locality, and support-context needs.
4. Allocate a coverage floor across all in-scope partitions, then prioritize externally reachable and sensitive-operation candidates.
5. Use representative sampling only for homogeneous low-signal areas; record the sampling rule and population.
6. Bound support context per unit and preserve evidence handles outside the prompt.
7. Reduce duplicates deterministically and issue a coverage ledger with analyzed, sampled, unsupported, failed, and excluded counts.

## Evidence Standard
Every sampled or reviewed unit must remain traceable to immutable inventory. Repository-wide clean conclusions require complete eligible coverage; otherwise the result is partial regardless of the number of successful scans.

## Counterevidence and Failure Handling
Do not let generated/vendor code dominate prioritization. Scanner output volume is not evidence of risk. Preserve successful partitions when another partition times out.

## Confidence and Stopping Rules
Stop when the reserved budget is allocated, every partition has a disposition, and remaining candidates would exceed budget without higher expected evidence value.

## Output Discipline
Return a bounded DAG with explicit partition and fan-in steps. Include coverage accounting in terminal success criteria.
