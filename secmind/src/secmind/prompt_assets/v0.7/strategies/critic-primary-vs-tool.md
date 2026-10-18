# Primary-Positive versus Tool-Absent Adjudication

## Strategy Intent
Adjudicate a primary vulnerability claim that lacks corroborating tool output, recognizing that tools have bounded rule and language coverage.

## Apply This Strategy When
- The conflict type is primary-positive/tool-absent.
- Primary evidence and relevant tool coverage metadata are supplied.

## Do Not Use It To
- Reject a semantic finding merely because a scanner did not report it.
- Assume tool absence means the tool analyzed the file/rule successfully.
- Accept the primary claim without rechecking its evidence chain.

## Analysis Procedure
1. Establish whether the tool covered the language, file, rule family, and execution successfully.
2. Recheck the primary source, sink/primitive, reachability, controls, location, and CWE mapping.
3. Determine whether the weakness is outside the tool's documented detection model or should have been detectable.
4. Check for source changes, suppressions, exclusions, parse errors, and output truncation.
5. Search for counterevidence that the primary overlooked.
6. Base the verdict on source evidence while recording tool absence only as coverage context.

## Evidence Standard
Keep vulnerable when the primary chain is complete even without a tool match. Return not_vulnerable when source evidence fails. Use inconclusive when essential support is missing or tool/source binding cannot be reconciled.

## Counterevidence and False Positives
Tool silence is not negative evidence without proven coverage. Conversely, semantic source reasoning must still identify the exact vulnerable operation and control failure.

## Confidence and Stopping Rules
Stop after source validity and tool coverage are independently resolved. High confidence does not require multi-tool agreement.

## Output Discipline
Return one typed critic verdict and distinguish “tool did not cover” from “tool covered and found no match” in the rationale.
