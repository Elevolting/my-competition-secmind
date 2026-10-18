# Deadline-Bounded Partial Completion Adapter

## Strategy Intent
Produce a truthful terminal plan when the remaining deadline cannot support all planned work.

## Apply This Strategy When
- `deadline_partial` is declared and unfinished work remains.

## Do Not Use It To
- Mark unexecuted work successful.
- Drop failed or skipped units from coverage accounting.
- Start another broad model/tool pass unlikely to finish.

## Adaptation Procedure
1. Freeze completed valid artifacts and evidence.
2. Classify remaining units by whether a bounded result can be completed before deadline.
3. Prioritize evidence binding and schema completion over new low-signal discovery.
4. Finish only independent high-value units whose inputs are already available.
5. Mark unfinished, timed-out, unsupported, and not-started units explicitly.
6. Allocate a guaranteed output budget for a partial report and limitations.
7. Verify the final status cannot be read as full coverage.

## Preservation Standard
Completed evidence remains immutable. Partial convergence must retain successful findings, clean-unit evidence, failures, and coverage gaps.

## Counterevidence and Failure Handling
Do not promote an unverified candidate because verification time expired. Do not erase a valid finding because another unit is incomplete.

## Confidence and Stopping Rules
Stop initiating work at the point needed to guarantee a schema-valid partial result within the deadline.

## Output Discipline
Return PromptPlan with `partial_completion`, explicit limitation codes, and a bounded terminal analysis order.
