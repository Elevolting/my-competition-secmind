# Task
You will receive a context bundle containing Origin, Goal, and Hints. You need to understand your starting point and the information already available (Origin and Hints), then become an expert in this domain.
But note that you are not continuing the task here. You do not need to wait for unfinished tasks or commands. You only need to summarize the key facts that have already been confirmed so far and are most helpful for reaching Goal.
This is the conclude phase. It overrides any earlier instruction in the same session that told you to keep working, continue exploring, solve Goal, wait for command results, or perform more actions.

## Output Requirements
Return only one raw JSON object. Do not output anything else. The JSON must be valid, including proper escaping of quotation marks.

If no confirmed fact can be reported within the authorized scope, return:
```json
{"accepted": false, "reason": "policy_refusal"}
```

Normal return example:
```json
{"accepted": true, "data": {"fact": {"description": "..."}}}
```

## Rules
- Stop immediately and produce the JSON now. Do not continue the task.
- Do not run any more commands, make any more tool calls, inspect anything else, wait for any unfinished command, or try to obtain any additional information.
- Base your answer only on information that has already been confirmed before this conclude prompt. If something has not already been confirmed, do not wait for it and do not include it.
- This JSON summary is your final output for this phase. After outputting it, stop.
- Do not output `complete` in this phase. Even if Goal is not achieved or you want to explain status, put that information into `fact.description` only.
- `fact.description` must be an already confirmed objective factual conclusion. Do not output plans, guesses, or explanatory filler.
- Do not put long data blobs in `fact.description`. Long data should be placed in a file and referenced from `description` instead.

# Context
## Origin
```
{origin}
```

## Goal
```
{goal}
```

## Hints
```
{hints}
```


# Structured result bundles
Where the protocol requests a fact description, it also accepts optional `title` and `items` alongside `description`. Keep `title` short and readable; keep raw logs and JSON in referenced attachments. Each item has a stable local `id`, `type` (fact, observation, finding, artifact), `title`, `summary`, and `evidence_ids` from actual tool receipts. Finding items may include `finding_id` and `verification_status` (candidate, pending, insufficient). Never invent evidence IDs or claim confirmed/ruled_out from tool success or your own assertion. Without recorded evidence, describe the item as a Worker report. Preserve the enclosing accepted/data or fact object required above. Produce one result bundle per exploration.
