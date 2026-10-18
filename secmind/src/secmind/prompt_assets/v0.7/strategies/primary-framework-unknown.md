# Framework-Unknown Conservative Source Review

## Strategy Intent
Produce a useful verdict from language-level semantics when framework identity or behavior is unknown, without importing unverified defaults.

## Apply This Strategy When
- Trusted context marks the framework as unknown.
- The supplied code still exposes a candidate source, sink, primitive, or configuration.

## Do Not Use It To
- Guess auto-escaping, parameterization, routing, authentication, binding, or serialization defaults.
- Treat unknown framework behavior as evidence of vulnerability.
- Expand beyond the immutable unit to compensate for missing context.

## Analysis Procedure
1. Separate language/API facts visible in source from framework-dependent assumptions.
2. Identify the target CWE's minimum evidence that can be established without framework semantics.
3. Trace local assignments, branches, constants, transformations, and direct API calls.
4. Record every decisive unknown, such as route reachability, template escaping, query binding, middleware order, or deserializer configuration.
5. Seek language-level counterevidence that remains valid regardless of framework, such as fixed constants or explicit safe API use.
6. Assign `vulnerable` only if the weakness is proven without the missing framework fact.
7. Otherwise choose `not_vulnerable` only with positive safe evidence, or `inconclusive` when the unknown can change the verdict.

## Evidence Standard
Every conclusion must cite visible source semantics. High confidence is permitted only when framework behavior is irrelevant to the decisive evidence. Do not use general framework memory as project evidence.

## Counterevidence and False Positives
Missing a known control is not proof that the control is absent. Conversely, a visible direct unsafe primitive may remain vulnerable regardless of framework. Preserve this distinction in the rationale.

## Confidence and Stopping Rules
Stop once all locally decidable facts and decisive framework unknowns are identified. Do not fill gaps with speculation.

## Output Discipline
Return typed verdicts with explicit limitations and a concise reason for why framework uncertainty does or does not affect the result.
