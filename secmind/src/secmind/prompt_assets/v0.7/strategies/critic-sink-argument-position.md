# Sink Argument Position Adjudication

## Strategy Intent
Resolve whether the candidate value reaches the security-relevant argument or configuration field of the cited sink.

## Apply This Strategy When
- The declared gap is an unknown sink argument.
- A candidate call/configuration and its local value flow are supplied.

## Do Not Use It To
- Treat the presence of a dangerous API as proof that its dangerous argument is controlled.
- Reclassify unrelated arguments as sinks because they share a variable.
- Guess overload signatures or named-parameter semantics not evidenced by code.

## Analysis Procedure
1. Identify the exact API/method overload or configuration assignment visible at the candidate sink.
2. Map actual arguments to formal semantic roles by position, name, builder mutation, or documented type evidence present in the unit.
3. Trace the candidate value into the final call state, accounting for later overwrite or list/builder mutation.
4. Distinguish structural arguments from ordinary bound/data arguments.
5. Verify the candidate reaches the invoked operation rather than logging, validation, or a never-executed builder.
6. Search for argument separation, safe binding, fixed replacement, or an alternate overload that refutes the candidate.

## Evidence Standard
Keep or upgrade to `vulnerable` only when the value reaches the argument that creates the target weakness and the rest of the flow evidence is complete. Return `not_vulnerable` when it reaches only a safe/non-sensitive argument. Use `inconclusive` for unresolved overloads or opaque wrappers.

## Counterevidence and False Positives
A user value bound to a prepared-query parameter is not SQL text. A process operand is not automatically a command string. A URL path on a fixed allowed origin is not the same as host control. Evaluate the exact API semantics.

## Confidence and Stopping Rules
Stop after the final sink call state is resolved. High confidence requires unambiguous argument semantics and value identity.

## Output Discipline
Return one typed critic verdict and cite the decisive argument role in the rationale without repeating source code.
