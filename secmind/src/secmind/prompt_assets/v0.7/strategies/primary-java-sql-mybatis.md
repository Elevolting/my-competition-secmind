# Java MyBatis SQL Injection Review

## Strategy Intent
Distinguish safe MyBatis value binding from unsafe textual substitution and dynamic SQL fragments, then determine whether attacker-controlled data reaches executable SQL grammar.

## Apply This Strategy When
- CWE-89 is targeted and Java/MyBatis mapper calls, annotations, or bounded mapper support are visible.

## Do Not Use It To
- Treat every `${...}` as automatically exploitable without checking provenance and allowlists.
- Treat `#{...}` value binding as textual SQL substitution.
- Invent missing XML mapper content or provider-method behavior.

## Analysis Procedure
1. Identify the mapper method and visible SQL source: annotation, XML support, provider, or dynamic builder.
2. Distinguish `#{}` parameter binding from `${}` text substitution and from server-generated fixed fragments.
3. Trace the substituted or concatenated value through request/service/mapper parameters and aliases.
4. Determine whether it controls identifiers, sort/order clauses, table names, operators, or arbitrary fragments.
5. Evaluate closed mappings, enums, switch statements, validators, and dynamic tags such as `if`, `choose`, `foreach`, and `bind` using the actual supplied logic.
6. Confirm the mapper is invoked on a reachable path and the unsafe fragment reaches execution.
7. Search for counterevidence in support mapper files before assigning a positive verdict.

## Evidence Standard
Return `vulnerable` only when visible evidence connects an attacker-controllable value to SQL text substitution or equivalent grammar construction without an effective closed mapping. Use CWE-89 and the exact sink/substitution line. If mapper SQL is missing and essential, return `inconclusive` with that limitation.

## Counterevidence and False Positives
`#{}` placeholders, fixed XML fragments, closed enum-to-column maps, and server-selected `<choose>` branches are strong counterevidence. `${}` applied only to a constant chosen internally is not attacker-controlled. `foreach` value binding is not inherently injection.

## Confidence and Stopping Rules
High confidence requires both Java call-site provenance and mapper SQL semantics. Do not elevate confidence based on a rule name alone. Stop after the supplied mapper chain and its relevant counterevidence are resolved.

## Output Discipline
Emit one concise `vulnerable`, `not_vulnerable`, or `inconclusive` verdict per unit. Do not include SQL payloads, remediation prose, or unsupported mapper assumptions.
