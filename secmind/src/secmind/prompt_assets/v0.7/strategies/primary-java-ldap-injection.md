# Java LDAP Filter Injection Review

## Strategy Intent
Determine whether attacker-controlled data can alter LDAP filter or distinguished-name structure at a reachable directory query or modification sink.

## Apply This Strategy When
- CWE-90 is targeted and LDAP/JNDI/directory filter construction or lookup is visible.

## Do Not Use It To
- Treat every LDAP query parameter as filter syntax.
- Confuse JNDI remote lookup risks, authorization flaws, or broad search scope with LDAP injection.
- Assume generic URL, HTML, or SQL escaping protects LDAP filter/DN contexts.

## Analysis Procedure
1. Identify the directory operation and whether the candidate controls a search filter, DN, attribute name, search base, or ordinary value.
2. Trace the exact argument backward to a visible lower-trust source.
3. Determine the syntax context: LDAP filter assertion value, filter grammar, or DN component.
4. Evaluate context-appropriate escaping, safe filter builders, typed mappings, allowlists, and post-escape concatenation.
5. Check whether attacker data can introduce operators, wildcards, additional clauses, or DN structure.
6. Confirm the query/modification is reachable and uses the candidate expression.
7. Seek fixed filters, closed mappings, safe APIs, or non-attacker-controlled values that refute the candidate.

## Evidence Standard
`vulnerable` requires proof that attacker-controlled data reaches LDAP structural syntax without correct context-specific protection at a reachable sink. Cite CWE-90 and the numbered operation/filter construction line. If the escaping helper is opaque or source provenance missing, return `inconclusive`.

## Counterevidence and False Positives
Correct LDAP filter-value escaping is different from DN escaping; use the one required by the context. Parameter-like APIs may be safe only if they actually encode structure. A wildcard intentionally selected from a closed server mapping is not attacker grammar control.

## Confidence and Stopping Rules
High confidence requires source, syntax context, transformation, sink, and reachability. Avoid high confidence from a scanner label without reviewing actual string placement.

## Output Discipline
Choose explicitly among `vulnerable`, `not_vulnerable`, and `inconclusive`, and avoid including executable filter payloads.
