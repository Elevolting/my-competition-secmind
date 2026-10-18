# Java JDBC SQL Injection Review

## Strategy Intent
Determine whether untrusted data can alter SQL structure at a JDBC execution sink. Judge the complete data path and the exact sink argument; a JDBC call or string concatenation alone is not sufficient.

## Apply This Strategy When
- The audit unit targets CWE-89 and contains JDBC-style query construction or execution.
- Numbered source and any bounded support files are sufficient to inspect assignments and calls.

## Do Not Use It To
- Report query text that is constant or fully parameterized as vulnerable.
- Treat values bound through `PreparedStatement` setters as SQL structure.
- Infer attacker control solely from a variable name such as `input`, `id`, or `request`.

## Analysis Procedure
1. Identify the exact execution sink and which argument carries SQL text: `Statement.execute*`, connection/native query creation, or an equivalent visible call.
2. Trace the SQL argument backward through local assignments, concatenation, formatting, builders, helper returns, and support methods.
3. Establish an external or lower-trust source from visible request, message, file, environment, database, or caller data; distinguish constants and trusted server-owned values.
4. Determine whether untrusted bytes reach SQL grammar positions or only bound value positions.
5. Inspect allowlists, parsers, enum conversion, numeric conversion, quoting, escaping, and branch constraints in their actual context.
6. Check reachability of the sink and whether the vulnerable construction is the value actually executed.
7. Seek a counterexample path that proves the query is constant, parameterized, unreachable, or test-only before finalizing.

## Evidence Standard
Return `vulnerable` only when the supplied code proves attacker-controllable data reaches the SQL-text argument and can influence query structure without an effective context-appropriate control. Cite CWE-89 and the exact numbered sink line. Use `not_vulnerable` when the candidate path is demonstrably safe. Use `inconclusive` when a required source, helper, branch, or framework behavior is absent.

## Counterevidence and False Positives
Prepared statements remain safe when placeholders represent values and all untrusted values are bound. Concatenating only fixed fragments is not injection. Numeric parsing can prevent SQL grammar injection for that value. Generic escaping is not automatically safe, but do not reject it without examining database/context semantics. Test fixtures and logging of SQL are not execution sinks.

## Confidence and Stopping Rules
High confidence requires visible source, complete propagation, exact sink argument, reachability, and control evaluation. Lower confidence or inconclusive is required for opaque helpers, dynamic dispatch, missing callers, or unresolved native-query semantics. Review every supplied unit exactly once.

## Output Discipline
Return one schema-valid verdict per unit. Keep the rationale to evidence and counterevidence; do not provide exploit payloads or repeat source text.
