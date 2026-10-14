# Java Server-Side Template Injection Review

## Strategy Intent
Determine whether attacker-controlled text is interpreted as template source or expression language rather than safely supplied as template data.

## Apply This Strategy When
- CWE-1336 is targeted and template compilation, parsing, evaluation, or dynamic expression APIs are visible.

## Do Not Use It To
- Treat ordinary model variables in a fixed template as template injection.
- Collapse XSS and server-side template injection into one verdict.
- Assume every `${...}` or `{{...}}` literal belongs to a template engine.

## Analysis Procedure
1. Identify the template/expression engine and the API argument that is parsed or evaluated as code/template syntax.
2. Distinguish template name selection, template source construction, expression evaluation, and data-model population.
3. Trace attacker influence to the parsed source/expression, not merely to a value rendered by a fixed template.
4. Evaluate closed template-name maps, sandbox configuration, expression restrictions, and pre-parse validation only when visible.
5. Confirm reachability and whether the dangerous engine mode is enabled in the supplied configuration.
6. Assess impact conservatively from visible engine capabilities; do not assume arbitrary code execution without evidence.
7. Seek counterevidence showing fixed templates, data-only binding, or a non-evaluating rendering path.

## Evidence Standard
Return `vulnerable` only when attacker-controlled content reaches template/expression syntax interpretation at a reachable sink. Cite CWE-1336 and the numbered parse/evaluate line. If engine configuration or helper behavior determines whether expressions execute and is absent, use `inconclusive`.

## Counterevidence and False Positives
User data rendered through a fixed template may create XSS but is not server-side template injection. Choosing from a fixed template allowlist is not arbitrary source evaluation. Escaping output after evaluation does not prevent server-side expression execution, but input treated strictly as a data value can.

## Confidence and Stopping Rules
High confidence requires engine identity, attacker source, syntax position, evaluation sink, and reachable path. Keep impact confidence separate from presence confidence in the rationale.

## Output Discipline
Choose explicitly among `vulnerable`, `not_vulnerable`, and `inconclusive`; do not provide engine-specific exploitation expressions.
