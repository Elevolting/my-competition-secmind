# Java Servlet Reflected or Stored XSS Review

## Strategy Intent
Determine whether attacker-controlled text reaches an HTTP response or rendered output in an executable browser context without context-appropriate encoding.

## Apply This Strategy When
- CWE-79 is targeted and servlet request/response APIs or direct response writers are visible.

## Do Not Use It To
- Treat every response write as XSS.
- Assume generic HTML escaping is correct for JavaScript, CSS, URL, attribute, or raw-text contexts.
- Report JSON or plain-text output as browser-executable without content-type/consumer evidence.

## Analysis Procedure
1. Identify the external source and whether it is reflected immediately or retrieved from stored lower-trust data.
2. Trace transformations to the exact response/rendering sink and sink line.
3. Establish output context: HTML text, attribute, URL, JavaScript, CSS, template, header, JSON, or plain text.
4. Evaluate encoder type and placement against that exact context, including double-decoding or post-encoding concatenation.
5. Inspect content type, framework/template behavior, CSP only as defense-in-depth, and whether the branch is reachable.
6. Distinguish server-side redirect/header injection and template injection from CWE-79 when semantics differ.
7. Seek evidence that the value is encoded, constrained to a safe closed set, or never included in browser-rendered output.

## Evidence Standard
`vulnerable` requires a visible attacker-controlled source, reachable browser-relevant sink, executable output context, and absent/ineffective context-specific encoding. Cite CWE-79 and the numbered response/render line. Missing template or content context yields `inconclusive`.

## Counterevidence and False Positives
Correct context-specific encoding, fixed allowlists, safe text APIs, and non-browser media types can refute XSS. Input validation alone is not automatically sufficient, but a closed safe character/value set may be. CSP does not repair unsafe output and should not be the sole reason for `not_vulnerable`.

## Confidence and Stopping Rules
High confidence requires source, context, sink, and encoder semantics. Cap confidence when the template, response type, or stored-data provenance is absent.

## Output Discipline
Return typed verdicts only; do not include executable payload examples or reproduce sensitive response data.
