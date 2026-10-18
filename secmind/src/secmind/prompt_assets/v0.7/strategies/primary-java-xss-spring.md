# Spring MVC Output Encoding and XSS Review

## Strategy Intent
Determine whether untrusted model, response-body, or template data becomes executable browser content under the actual Spring MVC rendering path.

## Apply This Strategy When
- CWE-79 is targeted and Spring controllers, model attributes, views, response bodies, or template support are visible.

## Do Not Use It To
- Assume all templates auto-escape or all `@ResponseBody` values execute as HTML.
- Treat model population as a sink without identifying how the view renders it.
- Ignore explicit raw/unescaped template operations in supplied support files.

## Analysis Procedure
1. Identify request/stored source, controller mapping, model/return value, view resolution, and final rendering context.
2. Distinguish view names, redirects, JSON serialization, direct HTML strings, and template variables.
3. Inspect the relevant template expression or rendering API for default escaping, raw output, URL building, script embedding, or attribute context.
4. Trace any transformation or validation and check whether concatenation occurs after encoding.
5. Determine content type and actual browser interpretation.
6. Check reachable branches and framework configuration that changes escaping only when supplied.
7. Seek counterevidence such as safe template operators, JSON content type, fixed values, or closed mappings.

## Evidence Standard
Return `vulnerable` only with an attacker-controlled value, a reachable Spring rendering path, a browser-executable context, and ineffective encoding. Cite CWE-79 and the exact source line that performs unsafe rendering or returns unsafe HTML. If the required template/configuration is not supplied, use `inconclusive`.

## Counterevidence and False Positives
Default escaping may be effective for HTML text but not every context. JSON serialization with correct media type is not XSS by itself. Redirect problems belong to redirect analysis unless response content executes. A model attribute that is never rendered is not a sink.

## Confidence and Stopping Rules
High confidence needs controller-to-template continuity and exact output context. Do not substitute general Spring knowledge for missing project evidence.

## Output Discipline
Return one `vulnerable`, `not_vulnerable`, or `inconclusive` verdict per unit, preserve limitations, and avoid copying template/user content into the rationale.
