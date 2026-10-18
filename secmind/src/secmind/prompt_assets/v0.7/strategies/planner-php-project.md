# PHP Project Audit Planning

## Strategy Intent
Plan a PHP audit that accounts for framework routing, dynamic includes, templates, dependency manifests, and trust boundaries common to web applications.

## Apply This Strategy When
- PHP is the sole supported language in one bounded project.
- Source, Composer metadata, routes, templates, configuration, or public entry points are present.

## Do Not Use It To
- Assume a framework or deployment profile not evidenced by files.
- Equate dynamic language features with exploitability.
- Require a running web server when only static capabilities are available.

## Analysis Procedure
1. Inventory public entry points, routes/controllers, middleware, templates, models, configuration, uploads, CLI commands, tests, and Composer files.
2. Separate first-party source from vendor, cache, generated, and fixture content.
3. Schedule compatible secret, dependency, and SAST capabilities over explicit scopes.
4. Prioritize semantic review for SQL/query construction, command execution, includes/file paths, upload handling, deserialization, template/output contexts, SSRF, redirects, session/auth logic, and unsafe configuration.
5. Include framework route/middleware evidence only when identified.
6. Deduplicate rule matches and verify source-to-sink reachability before promotion.
7. Report unscanned dynamic behavior and unavailable runtime context.

## Evidence Standard
Findings need path/line provenance and the relevant input-to-sensitive-operation path. Dependency findings need an observed Composer version source and advisory identity.

## Counterevidence and Failure Handling
Account for prepared statements, framework escaping, validation, allowlists, safe upload renaming/storage, disabled code paths, and dev-only configuration. Dynamic resolution that cannot be reconstructed is inconclusive.

## Confidence and Stopping Rules
Stop when entry points, framework boundaries, templates, dependencies, and file-handling surfaces have explicit coverage or limitations.

## Output Discipline
Use a bounded PlanOutput with artifact-backed success criteria and never add runtime exploitation steps to a static code-audit plan.
