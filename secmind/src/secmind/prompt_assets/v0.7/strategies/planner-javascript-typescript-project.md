# JavaScript and TypeScript Project Audit Planning

## Strategy Intent
Plan a Node, browser, or full-stack JavaScript/TypeScript audit that separates runtime surfaces, dependency evidence, generated bundles, and source-level security semantics.

## Apply This Strategy When
- JavaScript, TypeScript, or both form a single project.
- Package manifests, lockfiles, source directories, routes, frontend code, or server handlers are present.

## Do Not Use It To
- Assume browser code can keep server secrets.
- Scan vendored dependencies or generated bundles as if they were first-party source unless specifically required.
- Treat framework escaping, schema validation, or middleware as effective without checking its placement.

## Analysis Procedure
1. Classify server, browser, shared, build, test, generated, and configuration surfaces.
2. Identify package-manager/lockfile truth and workspace boundaries.
3. Schedule repository inventory, secret scanning, dependency analysis, and compatible SAST without duplicating the same files.
4. Prioritize source review for injection, template/DOM sinks, unsafe deserialization, path handling, SSRF, authorization middleware, token handling, and prototype/object merge behavior when relevant.
5. Preserve route-to-handler and middleware order as support context for semantic review.
6. Deduplicate transpiled/source-map copies using stable source identity.
7. Verify coverage separately for server and browser surfaces.

## Evidence Standard
Each finding must identify its execution surface and source form. Dependency claims require an observed resolved version. Secret findings must be redacted while retaining type, location, fingerprint, and provenance.

## Counterevidence and Failure Handling
Account for auto-escaping templates, parameterized drivers, runtime validation, environment-only placeholders, dead build artifacts, and test fixtures. Absence of a lockfile makes versions unresolved rather than safe.

## Confidence and Stopping Rules
Stop when runtime surfaces, package scopes, generated exclusions, and unsupported areas are all explicit.

## Output Discipline
Return a DAG with shared inventory first, compatible capabilities in parallel, and evidence/coverage verification at fan-in. Every step needs success criteria that can be checked without interpreting prose.
