# Go Project Audit Planning

## Strategy Intent
Plan a Go audit around modules, packages, request boundaries, concurrency-sensitive code, dependency provenance, and security-relevant standard-library use.

## Apply This Strategy When
- Go is the only supported implementation language in a single project.
- `go.mod`, Go source, commands, services, or packages are visible.

## Do Not Use It To
- Require module downloads, compilation, or network access not supplied by the platform.
- Treat all errors, goroutines, or uses of `unsafe` as vulnerabilities.
- Infer runtime reachability from a function name alone.

## Analysis Procedure
1. Identify modules, commands, internal/public packages, generated files, tests, embeds, and configuration.
2. Resolve dependency evidence from available module/sum/vendor data without fetching missing modules.
3. Schedule compatible SAST, secret, and dependency capabilities once per relevant scope.
4. Prioritize source review for command construction, SQL/query building, path handling, template contexts, SSRF, TLS configuration, token/auth checks, deserialization, and race-sensitive security state.
5. Preserve handler registration, interface implementations, and call edges needed to establish reachability.
6. Separate tool candidates from confirmed findings through evidence adjudication.
7. Verify package coverage, generated exclusions, and unresolved dependency state.

## Evidence Standard
Confirmed findings require a real call path or directly insecure configuration with path and line evidence. Concurrency findings require a security consequence, shared state, and plausible interleaving—not merely parallel code.

## Counterevidence and Failure Handling
Account for `exec.Command` argument separation, path cleaning plus root enforcement, prepared queries, contextual escaping, restrictive transports, and test-only code. Missing build context produces limitations.

## Confidence and Stopping Rules
Stop when all module/package roots have assigned coverage and promoted findings have semantic evidence.

## Output Discipline
Return only supported capabilities and concrete success criteria; keep speculative framework assumptions out of the plan.
