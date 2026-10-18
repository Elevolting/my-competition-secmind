# Multi-Module Repository Audit Planning

## Strategy Intent
Plan a repository with several related modules while preserving inter-module dependency and trust-boundary evidence.

## Apply This Strategy When
- The trusted shape is multi-module but not a broad monorepo.
- Modules share libraries, configuration, protocols, or deployment boundaries.

## Do Not Use It To
- Treat modules as independent when data or authorization crosses their boundary.
- Scan shared source repeatedly for every consumer.
- Assume a parent manifest fully describes child-module versions or configuration.

## Analysis Procedure
1. Map modules, manifests, source roots, produced artifacts, shared packages, and dependency directions.
2. Identify externally reachable modules and shared security-critical code.
3. Schedule shared inventory, secret, and dependency work once, with module-attributed outputs.
4. Fan out compatible module-local scans while respecting shared concurrency limits.
5. Create cross-module review units for authentication, serialization, configuration inheritance, data validation, and sensitive calls that cross boundaries.
6. Reduce findings using module-qualified fingerprints so shared flaws are not overcounted.
7. Verify per-module coverage and dependency-edge coverage before reporting.

## Evidence Standard
Cross-module findings require evidence from both sides of the boundary or an explicit missing-context limitation. A shared-library finding must identify affected call sites before claiming application impact.

## Counterevidence and Failure Handling
Account for module-specific profiles, dependency injection overrides, test modules, generated clients, and unused shared code. One failed module should yield partial coverage without erasing others.

## Confidence and Stopping Rules
Stop when every module and relevant dependency edge has an analysis disposition and duplicate shared evidence is reconciled.

## Output Discipline
Return PlanOutput with shared prerequisites, module fan-out, cross-boundary checks, deterministic fan-in, and evidence-addressable success criteria.
