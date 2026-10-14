# Monorepo Security Audit Planning

## Strategy Intent
Plan a representative, budgeted audit of a monorepo while preserving module ownership, shared components, and coverage truth.

## Apply This Strategy When
- The trusted repository shape is monorepo.
- Multiple top-level products, services, packages, or build roots are present.

## Do Not Use It To
- Create one step per file or one giant step for the entire repository.
- Spend the whole budget on the first module discovered.
- Infer that equivalent folder names imply equivalent security posture.

## Analysis Procedure
1. Build a module map using manifests, source roots, deployment units, ownership boundaries, and shared libraries.
2. Rank modules using exposed entry points, sensitive operations, dependency centrality, change relevance when supplied, and availability of compatible analyzers.
3. Allocate a minimum coverage floor to every in-scope module, then assign remaining budget to higher-risk modules and shared security-critical packages.
4. Execute repository-wide inventory/secret/dependency collection once and reuse its artifacts.
5. Fan out module-local scans with explicit concurrency keys and bounded retries.
6. Review shared authentication, serialization, configuration, and utility modules before interpreting dependent-module findings.
7. Reduce results by stable fingerprint and report coverage per module, including skipped and unsupported areas.

## Evidence Standard
Every step declares a module scope. Sampling is valid only when the selection rule and excluded modules are recorded. A repository-level conclusion requires coverage evidence from all in-scope modules or an explicit partial status.

## Counterevidence and Failure Handling
A clean high-risk module does not prove the monorepo is clean. A failed module scan must not invalidate successful independent results. Shared generated/vendor directories should be identified rather than silently dominating findings.

## Confidence and Stopping Rules
Stop when the budget allocation is explicit, no module is silently omitted, shared dependencies are covered, and reduction can distinguish duplicates from independent flaws.

## Output Discipline
Return a bounded PlanOutput with module fan-out, deterministic fan-in, and per-module success criteria. Keep priorities in the rationale summary, not as invented risk facts.
