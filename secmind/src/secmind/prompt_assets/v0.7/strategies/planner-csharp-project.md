# C# and .NET Project Audit Planning

## Strategy Intent
Plan a C#/.NET audit around projects, target frameworks, configuration, ASP.NET boundaries, dependency evidence, and source-level security behavior.

## Apply This Strategy When
- C# is the sole supported language in a single project.
- Project/solution files, NuGet lock/assets data, source, controllers, or configuration are present.

## Do Not Use It To
- Assume ASP.NET, Entity Framework, Windows-only behavior, or a target framework without evidence.
- Require package restore or build when unavailable.
- Treat attributes or middleware names as proof that controls execute in the correct order.

## Analysis Procedure
1. Identify solutions/projects, target frameworks, applications, libraries, generated code, configuration variants, tests, and dependency sources.
2. Schedule compatible inventory, secret, dependency, and SAST work with explicit first-party scopes.
3. Prioritize review of controllers/endpoints, model binding, authorization, SQL/ORM use, process execution, file paths/uploads, serialization, redirects, SSRF, cryptography, and logging of sensitive data.
4. Preserve middleware order, filters, dependency injection bindings, and configuration profile evidence needed for semantics.
5. Distinguish framework-managed parameterization/encoding from raw APIs.
6. Verify findings against exact source locations and observed target/configuration context.
7. Record unresolved package versions, conditional compilation, and unsupported projects.

## Evidence Standard
Each promoted finding needs a concrete endpoint or call path, the sensitive operation/configuration, and evidence that a relevant control is absent or ineffective.

## Counterevidence and Failure Handling
Account for policy/attribute enforcement, parameterized APIs, Razor encoding, path-root checks, secure serializers, and environment-specific configuration. Unknown deployment profiles cap confidence.

## Confidence and Stopping Rules
Stop when every in-scope project has a coverage disposition and all cross-project support context is bounded.

## Output Discipline
Return only supplied capability identifiers and make target-framework uncertainty a limitation rather than an invented plan fact. Give every step an observable success criteria tied to an artifact, coverage fact, or evidence check.
