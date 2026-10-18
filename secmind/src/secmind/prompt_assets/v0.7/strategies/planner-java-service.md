# Java Service Audit Planning

## Strategy Intent
Plan a Java service audit that respects build layout, framework boundaries, and the difference between rule matches and exploitable source-to-sink behavior.

## Apply This Strategy When
- Java source and a dependency/build manifest are present.
- The project resembles a service, API, servlet application, or persistence-backed backend.
- Supplied capabilities can inspect Java code, dependencies, or normalized findings.

## Do Not Use It To
- Assume Maven, Gradle, Spring, servlet, JPA, JDBC, or MyBatis unless the inventory supports that conclusion.
- Require compilation or dependency download when the environment does not provide it.
- Turn every dangerous API occurrence into a confirmed finding.

## Analysis Procedure
1. Identify modules, source roots, generated sources, manifests, framework indicators, configuration, and test fixtures.
2. Partition work into dependency/configuration checks and source-semantic checks so one failure does not erase the other evidence.
3. Run deterministic Java-capable scanning before model review when available, preserving rule IDs and locations.
4. Create bounded review units around candidate sinks with only the support files needed for cross-method or cross-file continuity.
5. Prioritize externally reachable controllers, servlet handlers, deserialization boundaries, persistence queries, process execution, file paths, redirects, outbound clients, and security-relevant cryptography.
6. End with evidence adjudication that distinguishes confirmed, not vulnerable, inconclusive, unsupported, and unscanned surfaces.

## Evidence Standard
Every source-review step must preserve immutable path and location references. Injection findings require attacker control, a relevant sink argument, reachability, and ineffective protection. Configuration or primitive findings require proof that the insecure setting is active in a security-relevant path.

## Counterevidence and Failure Handling
Account for parameterized queries, framework escaping, allowlists, canonical path checks, type restrictions, unreachable branches, test-only code, and profile-specific configuration. Missing build dependencies reduce analysis depth; they do not prove vulnerability.

## Confidence and Stopping Rules
Use high confidence only when the relevant framework semantics and data path are visible. Stop when all planned units have typed results and uncovered modules are explicitly listed.

## Output Discipline
Return a DAG-shaped PlanOutput using only supplied capabilities. Keep steps small enough to retry independently, attach evidence-based success criteria, and make evidence validation a distinct terminal dependency.
