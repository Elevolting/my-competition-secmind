# Java JPA and ORM Query Injection Review

## Strategy Intent
Determine whether untrusted data changes the structure of JPQL, HQL, criteria fragments, or native SQL executed through JPA/ORM APIs.

## Apply This Strategy When
- The target is CWE-89 and the unit uses `EntityManager`, repository query APIs, ORM query objects, or native-query construction.

## Do Not Use It To
- Treat ordinary repository method parameters or named query parameters as injection.
- Assume an ORM automatically protects dynamically constructed query text.
- Confuse authorization/filtering defects with SQL injection unless query structure is affected.

## Analysis Procedure
1. Locate the query creation/execution chain and distinguish JPQL/HQL from native SQL.
2. Identify which expression becomes query text and which values are passed through `setParameter`, named parameters, positional parameters, or typed criteria values.
3. Trace candidate input through controller/service/repository boundaries using only supplied evidence.
4. Analyze dynamic entity, property, order, projection, predicate, and fragment selection separately from ordinary values.
5. Evaluate allowlists, enum mappings, fixed switch branches, criteria builder APIs, and framework-generated repository methods.
6. Confirm the constructed query reaches execution and the candidate fragment is not overwritten.
7. Look for safe parameter binding or fixed query definitions that refute the candidate.

## Evidence Standard
`vulnerable` requires visible control of query grammar in executed JPQL/HQL/native SQL and an ineffective or absent structural allowlist. Provide CWE-89 and the numbered line where the unsafe query is created or executed, choosing the most semantically relevant sink line supported by the unit. Missing repository implementation or framework resolution yields `inconclusive`, not a guessed verdict.

## Counterevidence and False Positives
`setParameter`, derived repository methods, fixed `@Query` text with bound values, and typed criteria values are counterevidence. A user choosing among a closed server-defined sort/property mapping is not injection. A query returning excessive rows may be another weakness but is not CWE-89 by itself.

## Confidence and Stopping Rules
High confidence requires framework/API identification, source control, grammar influence, execution reachability, and absence of effective structural restriction. Cap confidence when generated repository behavior or an invoked query builder is not supplied.

## Output Discipline
Return only the typed unit verdicts. Preserve distinctions among vulnerable, not_vulnerable, and inconclusive and state framework uncertainty in limitations.
