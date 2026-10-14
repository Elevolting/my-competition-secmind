# Java Cookie Secure Transport Review

## Strategy Intent
Determine whether a security-sensitive cookie can be transmitted over an insecure channel because the Secure attribute is absent or conditionally disabled.

## Apply This Strategy When
- CWE-614 is targeted and servlet/Spring cookie creation or response-cookie configuration is visible.

## Do Not Use It To
- Report every cookie without first establishing sensitivity and transport conditions.
- Substitute HttpOnly or SameSite analysis for the Secure transport property.
- Assume TLS termination or deployment behavior that is not supplied.

## Analysis Procedure
1. Identify the cookie, its purpose, value sensitivity, creation path, and response path.
2. Resolve every configuration source and branch that controls the Secure attribute.
3. Determine whether the application can issue or accept the cookie over HTTP under the visible deployment/profile logic.
4. Inspect framework defaults and global cookie configuration only when supplied.
5. Check whether a reverse proxy/TLS setting changes request security detection in a way evidenced by code/config.
6. Distinguish production, development, test, local-only, and profile-specific branches.
7. Seek a guaranteed Secure setting on every relevant production path before assigning a positive verdict.

## Evidence Standard
Return `vulnerable` only when a sensitive cookie is reachable in a deployment-relevant path and Secure is absent/false such that insecure transport is possible. Cite CWE-614 and the numbered cookie configuration/addition line. If sensitivity or deployment transport is unknown, use `inconclusive`.

## Counterevidence and False Positives
An explicit unconditional Secure setting is counterevidence. A non-sensitive preference cookie may be outside CWE-614. Development-only HTTP configuration is not automatically a production finding. HttpOnly/SameSite do not compensate for missing Secure, but their absence is a different concern.

## Confidence and Stopping Rules
High confidence requires cookie sensitivity, active configuration, and transport possibility. Cap confidence when deployment profiles or global framework settings are missing.

## Output Discipline
Choose explicitly among `vulnerable`, `not_vulnerable`, and `inconclusive`, and name the decisive configuration without exposing cookie values.
