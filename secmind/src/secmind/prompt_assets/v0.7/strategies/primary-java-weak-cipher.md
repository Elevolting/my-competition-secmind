# Java Weak Cipher Review

## Strategy Intent
Determine whether code configures or uses a cryptographic cipher/mode that is unsuitable for the security property it protects.

## Apply This Strategy When
- CWE-327 is targeted and Java cryptographic transformation or cipher configuration is visible.

## Do Not Use It To
- Require attacker-controlled input; cryptographic primitive findings may be configuration-based.
- Report algorithm names found only in tests, compatibility metadata, comments, or non-security checks.
- Assume every use of a legacy algorithm has the same impact without examining purpose and mode.

## Analysis Procedure
1. Locate the actual `Cipher`/provider transformation and the code path that initializes and uses it.
2. Resolve constants, configuration, aliases, and conditional selections to the effective algorithm/mode/padding where possible.
3. Establish the security use: confidentiality, authenticated encryption, key wrapping, storage, transport, or non-security interoperability.
4. Check whether an insecure mode/primitive is active, including deterministic/unauthenticated encryption where integrity is required.
5. Inspect IV/nonce handling, authentication tag use, key handling, and fallback branches only as they affect the cited cipher weakness.
6. Distinguish decryption of fixed legacy test data or migration-only code from active protection of sensitive data.
7. Seek a secure active branch or evidence the candidate is unreachable/non-security use.

## Evidence Standard
Return `vulnerable` when the supplied code proves an unsuitable cipher transformation is actively used for a security purpose. Cite CWE-327 and the numbered initialization/use line. If the effective transformation or purpose is externally configured and absent, return `inconclusive`.

## Counterevidence and False Positives
An algorithm string in a constant is not enough without use. AES is not automatically safe: mode, padding, nonce, and authentication matter. Conversely, a legacy name used solely for file-format detection, checksum comparison, or test vectors may not be a cipher weakness in production.

## Confidence and Stopping Rules
High confidence requires effective configuration, reachable use, and security purpose. Do not infer key strength or provider behavior not present in evidence.

## Output Discipline
Return one `vulnerable`, `not_vulnerable`, or `inconclusive` verdict per unit and keep recommendations or migration design outside the rationale.
