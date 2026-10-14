# Java Hard-Coded Cryptographic Material Review

## Strategy Intent
Determine whether production code embeds secret cryptographic keys, private material, fixed sensitive seeds, or equivalent material that should be externally protected and rotatable.

## Apply This Strategy When
- CWE-321 is targeted and key/secret bytes, strings, private-key material, or deterministic key derivation from constants is visible.

## Do Not Use It To
- Report public keys, certificates, algorithm identifiers, non-secret salts, test vectors, or placeholders as secret keys.
- Reproduce the complete material in the rationale.
- Assume every constant passed to a crypto API is a key without checking its argument role.

## Analysis Procedure
1. Identify the cryptographic API and the exact argument representing key/private material.
2. Trace that value to a literal, static initializer, resource, configuration, environment, keystore, or derived constant.
3. Establish whether the material is secret/private and used in a reachable production security path.
4. Distinguish public verification material, IVs/nonces, salts, labels, aliases, and test vectors.
5. Check profile/test/example boundaries and whether the constant is overridden before use.
6. Evaluate whether deterministic derivation from a public constant is equivalent to embedding the key.
7. Seek evidence of external secret management, runtime injection, or public-by-design semantics.

## Evidence Standard
Return `vulnerable` only when visible constant material functions as a secret/private cryptographic key in reachable production use. Cite CWE-321 and the numbered key-construction/use line, never the secret value. If material role or deployment profile is uncertain, return `inconclusive`.

## Counterevidence and False Positives
Public keys and certificates are often intentionally embedded. Salts generally need uniqueness, not secrecy. Test fixtures and examples must be labeled but not promoted without production reachability. Environment-variable names are not embedded values.

## Confidence and Stopping Rules
High confidence requires secret semantics, constant provenance, and active use. Preserve redaction regardless of verdict.

## Output Discipline
Choose explicitly among `vulnerable`, `not_vulnerable`, and `inconclusive`, with a masked, non-recoverable description only; do not quote key bytes, tokens, or fingerprints that expose the material.
