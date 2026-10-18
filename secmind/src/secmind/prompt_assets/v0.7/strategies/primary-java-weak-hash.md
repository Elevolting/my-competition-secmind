# Java Weak Cryptographic Hash Review

## Strategy Intent
Determine whether a weak digest is used for a security property that depends on collision, preimage, password, signature, or integrity resistance.

## Apply This Strategy When
- CWE-328 is targeted and `MessageDigest`, password hashing, signature preparation, or related digest use is visible.

## Do Not Use It To
- Report MD5/SHA-1 used only as non-adversarial cache keys, deduplication hints, ETags, or file-change identifiers without a security claim.
- Treat encoding, CRC, or generic checksums as cryptographic password storage without evidence.
- Ignore salting, work factor, keyed MAC construction, or actual verification context.

## Analysis Procedure
1. Resolve the effective digest algorithm and reachable call path.
2. Determine the protected property and attacker model: password storage, integrity/authenticity, signature/certificate use, token generation, or non-security identification.
3. Trace how the digest is stored, compared, signed, or trusted.
4. For passwords, inspect salt, adaptive work factor, and password-specific KDF use; a fast digest remains unsuitable even if salted.
5. Distinguish a keyed MAC from a bare digest and inspect the actual primitive when visible.
6. Check production versus test/migration/compatibility branches.
7. Seek evidence that the digest is non-security metadata or that a secure active algorithm is selected.

## Evidence Standard
`vulnerable` requires an observed weak/unsuitable digest in a reachable security-relevant use. Cite CWE-328 and the numbered algorithm/use line. Use `inconclusive` if purpose or active configuration cannot be established.

## Counterevidence and False Positives
Algorithm occurrence alone is insufficient. A checksum used only to detect accidental corruption may have different requirements; state that distinction. A secure password KDF calling an internal digest is not equivalent to direct fast-hash password storage.

## Confidence and Stopping Rules
High confidence requires algorithm, security purpose, and active use. Keep impact proportional to the property actually evidenced.

## Output Discipline
Choose explicitly among `vulnerable`, `not_vulnerable`, and `inconclusive`; do not output password values, digests, or sensitive test material.
