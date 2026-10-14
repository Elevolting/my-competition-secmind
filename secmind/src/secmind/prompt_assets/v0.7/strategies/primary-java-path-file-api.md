# Java File API Path Traversal Review

## Strategy Intent
Determine whether attacker-controlled path material can escape an intended root or select an unauthorized file operation through Java file/path APIs.

## Apply This Strategy When
- CWE-22 is targeted and file read, write, delete, list, copy, move, or path resolution is visible.

## Do Not Use It To
- Report every `File`, `Path`, or `resolve` call as traversal.
- Treat normalization alone as proof of containment.
- Ignore operation type, root policy, symlinks, absolute paths, decoding, or platform path rules.

## Analysis Procedure
1. Identify the sensitive file operation and the exact path argument used at its sink line.
2. Trace attacker-controlled segments, base roots, defaults, and any path rewriting.
3. Determine handling of absolute paths, drive/UNC forms, separators, dot segments, percent/double decoding, and null/control characters when relevant to visible code.
4. Evaluate canonicalization/normalization and verify a post-resolution containment check against the intended root.
5. Review symlink behavior and TOCTOU exposure only when the operation and checks make them relevant.
6. Confirm the resolved value reaches the operation on a reachable path.
7. Seek counterevidence: server-owned filename mapping, basename-only policy, secure directory APIs, or canonical root enforcement after resolution.

## Evidence Standard
`vulnerable` requires attacker influence over the effective filesystem target and a reachable operation outside the intended authorization boundary. Cite CWE-22 and the numbered operation/path-resolution sink. If the intended root or helper containment logic is missing, return `inconclusive` rather than assuming failure.

## Counterevidence and False Positives
`normalize()` without root containment is insufficient, but a verified normalized/canonical path under a fixed root can be effective. Rejecting absolute paths alone does not stop dot traversal. A path used only for display or a server-generated immutable filename is not traversal.

## Confidence and Stopping Rules
High confidence requires source, effective target construction, intended root, control evaluation, and reachable operation. Cap confidence for opaque filesystem helpers or unknown symlink policy.

## Output Discipline
Choose explicitly among `vulnerable`, `not_vulnerable`, and `inconclusive`, and keep the rationale centered on effective target containment, not example attack strings.
