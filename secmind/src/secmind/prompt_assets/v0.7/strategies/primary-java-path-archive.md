# Java Archive Extraction Path Review

## Strategy Intent
Determine whether attacker-controlled archive entry names or link metadata can cause extraction outside the intended destination, overwrite protected files, or create ambiguous duplicate targets.

## Apply This Strategy When
- CWE-22 is targeted and ZIP/TAR/JAR or equivalent entry iteration and extraction is visible.

## Do Not Use It To
- Report archive parsing without a filesystem write.
- Assume entry-name normalization guarantees destination containment.
- Ignore duplicate paths, case folding, links, overwrite mode, or extraction order when evidenced.

## Analysis Procedure
1. Identify the archive trust boundary, destination root, entry-name source, and actual filesystem write sink.
2. Trace how each entry name becomes a destination path, including separator normalization and decoding.
3. Check absolute, drive/UNC, dot-segment, empty/control, and platform-specific forms relevant to the code.
4. Verify canonical/normalized destination containment after combining with the extraction root.
5. Analyze symbolic/hard link handling, parent-directory creation, pre-existing links, and overwrite behavior when supported by the archive API.
6. Check duplicate normalized destinations, case-insensitive collisions, and file-versus-directory conflicts.
7. Confirm validation precedes every write and is not bypassed by a different entry type or branch.

## Evidence Standard
Return `vulnerable` only when a hostile entry can reach a write outside the intended extraction boundary or create a security-relevant overwrite/collision through the visible path. Cite CWE-22 and the numbered extraction/write line. Missing helper or library extraction semantics require `inconclusive`.

## Counterevidence and False Positives
Rejecting `..` substrings alone is weak, but canonical destination containment plus safe link policy can be effective. Listing an archive, reading an entry in memory, or extracting only to a content-addressed non-filesystem store is not path traversal. A validated entry must not be re-resolved differently at write time.

## Confidence and Stopping Rules
High confidence requires archive provenance, entry-to-destination transformation, root policy, entry-type behavior, and reachable write evidence.

## Output Discipline
Choose explicitly among `vulnerable`, `not_vulnerable`, and `inconclusive`; describe the failed or effective invariant without providing a weaponized archive recipe.
