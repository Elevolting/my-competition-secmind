# Java Trust-Boundary Violation Review

## Strategy Intent
Determine whether data crosses from a lower-trust source into a security-sensitive operation without the validation, binding, or authorization required at that boundary.

## Apply This Strategy When
- CWE-501 is targeted and the unit explicitly identifies a lower-trust source and sensitive boundary.

## Do Not Use It To
- Label every input-validation issue as CWE-501.
- Invent a trust model that is not supported by scope, code, or supplied metadata.
- Replace a more precise CWE when the evidence clearly establishes injection, authorization, or another specific weakness.

## Analysis Procedure
1. Identify the two trust zones and the code event where data crosses between them.
2. Establish why the source is lower trust using visible origin and ownership, not naming.
3. Identify the sensitive consumer and the security property expected at the boundary: identity, integrity, format, scope, authorization, or provenance.
4. Trace validation, authentication/authorization binding, normalization, and transformations before consumption.
5. Check whether validation is applied to the same value and occurs before the boundary.
6. Confirm a realistic security consequence from accepting the lower-trust data.
7. Seek evidence that the source is trusted, the consumer is non-sensitive, or an effective boundary control exists.

## Evidence Standard
`vulnerable` requires a demonstrated lower-trust origin, reachable sensitive consumer, missing/ineffective boundary control, and security consequence. Cite CWE-501 and the numbered sensitive-boundary line. Use `inconclusive` when zone ownership, caller identity, or required policy is not supplied.

## Counterevidence and False Positives
Serialization, logging, or data transfer is not automatically a trust violation. Strong schema validation may address format but not authorization; evaluate the actual required property. Internal data is not automatically trusted if an external party can influence it, but do not assume that influence without evidence.

## Confidence and Stopping Rules
High confidence requires an explicit trust model derived from evidence. Prefer a specific CWE when it fully describes the observed flaw and use CWE-501 only for the boundary failure established here.

## Output Discipline
Choose explicitly among `vulnerable`, `not_vulnerable`, and `inconclusive`, with concise zone/source/consumer/control reasoning and no policy invention.
