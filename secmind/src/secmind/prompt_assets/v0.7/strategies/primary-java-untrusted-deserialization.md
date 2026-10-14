# Java Untrusted Deserialization Review

## Strategy Intent
Determine whether data from a lower-trust source is deserialized through a mechanism that can instantiate unsafe types or trigger dangerous behavior without an effective type boundary.

## Apply This Strategy When
- CWE-502 is targeted and object/binary/XML/JSON deserialization or a comparable object reconstruction API is visible.

## Do Not Use It To
- Report all JSON parsing or DTO binding as unsafe deserialization.
- Assume gadget availability or remote code execution without supplied evidence.
- Ignore allowlists, final DTO types, filters, signing, and source authenticity.

## Analysis Procedure
1. Identify the deserialization API, configured target type, polymorphic/type metadata behavior, and exact input source.
2. Establish whether an attacker can control the serialized bytes or authenticated object stream.
3. Inspect type restrictions, object filters, allowlists, class resolvers, polymorphic settings, and custom hooks.
4. Trace configuration and helper methods that enable default typing, native Java serialization, XML object construction, or arbitrary class selection.
5. Confirm the deserialization path is reachable and the data is processed before an authenticity/integrity boundary.
6. Distinguish potential unsafe type instantiation from proven impact; do not invent a gadget chain.
7. Seek fixed DTO schemas, safe parsers, strict allowlists, cryptographic authenticity checks, or trusted-only inputs.

## Evidence Standard
`vulnerable` requires a lower-trust source reaching a deserializer with unsafe type/object construction semantics and no effective restriction. Cite CWE-502 and the numbered deserialization line. Missing library configuration, source trust, or required type information yields `inconclusive`.

## Counterevidence and False Positives
Parsing into a fixed simple DTO is not equivalent to native object deserialization. Authentication alone may not establish message integrity, but a verified signature before deserialization can. A dangerous library dependency without a reachable unsafe deserializer is not enough.

## Confidence and Stopping Rules
High confidence requires source trust, API semantics, type policy, and reachability. Keep impact claims bounded to visible evidence.

## Output Discipline
Choose explicitly among `vulnerable`, `not_vulnerable`, and `inconclusive`; do not provide serialized payloads or gadget instructions.
