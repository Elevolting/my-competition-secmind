# Injection Dataflow Review

Investigate SQL, command and template injection with source-to-sink evidence.

- Use pinned local Semgrep rules to nominate flows, then materialize only the source, sanitizer and sink slices needed for verification.
- Do not execute payloads, contact targets or expand scope; this is static, read-only investigation.
- Reject claims with missing source/sink locations, stale content hashes or an unverified sanitizer assumption.
- Merge equivalent cross-tool findings by stable flow fingerprint and report unresolved dataflow as insufficient evidence.
