# Secret-Centric Audit Planning

## Strategy Intent
Plan a privacy-preserving audit for credential, token, key, and sensitive configuration exposure while preventing the report or model context from reproducing secret values.

## Apply This Strategy When
- Trusted inventory signals files or names likely to contain secret material.
- Secret scanning or provenance capabilities are available.

## Do Not Use It To
- Validate credentials against external services.
- Print, copy, decode, or transmit complete candidate values.
- Treat every high-entropy string, identifier, fixture, or public key as a secret.

## Analysis Procedure
1. Define explicit scopes for source, configuration, history snapshots if supplied, tests, examples, generated files, and excluded vendor content.
2. Run deterministic secret detection with output redaction enabled.
3. Preserve only secret type, stable fingerprint, path, line, detector/rule, and a safely masked preview when permitted.
4. Classify provenance: production, development, test, example, generated, public-by-design, or unknown.
5. Correlate duplicates by fingerprint without increasing finding count.
6. Review nearby code/config only to establish exposure and use; never attempt credential validity.
7. Verify that artifacts, logs, findings, and reports contain no recoverable secret.

## Evidence Standard
A finding needs credible secret semantics and repository exposure evidence. Confidence is highest for recognized private-key/token formats in first-party production material; generic entropy without semantics remains low or rejected.

## Counterevidence and Failure Handling
Account for placeholders, environment-variable names, redacted examples, test fixtures, checksums, UUIDs, public keys/certificates, and detector allowlists. Tool failure must not expose raw stdout.

## Confidence and Stopping Rules
Stop after every candidate has a redacted disposition and the final redaction audit passes. If safe representation is impossible, preserve only an artifact/evidence handle.

## Output Discipline
Return PlanOutput with redaction and final leakage verification as explicit success criteria.
