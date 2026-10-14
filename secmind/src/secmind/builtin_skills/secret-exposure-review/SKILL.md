# Secret Exposure Review

Detect credential candidates while preventing secondary disclosure.

- Use only approved `secret_scan` capabilities; prefer Gitleaks when its immutable image is healthy and use the deterministic pattern scanner as a bounded fallback.
- Never persist, quote, hash as a reversible lookup, or place a raw credential candidate in logs, prompts, reports or artifacts.
- Keep only redacted type, location, rule identifier and non-secret evidence metadata.
- A finding must identify rotation and secret-store remediation without reproducing the value.
