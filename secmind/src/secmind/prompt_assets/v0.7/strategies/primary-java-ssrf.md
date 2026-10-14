# Java Server-Side Request Forgery Review

## Strategy Intent
Determine whether attacker-controlled data can direct a server-side network client to an unauthorized destination or protocol without an effective post-resolution policy.

## Apply This Strategy When
- CWE-918 is targeted and URL/URI construction plus an outbound HTTP/network client is visible.

## Do Not Use It To
- Report user-controlled URL text that is never fetched server-side.
- Assume a hostname allowlist automatically covers redirects, DNS resolution, IP literals, or alternate protocols.
- Perform or recommend live network probing.

## Analysis Procedure
1. Identify the outbound request sink and the exact destination-bearing argument.
2. Trace attacker control over scheme, host, port, path, query, headers, or redirect target separately.
3. Determine parsing/canonicalization order and whether validation is applied to the same canonical destination that is fetched.
4. Evaluate scheme/host/port allowlists, DNS/IP range restrictions, loopback/link-local/private ranges, userinfo, encoding, and parser discrepancies where visible.
5. Inspect redirect handling and whether every hop is revalidated.
6. Confirm reachability and server-side execution of the request.
7. Seek fixed upstream mappings, approved service identifiers, disabled redirects, and post-resolution destination enforcement.

## Evidence Standard
`vulnerable` requires attacker influence over a reachable server-side request destination and a visible path to an unauthorized target class without effective restriction. Cite CWE-918 and the numbered client invocation line. Missing client configuration, redirect behavior, or validation helper requires `inconclusive` when decisive.

## Counterevidence and False Positives
Fetching only a server-chosen URL keyed by an opaque ID can be safe. Raw string prefix checks are weak, but a canonical allowlist with resolved-address and redirect enforcement can refute SSRF. An outbound request to a user-controlled path on a fixed trusted host is not automatically SSRF.

## Confidence and Stopping Rules
High confidence requires source, canonical destination control, policy evaluation, redirect/resolution semantics when relevant, and reachable fetch.

## Output Discipline
Choose explicitly among `vulnerable`, `not_vulnerable`, and `inconclusive`, and do not include internal target examples or probing steps.
