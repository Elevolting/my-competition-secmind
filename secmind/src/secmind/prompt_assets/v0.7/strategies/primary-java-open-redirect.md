# Java Open Redirect Review

## Strategy Intent
Determine whether attacker-controlled input can select an external redirect destination outside the intended trust boundary.

## Apply This Strategy When
- CWE-601 is targeted and servlet/Spring redirect APIs, redirect view names, or redirect response headers are visible.

## Do Not Use It To
- Report every dynamic path redirect as external-domain control.
- Treat server-side forwarding or route selection as redirect without response semantics.
- Assume prefix checks are safe without parsing/canonicalization evidence.

## Analysis Procedure
1. Identify the redirect sink and how the destination is interpreted by the framework/browser.
2. Trace attacker influence through decoding, normalization, URI building, concatenation, and helper returns.
3. Distinguish relative application paths, scheme-relative URLs, absolute URLs, encoded separators, backslashes, userinfo, and parser-confusion forms relevant to visible checks.
4. Evaluate destination parsing and allowlisting by canonical scheme/host/port rather than raw string appearance.
5. Check post-validation transformations, double decoding, and trusted-host suffix/prefix mistakes.
6. Confirm the branch is reachable and returns the controlled redirect.
7. Seek fixed route maps, safe relative-only construction, or exact canonical host allowlists.

## Evidence Standard
Return `vulnerable` only when attacker input can cause a reachable redirect to an unauthorized external destination. Cite CWE-601 and the numbered redirect sink. If framework parsing or the allowlist helper is absent and decisive, return `inconclusive`.

## Counterevidence and False Positives
A user-controlled internal route segment may create another issue but is not necessarily open redirect. Exact canonical host/scheme validation can be effective. Naive `startsWith`, substring, or suffix checks may be bypassable, but evaluate the concrete parser and subsequent reconstruction.

## Confidence and Stopping Rules
High confidence requires source, destination construction, canonical validation, browser/framework interpretation, and reachability.

## Output Discipline
Choose explicitly among `vulnerable`, `not_vulnerable`, and `inconclusive`; describe the destination-control invariant without providing phishing URLs.
