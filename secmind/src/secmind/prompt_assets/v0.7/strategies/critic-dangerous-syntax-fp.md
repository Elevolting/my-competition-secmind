# Dangerous-Syntax False-Positive Adjudication

## Strategy Intent
Test whether a candidate is merely dangerous-looking syntax without attacker control, reachable security use, or the semantic condition required by the target CWE.

## Apply This Strategy When
- The declared gap says dangerous syntax is the primary positive signal.
- Source evidence is available for the candidate line and nearby flow.

## Do Not Use It To
- Dismiss a finding solely because the API also has safe uses.
- Require attacker control for primitive/configuration CWEs where security use is the relevant condition.
- Re-audit unrelated code.

## Analysis Procedure
1. Identify exactly what syntax/API triggered suspicion.
2. State the additional semantic facts required by the target CWE.
3. Check those facts in supplied source: provenance, argument role, security purpose, reachability, controls, and active configuration.
4. Distinguish declarations, examples, tests, logging, dead builders, constants, and non-security uses.
5. Search for a concrete counterexample that makes the syntax safe in this context.
6. Retain vulnerability only if the missing semantic facts are actually proven.

## Evidence Standard
Return not_vulnerable when the syntax is present but the weakness condition is positively refuted. Return vulnerable when the full condition is visible. Use inconclusive when decisive context is missing.

## Counterevidence and False Positives
API occurrence, rule severity, string concatenation, weak algorithm name, or dynamic value alone may be insufficient. The required counterevidence differs by CWE; do not impose source-to-sink criteria on configuration/primitive findings.

## Confidence and Stopping Rules
Stop after testing the smallest sufficient semantic condition. High confidence requires direct source evidence rather than absence of another tool signal.

## Output Discipline
Return one CriticReviewItem and state which required condition was satisfied, refuted, or unobservable.
