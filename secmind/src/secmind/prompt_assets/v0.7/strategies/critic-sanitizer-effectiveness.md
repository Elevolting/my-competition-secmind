# Sanitizer Effectiveness Adjudication

## Strategy Intent
Determine whether the supplied sanitizer, validator, encoder, allowlist, parser, or normalization step actually neutralizes the target weakness in its final sink context.

## Apply This Strategy When
- Sanitizer effectiveness is the single declared evidence gap.
- The candidate flow identifies sanitizer sites and a target sink/CWE.

## Do Not Use It To
- Assume any function named `sanitize`, `escape`, `validate`, or `clean` is effective.
- Reject a control solely because it is unfamiliar.
- Re-audit unrelated sources or sinks.

## Analysis Procedure
1. Identify the exact value before and after each candidate control.
2. Determine the required security property from the target sink context: binding, structural allowlisting, contextual encoding, canonical containment, type restriction, destination policy, or another precise invariant.
3. Inspect the control's visible implementation/configuration and order relative to decoding, concatenation, parsing, and the sink.
4. Verify that the sanitized value—not the original—is the one consumed.
5. Check context mismatch, incomplete character/value coverage, post-control mutation, alternate branches, and double decoding.
6. Seek evidence that the control enforces a closed safe representation or that another path bypasses it.

## Evidence Standard
Return `not_vulnerable` only when the control enforces the required invariant on every reachable candidate path. Return `vulnerable` when visible code proves it is ineffective/bypassed and the remaining weakness evidence holds. Use `inconclusive` when the control implementation or sink context is missing.

## Counterevidence and False Positives
Input filtering is not equivalent to output encoding; normalization is not root containment; quoting is not parameter binding; authentication is not authorization. Conversely, typed parsing or a closed server mapping can be effective even without a function named sanitizer.

## Confidence and Stopping Rules
Stop once the control-to-sink invariant is resolved. High confidence requires implementation/configuration, ordering, value identity, and sink context.

## Output Discipline
Return one CriticReviewItem and describe only the control invariant and decisive evidence.
