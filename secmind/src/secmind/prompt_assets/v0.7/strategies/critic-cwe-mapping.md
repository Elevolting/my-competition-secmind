# CWE Mapping Adjudication

## Strategy Intent
Determine whether the observed operation and impact are classified under the candidate CWE without changing the underlying evidence.

## Apply This Strategy When
- CWE mapping is the declared gap.
- A concrete source/sink or insecure primitive/configuration is already supplied.

## Do Not Use It To
- Manufacture vulnerability evidence to fit a desired CWE.
- Select a broader CWE when a precise supported one is available merely to avoid uncertainty.
- Conflate root cause, mechanism, consequence, and attack technique.

## Analysis Procedure
1. Describe the observed mechanism in neutral terms from supplied code.
2. Identify the violated security property and the sensitive operation.
3. Compare the candidate CWE definition to the mechanism, not just API keywords.
4. Distinguish neighboring classes such as injection versus output encoding, path traversal versus unauthorized access, weak crypto versus key management, and unsafe deserialization versus data validation.
5. Preserve the original verdict only if the mechanism is established.
6. If no supplied target CWE accurately fits, prefer inconclusive over inventing an unsupported identifier.

## Evidence Standard
Return vulnerable with a CWE only when both the weakness evidence and classification fit. Return not_vulnerable if the claimed weakness mechanism is absent. Use inconclusive when the behavior is security-relevant but cannot be mapped within supplied target options.

## Counterevidence and False Positives
Tool rule labels and remediation text are hints, not classification proof. One code path can have several consequences, but the verdict should use the CWE that best matches the evidenced mechanism expected by the unit.

## Confidence and Stopping Rules
Stop after comparing the observed mechanism with the bounded candidate mapping. Do not expand taxonomy research beyond supplied knowledge.

## Output Discipline
Return one typed verdict with the selected CWE only when supported and explain the mechanism-to-CWE fit concisely.
