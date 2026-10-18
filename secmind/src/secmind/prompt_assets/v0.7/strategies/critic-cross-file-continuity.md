# Cross-File Continuity Adjudication

## Strategy Intent
Resolve one disputed symbol/dataflow edge between the primary file and allowlisted support files.

## Apply This Strategy When
- Cross-file continuity is the declared evidence gap.
- Relevant support files and immutable paths are supplied.

## Do Not Use It To
- Refer to repository files outside the support set.
- Bind classes by similar names without package/type/call evidence.
- Infer dependency-injection or framework wiring not present in context.

## Analysis Procedure
1. Identify the exact source symbol, target symbol, and proposed edge.
2. Resolve package/import/type identity, receiver, signature, and call direction.
3. Map the value across arguments, returns, fields, or constructed objects.
4. Account for transformations, controls, and alternate implementations in supplied files.
5. Verify the target implementation is selected on the candidate path.
6. Seek missing registration, mismatched symbols, safe replacement, or disconnected code that refutes the edge.

## Evidence Standard
Return vulnerable only when the cross-file edge is unambiguous and completes the target weakness. Return not_vulnerable for a proven disconnection and inconclusive when binding depends on absent configuration or code.

## Counterevidence and False Positives
An import or shared interface is not an invocation. A support method unused by the primary path is irrelevant. Different object instances can break apparent field continuity.

## Confidence and Stopping Rules
Stop at the bounded support frontier. High confidence requires symbol identity, invocation evidence, and value continuity.

## Output Discipline
Return one typed verdict and name only the decisive cross-file edge in the rationale.
