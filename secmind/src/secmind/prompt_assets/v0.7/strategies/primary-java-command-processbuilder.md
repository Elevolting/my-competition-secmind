# Java ProcessBuilder Command Injection Review

## Strategy Intent
Determine whether untrusted input can select or reshape a process launched by `ProcessBuilder`, distinguishing argument-array safety from shell invocation and option injection.

## Apply This Strategy When
- CWE-78 is targeted and `ProcessBuilder`, `.command(...)`, or a bounded wrapper is visible.

## Do Not Use It To
- Declare separated arguments safe without checking executable and option control.
- Declare any user-influenced argument vulnerable without a security-relevant interpretation.
- Ignore later mutations of the command list before `.start()`.

## Analysis Procedure
1. Identify the `ProcessBuilder` construction, every `.command` mutation, and the final `.start()` sink.
2. Resolve the final ordered command list at the sink rather than reviewing only its initial constructor.
3. Trace executable, interpreter/shell flag, options, operands, environment, and working-directory influences separately.
4. Determine whether an explicit shell/interpreter converts a data argument into command language.
5. Assess option injection when attacker-controlled values can be interpreted as flags by the fixed executable.
6. Evaluate closed mappings, allowlists, path/root checks, type conversion, and `--`/API semantics where evidenced.
7. Check branches and helper methods for overwrite or safe reconstruction before start.

## Evidence Standard
Return `vulnerable` only if the supplied code proves attacker control over executable/command structure, a shell-evaluated fragment, or a security-relevant option at the reachable `.start()` path. Cite the final start or command-construction line that best identifies the sink, with CWE-78.

## Counterevidence and False Positives
Separate argument elements avoid shell metacharacter expansion when no shell is used, but still review executable and options. A file name passed as an operand is not command injection merely because it contains spaces. A builder never started is not an execution sink.

## Confidence and Stopping Rules
High confidence requires the final command vector and source provenance. Missing mutations, wrapper behavior, or platform semantics require inconclusive or lower confidence.

## Output Discipline
Emit one of `vulnerable`, `not_vulnerable`, or `inconclusive` per unit and keep rationale focused on the exact command-vector boundary and counterevidence.
