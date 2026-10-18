# Java Runtime Command Injection Review

## Strategy Intent
Determine whether attacker-controlled data reaches a command string executed through `Runtime.exec` or an equivalent visible Runtime path, with special attention to shell interpretation and argument boundaries.

## Apply This Strategy When
- The target is CWE-78 and the unit contains `Runtime.getRuntime().exec(...)` or a directly related wrapper.

## Do Not Use It To
- Report every process launch as command injection.
- Assume shell metacharacters are interpreted when no shell is invoked and arguments are fixed.
- Treat control over a benign value as control over the executable or command structure without evidence.

## Analysis Procedure
1. Identify the exact overload and executed argument: one string, string array, command plus environment, or wrapper.
2. Trace executable, subcommand, option, and data arguments independently to their sources.
3. Determine whether a shell is explicitly invoked (`sh`, `bash`, `cmd`, PowerShell or equivalent) and where untrusted data is placed.
4. For single-string execution, assess platform/overload tokenization from visible evidence without assuming shell semantics that are not present.
5. Evaluate allowlists, exact mappings, numeric/type conversion, path constraints, and option termination.
6. Confirm reachability and that validation occurs before the executed value is formed.
7. Seek counterevidence showing a fixed executable with non-shell separated arguments and constrained data.

## Evidence Standard
`vulnerable` requires attacker influence over command structure, executable selection, options with security impact, or shell-interpreted content at a reachable Runtime sink. Cite CWE-78 and the numbered execution line. If platform behavior or source provenance is essential but absent, return `inconclusive`.

## Counterevidence and False Positives
A fixed executable plus a constrained argument is not automatically command injection. Quoting is not a universal defense when a shell is used, but absence of a shell matters. Logging a command, building a display string, or invoking a fixed maintenance command without attacker control is not sufficient.

## Confidence and Stopping Rules
High confidence requires a complete source-to-executed-argument path and correct shell/process semantics. Cap confidence for opaque wrappers or unknown platform-specific parsing.

## Output Discipline
Choose explicitly among `vulnerable`, `not_vulnerable`, and `inconclusive`. State the decisive argument boundary in the rationale without suggesting payloads or execution steps.
