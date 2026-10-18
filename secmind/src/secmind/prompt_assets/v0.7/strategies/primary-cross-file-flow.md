# Cross-File Dataflow Continuity Review

## Strategy Intent
Resolve a bounded candidate path across classes/files using supplied support context while preserving symbol identity, call direction, and scope.

## Apply This Strategy When
- Cross-file continuity is an explicit evidence gap.
- Support files are allowlisted for the immutable audit unit.

## Do Not Use It To
- Search or reason about files outside the supplied support set.
- Bind classes or methods by similar names alone.
- Assume framework wiring, inheritance, interface implementations, or dependency injection not evidenced by source.

## Analysis Procedure
1. Identify the exact symbol boundary from primary source to support file: import/type, constructor, field, interface, call, or returned object.
2. Resolve package/class/method identity and argument/return mapping.
3. Trace the candidate value across only the support files needed for source-to-sink or configuration continuity.
4. Account for validation, conversion, constants, and branches in every traversed file.
5. Check whether the relevant implementation is actually selected on the visible path.
6. Rejoin the final sink/primitive/configuration in the primary or support file with an exact numbered location.
7. Seek alternative implementations, fixed mappings, or broken call edges that refute the candidate.

## Evidence Standard
`vulnerable` requires a complete symbol-bound path that satisfies the target CWE evidence standard. Cite the final sink line and CWE. If an interface binding, framework registration, or helper file is required but absent, return `inconclusive`.

## Counterevidence and False Positives
Imports do not prove invocation. Interface implementation does not prove runtime selection. Shared field names across instances do not prove flow. Support code that validates or replaces the value can refute the path.

## Confidence and Stopping Rules
High confidence requires unambiguous symbol/call binding and complete value continuity. Stop at the bounded support frontier and list the exact missing file/edge when inconclusive.

## Output Discipline
Choose explicitly among `vulnerable`, `not_vulnerable`, and `inconclusive`; do not claim whole-repository coverage from one cross-file unit.
