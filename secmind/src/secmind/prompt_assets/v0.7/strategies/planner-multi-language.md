# Multi-Language Audit Planning

## Strategy Intent
Create a capability-aware plan for a repository containing multiple implementation languages without forcing all languages through one scanner or one review method.

## Apply This Strategy When
- At least two supported languages are present in the trusted inventory.
- Cross-language boundaries or shared deployment configuration may affect risk.

## Do Not Use It To
- Assign an incompatible tool to a language merely to keep the plan uniform.
- Duplicate the same repository-wide scan once per language.
- Lose cross-language evidence by treating every partition as unrelated.

## Analysis Procedure
1. Partition files by module and language, while separately identifying shared manifests, API contracts, templates, infrastructure, and generated artifacts.
2. Map each partition to compatible capabilities and explicitly mark partitions with no supported analyzer.
3. Schedule repository-wide inventory, secret, and dependency operations once; schedule language-specific SAST and source review per compatible partition.
4. Preserve boundary artifacts such as routes, RPC definitions, serialization formats, environment variables, and shared authentication configuration.
5. Allow independent language scans to run in parallel within the reserved concurrency budget.
6. Add a deterministic reduction step that deduplicates findings without discarding language-specific evidence.
7. Verify both per-language coverage and cross-language gaps before reporting.

## Evidence Standard
Each step identifies its language/module scope and produces evidence with stable paths. Cross-language claims require an explicit shared boundary; coincidental names are insufficient.

## Counterevidence and Failure Handling
Do not treat an unsupported language as clean. Do not treat a finding repeated by two tools as two vulnerabilities. Preserve partial results when one partition fails.

## Confidence and Stopping Rules
Stop when every identified language is either analyzed by a compatible capability or recorded as unsupported, shared boundaries are assigned, and evidence reduction has completed.

## Output Discipline
Return only PlanOutput. Use dependency edges to express shared inventory before fan-out and reduction after fan-in; success criteria must remain meaningful for each language capability. Do not encode execution commentary in step objectives.
