# Bounded Single-Language Audit Planning

## Strategy Intent
Create a short, executable audit plan for one language and one repository root. The plan must maximize verified coverage with the capabilities actually supplied in the task context, not with tools or access that merely seem useful.

## Apply This Strategy When
- The trusted inventory identifies exactly one supported language.
- The repository is a single bounded project rather than a monorepo.
- Inputs are readable enough to identify source, dependency, configuration, and test surfaces.

## Do Not Use It To
- Merge unrelated modules into one oversized step.
- Invent scanners, network access, credentials, build systems, or runtime environments.
- Treat a plan as permission to execute a tool.

## Analysis Procedure
1. Inventory the supplied files by source, dependency manifest, configuration, generated content, tests, and documentation.
2. State the audit scope and any excluded or unreadable surfaces before choosing work.
3. Select the smallest compatible capability sequence: inventory first, deterministic scanners next, bounded source review after candidate extraction, and evidence verification last.
4. Give every step a single measurable objective, explicit dependency IDs, bounded attempts, and success criteria that can be checked without subjective interpretation.
5. Keep independent read-only scans parallelizable; serialize only steps that consume prior artifacts.
6. Reserve a final verification step that checks evidence references, coverage gaps, tool failures, and clean-result validity.

## Evidence Standard
A valid plan names the input or prior artifact each step consumes, produces a typed result, and defines what proves completion. “Run a security audit” is not a success criterion. Prefer criteria such as valid structured output, coverage recorded, candidate locations preserved, and every final finding bound to evidence.

## Counterevidence and Failure Handling
Allow clean results, unavailable capabilities, unsupported files, and partial coverage. A tool failure must not become a vulnerability finding. A missing optional capability should produce a declared limitation or a safe fallback, not an invented replacement.

## Confidence and Stopping Rules
Stop adding steps when each in-scope surface has an owner, dependencies are acyclic, and remaining work would repeat an existing capability. If the inventory is incomplete, return a conservative plan with explicit limitations rather than claiming full coverage.

## Output Discipline
Return only the requested PlanOutput. Use stable unique step IDs, valid dependencies, supplied capability/tool identifiers, bounded attempts, concrete success criteria, and a concise rationale summary.
