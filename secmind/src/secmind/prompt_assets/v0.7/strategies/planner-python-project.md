# Python Project Audit Planning

## Strategy Intent
Plan a Python audit around import structure, framework entry points, dependency manifests, configuration, and high-signal static analysis.

## Apply This Strategy When
- Python is the only supported implementation language in a single project.
- Supplied capabilities include Python-compatible inventory, SAST, dependency, secret, or bounded source review.

## Do Not Use It To
- Assume a web framework from filenames alone.
- Require package installation, test execution, or network resolution when unavailable.
- Treat type stubs, generated code, fixtures, and production code as equivalent without labeling them.

## Analysis Procedure
1. Identify packages, applications, entry points, framework indicators, settings, templates, migrations, tests, and dependency files.
2. Run project inventory before SAST so excludes and source roots are explicit.
3. Schedule Python SAST and secret scanning independently when both capabilities exist.
4. Match dependency evidence from lock/resolution files where available and record unresolved ranges.
5. Use source review to adjudicate high-impact candidates involving command execution, SQL construction, deserialization, template rendering, file paths, redirects, authentication, and outbound requests.
6. Verify that normalized findings bind to real lines and distinguish test/example code.
7. End with coverage, tool-error, and evidence completeness checks.

## Evidence Standard
Plan steps must preserve rule ID, path, line, code context, and tool version. Confirmed semantic findings require a visible source-to-sensitive-operation path or a directly insecure configuration/primitive.

## Counterevidence and Failure Handling
Account for parameterized APIs, framework defaults, validation libraries, allowlists, unreachable code, test-only settings, and environment-derived values. Missing imports or dependencies create partial analysis, not automatic failure.

## Confidence and Stopping Rules
Stop when all Python source roots and manifests are assigned or explicitly excluded, and every promoted finding has an evidence-verification owner.

## Output Discipline
Return only supported tool candidates and evidence-based success criteria. If only one Python tool is available, build a truthful minimal plan instead of inventing a richer toolchain.
