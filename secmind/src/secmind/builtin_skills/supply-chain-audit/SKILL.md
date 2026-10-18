# Supply Chain Audit

Build an offline dependency evidence chain from repository manifests to vulnerabilities.

- Materialize the approved Syft CycloneDX artifact as the explicit dependency of the offline OSV step.
- Runtime network access remains disabled; advisory updates are a separate R2 operation outside this skill.
- Preserve package coordinates, lockfile/SBOM hashes, scanner version and OSV database digest.
- Distinguish unsupported ecosystems, incomplete lockfiles and tool failures as coverage limitations rather than clean results.
