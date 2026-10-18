# Dependency-Centric Audit Planning

## Strategy Intent
Plan an audit centered on declared and resolved dependencies, lockfiles, build plugins, provenance, and reachable vulnerable components.

## Apply This Strategy When
- Dependency manifests or lockfiles are present.
- The supplied objective or available capabilities emphasize SBOM or advisory matching.

## Do Not Use It To
- Claim exploitability from a version match alone.
- Download fresh dependencies or advisory data unless a separately approved capability explicitly permits it.
- Ignore first-party source and configuration when they determine reachability or exposure.

## Analysis Procedure
1. Inventory each ecosystem, manifest, lockfile, module relationship, and whether versions are exact, ranged, inherited, or unresolved.
2. Prefer lockfile/resolved-version evidence over manifest intent when both exist, while preserving discrepancies.
3. Generate or normalize an SBOM using supplied offline capabilities and capture tool/database versions.
4. Match components against the pinned advisory source and retain package, version, advisory, and source-file evidence.
5. Separate direct, transitive, development, test, optional, and build-time dependencies.
6. Add bounded source/config review only for high-impact candidates where usage or exposure can be established from supplied files.
7. Verify deduplication, unresolved components, database age, and coverage before reporting.

## Evidence Standard
A dependency finding needs a component identity, observed version or unresolved status, manifest/lockfile location, advisory identity, and database/tool version. Reachability and runtime impact must be labeled as verified, inferred, or unknown.

## Counterevidence and Failure Handling
Account for excluded scopes, patched vendor backports, platform-specific variants, unused optional packages, and lockfile/manifest drift. A stale or missing advisory database produces a limitation, not a clean bill of health.

## Confidence and Stopping Rules
Stop when all discovered ecosystems are processed or explicitly unsupported, unresolved versions are listed, and advisory evidence is reproducible from pinned data.

## Output Discipline
Return PlanOutput with separate inventory, matching, reachability, and verification steps. Give each step success criteria that distinguish completed inventory from confirmed exposure. Never invent a package version or advisory result.
