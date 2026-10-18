"""Allowlisted immutable external scanner manifests."""

# ruff: noqa: F401,F403,F405
import os
from pathlib import Path
from typing import Any

from secmind.language_registry import LANGUAGE_REGISTRY_VERSION
from secmind.sandbox import SandboxToolSpec
from secmind.schemas import *

EXTERNAL_TOOL_NAMES = (
    "semgrep_sast",
    "gitleaks_secret_scan",
    "syft_sbom",
    "osv_dependency_audit",
)
# SHA-256 over the reviewed rule files sorted by relative path, where each
# record is ``relative_path + NUL + sha256(file_bytes) + LF``. Updating the
# reviewed bundle requires an explicit code/config change and a new precision
# gate; an operator-provided digest alone cannot publish arbitrary rules.
SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST = "358d2fdefe8949bdfe0fc02e616f904a4d59a3baf88380d90552107004a09ac1"
SEMGREP_REVIEWED_RULE_LANGUAGES = ("java", "javascript", "python", "typescript")
_EXTERNAL_DEFAULT_WEAKNESS = {
    "gitleaks_secret_scan": "CWE-798",  # nosec B105
    "osv_dependency_audit": "CWE-1104",
}


def external_audit_manifests(
    specs: dict[str, SandboxToolSpec] | None = None,
) -> list[ToolManifest]:
    specs = specs or {}
    common_input = {
        "type": "object",
        "properties": {"target": {"type": "string"}},
        "required": ["target"],
        "additionalProperties": False,
    }
    manifests = [
        ToolManifest(
            name="semgrep_sast",
            version="adapter-1",
            description="Semgrep CE using an immutable offline rule bundle.",
            scenarios=[Scenario.CODE_AUDIT],
            input_schema=common_input,
            output_schema={"type": "object", "properties": {"findings": {"type": "array"}}},
            risk_level=RiskLevel.R1,
            permissions=["workspace:read"],
            capability_tags=["sast"],
            supported_languages=list(SEMGREP_REVIEWED_RULE_LANGUAGES),
            evidence_types=["sast_finding"],
            concurrency_key="sast",
            max_parallelism=2,
            health_status=ToolHealth.HEALTHY if "semgrep_sast" in specs else ToolHealth.UNAVAILABLE,
        ),
        ToolManifest(
            name="gitleaks_secret_scan",
            version="adapter-1",
            description="Gitleaks directory scan with complete secret-value redaction.",
            scenarios=[Scenario.CODE_AUDIT],
            input_schema=common_input,
            output_schema={"type": "object", "properties": {"findings": {"type": "array"}}},
            risk_level=RiskLevel.R1,
            permissions=["workspace:read"],
            capability_tags=["secret_scan"],
            evidence_types=["redacted_secret_finding"],
            concurrency_key="secret_scan",
            max_parallelism=2,
            health_status=ToolHealth.HEALTHY if "gitleaks_secret_scan" in specs else ToolHealth.UNAVAILABLE,
        ),
        ToolManifest(
            name="syft_sbom",
            version="adapter-1",
            description="Generate a CycloneDX software bill of materials using Syft.",
            scenarios=[Scenario.CODE_AUDIT],
            input_schema=common_input,
            output_schema={"type": "object"},
            risk_level=RiskLevel.R1,
            permissions=["workspace:read"],
            capability_tags=["sbom"],
            evidence_types=["cyclonedx_sbom"],
            concurrency_key="dependency",
            health_status=ToolHealth.HEALTHY if "syft_sbom" in specs else ToolHealth.UNAVAILABLE,
        ),
        ToolManifest(
            name="osv_dependency_audit",
            version="adapter-1",
            description="Match lockfiles and SBOMs against a pinned offline OSV database.",
            scenarios=[Scenario.CODE_AUDIT],
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "cyclonedx_sbom": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                },
                "required": ["target", "cyclonedx_sbom"],
                "additionalProperties": False,
            },
            output_schema={"type": "object", "properties": {"findings": {"type": "array"}}},
            risk_level=RiskLevel.R1,
            permissions=["workspace:read"],
            capability_tags=["dependency_audit"],
            evidence_types=["dependency_vulnerability"],
            concurrency_key="dependency",
            health_status=ToolHealth.HEALTHY if "osv_dependency_audit" in specs else ToolHealth.UNAVAILABLE,
        ),
    ]
    for manifest in manifests:
        spec = specs.get(manifest.name)
        if spec is None:
            continue
        manifest.execution = manifest.execution.model_copy(
            update={
                "image_digest": spec.image_digest,
                "entrypoint": list(spec.entrypoint),
                "cpu_limit": spec.limits.cpu_cores,
                "memory_mb": spec.limits.memory_bytes // (1024 * 1024),
                "pids_limit": spec.limits.pids_limit,
                "tmpfs_mb": spec.limits.tmpfs_bytes // (1024 * 1024),
                "output_limit_bytes": spec.limits.max_output_bytes,
            }
        )
        manifest.timeout_seconds = spec.limits.timeout_seconds
        manifest.max_parallelism = spec.limits.max_parallelism
        digest_name = f"SECMIND_{manifest.name.upper()}_RULE_BUNDLE_DIGEST"
        manifest.rule_bundle_digest = os.getenv(digest_name) or None
    return manifests
