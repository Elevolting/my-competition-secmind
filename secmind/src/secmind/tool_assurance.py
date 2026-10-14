"""Platform-owned assurance contracts for deterministic audit tools.

The contract is a trust boundary, not a label emitted by a scanner.  A
semantic contract is therefore only useful when it is signed by a platform
key that is configured outside this package.  The private key is intentionally
loaded only by the platform process; verification uses a separately supplied
public-key trust root.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict

from secmind.schemas import (
    Evidence,
    Finding,
    InputArtifact,
    PlanStep,
    StepRuntime,
    StepStatus,
    ToolResult,
    ToolStatus,
)
from secmind.task_contract import canonical_digest

TOOL_ASSURANCE_CONTRACT_VERSION = "tool-assurance-2.0"
TOOL_ASSURANCE_PRIVATE_KEY_FILE_ENV = "SECMIND_TOOL_ASSURANCE_PRIVATE_KEY_FILE"
TOOL_ASSURANCE_PUBLIC_KEY_FILE_ENV = "SECMIND_TOOL_ASSURANCE_PUBLIC_KEY_FILE"
# This alias is useful for deployments that name the public key as a trust
# root.  It is read only when the primary variable is absent.
TOOL_ASSURANCE_TRUSTED_PUBLIC_KEY_FILE_ENV = "SECMIND_TOOL_ASSURANCE_TRUSTED_PUBLIC_KEY_FILE"
TOOL_ASSURANCE_SIGNER_ID_ENV = "SECMIND_TOOL_ASSURANCE_SIGNER_ID"
TOOL_ASSURANCE_HELDOUT_VERSION_ENV = "SECMIND_TOOL_ASSURANCE_HELDOUT_VERSION"
TOOL_ASSURANCE_HELDOUT_MANIFEST_DIGEST_ENV = "SECMIND_TOOL_ASSURANCE_HELDOUT_MANIFEST_DIGEST"
TOOL_ASSURANCE_HELDOUT_REPORT_DIGEST_ENV = "SECMIND_TOOL_ASSURANCE_HELDOUT_REPORT_DIGEST"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE_ALGORITHM = "Ed25519"

SemanticAssurance = Literal[
    "observation_only",
    "deterministic_rule_hit",
    "deterministic_semantic",
    "calibrated_security_claim",
]


class _ReadableCAS(Protocol):
    """The small CAS surface required by the independent verifier."""

    def read(self, artifact_id: str) -> bytes: ...

    def metadata_for(self, artifact_id: str) -> Any: ...


@dataclass(frozen=True, slots=True)
class CASRehashResult:
    """Independent byte verification for one Evidence artifact."""

    evidence_id: str
    artifact_ref: str | None
    observed_sha256: str | None
    declared_sha256: str | None
    ok: bool
    reason: str | None = None


def independently_rehash_artifact(
    artifact_store: _ReadableCAS,
    artifact_ref: str,
    *,
    run_id: str | None = None,
) -> tuple[str | None, str | None]:
    """Read CAS bytes and calculate their digest independently.

    A scanner-provided ``sha256`` or ``metadata.file_sha256`` is never used as
    the expected digest for the read.  The CAS key is checked against bytes
    returned by the store, and a bound artifact must belong to ``run_id``.
    The function is intentionally tiny so Admission and the tool gate can
    call the same fail-closed primitive.
    """

    if not _is_sha256(artifact_ref):
        return None, "CAS_REFERENCE_INVALID"
    try:
        metadata_for = getattr(artifact_store, "metadata_for", None)
        if callable(metadata_for) and run_id is not None:
            metadata = metadata_for(artifact_ref)
            globally_bound = bool(getattr(metadata, "globally_bound", False))
            run_ids = tuple(getattr(metadata, "run_ids", ()))
            if not globally_bound and run_id not in run_ids:
                return None, "CAS_SCOPE_MISMATCH"
        payload = artifact_store.read(artifact_ref)
    except PermissionError:
        return None, "CAS_PERMISSION_DENIED"
    except (OSError, ValueError, TypeError, KeyError):
        return None, "CAS_OBJECT_UNAVAILABLE"
    if not isinstance(payload, bytes):
        return None, "CAS_OBJECT_INVALID"
    observed = hashlib.sha256(payload).hexdigest()
    if not hmac.compare_digest(observed, artifact_ref.lower()):
        return observed, "CAS_KEY_DIGEST_MISMATCH"
    return observed, None


def independently_rehash_evidence(
    evidence: Evidence,
    artifact_store: _ReadableCAS,
    *,
    run_id: str | None = None,
) -> CASRehashResult:
    """Verify one Evidence object against independently read CAS bytes."""

    artifact_ref = evidence.artifact_ref
    if not isinstance(artifact_ref, str):
        return CASRehashResult(evidence.evidence_id, None, None, evidence.sha256, False, "CAS_REFERENCE_REQUIRED")
    observed, failure = independently_rehash_artifact(artifact_store, artifact_ref, run_id=run_id)
    if failure is not None or observed is None:
        return CASRehashResult(evidence.evidence_id, artifact_ref, observed, evidence.sha256, False, failure)
    declared = evidence.sha256.lower() if isinstance(evidence.sha256, str) else None
    if declared is None:
        return CASRehashResult(evidence.evidence_id, artifact_ref, observed, None, False, "EVIDENCE_DIGEST_REQUIRED")
    if not _is_sha256(declared) or not hmac.compare_digest(observed, declared):
        return CASRehashResult(
            evidence.evidence_id,
            artifact_ref,
            observed,
            declared,
            False,
            "EVIDENCE_DIGEST_MISMATCH",
        )
    return CASRehashResult(evidence.evidence_id, artifact_ref, observed, declared, True, None)


def independently_rehash_evidence_set(
    evidence: Mapping[str, Evidence],
    artifact_store: _ReadableCAS,
    *,
    run_id: str | None = None,
) -> tuple[dict[str, str], dict[str, str]]:
    """Return ``(verified, failures)`` for a deterministic Evidence batch."""

    verified: dict[str, str] = {}
    failures: dict[str, str] = {}
    for evidence_id in sorted(evidence):
        result = independently_rehash_evidence(evidence[evidence_id], artifact_store, run_id=run_id)
        if result.ok and result.observed_sha256 is not None and result.artifact_ref is not None:
            verified[evidence_id] = result.observed_sha256
        else:
            failures[evidence_id] = result.reason or "CAS_REHASH_FAILED"
    return verified, failures


# Short aliases retained for callers that describe this boundary as a
# ``rehash`` rather than an ``independent`` verification.
rehash_cas_artifact = independently_rehash_artifact
rehash_evidence = independently_rehash_evidence
rehash_evidence_set = independently_rehash_evidence_set


class ToolAssuranceContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: str = TOOL_ASSURANCE_CONTRACT_VERSION
    tool_name: str
    tool_version: str
    input_manifest_digest: str
    finding_fingerprint: str
    rule_bundle_digest: str | None = None
    provenance: Literal["manifest_bound"] = "manifest_bound"
    integrity: Literal["cas_rehash_required"] = "cas_rehash_required"
    semantic: SemanticAssurance
    replayable: bool = True
    allowed_patch_classes: tuple[str, ...] = ("ADD", "SUPPLEMENT")
    calibration_digest: str | None = None
    calibration_version: str | None = None
    calibration_manifest_digest: str | None = None
    calibration_report_digest: str | None = None
    signature_algorithm: Literal["Ed25519"] | None = None
    signer_id: str | None = None
    signature: str | None = None
    contract_digest: str


_SEMANTIC_BY_TOOL: dict[str, SemanticAssurance] = {
    "semgrep_sast": "calibrated_security_claim",
    # Bandit treats the tool name as a password-like assignment.
    "gitleaks_secret_scan": "calibrated_security_claim",  # nosec B105
    "osv_dependency_audit": "deterministic_rule_hit",
    "syft_sbom": "observation_only",
    "bandit_python_audit": "deterministic_rule_hit",
    "python_taint_audit": "deterministic_semantic",
    "java_semantic_sast": "deterministic_semantic",
    "web_workflow_audit": "deterministic_semantic",
}

_SECURITY_SCANNERS = frozenset(
    {
        "bandit_python_audit",
        "python_taint_audit",
        "java_semantic_sast",
        "web_workflow_audit",
        "semgrep_sast",
        "gitleaks_secret_scan",
        "osv_dependency_audit",
    }
)

_UNCALIBRATED_SEMANTIC_BY_TOOL: dict[str, SemanticAssurance] = {
    # These tools still provide deterministic rule semantics when the
    # deployment has not supplied held-out calibration material.  They must
    # never be represented as calibrated claims in that configuration.
    "semgrep_sast": "deterministic_semantic",
    # Bandit treats the tool name as a password-like assignment.
    "gitleaks_secret_scan": "deterministic_rule_hit",  # nosec B105
}


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _contract_digest_payload(values: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if key not in {"contract_digest", "signature"}}


def _signature_payload(values: Mapping[str, Any]) -> bytes:
    return _canonical_json({key: value for key, value in values.items() if key != "signature"})


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value.lower()) is not None


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_b64url(value: str) -> bytes:
    if not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid base64url signature")
    padded = value + "=" * (-len(value) % 4)
    decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    if _b64url(decoded) != value:
        raise ValueError("non-canonical base64url signature")
    return decoded


def _load_private_key_from_environment() -> Ed25519PrivateKey | None:
    raw_path = os.environ.get(TOOL_ASSURANCE_PRIVATE_KEY_FILE_ENV)
    if not raw_path:
        return None
    key = serialization.load_pem_private_key(Path(raw_path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("tool assurance private key must be Ed25519")
    return key


def _load_public_key_from_environment() -> Ed25519PublicKey | None:
    raw_path = os.environ.get(TOOL_ASSURANCE_PUBLIC_KEY_FILE_ENV) or os.environ.get(
        TOOL_ASSURANCE_TRUSTED_PUBLIC_KEY_FILE_ENV
    )
    if not raw_path:
        return None
    key = serialization.load_pem_public_key(Path(raw_path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("tool assurance trusted public key must be Ed25519")
    return key


def tool_assurance_readiness(*, required: bool) -> dict[str, Any]:
    """Return a secret-free deployment status for the tool-assurance root.

    Competition/production execution roles call this with ``required=True``
    during startup.  Development roles may remain degraded, but the same
    explicit state is projected by ``/health/ready`` rather than silently
    treating unsigned or uncalibrated scanner output as production evidence.
    The private key is loaded only to validate its Ed25519 type and that its
    derived public key matches the configured trust root; key bytes and paths
    never enter the returned health payload.
    """

    private_path = os.environ.get(TOOL_ASSURANCE_PRIVATE_KEY_FILE_ENV, "").strip()
    trusted_path = os.environ.get(TOOL_ASSURANCE_TRUSTED_PUBLIC_KEY_FILE_ENV, "").strip()
    public_path = os.environ.get(TOOL_ASSURANCE_PUBLIC_KEY_FILE_ENV, "").strip()
    trusted_source = "trusted_public_key" if trusted_path else ("public_key" if public_path else None)
    public_path = trusted_path or public_path
    calibration_version = os.environ.get(TOOL_ASSURANCE_HELDOUT_VERSION_ENV, "").strip()
    calibration_manifest = os.environ.get(TOOL_ASSURANCE_HELDOUT_MANIFEST_DIGEST_ENV, "").strip().lower()
    calibration_report = os.environ.get(TOOL_ASSURANCE_HELDOUT_REPORT_DIGEST_ENV, "").strip().lower()
    reasons: list[str] = []
    private_configured = bool(private_path)
    trusted_configured = bool(public_path)
    private_valid = False
    trusted_valid = False
    public_keys_match = False

    private_key: Ed25519PrivateKey | None = None
    trusted_key: Ed25519PublicKey | None = None
    if not private_configured:
        reasons.append("private_key_unconfigured")
    else:
        try:
            private_key = _load_private_key_from_environment()
            private_valid = private_key is not None
        except (OSError, TypeError, ValueError):
            reasons.append("private_key_invalid")
        if not private_valid and "private_key_invalid" not in reasons:
            reasons.append("private_key_invalid")
    if not trusted_configured:
        reasons.append("trusted_public_key_unconfigured")
    else:
        try:
            trusted_key = _load_public_key_from_environment()
            trusted_valid = trusted_key is not None
        except (OSError, TypeError, ValueError):
            reasons.append("trusted_public_key_invalid")
        if not trusted_valid and "trusted_public_key_invalid" not in reasons:
            reasons.append("trusted_public_key_invalid")
    if private_key is not None and trusted_key is not None:
        private_raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        trusted_raw = trusted_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        public_keys_match = hmac.compare_digest(private_raw, trusted_raw)
        if not public_keys_match:
            reasons.append("private_public_key_mismatch")

    calibration_complete = bool(
        calibration_version and _is_sha256(calibration_manifest) and _is_sha256(calibration_report)
    )
    if not calibration_version:
        reasons.append("heldout_calibration_version_unconfigured")
    if not _is_sha256(calibration_manifest):
        reasons.append("heldout_calibration_manifest_digest_invalid")
    if not _is_sha256(calibration_report):
        reasons.append("heldout_calibration_report_digest_invalid")
    calibration_digest = (
        canonical_digest(
            {
                "version": calibration_version,
                "manifest_digest": calibration_manifest,
                "report_digest": calibration_report,
            }
        )
        if calibration_complete
        else None
    )
    ready = not reasons
    configured_any = bool(
        private_path or public_path or calibration_version or calibration_manifest or calibration_report
    )
    if ready:
        state = "ready"
    elif required:
        state = "not_ready"
    elif not configured_any:
        state = "not_configured"
    else:
        state = "degraded"
    return {
        "status": state,
        "required": required,
        "signature_algorithm": _SIGNATURE_ALGORITHM,
        "private_key_configured": private_configured and private_valid,
        "trusted_public_key_configured": trusted_configured and trusted_valid,
        "trusted_public_key_source": trusted_source,
        "private_public_key_match": public_keys_match,
        "signer_id_configured": bool(os.environ.get(TOOL_ASSURANCE_SIGNER_ID_ENV, "").strip()),
        "heldout_calibration_version": calibration_version or None,
        "heldout_calibration_manifest_digest": calibration_manifest or None,
        "heldout_calibration_report_digest": calibration_report or None,
        "heldout_calibration_digest": calibration_digest,
        "reasons": sorted(set(reasons)),
    }


def require_tool_assurance_readiness() -> dict[str, Any]:
    """Fail closed when a strict execution role lacks its assurance root."""

    state = tool_assurance_readiness(required=True)
    if state["status"] != "ready":
        reasons = ", ".join(state["reasons"])
        raise RuntimeError(f"production tool assurance trust root is not ready: {reasons}")
    return state


def _public_key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return f"ed25519-{hashlib.sha256(raw).hexdigest()[:16]}"


def _calibration_values(
    *,
    calibration_version: str | None,
    calibration_manifest_digest: str | None,
    calibration_report_digest: str | None,
) -> tuple[str, str, str, str] | None:
    version = calibration_version or os.environ.get(TOOL_ASSURANCE_HELDOUT_VERSION_ENV)
    manifest = calibration_manifest_digest or os.environ.get(TOOL_ASSURANCE_HELDOUT_MANIFEST_DIGEST_ENV)
    report = calibration_report_digest or os.environ.get(TOOL_ASSURANCE_HELDOUT_REPORT_DIGEST_ENV)
    if not isinstance(version, str) or not version.strip() or not _is_sha256(manifest) or not _is_sha256(report):
        return None
    normalized_manifest = str(manifest).lower()
    normalized_report = str(report).lower()
    digest = canonical_digest(
        {
            "version": version.strip(),
            "manifest_digest": normalized_manifest,
            "report_digest": normalized_report,
        }
    )
    return version.strip(), normalized_manifest, normalized_report, digest


def _calibration_is_valid(contract: ToolAssuranceContract) -> bool:
    if contract.semantic != "calibrated_security_claim":
        return True
    if (
        not isinstance(contract.calibration_version, str)
        or not contract.calibration_version.strip()
        or not _is_sha256(contract.calibration_manifest_digest)
        or not _is_sha256(contract.calibration_report_digest)
        or not isinstance(contract.calibration_digest, str)
    ):
        return False
    manifest_digest = contract.calibration_manifest_digest
    report_digest = contract.calibration_report_digest
    if manifest_digest is None or report_digest is None:
        return False
    expected = canonical_digest(
        {
            "version": contract.calibration_version.strip(),
            "manifest_digest": manifest_digest.lower(),
            "report_digest": report_digest.lower(),
        }
    )
    return contract.calibration_digest == expected


def finding_assurance_fingerprint(finding: Finding, *, file_sha256: str | None = None) -> str:
    """Return the exact finding binding used by platform-created contracts."""

    return canonical_digest(
        {
            "finding_id": finding.finding_id,
            "rule_id": finding.rule_id,
            "path": finding.path,
            "line": finding.line,
            "file_sha256": file_sha256 or str(finding.raw.get("file_sha256") or ""),
        }
    )


def build_tool_assurance(
    *,
    tool_name: str,
    tool_version: str,
    input_manifest_digest: str,
    finding_fingerprint: str,
    rule_bundle_digest: str | None,
    signing_key: Ed25519PrivateKey | None = None,
    signer_id: str | None = None,
    calibration_version: str | None = None,
    calibration_manifest_digest: str | None = None,
    calibration_report_digest: str | None = None,
) -> ToolAssuranceContract:
    requested_semantic = _SEMANTIC_BY_TOOL.get(tool_name, "observation_only")
    calibration = _calibration_values(
        calibration_version=calibration_version,
        calibration_manifest_digest=calibration_manifest_digest,
        calibration_report_digest=calibration_report_digest,
    )
    if requested_semantic == "calibrated_security_claim" and calibration is None:
        semantic = _UNCALIBRATED_SEMANTIC_BY_TOOL.get(tool_name, "deterministic_rule_hit")
    else:
        semantic = requested_semantic

    if signing_key is None:
        signing_key = _load_private_key_from_environment()
    if signing_key is not None and not isinstance(signing_key, Ed25519PrivateKey):
        raise TypeError("tool assurance signing key must be Ed25519")
    public_key = signing_key.public_key() if signing_key is not None else None
    resolved_signer_id = signer_id or os.environ.get(TOOL_ASSURANCE_SIGNER_ID_ENV)
    if public_key is not None:
        resolved_signer_id = resolved_signer_id or _public_key_id(public_key)

    values: dict[str, Any] = {
        "contract_version": TOOL_ASSURANCE_CONTRACT_VERSION,
        "tool_name": tool_name,
        "tool_version": tool_version,
        "input_manifest_digest": input_manifest_digest,
        "finding_fingerprint": finding_fingerprint,
        "rule_bundle_digest": rule_bundle_digest,
        "provenance": "manifest_bound",
        "integrity": "cas_rehash_required",
        "semantic": semantic,
        "replayable": True,
        "allowed_patch_classes": ("ADD", "SUPPLEMENT"),
        "calibration_digest": calibration[3] if semantic == "calibrated_security_claim" and calibration else None,
        "calibration_version": calibration[0] if semantic == "calibrated_security_claim" and calibration else None,
        "calibration_manifest_digest": (
            calibration[1] if semantic == "calibrated_security_claim" and calibration else None
        ),
        "calibration_report_digest": (
            calibration[2] if semantic == "calibrated_security_claim" and calibration else None
        ),
        "signature_algorithm": _SIGNATURE_ALGORITHM if public_key is not None else None,
        "signer_id": resolved_signer_id if public_key is not None else None,
        "signature": None,
    }

    contract_digest = canonical_digest(_contract_digest_payload(values))
    values["contract_digest"] = contract_digest
    if signing_key is not None:
        values["signature"] = _b64url(signing_key.sign(_signature_payload(values)))
    return ToolAssuranceContract.model_validate(values)


def verified_semantic_assurance(
    metadata: Mapping[str, Any],
    *,
    trusted_public_key: Ed25519PublicKey | None = None,
    expected_finding_fingerprint: str | None = None,
) -> bool:
    raw = metadata.get("tool_assurance")
    if not isinstance(raw, Mapping):
        return False
    try:
        contract = ToolAssuranceContract.model_validate(dict(raw))
    except ValueError:
        return False
    if contract.contract_version != TOOL_ASSURANCE_CONTRACT_VERSION:
        return False
    if (
        not _is_sha256(contract.input_manifest_digest)
        or not _is_sha256(contract.finding_fingerprint)
        or (contract.rule_bundle_digest is not None and not _is_sha256(contract.rule_bundle_digest))
    ):
        return False
    metadata_tool = metadata.get("tool_name")
    metadata_version = metadata.get("tool_version")
    if metadata_tool is not None and (not isinstance(metadata_tool, str) or metadata_tool != contract.tool_name):
        return False
    if metadata_version is not None and (
        not isinstance(metadata_version, str) or metadata_version != contract.tool_version
    ):
        return False
    if contract.semantic not in {
        "deterministic_rule_hit",
        "deterministic_semantic",
        "calibrated_security_claim",
    }:
        return False
    if not _calibration_is_valid(contract):
        return False
    if expected_finding_fingerprint is not None and contract.finding_fingerprint != expected_finding_fingerprint:
        return False
    expected = canonical_digest(_contract_digest_payload(contract.model_dump(mode="json")))
    if contract.contract_digest != expected:
        return False
    if contract.signature_algorithm != _SIGNATURE_ALGORITHM or not contract.signer_id or not contract.signature:
        return False
    if trusted_public_key is None:
        try:
            trusted_public_key = _load_public_key_from_environment()
        except (OSError, TypeError, ValueError):
            return False
    if trusted_public_key is None or contract.signer_id != _public_key_id(trusted_public_key):
        return False
    try:
        trusted_public_key.verify(
            _decode_b64url(contract.signature),
            _signature_payload(contract.model_dump(mode="json")),
        )
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def bind_evidence_to_input_cas(
    evidence_items: list[Evidence],
    findings: list[Finding],
    input_artifacts: list[InputArtifact],
) -> list[Evidence]:
    """Project uniquely bound scanner records onto immutable input objects.

    This pure boundary deliberately does not read the CAS.  It only establishes
    the expected object identity after path and digest agree; the caller must
    still read and re-hash every returned artifact before verification.
    """

    findings_by_evidence = {evidence_id: finding for finding in findings for evidence_id in finding.evidence_ids}
    projected: list[Evidence] = []
    for evidence in evidence_items:
        metadata = dict(evidence.metadata)
        if evidence.artifact_ref is not None:
            projected.append(evidence)
            continue
        raw_path = metadata.get("path")
        declared_digest = metadata.get("file_sha256")
        if not isinstance(raw_path, str) or not isinstance(declared_digest, str):
            projected.append(evidence)
            continue
        normalized = raw_path.replace("\\", "/")
        if normalized.startswith("/input/"):
            normalized = normalized.removeprefix("/input/")
        elif normalized.startswith("./"):
            normalized = normalized.removeprefix("./")
        candidates = [
            item
            for item in input_artifacts
            if item.relative_path.replace("\\", "/") == normalized
            or item.relative_path.replace("\\", "/").endswith("/" + normalized)
        ]
        matching = [item for item in candidates if item.sha256.lower() == declared_digest.lower()]
        if len(matching) != 1:
            projected.append(evidence)
            continue
        matched = matching[0]
        tool_name = metadata.get("tool_name")
        tool_version = metadata.get("tool_version")
        finding = findings_by_evidence.get(evidence.evidence_id)
        if (
            finding is not None
            and isinstance(tool_name, str)
            and isinstance(tool_version, str)
            and not isinstance(metadata.get("tool_assurance"), dict)
        ):
            assurance = build_tool_assurance(
                tool_name=tool_name,
                tool_version=tool_version,
                input_manifest_digest=str(metadata.get("input_manifest_digest") or "0" * 64),
                rule_bundle_digest=(
                    str(metadata["rule_bundle_digest"]) if isinstance(metadata.get("rule_bundle_digest"), str) else None
                ),
                finding_fingerprint=finding_assurance_fingerprint(finding, file_sha256=matched.sha256),
            )
            metadata["tool_assurance"] = assurance.model_dump(mode="json")
            metadata["record_fingerprint"] = assurance.finding_fingerprint
        projected.append(
            evidence.model_copy(
                update={
                    "artifact_ref": matched.sha256,
                    "sha256": matched.sha256,
                    "metadata": metadata,
                }
            )
        )
    return projected


def deterministic_negative_coverage_complete(
    *,
    plan: list[PlanStep],
    runtimes: Mapping[str, StepRuntime],
    observations: list[ToolResult],
    findings: list[Finding],
    quarantined_finding_ids: set[str],
) -> bool:
    """Return whether bounded scanners proved an explicit negative result.

    Absence of a finding is never evidence by itself.  A negative result is
    complete only when at least one security scanner actually ran, every
    selected scanner terminated successfully, every referenced observation is
    a complete parse, and no candidate was rejected, truncated, or
    quarantined.  The caller records the resulting coverage receipt in the
    audit ledger; this helper deliberately performs no mutation or I/O.
    """

    if findings or quarantined_finding_ids:
        return False
    scanner_steps: list[tuple[PlanStep, StepRuntime]] = []
    for step in plan:
        runtime = runtimes.get(step.step_id)
        if runtime is None:
            continue
        selected_tool = runtime.actual_tool_name or next(
            (item for item in step.tool_candidates if item in _SECURITY_SCANNERS),
            None,
        )
        if selected_tool in _SECURITY_SCANNERS:
            scanner_steps.append((step, runtime))
    if not scanner_steps:
        return False
    for _, runtime in scanner_steps:
        if runtime.status != StepStatus.SUCCEEDED or not runtime.observation_indexes:
            return False
        for index in runtime.observation_indexes:
            if index < 0 or index >= len(observations):
                return False
            observation = observations[index]
            if observation.status != ToolStatus.SUCCESS:
                return False
            data = observation.data
            manifest_digest = data.get("input_manifest_digest")
            if not isinstance(manifest_digest, str) or len(manifest_digest) != 64:
                return False
            if not any(item.metadata.get("evidence_type") == "execution_coverage" for item in observation.evidence):
                return False
            if data.get("rejected_findings") or data.get("truncated") is True:
                return False
            if int(data.get("parse_failures", 0) or 0) > 0:
                return False
            coverage = data.get("coverage")
            if isinstance(coverage, Mapping) and coverage.get("complete") is False:
                return False
    return True


__all__ = [
    "CASRehashResult",
    "TOOL_ASSURANCE_CONTRACT_VERSION",
    "TOOL_ASSURANCE_HELDOUT_MANIFEST_DIGEST_ENV",
    "TOOL_ASSURANCE_HELDOUT_REPORT_DIGEST_ENV",
    "TOOL_ASSURANCE_HELDOUT_VERSION_ENV",
    "TOOL_ASSURANCE_PRIVATE_KEY_FILE_ENV",
    "TOOL_ASSURANCE_PUBLIC_KEY_FILE_ENV",
    "TOOL_ASSURANCE_SIGNER_ID_ENV",
    "TOOL_ASSURANCE_TRUSTED_PUBLIC_KEY_FILE_ENV",
    "ToolAssuranceContract",
    "bind_evidence_to_input_cas",
    "build_tool_assurance",
    "deterministic_negative_coverage_complete",
    "finding_assurance_fingerprint",
    "independently_rehash_artifact",
    "independently_rehash_evidence",
    "independently_rehash_evidence_set",
    "rehash_cas_artifact",
    "rehash_evidence",
    "rehash_evidence_set",
    "require_tool_assurance_readiness",
    "tool_assurance_readiness",
    "verified_semantic_assurance",
]
