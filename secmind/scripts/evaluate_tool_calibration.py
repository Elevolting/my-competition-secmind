"""Run and evaluate the frozen held-out tool calibration set.

Without ``--run`` this command only evaluates a sealed observation document.
With ``--run`` it executes the repository's deterministic built-in tools and,
when a frozen image config and rootless runner are available, executes external
scanners through their immutable containers. Missing execution-plane material
is listed as ``unavailable`` and required external rows fail closed.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Literal, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

_SYNTHETIC_FIXTURE_HEADER = "SECMIND_SYNTHETIC_FIXTURE_XOR_V1"
_SYNTHETIC_FIXTURE_MAX_BYTES = 1024 * 1024
_MATERIALIZED_FIXTURE_ROOT = tempfile.TemporaryDirectory(prefix="secmind-calibration-")

from secmind.sandbox import (  # noqa: E402
    DockerSandboxBackend,
    SandboxError,
    SandboxInputFile,
    SandboxInvocation,
    SandboxLimits,
    SandboxRunner,
    SandboxStagingSpec,
    SandboxToolSpec,
)
from secmind.schemas import ToolContext, ToolStatus  # noqa: E402
from secmind.task_contract import canonical_digest  # noqa: E402
from secmind.tool_assurance import (  # noqa: E402
    ToolAssuranceContract,
    build_tool_assurance,
    verified_semantic_assurance,
)
from secmind.tooling.external_manifests import EXTERNAL_TOOL_NAMES  # noqa: E402
from secmind.tools import default_registry  # noqa: E402
from secmind_dev.tool_calibration import (  # noqa: E402
    CalibrationAssuranceLineage,
    CalibrationCase,
    CalibrationManifest,
    CalibrationObservation,
    CalibrationObservations,
    ToolCalibrationError,
    ToolCalibrationPolicy,
    evaluate_tool_calibration,
    evaluate_tool_calibration_files,
)

AssuranceLevel = Literal[
    "observation_only",
    "deterministic_rule_hit",
    "deterministic_semantic",
    "calibrated_security_claim",
]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate frozen held-out scanner calibration")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--observations", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run", action="store_true", help="execute built-in tools over manifest fixtures")
    parser.add_argument(
        "--fixture-root",
        type=Path,
        help="root used to resolve manifest fixture_path values (defaults to repository root)",
    )
    parser.add_argument("--required-tool", action="append", default=[])
    parser.add_argument("--minimum-cases", type=int, default=10)
    parser.add_argument("--minimum-positive", type=int, default=3)
    parser.add_argument("--minimum-negative", type=int, default=3)
    parser.add_argument("--minimum-precision", type=float, default=0.90)
    parser.add_argument("--minimum-recall", type=float, default=0.90)
    parser.add_argument("--minimum-evidence-completeness", type=float, default=1.0)
    parser.add_argument("--require-trusted-signer", action="store_true")
    parser.add_argument("--require-calibrated-claim", action="store_true")
    parser.add_argument("--require-toolchain-complete", action="store_true")
    parser.add_argument("--require-untouched-holdout", action="store_true")
    parser.add_argument("--expected-independent-source-count", type=int, default=0)
    parser.add_argument("--require-same-source-double-report", action="store_true")
    parser.add_argument(
        "--trusted-public-key",
        type=Path,
        help="Ed25519 PEM trust root used to verify tool-assurance contracts",
    )
    parser.add_argument(
        "--signing-private-key",
        type=Path,
        help="Ed25519 PEM key used only to seal a new signed acceptance observation",
    )
    parser.add_argument(
        "--platform-signer",
        action="store_true",
        help=(
            "use the configured platform ToolAssurance private/public-key environment; "
            "required for a non-qualification release manifest"
        ),
    )
    parser.add_argument(
        "--calibration-version",
        help="version label bound into a signed calibrated-security claim",
    )
    parser.add_argument(
        "--calibration-report-digest",
        help="digest of the already sealed metric report bound into signed claims",
    )
    parser.add_argument(
        "--assurance-source-id",
        default="heldout-rootless-signed-runner",
        help="single source identity used by a signed acceptance seal",
    )
    parser.add_argument(
        "--unavailable-tool",
        action="append",
        default=[],
        metavar="NAME=REASON",
        help="record an unavailable external tool explicitly (repeatable)",
    )
    parser.add_argument(
        "--external-config",
        type=Path,
        default=ROOT / "evaluation/tool-calibration/external-images.json",
        help="frozen image/entrypoint/digest config for external scanners",
    )
    parser.add_argument(
        "--docker-host",
        default=None,
        help="rootless Docker host (defaults to SECMIND_SANDBOX_DOCKER_HOST)",
    )
    parser.add_argument(
        "--staging-image",
        default=None,
        help="digest-pinned staging helper (defaults to SECMIND_SANDBOX_STAGING_IMAGE)",
    )
    return parser


def _policy(args: argparse.Namespace, required_tools: tuple[str, ...]) -> ToolCalibrationPolicy:
    return ToolCalibrationPolicy(
        required_tools=required_tools,
        minimum_cases_per_tool=args.minimum_cases,
        minimum_positive_cases_per_tool=args.minimum_positive,
        minimum_negative_cases_per_tool=args.minimum_negative,
        minimum_precision=args.minimum_precision,
        minimum_recall=args.minimum_recall,
        required_evidence_completeness=args.minimum_evidence_completeness,
        require_trusted_signer=args.require_trusted_signer,
        require_calibrated_security_claim=args.require_calibrated_claim,
        expected_independent_source_count=args.expected_independent_source_count,
        require_same_source_double_report=args.require_same_source_double_report,
        require_toolchain_complete=args.require_toolchain_complete,
        require_untouched_holdout=args.require_untouched_holdout,
    )


def _read_manifest(path: Path) -> CalibrationManifest:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolCalibrationError(f"cannot read calibration manifest: {path}") from exc
    return CalibrationManifest.model_validate(value)


def _parse_unavailable(items: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items:
        name, separator, reason = item.partition("=")
        if not separator or not name.strip() or not reason.strip():
            raise ToolCalibrationError("--unavailable-tool must use NAME=REASON")
        result[name.strip()] = reason.strip()
    return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise ToolCalibrationError(f"cannot read calibration fixture: {path}") from exc
    return digest.hexdigest()


def _input_manifest_digest(path: str, input_sha256: str, size_bytes: int) -> str:
    payload = [{"path": path.replace("\\", "/"), "sha256": input_sha256, "size_bytes": size_bytes}]
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _materialize_synthetic_fixture(candidate: Path, case: CalibrationCase) -> Path | None:
    """Decode a committed synthetic-secret envelope into an ephemeral fixture.

    Positive secret-scanner fixtures must resemble credentials to exercise the
    detector, but committing their plaintext makes repository push protection
    indistinguishable from a real leak.  The envelope is reversible obfuscation,
    not encryption: integrity and provenance still come exclusively from the
    manifest's pre-sealed SHA-256.  Decoded bytes exist only under an OS-owned
    temporary directory and are removed when the calibration process exits.
    """

    try:
        if candidate.stat().st_size > _SYNTHETIC_FIXTURE_MAX_BYTES * 2:
            raise ToolCalibrationError(f"synthetic fixture envelope is too large for {case.case_id}")
        lines = candidate.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ToolCalibrationError(f"cannot read calibration fixture envelope: {candidate}") from exc
    if not lines or lines[0] != _SYNTHETIC_FIXTURE_HEADER:
        return None
    fields: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition("=")
        if not separator or name in fields:
            raise ToolCalibrationError(f"invalid synthetic fixture envelope for {case.case_id}")
        fields[name] = value
    if set(fields) != {"case_id", "data"} or fields["case_id"] != case.case_id:
        raise ToolCalibrationError(f"synthetic fixture envelope identity mismatch for {case.case_id}")
    try:
        sealed = base64.b64decode(fields["data"].encode("ascii"), validate=True)
    except (UnicodeError, ValueError) as exc:
        raise ToolCalibrationError(f"invalid synthetic fixture payload for {case.case_id}") from exc
    if not sealed or len(sealed) > _SYNTHETIC_FIXTURE_MAX_BYTES:
        raise ToolCalibrationError(f"synthetic fixture payload size is invalid for {case.case_id}")
    key = hashlib.sha256(f"secmind-tool-calibration:{case.case_id}".encode()).digest()
    content = bytes(value ^ key[index % len(key)] for index, value in enumerate(sealed))
    observed = hashlib.sha256(content).hexdigest()
    if observed != case.input_sha256:
        raise ToolCalibrationError(f"synthetic fixture digest mismatch for {case.case_id}")
    target_root = Path(_MATERIALIZED_FIXTURE_ROOT.name) / case.input_sha256
    target_root.mkdir(parents=True, exist_ok=True)
    target = target_root / candidate.name
    if not target.is_file() or _sha256(target) != case.input_sha256:
        target.write_bytes(content)
    return target


def _fixture_path(case: CalibrationCase, fixture_root: Path) -> Path:
    if case.fixture_path is None:
        raise ToolCalibrationError(f"case {case.case_id} has no fixture_path; --run needs frozen fixtures")
    candidate = (fixture_root / case.fixture_path).resolve()
    root = fixture_root.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ToolCalibrationError(f"fixture escapes fixture root: {case.fixture_path}") from exc
    if not candidate.is_file():
        raise ToolCalibrationError(f"calibration fixture is missing: {case.fixture_path}")
    observed = _sha256(candidate)
    if observed == case.input_sha256:
        return candidate
    materialized = _materialize_synthetic_fixture(candidate, case)
    if materialized is None:
        raise ToolCalibrationError(f"fixture digest mismatch for {case.case_id}")
    return materialized


def _relative_fixture_target(fixture: Path, fixture_root: Path) -> str:
    return fixture.relative_to(fixture_root).as_posix()


def _verify_fixture_tree(manifest: CalibrationManifest) -> None:
    """Verify the manifest's frozen case-path/digest commitment."""

    if manifest.fixture_tree_digest is None:
        return
    rows = "".join(
        f"{case.fixture_path}\0{case.input_sha256}\n"
        for case in sorted(
            (item for item in manifest.cases if item.fixture_path is not None),
            key=lambda item: item.fixture_path or "",
        )
    )
    observed = hashlib.sha256(rows.encode("utf-8")).hexdigest()
    if observed != manifest.fixture_tree_digest:
        raise ToolCalibrationError("fixture tree digest mismatch")


def _finding_fingerprint(finding: dict[str, Any]) -> str:
    payload = {
        "finding_id": finding.get("finding_id"),
        "rule_id": finding.get("rule_id"),
        "native_rule_id": finding.get("native_rule_id"),
        "path": finding.get("path"),
        "line": finding.get("line"),
        "file_sha256": (
            finding.get("file_sha256")
            if isinstance(finding.get("file_sha256"), str)
            else (finding.get("raw") or {}).get("file_sha256")
            if isinstance(finding.get("raw"), dict)
            else None
        ),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _evidence_complete(result: Any) -> bool:
    if result.status != ToolStatus.SUCCESS:
        return False
    data = result.data if isinstance(result.data, dict) else {}
    if int(data.get("parse_failures", 0) or 0) > 0:
        return False
    findings = data.get("findings", [])
    if not isinstance(findings, list):
        return False
    evidence_ids = {item.evidence_id for item in result.evidence}
    return all(isinstance(item, dict) and set(item.get("evidence_ids", [])) <= evidence_ids for item in findings)


def _load_trusted_key(path: Path | None) -> Any | None:
    if path is None:
        return None
    from cryptography.hazmat.primitives import serialization

    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ToolCalibrationError(f"cannot read trusted signer key: {path}") from exc
    return key


def _load_signing_key(path: Path | None) -> Ed25519PrivateKey | None:
    if path is None:
        return None
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError) as exc:
        raise ToolCalibrationError(f"cannot read signing key: {path}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ToolCalibrationError("signing key must be Ed25519")
    return key


def _resolve_platform_signer(
    args: argparse.Namespace,
    manifest: CalibrationManifest,
    trusted_public_key: Ed25519PublicKey | None,
) -> tuple[Ed25519PrivateKey | None, Ed25519PublicKey | None]:
    """Resolve only the platform-configured signer for a release manifest.

    The evaluator private-key option remains available for the historical v2
    qualification seal. A fresh release holdout must use the platform's
    existing ToolAssurance environment instead; silently accepting an
    evaluator-generated key would turn a qualification receipt into a release
    claim.
    """

    if manifest.qualification_only:
        raise ToolCalibrationError("--platform-signer is only valid for a non-qualification release manifest")
    if args.signing_private_key is not None:
        raise ToolCalibrationError("--platform-signer cannot be combined with --signing-private-key")
    private_path = os.environ.get("SECMIND_TOOL_ASSURANCE_PRIVATE_KEY_FILE", "").strip()
    if not private_path:
        raise ToolCalibrationError("platform signer is unavailable: SECMIND_TOOL_ASSURANCE_PRIVATE_KEY_FILE is unset")
    signing_key = _load_signing_key(Path(private_path))
    if signing_key is None:
        raise ToolCalibrationError("platform signer is unavailable: configured private key could not be loaded")
    if trusted_public_key is None:
        public_path = (
            os.environ.get("SECMIND_TOOL_ASSURANCE_TRUSTED_PUBLIC_KEY_FILE", "").strip()
            or os.environ.get("SECMIND_TOOL_ASSURANCE_PUBLIC_KEY_FILE", "").strip()
        )
        if not public_path:
            raise ToolCalibrationError(
                "platform signer is unavailable: SECMIND_TOOL_ASSURANCE_TRUSTED_PUBLIC_KEY_FILE "
                "or SECMIND_TOOL_ASSURANCE_PUBLIC_KEY_FILE is unset"
            )
        trusted_public_key = _load_trusted_key(Path(public_path))
    if trusted_public_key is None or _public_key_id(trusted_public_key) != _public_key_id(signing_key.public_key()):
        raise ToolCalibrationError("platform signer private key does not match the approved public trust root")
    return signing_key, trusted_public_key


def _public_key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"ed25519-{hashlib.sha256(raw).hexdigest()[:16]}"


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _signed_observation_lineage(
    case: CalibrationCase,
    *,
    tool_version: str,
    input_manifest_digest: str,
    rule_bundle_digest: str | None,
    found_rule_ids: tuple[str, ...],
    observed_component_ids: tuple[str, ...],
    finding_fingerprints: tuple[str, ...],
    status: str,
    source_id: str,
    manifest_digest: str,
    calibration_version: str,
    calibration_report_digest: str,
    signing_key: Ed25519PrivateKey,
) -> CalibrationAssuranceLineage:
    """Sign the bounded observation tuple after a real scanner invocation."""

    public_key = signing_key.public_key()
    signer_id = _public_key_id(public_key)
    observation_payload = {
        "case_id": case.case_id,
        "tool_name": case.tool_name,
        "tool_version": tool_version,
        "input_sha256": case.input_sha256,
        "input_manifest_digest": input_manifest_digest,
        "rule_bundle_digest": rule_bundle_digest,
        "found_rule_ids": list(found_rule_ids),
        "observed_component_ids": list(observed_component_ids),
        "finding_fingerprints": list(finding_fingerprints),
        "status": status,
    }
    finding_fingerprint = hashlib.sha256(_canonical_json(observation_payload)).hexdigest()
    calibration_values = {
        "version": calibration_version,
        "manifest_digest": manifest_digest,
        "report_digest": calibration_report_digest,
    }
    values: dict[str, Any] = {
        "contract_version": "tool-assurance-2.0",
        "tool_name": case.tool_name,
        "tool_version": tool_version,
        "input_manifest_digest": input_manifest_digest,
        "finding_fingerprint": finding_fingerprint,
        "rule_bundle_digest": rule_bundle_digest,
        "provenance": "manifest_bound",
        "integrity": "cas_rehash_required",
        "semantic": "calibrated_security_claim",
        "replayable": True,
        "allowed_patch_classes": ["ADD", "SUPPLEMENT"],
        "calibration_digest": canonical_digest(calibration_values),
        "calibration_version": calibration_version,
        "calibration_manifest_digest": manifest_digest,
        "calibration_report_digest": calibration_report_digest,
        "signature_algorithm": "Ed25519",
        "signer_id": signer_id,
        "signature": None,
    }
    values["contract_digest"] = canonical_digest(
        {key: value for key, value in values.items() if key not in {"contract_digest", "signature"}}
    )
    values["signature"] = _b64url(
        signing_key.sign(_canonical_json({key: value for key, value in values.items() if key != "signature"}))
    )
    # Validate both the contract schema and the Ed25519 signature before it is
    # released into the sealed observation document.
    ToolAssuranceContract.model_validate(values)
    if not verified_semantic_assurance({"tool_assurance": values}, trusted_public_key=public_key):
        raise ToolCalibrationError(f"generated assurance signature failed verification for {case.case_id}")
    return CalibrationAssuranceLineage(
        source_id=source_id,
        report_id=f"{source_id}:{case.tool_name}:{case.case_id}",
        assurance_level="calibrated_security_claim",
        signer_id=signer_id,
        signature_algorithm="Ed25519",
        signature_valid=True,
        trusted_signer=True,
        calibration_version=calibration_version,
        calibration_manifest_digest=manifest_digest,
        calibration_report_digest=calibration_report_digest,
        contract_digest=str(values["contract_digest"]),
        assurance_contract=values,
    )


def _platform_observation_lineage(
    case: CalibrationCase,
    *,
    tool_version: str,
    input_manifest_digest: str,
    rule_bundle_digest: str | None,
    found_rule_ids: tuple[str, ...],
    observed_component_ids: tuple[str, ...],
    finding_fingerprints: tuple[str, ...],
    status: str,
    source_id: str,
    manifest_digest: str,
    calibration_version: str,
    calibration_report_digest: str,
    signing_key: Ed25519PrivateKey,
    trusted_public_key: Ed25519PublicKey,
) -> CalibrationAssuranceLineage:
    """Seal one ToolResult projection with the platform assurance contract.

    The contract is created by ``secmind.tool_assurance.build_tool_assurance``
    rather than by the evaluator's historical qualification signer.  The
    observation tuple is the signed execution-coverage identity for a case;
    individual ToolResult findings retain their own platform contracts in the
    runner result before this bounded projection is emitted.
    """

    observation_payload = {
        "case_id": case.case_id,
        "tool_name": case.tool_name,
        "tool_version": tool_version,
        "input_sha256": case.input_sha256,
        "input_manifest_digest": input_manifest_digest,
        "rule_bundle_digest": rule_bundle_digest,
        "found_rule_ids": list(found_rule_ids),
        "observed_component_ids": list(observed_component_ids),
        "finding_fingerprints": list(finding_fingerprints),
        "status": status,
    }
    finding_fingerprint = hashlib.sha256(_canonical_json(observation_payload)).hexdigest()
    contract = build_tool_assurance(
        tool_name=case.tool_name,
        tool_version=tool_version,
        input_manifest_digest=input_manifest_digest,
        finding_fingerprint=finding_fingerprint,
        rule_bundle_digest=rule_bundle_digest,
        signing_key=signing_key,
        signer_id=None,
        calibration_version=calibration_version,
        calibration_manifest_digest=manifest_digest,
        calibration_report_digest=calibration_report_digest,
    )
    values = contract.model_dump(mode="json")
    contract_valid = verified_semantic_assurance(
        {"tool_assurance": values},
        trusted_public_key=trusted_public_key,
        expected_finding_fingerprint=finding_fingerprint,
    )
    if contract.semantic == "observation_only" and not contract_valid:
        # Syft intentionally has observation-only semantics.  The common
        # semantic verifier rejects that level because it cannot authorize a
        # security claim; verify its Ed25519 contract here for the SBOM
        # completeness lane without upgrading its assurance level.
        try:
            expected_digest = canonical_digest(
                {key: value for key, value in values.items() if key not in {"contract_digest", "signature"}}
            )
            signature = str(values.get("signature") or "")
            decoded = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
            trusted_public_key.verify(
                decoded,
                _canonical_json({key: value for key, value in values.items() if key != "signature"}),
            )
            contract_valid = values.get("contract_digest") == expected_digest
        except (ValueError, TypeError):
            contract_valid = False
    if not contract_valid:
        raise ToolCalibrationError(f"platform ToolResult assurance failed verification for {case.case_id}")
    assurance_level = cast(AssuranceLevel, contract.semantic)
    return CalibrationAssuranceLineage(
        source_id=source_id,
        report_id=f"{source_id}:{case.tool_name}:{case.case_id}",
        assurance_level=assurance_level,
        signer_id=contract.signer_id,
        signature_algorithm=contract.signature_algorithm,
        signature_valid=True,
        trusted_signer=True,
        calibration_version=contract.calibration_version,
        calibration_manifest_digest=contract.calibration_manifest_digest,
        calibration_report_digest=contract.calibration_report_digest,
        contract_digest=contract.contract_digest,
        assurance_contract=values,
    )


def _lineage(
    case: CalibrationCase,
    result: Any,
    *,
    trusted_public_key: Any | None,
    manifest_digest: str,
) -> CalibrationAssuranceLineage:
    evidence = result.evidence[0] if result.evidence else None
    raw_contract = evidence.metadata.get("tool_assurance") if evidence is not None else None
    if isinstance(raw_contract, dict):
        verified = bool(
            trusted_public_key is not None
            and evidence is not None
            and verified_semantic_assurance(evidence.metadata, trusted_public_key=trusted_public_key)
        )
        return CalibrationAssuranceLineage(
            source_id=case.tool_name,
            report_id=f"{case.tool_name}:{case.case_id}",
            assurance_level=cast(AssuranceLevel, str(raw_contract.get("semantic", "observation_only"))),
            signer_id=str(raw_contract["signer_id"]) if raw_contract.get("signer_id") else None,
            signature_algorithm=("Ed25519" if raw_contract.get("signature_algorithm") == "Ed25519" else None),
            signature_valid=verified,
            trusted_signer=verified,
            calibration_version=(
                str(raw_contract["calibration_version"]) if raw_contract.get("calibration_version") else None
            ),
            calibration_manifest_digest=(
                str(raw_contract["calibration_manifest_digest"])
                if raw_contract.get("calibration_manifest_digest")
                else None
            ),
            calibration_report_digest=(
                str(raw_contract["calibration_report_digest"])
                if raw_contract.get("calibration_report_digest")
                else None
            ),
            contract_digest=(str(raw_contract["contract_digest"]) if raw_contract.get("contract_digest") else None),
        )
    if case.tool_name == "python_taint_audit" or case.tool_name == "java_semantic_sast":
        level: AssuranceLevel = "deterministic_semantic"
    elif case.tool_name in {"bandit_python_audit", "secret_pattern_scan"}:
        level = "deterministic_rule_hit"
    else:
        level = "observation_only"
    return CalibrationAssuranceLineage(
        source_id=case.tool_name,
        report_id=f"{case.tool_name}:{case.case_id}",
        assurance_level=level,
        calibration_manifest_digest=manifest_digest if level == "calibrated_security_claim" else None,
    )


def _read_external_config(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolCalibrationError(f"cannot read external image config: {path}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("tools"), dict):
        raise ToolCalibrationError("external image config must contain a tools object")
    missing = sorted(set(EXTERNAL_TOOL_NAMES) - set(value["tools"]))
    if missing:
        raise ToolCalibrationError(f"external image config is missing tools: {missing!r}")
    return value


def _external_limits(name: str) -> SandboxLimits:
    timeout = 300 if name == "osv_dependency_audit" else (180 if name in {"semgrep_sast", "syft_sbom"} else 120)
    return SandboxLimits(timeout_seconds=timeout, max_parallelism=1)


async def _build_external_runner(
    args: argparse.Namespace,
) -> tuple[SandboxRunner | None, dict[str, dict[str, Any]], str | None]:
    try:
        config = _read_external_config(args.external_config)
    except ToolCalibrationError as exc:
        return None, {}, f"unavailable: {exc}"
    staging_image = str(
        args.staging_image or os.environ.get("SECMIND_SANDBOX_STAGING_IMAGE", "") or config.get("staging_image", "")
    ).strip()
    docker_host = str(args.docker_host or os.environ.get("SECMIND_SANDBOX_DOCKER_HOST", "")).strip()
    if not staging_image or not docker_host:
        return None, {}, "unavailable: immutable staging image and rootless Docker host are not configured"
    try:
        allowlist: dict[str, SandboxToolSpec] = {}
        metadata: dict[str, dict[str, Any]] = {}
        for name in EXTERNAL_TOOL_NAMES:
            item = config["tools"].get(name)
            if not isinstance(item, dict):
                raise ToolCalibrationError(f"external image config for {name} is not an object")
            image_digest = str(item.get("image_digest", ""))
            entrypoint = item.get("entrypoint")
            if not isinstance(entrypoint, list) or not all(isinstance(part, str) and part for part in entrypoint):
                raise ToolCalibrationError(f"external image config for {name} has no fixed entrypoint")
            allowlist[name] = SandboxToolSpec(
                name=name,
                image_digest=image_digest,
                entrypoint=tuple(entrypoint),
                limits=_external_limits(name),
            )
            rule_bundle_digest = item.get("rule_bundle_digest")
            if not isinstance(rule_bundle_digest, str):
                raise ToolCalibrationError(f"external image config for {name} has no rule/database digest")
            metadata[name] = item
        backend = DockerSandboxBackend(
            base_url=docker_host,
            require_rootless=True,
            staging_spec=SandboxStagingSpec(image_digest=staging_image),
        )
        runner = SandboxRunner(backend, allowlist, max_parallelism=1)
        await runner.readiness()
        return runner, metadata, None
    except (SandboxError, ToolCalibrationError, ValueError) as exc:
        return None, {}, f"unavailable: rootless runner readiness failed ({type(exc).__name__})"


def _external_finding_path(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    path = value.replace("\\", "/")
    if path.startswith("/input/"):
        path = path.removeprefix("/input/")
    return path if path and "/" not in path and path not in {".", ".."} else None


def _external_evidence_complete(result: Any, fixture: Path, input_sha256: str) -> bool:
    if result.status != "success" or not isinstance(result.data, dict):
        return False
    findings = result.data.get("findings", [])
    if not isinstance(findings, list):
        return False
    if int(result.data.get("rejected_unbound_findings", 0) or 0) > 0:
        return False
    line_count = max(1, fixture.read_bytes().count(b"\n"))
    for finding in findings:
        if not isinstance(finding, dict):
            return False
        if _external_finding_path(finding.get("path")) != fixture.name:
            return False
        if finding.get("file_sha256") != input_sha256:
            return False
        line = finding.get("line")
        if not isinstance(line, int) or isinstance(line, bool) or line < 1 or line > line_count:
            return False
    if result.data.get("components") is not None:
        components = result.data.get("components")
        if not isinstance(components, list) or any(
            not isinstance(item, dict) or not isinstance(item.get("purl"), str) for item in components
        ):
            return False
    return True


def _external_lineage(case: CalibrationCase, metadata: dict[str, Any]) -> CalibrationAssuranceLineage:
    if case.tool_name == "semgrep_sast":
        level: AssuranceLevel = "deterministic_semantic"
    elif case.tool_name == "syft_sbom":
        level = "observation_only"
    else:
        level = "deterministic_rule_hit"
    return CalibrationAssuranceLineage(
        source_id=str(metadata.get("source_id", "rootless-image-runner")),
        report_id=f"{metadata.get('source_id', 'rootless-image-runner')}:{case.tool_name}:{case.case_id}",
        assurance_level=level,
    )


async def _run_cases(
    manifest: CalibrationManifest,
    fixture_root: Path,
    *,
    trusted_public_key: Any | None,
    args: argparse.Namespace,
) -> tuple[CalibrationObservations, dict[str, str]]:
    _verify_fixture_tree(manifest)
    registry = default_registry()
    manifest_digest = hashlib.sha256(
        json.dumps(manifest.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if not manifest.qualification_only and not args.platform_signer:
        raise ToolCalibrationError(
            "a non-qualification release manifest requires --platform-signer; "
            "the evaluator private-key path cannot seal release evidence"
        )
    signing_key = _load_signing_key(args.signing_private_key)
    if args.platform_signer:
        signing_key, trusted_public_key = _resolve_platform_signer(args, manifest, trusted_public_key)
    signing_source_id = str(args.assurance_source_id).strip()
    calibration_version = str(args.calibration_version or "").strip()
    calibration_report_digest = str(args.calibration_report_digest or "").strip().lower()
    if signing_key is not None:
        if not signing_source_id:
            raise ToolCalibrationError("signed acceptance requires a non-empty assurance source id")
        if not calibration_version or not re.fullmatch(r"[a-f0-9]{64}", calibration_report_digest):
            raise ToolCalibrationError(
                "signed acceptance requires --calibration-version and a 64-character --calibration-report-digest"
            )
        signing_public = signing_key.public_key()
        if trusted_public_key is not None:
            key_matches = isinstance(trusted_public_key, Ed25519PublicKey) and _public_key_id(
                trusted_public_key
            ) == _public_key_id(signing_public)
            if not key_matches:
                raise ToolCalibrationError("signing key does not match the trusted public key")
        else:
            trusted_public_key = signing_public
    rows: list[CalibrationObservation] = []
    unavailable: dict[str, str] = {
        name: "unavailable: immutable external image and sandbox runner are not configured"
        for name in EXTERNAL_TOOL_NAMES
    }
    external_runner, external_metadata, external_error = await _build_external_runner(args)
    if external_runner is not None:
        unavailable.clear()
    elif external_error is not None:
        unavailable = {name: external_error for name in EXTERNAL_TOOL_NAMES}
    for case in manifest.cases:
        fixture = _fixture_path(case, fixture_root)
        if case.tool_name in EXTERNAL_TOOL_NAMES:
            if external_runner is not None:
                metadata = external_metadata[case.tool_name]
                input_manifest_digest = _input_manifest_digest(
                    fixture.name,
                    case.input_sha256,
                    fixture.stat().st_size,
                )
                try:
                    content = fixture.read_bytes()
                    invocation = SandboxInvocation(
                        run_id="heldout-tool-calibration",
                        invocation_id=f"calibration-{case.case_id}",
                        tool_name=case.tool_name,
                        files=[
                            SandboxInputFile(
                                path=fixture.name,
                                content_base64=base64.b64encode(content).decode("ascii"),
                            )
                        ],
                    )
                    result = await external_runner.execute(invocation)
                    data = result.data if isinstance(result.data, dict) else {}
                    findings = data.get("findings", [])
                    if not isinstance(findings, list):
                        findings = []
                    components = data.get("components", [])
                    if not isinstance(components, list):
                        components = []
                    found_rule_ids = tuple(
                        sorted(
                            {
                                str(item.get("rule_id"))
                                for item in findings
                                if isinstance(item, dict) and isinstance(item.get("rule_id"), str)
                            }
                        )
                    )
                    observed_component_ids = tuple(
                        sorted(
                            {
                                str(item.get("purl"))
                                for item in components
                                if isinstance(item, dict) and isinstance(item.get("purl"), str)
                            }
                        )
                    )
                    finding_fingerprints = tuple(
                        sorted({_finding_fingerprint(item) for item in findings if isinstance(item, dict)})
                    )
                    external_status: Literal["success", "unavailable", "error"] = (
                        "success" if result.status == "success" else "error"
                    )
                    lineage = _external_lineage(case, metadata)
                    if args.platform_signer:
                        if not isinstance(trusted_public_key, Ed25519PublicKey) or signing_key is None:
                            raise ToolCalibrationError("platform signer trust root is not available")
                        lineage = _platform_observation_lineage(
                            case,
                            tool_version=str(metadata["version"]),
                            input_manifest_digest=input_manifest_digest,
                            rule_bundle_digest=str(metadata["rule_bundle_digest"]),
                            found_rule_ids=found_rule_ids,
                            observed_component_ids=observed_component_ids,
                            finding_fingerprints=finding_fingerprints,
                            status=external_status,
                            source_id=signing_source_id,
                            manifest_digest=manifest_digest,
                            calibration_version=calibration_version,
                            calibration_report_digest=calibration_report_digest,
                            signing_key=signing_key,
                            trusted_public_key=trusted_public_key,
                        )
                    elif signing_key is not None:
                        lineage = _signed_observation_lineage(
                            case,
                            tool_version=str(metadata["version"]),
                            input_manifest_digest=input_manifest_digest,
                            rule_bundle_digest=str(metadata["rule_bundle_digest"]),
                            found_rule_ids=found_rule_ids,
                            observed_component_ids=observed_component_ids,
                            finding_fingerprints=finding_fingerprints,
                            status=external_status,
                            source_id=signing_source_id,
                            manifest_digest=manifest_digest,
                            calibration_version=calibration_version,
                            calibration_report_digest=calibration_report_digest,
                            signing_key=signing_key,
                        )
                    rows.append(
                        CalibrationObservation(
                            case_id=case.case_id,
                            tool_name=case.tool_name,
                            tool_version=str(metadata["version"]),
                            input_sha256=case.input_sha256,
                            evaluation_kind=case.evaluation_kind,
                            found_rule_ids=found_rule_ids,
                            observed_component_ids=observed_component_ids,
                            parse_complete=result.status == "success" and "debug" not in data,
                            evidence_complete=_external_evidence_complete(result, fixture, case.input_sha256),
                            status=external_status,
                            execution_source="external_image",
                            rule_bundle_digest=str(metadata["rule_bundle_digest"]),
                            input_manifest_digest=input_manifest_digest,
                            finding_fingerprints=finding_fingerprints,
                            assurance_lineage=lineage,
                        )
                    )
                except (OSError, SandboxError, ValueError):
                    rows.append(
                        CalibrationObservation(
                            case_id=case.case_id,
                            tool_name=case.tool_name,
                            tool_version=str(metadata["version"]),
                            input_sha256=case.input_sha256,
                            evaluation_kind=case.evaluation_kind,
                            parse_complete=False,
                            evidence_complete=False,
                            status="error",
                            execution_source="external_image",
                            rule_bundle_digest=str(metadata["rule_bundle_digest"]),
                            input_manifest_digest=input_manifest_digest,
                            assurance_lineage=_external_lineage(case, metadata),
                        )
                    )
                continue
            rows.append(
                CalibrationObservation(
                    case_id=case.case_id,
                    tool_name=case.tool_name,
                    tool_version="unavailable",
                    input_sha256=case.input_sha256,
                    evaluation_kind=case.evaluation_kind,
                    parse_complete=False,
                    evidence_complete=False,
                    status="unavailable",
                    execution_source="external_image",
                )
            )
            continue
        try:
            tool = registry.get(case.tool_name)
        except Exception as exc:  # registry errors are release evidence, not a pass
            rows.append(
                CalibrationObservation(
                    case_id=case.case_id,
                    tool_name=case.tool_name,
                    tool_version="error",
                    input_sha256=case.input_sha256,
                    evaluation_kind=case.evaluation_kind,
                    parse_complete=False,
                    evidence_complete=False,
                    status="error",
                    execution_source="builtin",
                )
            )
            unavailable[case.tool_name] = f"error: {type(exc).__name__}"
            continue
        workspace = str(fixture_root)
        context = ToolContext(
            run_id="heldout-tool-calibration",
            step_id=f"calibration-{case.case_id}",
            workspace=workspace,
            allowed_paths=[workspace],
        )
        relative_target = _relative_fixture_target(fixture, fixture_root)
        builtin_result = await tool.invoke({"target": relative_target}, context)
        findings = builtin_result.data.get("findings", []) if isinstance(builtin_result.data, dict) else []
        if not isinstance(findings, list):
            findings = []
        found_rules = tuple(sorted({str(item.get("rule_id")) for item in findings if isinstance(item, dict)}))
        builtin_status: Literal["success", "unavailable", "error"] = (
            "success" if builtin_result.status == ToolStatus.SUCCESS else "error"
        )
        lineage = _lineage(
            case,
            builtin_result,
            trusted_public_key=trusted_public_key,
            manifest_digest=manifest_digest,
        )
        finding_fingerprints = tuple(sorted(_finding_fingerprint(item) for item in findings if isinstance(item, dict)))
        if args.platform_signer:
            if not isinstance(trusted_public_key, Ed25519PublicKey) or signing_key is None:
                raise ToolCalibrationError("platform signer trust root is not available")
            lineage = _platform_observation_lineage(
                case,
                tool_version=tool.manifest.version,
                input_manifest_digest=(
                    str(builtin_result.data["input_manifest_digest"])
                    if isinstance(builtin_result.data, dict)
                    and isinstance(builtin_result.data.get("input_manifest_digest"), str)
                    else _input_manifest_digest(fixture.name, case.input_sha256, fixture.stat().st_size)
                ),
                rule_bundle_digest=(
                    str(builtin_result.data["rule_bundle_digest"])
                    if isinstance(builtin_result.data, dict)
                    and isinstance(builtin_result.data.get("rule_bundle_digest"), str)
                    else None
                ),
                found_rule_ids=found_rules,
                observed_component_ids=(),
                finding_fingerprints=finding_fingerprints,
                status=builtin_status,
                source_id=signing_source_id,
                manifest_digest=manifest_digest,
                calibration_version=calibration_version,
                calibration_report_digest=calibration_report_digest,
                signing_key=signing_key,
                trusted_public_key=trusted_public_key,
            )
        elif signing_key is not None:
            lineage = _signed_observation_lineage(
                case,
                tool_version=tool.manifest.version,
                input_manifest_digest=(
                    str(builtin_result.data["input_manifest_digest"])
                    if isinstance(builtin_result.data, dict)
                    and isinstance(builtin_result.data.get("input_manifest_digest"), str)
                    else _input_manifest_digest(fixture.name, case.input_sha256, fixture.stat().st_size)
                ),
                rule_bundle_digest=(
                    str(builtin_result.data["rule_bundle_digest"])
                    if isinstance(builtin_result.data, dict)
                    and isinstance(builtin_result.data.get("rule_bundle_digest"), str)
                    else None
                ),
                found_rule_ids=found_rules,
                observed_component_ids=(),
                finding_fingerprints=finding_fingerprints,
                status=builtin_status,
                source_id=signing_source_id,
                manifest_digest=manifest_digest,
                calibration_version=calibration_version,
                calibration_report_digest=calibration_report_digest,
                signing_key=signing_key,
            )
        rows.append(
            CalibrationObservation(
                case_id=case.case_id,
                tool_name=case.tool_name,
                tool_version=tool.manifest.version,
                input_sha256=case.input_sha256,
                evaluation_kind=case.evaluation_kind,
                found_rule_ids=found_rules,
                parse_complete=builtin_result.status == ToolStatus.SUCCESS
                and int(builtin_result.data.get("parse_failures", 0) or 0) == 0,
                evidence_complete=_evidence_complete(builtin_result),
                status=builtin_status,
                execution_source="builtin",
                rule_bundle_digest=(
                    str(builtin_result.data["rule_bundle_digest"])
                    if isinstance(builtin_result.data.get("rule_bundle_digest"), str)
                    else None
                ),
                input_manifest_digest=(
                    str(builtin_result.data["input_manifest_digest"])
                    if isinstance(builtin_result.data.get("input_manifest_digest"), str)
                    else None
                ),
                finding_fingerprints=finding_fingerprints,
                assurance_lineage=lineage,
            )
        )
    return CalibrationObservations(
        schema_version="tool-calibration-observations-1.0",
        dataset_id=manifest.dataset_id,
        cases=tuple(rows),
    ), unavailable


async def _async_main(args: argparse.Namespace) -> int:
    manifest = _read_manifest(args.manifest)
    trusted_key = _load_trusted_key(args.trusted_public_key)
    unavailable = _parse_unavailable(args.unavailable_tool)
    if args.run:
        fixture_root = (args.fixture_root or ROOT).resolve()
        observations, run_unavailable = await _run_cases(
            manifest,
            fixture_root,
            trusted_public_key=trusted_key,
            args=args,
        )
        unavailable.update(run_unavailable)
        if args.observations is None:
            raise ToolCalibrationError("--run requires --observations so the execution evidence is sealed")
        args.observations.parent.mkdir(parents=True, exist_ok=True)
        args.observations.write_text(
            json.dumps(observations.model_dump(mode="json"), sort_keys=True, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        policy_tools = tuple(sorted(set(args.required_tool) or {case.tool_name for case in manifest.cases}))
        report = evaluate_tool_calibration(
            manifest,
            observations,
            _policy(args, policy_tools),
            unavailable_tools=unavailable,
        )
    else:
        if args.observations is None:
            raise ToolCalibrationError("--observations is required without --run")
        declared_tools = {case.tool_name for case in manifest.cases}
        for name in EXTERNAL_TOOL_NAMES:
            if name not in declared_tools:
                unavailable.setdefault(
                    name,
                    "unavailable: immutable external image and sandbox runner are not configured",
                )
        required_tools = tuple(sorted(set(args.required_tool) or declared_tools))
        report = evaluate_tool_calibration_files(
            args.manifest,
            args.observations,
            _policy(args, required_tools),
            unavailable_tools=unavailable,
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0 if report["release_eligible"] else 1


def main() -> int:
    args = _parser().parse_args()
    try:
        return asyncio.run(_async_main(args))
    except ToolCalibrationError as exc:
        print(f"tool calibration unavailable: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
