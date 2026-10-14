"""Shared tool contracts, validation errors, and finding normalization helpers."""

# ruff: noqa: F401,F403
from __future__ import annotations

import ast
import asyncio
import base64
import hashlib
import hmac
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid5

import httpx
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from secmind.artifact_store import ArtifactStoreError, ContentAddressedArtifactStore
from secmind.coordinator import CoordinatorStore
from secmind.execution import ExecutionConflict, ExecutionStore, parameters_hash
from secmind.guardrail import Guardrail, GuardrailAction, GuardrailDecision
from secmind.hook_bus import HookBus, HookExecutionError
from secmind.investigation.contracts import (
    ArtifactDataClass,
    ArtifactSecurityLabel,
    ArtifactView,
    DispatchPermit,
    ExecutionIdentity,
    seal_contract,
)
from secmind.investigation.store import InvestigationStore
from secmind.java_semantic_sast import (
    RULE_BUNDLE_DIGEST as JAVA_SEMANTIC_RULE_BUNDLE_DIGEST,
)
from secmind.java_semantic_sast import (
    TOOL_NAME as JAVA_SEMANTIC_TOOL_NAME,
)
from secmind.java_semantic_sast import (
    TOOL_VERSION as JAVA_SEMANTIC_TOOL_VERSION,
)
from secmind.java_semantic_sast import (
    JavaSource,
    analyze_java_sources,
)
from secmind.language_registry import (
    LANGUAGE_REGISTRY_VERSION,
    LANGUAGE_SUFFIXES,
)
from secmind.ledger import LedgerStore, canonical_json, redact
from secmind.metrics import TOOL_CALLS
from secmind.policy import PolicyDecisionPoint, manifest_digest
from secmind.python_dataflow import analyze_python_source
from secmind.sandbox import (
    SandboxInputFile,
    SandboxInvocation,
    SandboxResult,
    SandboxToolSpec,
    collect_sandbox_input_files,
    validate_relative_path,
)
from secmind.schemas import (
    ApprovalRequest,
    ApprovalResponse,
    ArtifactRef,
    DataSensitivity,
    DataView,
    Evidence,
    Finding,
    HookDecision,
    HookEvent,
    InputMutation,
    InvocationStatus,
    LogLayer,
    PolicyAction,
    PolicyInput,
    RiskLevel,
    Scenario,
    ToolContext,
    ToolHealth,
    ToolInputEnvelope,
    ToolManifest,
    ToolResult,
    ToolStatus,
)
from secmind.secret_scrubber import scrub_text, scrub_value
from secmind.tool_assurance import build_tool_assurance
from secmind.unit_of_work import ControlPlaneUnitOfWork, UnitOfWorkConflict

_SENSITIVE_ENV_NAME = re.compile(
    r"(?:api[_-]?key|secret|token|password|passwd|credential|private[_-]?key|access[_-]?key)",
    re.IGNORECASE,
)
_TOOL_ENV_ALLOWLIST = frozenset(
    {
        "COMSPEC",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
        "USERPROFILE",
        "WINDIR",
    }
)
_TOOL_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")


def sanitized_tool_environment(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build a child environment that cannot inherit service/model secrets."""

    environment = {name.upper(): value for name, value in os.environ.items() if name.upper() in _TOOL_ENV_ALLOWLIST}
    if overrides:
        for name, value in overrides.items():
            normalized = name.upper()
            if (
                not _TOOL_ENV_NAME.fullmatch(normalized)
                or _SENSITIVE_ENV_NAME.search(normalized)
                or "\x00" in value
                or len(value) > 4096
            ):
                raise ValueError("tool environment override is not safe")
            environment[normalized] = value
    return environment


class ToolError(RuntimeError):
    pass


class ToolValidationError(ToolError):
    pass


class ToolInvocationIdentityError(ToolError):
    pass


def public_evidence_id(digest: str) -> str:
    """Return a scrubber-safe public identity for server-derived evidence.

    Tool evidence historically used an unlabelled 24-hex digest.  That shape is
    intentionally treated as a possible secret by the generic scrubber, which
    collapsed unrelated evidence to the same ``[REDACTED]`` identity.  Keep the
    established 96-bit digest payload while placing it in the explicit public
    evidence namespace.
    """

    normalized = digest.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", normalized):
        raise ValueError("evidence identity requires a SHA-256 hex digest")
    return f"evidence-{normalized[:24]}"


def _policy_path(value: str, *, base: str | None = None) -> str:
    path = Path(value)
    if base is not None and not path.is_absolute():
        path = Path(base) / path
    return path.resolve().as_posix()


class BaseTool(ABC):
    manifest: ToolManifest

    @abstractmethod
    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        raise NotImplementedError


def _validate_with(validator: Draft202012Validator, value: Any, *, path: str) -> None:
    try:
        validator.validate(value)
    except ValidationError as exc:
        location = ".".join(str(item) for item in exc.absolute_path)
        suffix = f".{location}" if location else ""
        raise ToolValidationError(f"{path}{suffix}: {exc.message}") from exc


REMEDIATIONS = {
    "B105": "Move hard-coded secrets to an injected secret store and rotate exposed values.",
    "B301": "Avoid unsafe deserialization; use a safe, schema-validated format such as JSON.",
    "B602": "Avoid shell=True and pass a fixed argument vector to subprocess APIs.",
    "B608": "Use parameterized queries rather than constructing SQL with string interpolation.",
}

# Bandit's native B-codes remain in evidence metadata, while reportable
# findings use the interoperable weakness identifier expected by correlators,
# SARIF consumers and evaluation.  Import-only blacklist checks are context
# hints rather than proven vulnerabilities and are deliberately not emitted as
# standalone findings.
BANDIT_CWE: dict[str, str] = {
    "B102": "CWE-95",
    "B105": "CWE-798",
    "B106": "CWE-798",
    "B107": "CWE-798",
    "B301": "CWE-502",
    "B302": "CWE-502",
    "B303": "CWE-327",
    "B304": "CWE-327",
    "B305": "CWE-327",
    "B306": "CWE-377",
    "B307": "CWE-95",
    "B308": "CWE-79",
    "B311": "CWE-330",
    "B312": "CWE-319",
    "B313": "CWE-611",
    "B314": "CWE-611",
    "B315": "CWE-611",
    "B316": "CWE-611",
    "B317": "CWE-611",
    "B318": "CWE-611",
    "B319": "CWE-611",
    "B320": "CWE-611",
    "B321": "CWE-319",
    "B323": "CWE-295",
    "B324": "CWE-327",
    "B501": "CWE-295",
    "B502": "CWE-327",
    "B503": "CWE-327",
    "B505": "CWE-326",
    "B506": "CWE-502",
    "B507": "CWE-295",
    "B601": "CWE-78",
    "B602": "CWE-78",
    "B604": "CWE-78",
    "B605": "CWE-78",
    "B607": "CWE-426",
    "B608": "CWE-89",
    "B609": "CWE-78",
    "B610": "CWE-89",
    "B611": "CWE-89",
    "B614": "CWE-502",
    "B615": "CWE-494",
}
BANDIT_CONTEXT_ONLY_RULES = {f"B{value}" for value in range(401, 416)}
CWE_TITLES = {
    "CWE-22": "Path traversal",
    "CWE-78": "Operating-system command injection",
    "CWE-79": "Cross-site scripting",
    "CWE-89": "SQL injection",
    "CWE-95": "Dynamic code evaluation",
    "CWE-295": "Improper certificate validation",
    "CWE-319": "Cleartext transmission of sensitive information",
    "CWE-327": "Use of a broken or risky cryptographic algorithm",
    "CWE-502": "Deserialization of untrusted data",
    "CWE-611": "Improper restriction of XML external entities",
    "CWE-798": "Use of hard-coded credentials",
}
CWE_IMPACTS = {
    "CWE-78": "An attacker may execute commands with the privileges of the application process.",
    "CWE-79": "An attacker may execute script in another user's browser context.",
    "CWE-89": "An attacker may read or modify database data and bypass authorization.",
    "CWE-95": "An attacker may execute arbitrary code in the application process.",
    "CWE-295": "An attacker may impersonate a remote endpoint and intercept protected traffic.",
    "CWE-319": "Network observers may recover sensitive data or credentials.",
    "CWE-327": "Protected data may be recovered or forged because the cryptographic primitive is weak.",
    "CWE-502": "A crafted payload may execute code or corrupt application state during deserialization.",
    "CWE-611": "An attacker may read local files, trigger server-side requests, or exhaust parser resources.",
    "CWE-798": "Anyone with source or artifact access may recover and misuse the embedded credential.",
}
DEPENDENCY_FILES = {
    "cargo.lock",
    "go.mod",
    "package-lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pyproject.toml",
    "requirements.txt",
    "uv.lock",
}
SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:[A-Za-z0-9]+[_-])?"
    r"(api[_-]?key|access[_-]?token|client[_-]?secret|password|private[_-]?key)"
    r"(?![A-Za-z0-9])"
    r"\s*(?:(?::\s*[A-Za-z_][A-Za-z0-9_.\[\]]*)?\s*=\s*|:\s*)"
    r"['\"]([^'\"\r\n]{8,})['\"]"
)

# These digests identify the executable rule/algorithm contract, not the input
# source.  Keeping them in every evidence item makes a Finding replayable even
# after a worker process or temporary runner has disappeared.
BANDIT_RULE_BUNDLE_DIGEST = hashlib.sha256(b"secmind.bandit.rules.v2-safe-fixed-argv").hexdigest()
PYTHON_DATAFLOW_RULE_BUNDLE_DIGEST = hashlib.sha256(
    b"secmind.python-dataflow.rules.v3-call-chain-and-predictable-prng"
).hexdigest()
SECRET_PATTERN_RULE_BUNDLE_DIGEST = hashlib.sha256(
    b"secmind.secret-pattern.rules.v2-prefixed-comment-placeholder"
).hexdigest()


def compute_input_manifest_digest(entries: Sequence[Mapping[str, Any]]) -> str:
    """Hash a canonical, source-free input manifest.

    A manifest contains only normalized path, byte count, and content SHA.  It
    can therefore be recorded in public Evidence without leaking source text,
    while still binding a scanner result to the exact snapshot it inspected.
    """

    normalized: list[dict[str, Any]] = []
    for item in entries:
        path = str(item.get("path") or item.get("relative_path") or "").replace("\\", "/")
        digest = str(item.get("sha256") or item.get("file_sha256") or "").lower()
        size = item.get("size_bytes", item.get("size", 0))
        if not path or not re.fullmatch(r"[a-f0-9]{64}", digest) or not isinstance(size, int) or size < 0:
            raise ValueError("input manifest entries must contain safe path, sha256, and non-negative size")
        normalized.append({"path": path, "sha256": digest, "size_bytes": size})
    payload = sorted(normalized, key=lambda item: item["path"].casefold())
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def workspace_input_manifest(workspace: Path, target: Path | None = None) -> list[dict[str, Any]]:
    """Build a bounded scanner input manifest without retaining source bytes."""

    root = workspace.resolve()
    selected = (target or root).resolve()
    paths = [selected] if selected.is_file() else sorted(path for path in selected.rglob("*") if path.is_file())
    rows: list[dict[str, Any]] = []
    for path in paths[:2_000]:
        if path.is_symlink():
            continue
        try:
            resolved = path.resolve(strict=True)
            relative = resolved.relative_to(root).as_posix()
            digest = hashlib.sha256()
            size = 0
            with resolved.open("rb") as stream:
                while chunk := stream.read(64 * 1024):
                    digest.update(chunk)
                    size += len(chunk)
        except (OSError, ValueError):
            continue
        rows.append({"path": relative, "sha256": digest.hexdigest(), "size_bytes": size})
    return rows


def _provenance_metadata(
    *,
    path: str,
    line: int | None,
    file_sha256: str | None,
    input_manifest_digest: str,
    rule_bundle_digest: str | None,
    finding_id: str | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "path": path,
        "line": line,
        "file_sha256": file_sha256,
        "input_manifest_digest": input_manifest_digest,
        "rule_bundle_digest": rule_bundle_digest,
    }
    if finding_id is not None:
        metadata["finding_id"] = finding_id
    return metadata


def normalize_bandit_findings(
    items: list[dict[str, Any]],
    tool_version: str,
    workspace: Path | None = None,
    *,
    input_manifest_digest: str | None = None,
    rule_bundle_digest: str = BANDIT_RULE_BUNDLE_DIGEST,
) -> tuple[list[Evidence], list[dict[str, Any]]]:
    evidence: list[Evidence] = []
    findings: list[dict[str, Any]] = []
    for item in items:
        native_rule_id = str(item.get("test_id") or "UNKNOWN")
        if native_rule_id in BANDIT_CONTEXT_ONLY_RULES or _is_safe_bandit_fixed_argv(item, native_rule_id):
            continue
        rule_id = _bandit_cwe_id(item, native_rule_id)
        if rule_id is None:
            # A native scanner rule without a stable weakness identity remains
            # context only; it cannot become a reportable Finding.
            continue
        weakness_ids = [rule_id]
        evidence_digest = hashlib.sha256(json.dumps(item, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        evidence_id = public_evidence_id(evidence_digest)
        finding_id = f"finding-{evidence_digest[:32]}"
        raw_path = str(item.get("filename") or "unknown")
        path = raw_path
        file_sha256: str | None = None
        if workspace is not None:
            candidate = Path(raw_path)
            try:
                resolved = candidate.resolve() if candidate.is_absolute() else (workspace / candidate).resolve()
                path = resolved.relative_to(workspace.resolve()).as_posix()
                if resolved.is_file():
                    file_sha256 = hashlib.sha256(resolved.read_bytes()).hexdigest()
            except (OSError, ValueError):
                path = raw_path.replace("\\", "/")
        ev = Evidence(
            evidence_id=evidence_id,
            source=f"bandit:{tool_version}",
            summary=f"{native_rule_id}/{rule_id} at {path}:{item.get('line_number')}",
            sha256=evidence_digest,
            metadata={
                "evidence_type": "sast_finding",
                "tool_name": "bandit_python_audit",
                "tool_version": tool_version,
                "test_id": native_rule_id,
                "native_rule_id": native_rule_id,
                "normalized_rule_id": rule_id,
                "weakness_ids": weakness_ids,
                "test_name": item.get("test_name"),
                "path": path,
                "file_sha256": file_sha256,
                "assurance_level": "integrity_verified",
                **_provenance_metadata(
                    path=path,
                    line=item.get("line_number"),
                    file_sha256=file_sha256,
                    input_manifest_digest=input_manifest_digest or "0" * 64,
                    rule_bundle_digest=rule_bundle_digest,
                    finding_id=finding_id,
                ),
            },
        )
        evidence.append(ev)
        finding = Finding(
            finding_id=finding_id,
            rule_id=rule_id,
            severity=item.get("issue_severity", "UNKNOWN"),
            confidence=item.get("issue_confidence", "UNKNOWN"),
            path=path,
            line=item.get("line_number"),
            title=CWE_TITLES.get(rule_id, str(item.get("test_name") or rule_id)),
            description=item.get("issue_text", ""),
            remediation=REMEDIATIONS.get(native_rule_id),
            evidence_ids=[evidence_id],
            raw={
                "filename": path,
                "issue_confidence": item.get("issue_confidence"),
                "issue_severity": item.get("issue_severity"),
                "line_number": item.get("line_number"),
                "test_id": native_rule_id,
                "native_rule_id": native_rule_id,
                "normalized_rule_id": rule_id,
                "weakness_ids": weakness_ids,
                "test_name": item.get("test_name"),
                "root_cause": item.get("issue_text", ""),
                "impact": CWE_IMPACTS.get(rule_id, ""),
                "file_sha256": file_sha256,
                "input_manifest_digest": input_manifest_digest or "0" * 64,
                "rule_bundle_digest": rule_bundle_digest,
            },
        )
        findings.append(finding.model_dump(mode="json"))
    return evidence, findings


def _is_safe_bandit_fixed_argv(item: Mapping[str, Any], native_rule_id: str) -> bool:
    """Drop Bandit's B603 context hit for a fixed literal executable vector.

    Bandit reports B603 for every subprocess call without ``shell=True``.  A
    fixed argv list is a deliberate safe boundary, so this low-confidence
    context hit must not become a CWE-78 finding.  Parse Bandit's numbered
    source excerpt instead of relying on a text-only ``shell=False`` check;
    dynamic call shapes remain reportable.
    """

    if native_rule_id != "B603":
        return False
    code = item.get("code")
    if not isinstance(code, str):
        return False
    source_lines: list[str] = []
    for line in code.splitlines():
        # Bandit prefixes each excerpt line with ``<line-number> ``.  Consume
        # only that separator so indentation in the Python body remains
        # parseable.
        numbered = re.match(r"^\s*\d+[ \t](.*)$", line)
        source_lines.append(numbered.group(1) if numbered is not None else line)
    try:
        tree = ast.parse("\n".join(source_lines))
    except (SyntaxError, ValueError):
        return False
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        function = call.func
        if (
            not isinstance(function, ast.Attribute)
            or not isinstance(function.value, ast.Name)
            or function.value.id != "subprocess"
            or function.attr not in {"run", "call", "check_call", "check_output", "Popen"}
        ):
            continue
        shell_false = any(
            keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is False
            for keyword in call.keywords
        )
        first_argument = call.args[0] if call.args else None
        fixed_executable = (
            isinstance(first_argument, ast.List)
            and bool(first_argument.elts)
            and isinstance(first_argument.elts[0], ast.Constant)
            and isinstance(first_argument.elts[0].value, str)
        )
        if shell_false and fixed_executable:
            return True
    return False


def _bandit_cwe_id(item: Mapping[str, Any], native_rule_id: str) -> str | None:
    mapped = BANDIT_CWE.get(native_rule_id)
    if mapped is not None:
        return mapped
    issue_cwe: Any = item.get("issue_cwe")
    if isinstance(issue_cwe, Mapping):
        issue_cwe = issue_cwe.get("id")
    match = re.fullmatch(r"(?:CWE-)?([1-9][0-9]*)", str(issue_cwe or ""), flags=re.IGNORECASE)
    return f"CWE-{match.group(1)}" if match else None
