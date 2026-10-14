"""Run the platform's generic bridge with SecMind v0.8.3 contract patches.

This file intentionally imports the platform bridge at runtime.  It avoids a
forked thousand-line copy while keeping the product-specific translation under
version control with the Agent.
"""

from __future__ import annotations

import argparse
import ast
import atexit
import hashlib
import http.client
import importlib.util
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Mapping, MutableMapping
from copy import deepcopy
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Literal
from urllib.parse import quote

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from secmind.integrations.test3 import (  # noqa: E402
    MAX_PUBLIC_EVIDENCE,
    MAX_PUBLIC_FINDINGS,
    MAX_PUBLIC_ITEMS_PER_FIELD,
    build_trusted_task_payload,
    project_domain_result,
    read_projection_page,
    trusted_exact_answer_values,
)
from secmind.secret_scrubber import scrub_artifact  # noqa: E402

LOCAL_API_TIMEOUT_SECONDS = 180.0
IDEMPOTENT_GET_ATTEMPTS = 3
IDEMPOTENT_GET_RETRY_DELAY_SECONDS = 0.1
EVALUATION_RELEASE_TOKEN = secrets.token_urlsafe(32)
UPLOAD_CHUNK_BYTES = 1024 * 1024
BRIDGE_PIN_ENV = "SECMIND_V083_BRIDGE_SHA256"
BRIDGE_MANIFEST_ENV = "SECMIND_V083_BRIDGE_MANIFEST"
REQUIRE_BRIDGE_PIN_ENV = "SECMIND_V083_REQUIRE_BRIDGE_PIN"
AGENT_SHA_ENV = "SECMIND_V083_AGENT_GIT_SHA"
BRIDGE_MANIFEST_SCHEMA_VERSION = "secmind-bridge-manifest-v1"
GOLDEN_PREFLIGHT_SCHEMA_VERSION = "secmind-bridge-golden-preflight-v1"
REQUIRED_BRIDGE_SYMBOLS = frozenset(
    {"build_task_payload", "convert_result", "SecMindClient", "main", "MAX_RESPONSE_BYTES"}
)
_MAX_STATIC_INTEGER = 1 << 40


def _pin_source_path(environment: MutableMapping[str, str]) -> None:
    """Make child services independent of locale-sensitive editable ``.pth`` files."""

    source = str(REPOSITORY_ROOT / "src")
    existing = environment.get("PYTHONPATH", "")
    entries = [item for item in existing.split(os.pathsep) if item]
    environment["PYTHONPATH"] = os.pathsep.join([source, *(item for item in entries if item != source)])


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalise_sha256(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    if candidate.startswith("sha256:"):
        candidate = candidate[7:]
    if len(candidate) != 64 or any(character not in "0123456789abcdef" for character in candidate):
        return None
    return candidate


def _restore_input_bound_paths(
    report: Mapping[str, Any] | None,
    input_dir: Path,
    *,
    iter_safe_files: Any,
) -> dict[str, Any] | None:
    """Restore only input-relative locators proven by an immutable file hash.

    The operator report is deliberately scrubbed and may replace a harmless
    source filename with ``[REDACTED]``.  The evaluator already owns the input
    files, so it can safely recover a locator when (and only when) the report's
    declared file SHA-256 uniquely matches that immutable input inventory.
    Host paths, ambiguous duplicate-content paths and unbound model claims are
    never restored.
    """

    if report is None:
        return None
    output = deepcopy(dict(report))
    digest_paths: dict[str, list[str]] = {}
    safe_paths: set[str] = set()
    for path, relative in iter_safe_files(input_dir):
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        normalized = str(relative).replace("\\", "/")
        safe_paths.add(normalized)
        digest_paths.setdefault(digest.hexdigest(), []).append(normalized)

    def bound_path(value: object, digest_value: object) -> str | None:
        raw = str(value or "").replace("\\", "/").strip()
        if raw in safe_paths:
            return raw
        digest = _normalise_sha256(digest_value)
        matches = digest_paths.get(digest or "", [])
        return matches[0] if len(matches) == 1 else None

    findings = output.get("findings")
    if isinstance(findings, list):
        for item in findings:
            if not isinstance(item, MutableMapping):
                continue
            raw = item.get("raw")
            raw_mapping = raw if isinstance(raw, Mapping) else {}
            path = bound_path(item.get("path"), raw_mapping.get("file_sha256"))
            if path is not None:
                item["path"] = path

    evidence = output.get("evidence")
    if isinstance(evidence, list):
        for item in evidence:
            if not isinstance(item, MutableMapping):
                continue
            metadata = item.get("metadata")
            if not isinstance(metadata, MutableMapping):
                continue
            digest_value = metadata.get("file_sha256") or item.get("file_sha256")
            path = bound_path(metadata.get("path") or item.get("path"), digest_value)
            if path is not None:
                metadata["path"] = path
                item["path"] = path
                item["file_sha256"] = _normalise_sha256(digest_value)
    return output


def _bounded_static_integer(node: ast.AST) -> int | None:
    """Evaluate a tiny, side-effect-free integer expression from bridge source.

    Platform constants commonly use forms such as ``8 * 1024 * 1024``.  The
    golden preflight must accept those without importing or executing the
    bridge.  Calls, names, attributes, powers, booleans and oversized results
    remain rejected.
    """

    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        value = int(node.value)
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        operand = _bounded_static_integer(node.operand)
        if operand is None:
            return None
        value = operand if isinstance(node.op, ast.UAdd) else -operand
    elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv)):
        left = _bounded_static_integer(node.left)
        right = _bounded_static_integer(node.right)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Add):
            value = left + right
        elif isinstance(node.op, ast.Sub):
            value = left - right
        elif isinstance(node.op, ast.Mult):
            value = left * right
        else:
            if right == 0:
                return None
            value = left // right
    else:
        return None
    return value if abs(value) <= _MAX_STATIC_INTEGER else None


def _golden_preflight(path: Path, *, require_symbols: bool = True) -> dict[str, Any]:
    """Inspect bridge source without importing or executing it."""

    bridge_path = path.resolve(strict=True)
    try:
        source = bridge_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(bridge_path))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise RuntimeError("Test 3.0 bridge failed static golden preflight") from exc
    names: set[str] = set()
    literals: dict[str, Any] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    value = node.value
                    if value is None:
                        continue
                    names.add(target.id)
                    try:
                        literals[target.id] = ast.literal_eval(value)
                    except (ValueError, TypeError, SyntaxError):
                        static_integer = _bounded_static_integer(value)
                        if static_integer is not None:
                            literals[target.id] = static_integer
    missing = sorted(REQUIRED_BRIDGE_SYMBOLS.difference(names))
    if require_symbols and missing:
        raise RuntimeError("Test 3.0 bridge golden preflight missing " + ", ".join(missing))
    version = literals.get("BRIDGE_VERSION")
    max_response = literals.get("MAX_RESPONSE_BYTES")
    if require_symbols and (not isinstance(version, str) or not version.strip()):
        raise RuntimeError("Test 3.0 bridge golden preflight requires literal BRIDGE_VERSION")
    if require_symbols and (not isinstance(max_response, int) or isinstance(max_response, bool) or max_response <= 0):
        raise RuntimeError("Test 3.0 bridge golden preflight requires positive MAX_RESPONSE_BYTES")
    golden = {
        "schema_version": GOLDEN_PREFLIGHT_SCHEMA_VERSION,
        "required_symbols": sorted(REQUIRED_BRIDGE_SYMBOLS),
        "symbol_digest": _canonical_digest(sorted(names)),
        "bridge_version": version,
        "max_response_bytes": max_response,
    }
    golden["golden_digest"] = _canonical_digest(golden)
    return golden


def _verify_bridge_pin(
    path: Path,
    manifest_path: Path | None = None,
    *,
    require_pin: bool = True,
    require_manifest: bool = False,
    check_golden: bool = False,
) -> dict[str, Any]:
    """Hash and validate the bridge before executing any bridge module code.

    A pin is fail-closed by default.  ``require_manifest`` is used by the
    executable entrypoint so every live run also carries a versioned manifest;
    ``check_golden`` keeps static symbol/version checks ahead of import.
    """

    bridge_path = path.resolve(strict=True)
    if not bridge_path.is_file():
        raise RuntimeError("Test 3.0 bridge path is not a regular file")
    actual_sha256 = hashlib.sha256(bridge_path.read_bytes()).hexdigest()
    candidate_manifest = manifest_path
    if candidate_manifest is None:
        configured_manifest = os.environ.get(BRIDGE_MANIFEST_ENV)
        if configured_manifest:
            candidate_manifest = Path(configured_manifest)
    if require_manifest and candidate_manifest is None:
        raise RuntimeError("Test 3.0 versioned bridge manifest is required")
    expected: set[str] = set()
    required_digests: set[str] = set()
    allowed_digests: set[str] = set()
    source = "none"
    manifest_data: Mapping[str, Any] = {}
    if candidate_manifest is not None:
        try:
            manifest_file = candidate_manifest.resolve(strict=True)
        except OSError as exc:
            raise RuntimeError("Test 3.0 bridge pin manifest is unavailable") from exc
        try:
            loaded = json.loads(manifest_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("invalid Test 3.0 bridge pin manifest") from exc
        if not isinstance(loaded, Mapping):
            raise RuntimeError("Test 3.0 bridge pin manifest must be an object")
        manifest_data = loaded
        source = "manifest"
        manifest_digest = loaded.get("manifest_digest")
        if manifest_digest is not None:
            normalized_manifest_digest = _normalise_sha256(manifest_digest)
            unsigned_manifest = {key: value for key, value in loaded.items() if key != "manifest_digest"}
            if normalized_manifest_digest is None or normalized_manifest_digest != _canonical_digest(unsigned_manifest):
                raise RuntimeError("Test 3.0 bridge manifest integrity digest does not match")
        manifest_version = loaded.get("manifest_version", loaded.get("schema_version"))
        if require_manifest and manifest_version != BRIDGE_MANIFEST_SCHEMA_VERSION:
            raise RuntimeError("Test 3.0 bridge manifest version is missing or unsupported")
        if manifest_version is not None and manifest_version != BRIDGE_MANIFEST_SCHEMA_VERSION:
            raise RuntimeError("Test 3.0 bridge manifest version is unsupported")
        for key in ("bridge_sha256", "sha256"):
            raw = loaded.get(key)
            if raw is not None:
                digest = _normalise_sha256(raw)
                if digest is None:
                    raise RuntimeError("Test 3.0 bridge pin manifest contains an invalid SHA-256")
                expected.add(digest)
                required_digests.add(digest)
        allowed = loaded.get("allowed_sha256")
        if allowed is not None:
            if not isinstance(allowed, list):
                raise RuntimeError("Test 3.0 bridge allowed_sha256 must be a list")
            for item in allowed:
                digest = _normalise_sha256(item)
                if digest is None:
                    raise RuntimeError("Test 3.0 bridge pin manifest contains an invalid allowed SHA-256")
                expected.add(digest)
                allowed_digests.add(digest)
        allowed_root = loaded.get("allowed_root")
        if isinstance(allowed_root, str) and allowed_root.strip():
            root = Path(allowed_root).resolve(strict=True)
            if not bridge_path.is_relative_to(root):
                raise RuntimeError("Test 3.0 bridge is outside the pinned root")
        elif allowed_root is not None:
            raise RuntimeError("Test 3.0 bridge allowed_root must be a path")
        if require_manifest:
            if not isinstance(manifest_digest, str) or _normalise_sha256(manifest_digest) is None:
                raise RuntimeError("Test 3.0 bridge manifest requires an integrity digest")
            golden_digest = loaded.get("golden_digest")
            if not isinstance(golden_digest, str) or not golden_digest.strip():
                raise RuntimeError("Test 3.0 bridge manifest requires a golden preflight digest")
            adapter_pin = loaded.get("adapter_sha256")
            if not isinstance(adapter_pin, str) or not adapter_pin.strip():
                raise RuntimeError("Test 3.0 bridge manifest requires an adapter SHA-256")
            profile_value = loaded.get("evaluation_profile", loaded.get("profile"))
            if not isinstance(profile_value, str) or not profile_value.strip():
                raise RuntimeError("Test 3.0 bridge manifest requires an evaluation profile")
            agent_git_sha = loaded.get("agent_git_sha")
            if not isinstance(agent_git_sha, str) or re.fullmatch(r"[0-9a-fA-F]{40,64}", agent_git_sha) is None:
                raise RuntimeError("Test 3.0 bridge manifest requires a pinned Agent git SHA")
            agent_snapshot_digest = loaded.get("agent_snapshot_digest")
            if _normalise_sha256(agent_snapshot_digest) is None:
                raise RuntimeError("Test 3.0 bridge manifest requires a pinned Agent snapshot digest")
    environment_raw = os.environ.get(BRIDGE_PIN_ENV, "")
    environment_expected = _normalise_sha256(environment_raw) if environment_raw else None
    if environment_raw and environment_expected is None:
        raise RuntimeError("Test 3.0 bridge environment pin is not a SHA-256")
    if environment_expected:
        expected.add(environment_expected)
        required_digests.add(environment_expected)
        source = "environment" if source == "none" else "manifest+environment"
    if candidate_manifest is not None and not expected:
        raise RuntimeError("Test 3.0 bridge pin manifest has no valid SHA-256")
    if require_pin and not expected:
        raise RuntimeError("Test 3.0 bridge pin is required but no SHA-256 was supplied")
    # Exact pins are assertions; an allowed list is intentionally an OR-set.
    # A stale exact manifest must not be bypassed merely because an environment
    # pin happens to match (and vice versa).
    if required_digests and any(digest != actual_sha256 for digest in required_digests):
        raise RuntimeError("Test 3.0 bridge SHA-256 does not match the pinned digest")
    if allowed_digests and actual_sha256 not in allowed_digests:
        raise RuntimeError("Test 3.0 bridge SHA-256 does not match the pinned digest")
    golden = _golden_preflight(bridge_path, require_symbols=check_golden)
    expected_golden = manifest_data.get("golden_digest")
    if expected_golden is not None and expected_golden != golden["golden_digest"]:
        raise RuntimeError("Test 3.0 bridge golden preflight digest does not match the manifest")
    expected_golden_object = manifest_data.get("golden_preflight")
    if isinstance(expected_golden_object, Mapping) and (
        _canonical_digest({key: value for key, value in expected_golden_object.items() if key != "golden_digest"})
        != golden["golden_digest"]
    ):
        raise RuntimeError("Test 3.0 bridge golden preflight record does not match the manifest")
    expected_version = manifest_data.get("bridge_version", manifest_data.get("version"))
    if expected_version is not None and golden.get("bridge_version") is not None:
        if str(expected_version) != str(golden["bridge_version"]):
            raise RuntimeError("Test 3.0 bridge version does not match the manifest")
    profile = manifest_data.get("evaluation_profile", manifest_data.get("profile"))
    current_profile = _config_snapshot()["profile"]
    if profile is not None and str(profile) != str(current_profile):
        raise RuntimeError("Test 3.0 bridge evaluation profile does not match the manifest")
    adapter_sha256 = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()
    expected_adapter_sha256 = manifest_data.get("adapter_sha256")
    if expected_adapter_sha256 is not None:
        normalized_adapter = _normalise_sha256(expected_adapter_sha256)
        if normalized_adapter is None or normalized_adapter != adapter_sha256:
            raise RuntimeError("SecMind adapter SHA-256 does not match the pinned manifest")
    return {
        "bridge_sha256": actual_sha256,
        "bridge_pin_status": "VERIFIED" if expected else "UNPINNED",
        "bridge_pin_source": source,
        "bridge_expected_sha256": sorted(expected),
        "bridge_manifest_version": manifest_data.get("manifest_version", manifest_data.get("schema_version")),
        "bridge_expected_version": expected_version,
        "agent_expected_git_sha": manifest_data.get("agent_git_sha"),
        "agent_expected_snapshot_digest": manifest_data.get("agent_snapshot_digest"),
        "profile_expected": profile,
        "adapter_sha256": adapter_sha256,
        "adapter_expected_sha256": expected_adapter_sha256,
        "golden_preflight": golden,
    }


def build_bridge_manifest(
    bridge_path: Path,
    *,
    allowed_root: Path | None = None,
    agent_root: Path | None = None,
    evaluation_profile: str | None = None,
) -> dict[str, Any]:
    """Create the versioned pin manifest consumed by :func:`main`."""

    path = bridge_path.resolve(strict=True)
    golden = _golden_preflight(path, require_symbols=True)
    manifest: dict[str, Any] = {
        "manifest_version": BRIDGE_MANIFEST_SCHEMA_VERSION,
        "bridge_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "bridge_version": golden["bridge_version"],
        "golden_digest": golden["golden_digest"],
        "golden_preflight": golden,
        "adapter_sha256": hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest(),
        "evaluation_profile": (evaluation_profile or _config_snapshot()["profile"]).strip(),
    }
    if allowed_root is not None:
        manifest["allowed_root"] = str(allowed_root.resolve(strict=True))
    if evaluation_profile:
        manifest["evaluation_profile"] = evaluation_profile.strip()
    if agent_root is not None:
        snapshot = _agent_snapshot(agent_root)
        manifest["agent_git_sha"] = snapshot["agent_git_sha"]
        manifest["agent_snapshot_digest"] = snapshot["agent_snapshot_digest"]
        manifest.setdefault("evaluation_profile", snapshot["agent_profile"])
    manifest["manifest_digest"] = _canonical_digest(manifest)
    return manifest


def write_bridge_manifest(manifest_path: Path, manifest: Mapping[str, Any]) -> Path:
    """Write a deterministic UTF-8 manifest without exposing credentials."""

    target = manifest_path.resolve()
    target.write_text(json.dumps(dict(manifest), ensure_ascii=True, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return target


def _git_value(root: Path, *arguments: str) -> str | None:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed git executable and trusted repository root
            ["git", "-C", str(root), *arguments],  # noqa: S607 - git is the fixed VCS executable
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    return value or None


def _dependency_snapshot(root: Path) -> dict[str, Any]:
    names: set[str] = set()
    for pattern in ("*.lock", "requirements*.txt", "pyproject.toml", "poetry.lock", "Pipfile"):
        names.update(path.name for path in root.glob(pattern) if path.is_file())
    files: dict[str, str] = {}
    for name in sorted(names):
        path = root / name
        try:
            files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            continue
    return {
        "files": files,
        "lockfile_digest": _canonical_digest(files),
        "dependency_digest": _canonical_digest({"files": files, "python": sys.version.split()[0]}),
    }


def _config_snapshot() -> dict[str, Any]:
    profile_keys = (
        "SECMIND_EVALUATION_PROFILE",
        "SECMIND_PROFILE",
        "SECMIND_PROMPT_PROFILE",
        "SECMIND_AUDIT_PROFILE",
    )
    profile = next(
        (os.environ[key].strip()[:128] for key in profile_keys if os.environ.get(key, "").strip()),
        "unknown",
    )
    flags: dict[str, Any] = {}
    for key, value in sorted(os.environ.items()):
        if not key.startswith("SECMIND_"):
            continue
        # This marker is injected only when the wrapper re-execs the same
        # candidate interpreter.  It is a transport detail, not an effective
        # evaluation profile input; including it would make a pinned agent
        # snapshot fail solely because the child process was entered.
        if key == "SECMIND_V083_PINNED_ENV":
            continue
        sensitive = any(token in key.casefold() for token in ("key", "token", "secret", "password", "credential"))
        flags[key] = {"present": True, "redacted": sensitive}
        if not sensitive:
            flags[key]["value_sha256"] = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()
    snapshot = {
        "profile": profile,
        "flags": flags,
        "config_digest": _canonical_digest({"profile": profile, "flags": flags}),
        "effective_env_digest": _canonical_digest(flags),
    }
    return snapshot


def _agent_snapshot(agent_root: Path) -> dict[str, Any]:
    root = agent_root.resolve()
    dependencies = _dependency_snapshot(root)
    config = _config_snapshot()
    snapshot: dict[str, Any] = {
        "agent_git_sha": _git_value(root, "rev-parse", "HEAD") or "UNKNOWN",
        "agent_git_tree_sha": _git_value(root, "rev-parse", "HEAD^{tree}") or "UNKNOWN",
        "agent_git_dirty": bool(_git_value(root, "status", "--porcelain", "--untracked-files=all")),
        "agent_dependency_digest": dependencies["dependency_digest"],
        "agent_lockfile_digest": dependencies["lockfile_digest"],
        "dependency_files": dependencies["files"],
        "agent_config_digest": config["config_digest"],
        "agent_effective_env_digest": config["effective_env_digest"],
        "agent_profile": config["profile"],
    }
    snapshot["agent_snapshot_digest"] = _canonical_digest(snapshot)
    return snapshot


def _agent_root_from_args(arguments: list[str]) -> Path:
    try:
        root_index = arguments.index("--agent-root") + 1
        return Path(arguments[root_index]).resolve(strict=True)
    except (ValueError, IndexError, OSError):
        return REPOSITORY_ROOT


def _validate_agent_snapshot(
    snapshot: Mapping[str, Any],
    expected_git_sha: object = None,
    expected_profile: object = None,
    expected_snapshot_digest: object = None,
) -> dict[str, Any]:
    expected = expected_git_sha or os.environ.get(AGENT_SHA_ENV)
    expected_text = str(expected).strip().lower() if expected else ""
    actual = str(snapshot.get("agent_git_sha", "")).strip().lower()
    if expected_text and actual != expected_text:
        raise RuntimeError("SecMind agent git SHA does not match the pinned digest")
    expected_profile_text = str(expected_profile).strip() if expected_profile else ""
    if expected_profile_text and str(snapshot.get("agent_profile", "")).strip() != expected_profile_text:
        raise RuntimeError("SecMind evaluation profile does not match the pinned manifest")
    expected_snapshot_text = str(expected_snapshot_digest).strip().lower() if expected_snapshot_digest else ""
    if expected_snapshot_text and (
        str(snapshot.get("agent_snapshot_digest", "")).strip().lower() != expected_snapshot_text
    ):
        raise RuntimeError("SecMind agent snapshot digest does not match the pinned manifest")
    return {
        "agent_pin_status": "VERIFIED" if expected_text else "UNPINNED",
        "agent_expected_git_sha": expected_text or None,
        "profile_pin_status": "VERIFIED" if expected_profile_text else "UNPINNED",
        "profile_expected": expected_profile_text or None,
        "agent_snapshot_pin_status": "VERIFIED" if expected_snapshot_text else "UNPINNED",
        "agent_snapshot_expected_digest": expected_snapshot_text or None,
    }


def _trusted_request_task(request: Any) -> dict[str, Any]:
    """Merge evaluator-owned request identity into the task contract only."""

    raw_task = getattr(request, "task", {})
    task = dict(raw_task) if isinstance(raw_task, Mapping) else {}
    for key in (
        "task_id",
        "invocation_id",
        "case_id",
        "question_id",
        "benchmark_id",
        "category",
        "task_version",
        "dataset_version",
        "evaluation_profile",
        "randomization_block",
        "block_id",
    ):
        value = getattr(request, key, None)
        if value is not None and key not in task:
            task[key] = value
    return task


def _run_manifest(
    bridge_snapshot: Mapping[str, Any],
    agent_snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "schema_version": "secmind-run-manifest-v0.8.6-1",
        "bridge_manifest_schema_version": BRIDGE_MANIFEST_SCHEMA_VERSION,
        "adapter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        **{str(key): value for key, value in bridge_snapshot.items()},
        **{str(key): value for key, value in agent_snapshot.items()},
    }
    manifest["run_manifest_digest"] = _canonical_digest(manifest)
    return manifest


class _RobustTemporaryDirectory:
    """Windows-safe task directory whose cleanup cannot erase a valid result."""

    def __init__(self, *, prefix: str) -> None:
        self.name = tempfile.mkdtemp(prefix=prefix)

    def __enter__(self) -> str:
        return self.name

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> Literal[False]:
        for attempt in range(8):
            try:
                shutil.rmtree(self.name)
                return False
            except FileNotFoundError:
                return False
            except OSError:
                time.sleep(0.1 * (attempt + 1))
        # A late-closing SQLite handle must not replace a completed answer with
        # INFRA_ERROR. Retry once at process exit, after all imported services
        # and threads have terminated; never mask the original task outcome.
        atexit.register(shutil.rmtree, self.name, True)
        return False


def _load_bridge(path: Path, expected_sha256: str | None = None) -> ModuleType:
    bridge_path = path.resolve(strict=True)
    source = bridge_path.read_bytes()
    current_sha256 = hashlib.sha256(source).hexdigest()
    if expected_sha256 is None or current_sha256 != expected_sha256:
        raise RuntimeError("Test 3.0 bridge changed or has no preflight digest pin")
    golden = _golden_preflight(bridge_path, require_symbols=True)
    code = compile(source, str(bridge_path), "exec", dont_inherit=True)
    module = ModuleType("secmind_test3_platform_bridge")
    module.__file__ = str(bridge_path)
    module.__package__ = ""
    spec = importlib.util.spec_from_file_location(module.__name__, bridge_path)
    if spec is not None:
        module.__spec__ = spec
        module.__loader__ = spec.loader
    sys.modules[module.__name__] = module
    exec(code, module.__dict__)  # noqa: S102 - pinned source is compiled after digest/golden preflight
    required = REQUIRED_BRIDGE_SYMBOLS
    missing = sorted(required.difference(module.__dict__))
    if missing:
        raise RuntimeError(f"unsupported Test 3.0 bridge contract; missing {', '.join(missing)}")
    if str(getattr(module, "BRIDGE_VERSION", "")) != str(golden.get("bridge_version")):
        raise RuntimeError("Test 3.0 bridge version changed during import")
    if int(getattr(module, "MAX_RESPONSE_BYTES", 0)) != int(golden.get("max_response_bytes", 0)):
        raise RuntimeError("Test 3.0 bridge response limit changed during import")
    if hashlib.sha256(bridge_path.read_bytes()).hexdigest() != expected_sha256:
        raise RuntimeError("Test 3.0 bridge changed during import")
    return module


def _force_stop_service_process(process: Any) -> None:
    """Best-effort process-tree kill used only when the platform hook fails."""

    pid = getattr(process, "pid", None)
    if isinstance(pid, int) and pid > 0:
        if os.name == "nt":
            try:
                subprocess.run(  # noqa: S603, S607 - fixed Windows process-tree cleanup command
                    ["taskkill.exe", "/PID", str(pid), "/T", "/F"],  # noqa: S607 - fixed executable
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                pass
        else:
            try:
                killpg = getattr(os, "killpg", None)
                if callable(killpg):
                    killpg(pid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass
    try:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
    except (OSError, subprocess.SubprocessError, AttributeError):
        try:
            process.kill()
            process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError, AttributeError):
            pass


def _stop_service_process(bridge: ModuleType, process: Any) -> None:
    """Stop a service and its process tree without masking the startup error."""

    if process is None:
        return
    stop_service = bridge.__dict__.get("stop_service")
    try:
        if callable(stop_service):
            stop_service(process)
    except BaseException:
        # Cleanup must not replace the health/startup exception.  The fallback
        # below still attempts both process-tree and direct-child termination.
        _force_stop_service_process(process)
    try:
        alive = process.poll() is None
    except (OSError, AttributeError):
        alive = True
    if alive:
        _force_stop_service_process(process)


def _safe_start_service(
    bridge: ModuleType,
    agent_root: Path,
    *,
    environment: Mapping[str, str],
    port: int,
) -> Any:
    """Start the platform service with cleanup on every startup exception.

    The platform Bridge is loaded from a pinned external source, so the adapter
    supplies this narrow wrapper rather than editing that source. Its normal
    successful path is identical to the platform implementation; only startup
    exception handling is strengthened. HTTP retry policy remains in the
    patched client and is intentionally not involved here.
    """

    service_commands = bridge.__dict__.get("service_commands")
    wait_for_health = bridge.__dict__.get("wait_for_health")
    server_process_type = bridge.__dict__.get("ServerProcess")
    client_type = bridge.__dict__.get("SecMindClient")
    bridge_error_type = bridge.__dict__.get("BridgeError")
    agent_process_error_type = bridge.__dict__.get("AgentProcessError")
    platform_subprocess = bridge.__dict__.get("subprocess", subprocess)
    if not callable(service_commands) or not callable(wait_for_health):
        raise RuntimeError("Test 3.0 platform bridge does not expose service startup hooks")
    if not callable(server_process_type) or not callable(client_type):
        raise RuntimeError("Test 3.0 platform bridge does not expose service types")
    if not isinstance(bridge_error_type, type) or not isinstance(agent_process_error_type, type):
        raise RuntimeError("Test 3.0 platform bridge does not expose service error types")

    errors: list[str] = []
    for base_command in service_commands(agent_root):
        command = list(base_command)
        if "uvicorn" in command:
            command.extend(["--port", str(port)])
        process: Any = None
        keep_process = False
        try:
            process = platform_subprocess.Popen(  # noqa: S603 - command is restricted by the pinned Bridge
                command,
                cwd=agent_root,
                env=dict(environment),
                stdin=platform_subprocess.DEVNULL,
                stdout=platform_subprocess.DEVNULL,
                stderr=platform_subprocess.STDOUT,
                start_new_session=os.name != "nt",
                creationflags=(getattr(platform_subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0),
            )
            server = server_process_type(process, client_type(port))
            wait_for_health(server)
            keep_process = True
            return server
        except Exception as exc:
            if isinstance(exc, bridge_error_type):
                errors.append(str(exc))
            else:
                raise
        finally:
            if not keep_process:
                _stop_service_process(bridge, process)
    raise agent_process_error_type(f"could not start SecMind service ({'; '.join(errors)})")


def _install_contract_patches(
    bridge: ModuleType,
    *,
    bridge_sha256: str,
    bridge_snapshot: Mapping[str, Any] | None = None,
    agent_snapshot: Mapping[str, Any] | None = None,
    agent_root: Path | None = None,
) -> None:
    original_build = bridge.__dict__["build_task_payload"]
    original_convert = bridge.__dict__["convert_result"]
    original_client = bridge.__dict__["SecMindClient"]
    original_environment_builder = bridge.__dict__.get("build_service_environment")
    original_mode_resolver = bridge.__dict__.get("resolve_model_mode")
    pinned_bridge = dict(bridge_snapshot or {"bridge_sha256": bridge_sha256, "bridge_pin_status": "UNPINNED"})
    pinned_bridge.setdefault("bridge_sha256", bridge_sha256)
    pinned_agent = dict(agent_snapshot or _agent_snapshot(agent_root or REPOSITORY_ROOT))
    run_manifest = _run_manifest(pinned_bridge, pinned_agent)

    def build_task_payload(request: Any, upload: Any) -> dict[str, Any]:
        task = _trusted_request_task(request)
        return build_trusted_task_payload(original_build(request, upload), task)

    def resolve_model_mode(requested: str, environ: Mapping[str, str]) -> tuple[str, str | None]:
        """Allow an explicitly configured OpenAI-compatible credential path.

        The platform bridge predates provider-specific credentials and seals
        every live run to DeepSeek. Preserve that default, while allowing a
        reviewed candidate manifest to opt into the Agent's existing
        ``openai-compatible`` policy and dedicated key field.
        """

        provider = str(environ.get("SECMIND_MODEL_BASE_URL_PROVIDER", "")).strip()
        if requested != "live" or provider != "openai-compatible":
            if not callable(original_mode_resolver):
                raise bridge.BridgeError("platform bridge does not expose its model mode resolver")
            return original_mode_resolver(requested, environ)
        key = str(environ.get("SECMIND_OPENAI_API_KEY", "")).strip()
        if not key:
            raise bridge.BridgeError("live OpenAI-compatible mode requires SECMIND_OPENAI_API_KEY")
        return "live", key

    def build_service_environment(*args: Any, **kwargs: Any) -> dict[str, str]:
        """Keep one Primary plus one fallback inside the evaluator token cap.

        The generic bridge divides every task's combined model-token cap into
        a fixed 80/20 input/output envelope.  That makes a legal 16k Primary
        plus 12k bounded fallback impossible for 120k-token tasks: the output
        parent is only 24k and rejects recovery before transport.  Rebalance
        the same total cap without increasing it or weakening any per-request
        limit.
        """

        if not callable(original_environment_builder):
            raise bridge.BridgeError("platform bridge does not expose its service environment builder")
        raw_environment = original_environment_builder(*args, **kwargs)
        environment = {str(key): str(value) for key, value in dict(raw_environment).items()}
        # The token is process-local and passed only to the child service.  It
        # is never written into a task, report, manifest, or diagnostic; the
        # normal API consequently cannot request the value-bearing projection.
        environment["SECMIND_EVALUATION_BRIDGE_TOKEN"] = EVALUATION_RELEASE_TOKEN
        base = args[0] if args else kwargs.get("base")
        base_environment = base if isinstance(base, Mapping) else {}
        mode = str(kwargs.get("mode", ""))
        provider = str(base_environment.get("SECMIND_MODEL_BASE_URL_PROVIDER", "")).strip()
        if mode == "live" and provider == "openai-compatible":
            required_names = (
                "SECMIND_QWEN_BASE_URL",
                "SECMIND_TRUSTED_MODEL_BASE_URLS",
                "SECMIND_PLANNER_MODEL",
                "SECMIND_WORKER_MODEL",
                "SECMIND_FALLBACK_MODEL",
            )
            missing = [name for name in required_names if not str(base_environment.get(name, "")).strip()]
            if missing:
                raise bridge.BridgeError(
                    "OpenAI-compatible live mode is missing reviewed provider settings: " + ", ".join(missing)
                )
            api_key = str(kwargs.get("api_key", "")).strip()
            if not api_key:
                raise bridge.BridgeError("live OpenAI-compatible key was not resolved")
            environment.update(
                {name: str(base_environment[name]) for name in (*required_names, "SECMIND_MODEL_BASE_URL_PROVIDER")}
            )
            environment["SECMIND_OPENAI_API_KEY"] = api_key
            environment["SECMIND_QWEN_API_KEY"] = ""
            environment.pop("SECMIND_DEEPSEEK_API_KEY", None)
        task = kwargs.get("task")
        budget = task.get("budget") if isinstance(task, Mapping) else None
        token_cap = budget.get("model_token_cap") if isinstance(budget, Mapping) else None
        if not isinstance(token_cap, int) or isinstance(token_cap, bool) or token_cap <= 0:
            return environment
        bounded_cap = min(token_cap, 20_000_000)

        def positive_integer(name: str, default: int) -> int:
            try:
                value = int(environment.get(name, default))
            except (TypeError, ValueError):
                return default
            return max(1, value)

        primary_output = positive_integer("SECMIND_MODEL_MAX_OUTPUT_TOKENS", 16_000)
        fallback_output = positive_integer("SECMIND_MODEL_FALLBACK_MAX_OUTPUT_TOKENS", 12_000)
        minimum_input = 1_000
        recovery_output = min(primary_output + fallback_output, max(1_000, bounded_cap - minimum_input))
        configured_output = positive_integer("SECMIND_MAX_OUTPUT_TOKENS", 1_000)
        output_budget = min(bounded_cap - minimum_input, max(configured_output, recovery_output))
        input_budget = max(minimum_input, bounded_cap - output_budget)
        environment["SECMIND_MAX_INPUT_TOKENS"] = str(input_budget)
        environment["SECMIND_MAX_OUTPUT_TOKENS"] = str(output_budget)
        return environment

    def convert_result(
        request: Any,
        summary: Any,
        report: Any,
        *,
        wall_time: float,
        report_error: str | None = None,
    ) -> dict[str, Any]:
        task = _trusted_request_task(request)
        # The platform converter is allowed to return a compatibility
        # projection whose locators no longer match the server attestation.
        # Snapshot the server report before invoking it, then use that
        # immutable snapshot for both exact-answer decisions in this wrapper
        # and the integration projection.  Never re-sign a scrubbed result.
        raw_report = deepcopy(dict(report)) if isinstance(report, Mapping) else None
        if raw_report is not None:
            raw_report = _restore_input_bound_paths(
                raw_report,
                Path(request.input_dir),
                iter_safe_files=bridge.iter_safe_files,
            )
        raw_report_for_trust = raw_report if raw_report is not None else {}
        raw_answer_payload = raw_report_for_trust.get("answer_payload", {})
        trusted_exact_answers = trusted_exact_answer_values(
            raw_answer_payload if isinstance(raw_answer_payload, Mapping) else {},
            raw_report_for_trust,
            task,
            report=raw_report,
        )
        base = original_convert(
            request,
            summary,
            raw_report if raw_report is not None else report,
            wall_time=wall_time,
            report_error=report_error,
        )
        # ``raw_report_for_trust`` is intentionally separate from ``base``:
        # the latter may have had source locators scrubbed or aliased by the
        # platform converter before this adapter sees it.
        projected = project_domain_result(
            base,
            raw_report if raw_report is not None else report,
            summary=summary,
            task=task,
            raw_report_for_trust=raw_report,
        )
        proof = projected.setdefault("run_proof", {})
        if isinstance(proof, dict):
            bridge_version = str(getattr(bridge, "BRIDGE_VERSION", "unknown"))
            proof["platform_bridge_sha256"] = bridge_sha256
            proof["platform_bridge_version"] = bridge_version
            proof["runtime_python"] = ".".join(str(part) for part in sys.version_info[:3])
            final_agent = _agent_snapshot(agent_root or REPOSITORY_ROOT)
            final_manifest = {
                **run_manifest,
                "bridge_version": bridge_version,
                "agent_snapshot_final_digest": final_agent["agent_snapshot_digest"],
            }
            final_manifest.pop("run_manifest_digest", None)
            final_manifest["run_manifest_digest"] = _canonical_digest(final_manifest)
            proof["run_manifest"] = final_manifest
            proof["run_manifest_digest"] = final_manifest["run_manifest_digest"]
            proof["snapshot_validation"] = {
                "bridge_sha256_matches_preflight": bridge_sha256 == pinned_bridge.get("bridge_sha256"),
                "agent_snapshot_consistent": final_agent["agent_snapshot_digest"]
                == pinned_agent.get("agent_snapshot_digest"),
                "agent_git_sha_matches_preflight": final_agent.get("agent_git_sha")
                == pinned_agent.get("agent_git_sha"),
            }
        # The bridge-owned proof fields are appended after the integration
        # projection, so run the complete artifact gate once more at the last
        # public boundary instead of assuming those fields are inherently
        # safe.
        return scrub_artifact(
            projected,
            max_depth=12,
            max_items=256,
            trusted_exact_answers=trusted_exact_answers,
        )

    class V083SecMindClient:
        def __init__(self, port: int, *, timeout: float = LOCAL_API_TIMEOUT_SECONDS) -> None:
            self.port = port
            self.timeout = timeout
            self._delegate = original_client(port, timeout=timeout)

        def request(self, *args: Any, **kwargs: Any) -> Any:
            method = str(args[0] if args else kwargs.get("method", "GET"))
            path = str(args[1] if len(args) > 1 else kwargs.get("path", "/"))
            body = kwargs.get("body")
            content_type = kwargs.get("content_type")
            accepted = tuple(kwargs.get("accepted", (200,)))
            headers = {
                "Accept": "application/json",
                "X-SecMind-Evaluation-Bridge": EVALUATION_RELEASE_TOKEN,
            }
            if content_type is not None:
                headers["Content-Type"] = str(content_type)
            attempts = IDEMPOTENT_GET_ATTEMPTS if method.upper() == "GET" else 1
            last_transport_error: Exception | None = None
            for attempt in range(1, attempts + 1):
                connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=self.timeout)
                try:
                    connection.request(method, path, body=body, headers=headers)
                    response = connection.getresponse()
                    raw = response.read(bridge.MAX_RESPONSE_BYTES + 1)
                except (OSError, http.client.HTTPException) as exc:
                    last_transport_error = exc
                    if attempt < attempts:
                        time.sleep(IDEMPOTENT_GET_RETRY_DELAY_SECONDS * attempt)
                        continue
                    raise bridge.BridgeError(
                        f"SecMind API transport failed for {method} {path}: {type(exc).__name__}"
                    ) from exc
                finally:
                    connection.close()
                if len(raw) > bridge.MAX_RESPONSE_BYTES:
                    raise bridge.BridgeError(f"SecMind API response exceeded 8 MiB for {method} {path}")
                try:
                    payload = json.loads(raw.decode("utf-8")) if raw else {}
                except (UnicodeError, json.JSONDecodeError) as exc:
                    if response.status >= 500 and attempt < attempts:
                        time.sleep(IDEMPOTENT_GET_RETRY_DELAY_SECONDS * attempt)
                        continue
                    digest = hashlib.sha256(raw).hexdigest()
                    media_type = str(response.getheader("Content-Type") or "unknown").split(";", 1)[0]
                    raise bridge.BridgeError(
                        f"SecMind API returned non-JSON HTTP {response.status} for {method} {path} "
                        f"(content_type={media_type}, bytes={len(raw)}, sha256={digest})"
                    ) from exc
                result = bridge._object(payload, "SecMind API response")  # noqa: SLF001
                if response.status not in accepted:
                    if response.status >= 500 and attempt < attempts:
                        time.sleep(IDEMPOTENT_GET_RETRY_DELAY_SECONDS * attempt)
                        continue
                    detail = result.get("detail")
                    message = detail if isinstance(detail, str) else f"HTTP {response.status}"
                    raise bridge.BridgeError(f"SecMind API rejected {method} {path}: {message}")
                return response.status, result
            error_name = type(last_transport_error).__name__ if last_transport_error is not None else "unknown"
            raise bridge.BridgeError(f"SecMind API transport failed for {method} {path}: {error_name}")

        def health(self) -> bool:
            try:
                status, payload = self.request("GET", "/health/live", accepted=(200,))
            except bridge.BridgeError:
                return False
            return status == 200 and payload.get("status") == "ok"

        def create_task(self, payload: Any) -> str:
            # This is a local control-plane request, not a log sink.  Redacting
            # it mutates opaque attachment references: the secret scrubber can
            # classify a random UUID as high entropy and turn
            # ``<uuid>-evaluation-input.zip`` into ``[REDACTED].zip``.  The
            # subsequent ingest then fails nondeterministically even though
            # the immutable upload exists.  Untrusted task content must reach
            # the Agent byte-for-byte; scrub only outbound diagnostics/results.
            _, result = self.request(
                "POST",
                "/api/v1/tasks",
                body=json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
                content_type="application/json",
                accepted=(202,),
            )
            run_id = result.get("run_id")
            if not isinstance(run_id, str) or not run_id:
                raise bridge.BridgeError("SecMind task response is missing run_id")
            return run_id

        def summary(self, run_id: str) -> dict[str, Any]:
            encoded_run_id = quote(str(run_id), safe="")
            return dict(self.request("GET", f"/api/v1/runs/{encoded_run_id}", accepted=(200,))[1])

        def report(self, run_id: str) -> dict[str, Any]:
            encoded_run_id = quote(str(run_id), safe="")
            return dict(
                self.request(
                    "GET",
                    f"/api/v1/runs/{encoded_run_id}/report?format=json&audience=evaluation",
                    accepted=(200,),
                )[1]
            )

        def read_page(
            self,
            run_id_or_source: Any,
            collection: str = "evidence",
            *,
            cursor: str | None = None,
            page_size: int = 64,
        ) -> dict[str, Any]:
            """Read a bounded projection page, locally or through the API.

            Local mappings/sequences are useful for deterministic replay.  A
            live run uses the read-only report endpoint with an integrity-
            checked cursor; the endpoint may return a page directly or a
            collection envelope, both are normalized to the Test 3 contract.
            """

            if isinstance(run_id_or_source, Mapping) or (
                isinstance(run_id_or_source, (list, tuple))
                and not isinstance(run_id_or_source, (str, bytes, bytearray))
            ):
                return read_projection_page(
                    run_id_or_source,
                    collection=collection,
                    cursor=cursor,
                    page_size=page_size,
                )
            run_id = quote(str(run_id_or_source), safe="")
            name = quote(str(collection), safe="")
            if isinstance(page_size, bool) or not isinstance(page_size, int) or page_size < 1:
                raise bridge.BridgeError("SecMind projection page_size must be a positive integer")
            collection_name = str(collection).casefold()
            cap = (
                MAX_PUBLIC_EVIDENCE
                if collection_name == "evidence"
                else MAX_PUBLIC_FINDINGS
                if collection_name == "findings"
                else MAX_PUBLIC_ITEMS_PER_FIELD
            )
            page_size = min(page_size, cap)
            query = f"format=json&collection={name}&limit={page_size}"
            if cursor:
                query += "&cursor=" + quote(cursor, safe="")
            payload = self.request("GET", f"/api/v1/runs/{run_id}/report?{query}", accepted=(200,))[1]
            if isinstance(payload, Mapping) and isinstance(payload.get("items"), list):
                return dict(payload)
            if isinstance(payload, Mapping):
                return read_projection_page(payload, collection=collection, cursor=cursor, page_size=page_size)
            raise bridge.BridgeError("SecMind projection page response is not an object")

        read_projection_page = read_page
        read = read_page

        def iter_pages(
            self,
            run_id_or_source: Any,
            collection: str = "evidence",
            *,
            page_size: int = 64,
        ):
            cursor: str | None = None
            for _ in range(10_000):
                page = self.read_page(
                    run_id_or_source,
                    collection,
                    cursor=cursor,
                    page_size=page_size,
                )
                yield page
                cursor = page.get("next_cursor") if isinstance(page, Mapping) else None
                if not cursor:
                    return
            raise bridge.BridgeError("SecMind projection pagination exceeded the safety page limit")

        def download(
            self,
            run_id: str,
            artifact_id: str,
            *,
            expected_sha256: str | None = None,
            view: str | None = None,
            purpose: str = "bridge_artifact_download",
        ) -> bytes:
            """Download an authorized artifact with a hard byte cap and digest."""

            path = f"/api/v1/runs/{quote(str(run_id), safe='')}/artifacts/{quote(str(artifact_id), safe='')}"
            if view:
                path += "?view=" + quote(str(view), safe="")
            headers = {"Accept": "application/octet-stream"}
            purpose_text = str(purpose).strip() if purpose is not None else ""
            if purpose_text:
                headers["X-SecMind-Access-Purpose"] = purpose_text[:200]
            connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=self.timeout)
            try:
                connection.request("GET", path, headers=headers)
                response = connection.getresponse()
                raw = response.read(bridge.MAX_RESPONSE_BYTES + 1)
            except OSError as exc:
                raise bridge.BridgeError(f"SecMind artifact download failed: {type(exc).__name__}") from exc
            finally:
                connection.close()
            if len(raw) > bridge.MAX_RESPONSE_BYTES:
                raise bridge.BridgeError("SecMind artifact exceeded the bridge response limit")
            if response.status != 200:
                raise bridge.BridgeError(f"SecMind artifact download rejected: HTTP {response.status}")
            digest = hashlib.sha256(raw).hexdigest()
            if expected_sha256 is not None and _normalise_sha256(expected_sha256) != digest:
                raise bridge.BridgeError("SecMind artifact digest does not match the requested artifact")
            return raw

        read_artifact = download

        def upload(self, archive_path: Path) -> dict[str, Any]:
            boundary = f"secmind-v083-{uuid.uuid4().hex}"
            prefix = (
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="file"; filename="evaluation-input.zip"\r\n'
                "Content-Type: application/zip\r\n\r\n"
            ).encode("ascii")
            suffix = f"\r\n--{boundary}--\r\n".encode("ascii")
            length = len(prefix) + archive_path.stat().st_size + len(suffix)
            connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=self.timeout)
            try:
                connection.putrequest("POST", "/api/v1/uploads")
                connection.putheader("Accept", "application/json")
                connection.putheader("Content-Type", f"multipart/form-data; boundary={boundary}")
                connection.putheader("Content-Length", str(length))
                connection.endheaders()
                connection.send(prefix)
                with archive_path.open("rb") as stream:
                    while chunk := stream.read(UPLOAD_CHUNK_BYTES):
                        connection.send(chunk)
                connection.send(suffix)
                response = connection.getresponse()
                raw = response.read(bridge.MAX_RESPONSE_BYTES + 1)
            except OSError as exc:
                raise bridge.BridgeError(f"SecMind streaming upload failed: {type(exc).__name__}") from exc
            finally:
                connection.close()
            if len(raw) > bridge.MAX_RESPONSE_BYTES:
                raise bridge.BridgeError("SecMind API response exceeded 8 MiB")
            try:
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise bridge.BridgeError("SecMind API returned invalid JSON") from exc
            result = bridge._object(payload, "SecMind API response")  # noqa: SLF001
            if response.status != 201:
                detail = result.get("detail")
                message = detail if isinstance(detail, str) else f"HTTP {response.status}"
                raise bridge.BridgeError(f"SecMind API rejected the request: {message}")
            if not isinstance(result.get("ref"), str):
                raise bridge.BridgeError("SecMind upload response is missing ref")
            return result

    bridge.__dict__["build_task_payload"] = build_task_payload
    if callable(original_mode_resolver):
        bridge.__dict__["resolve_model_mode"] = resolve_model_mode
    if callable(original_environment_builder):
        bridge.__dict__["build_service_environment"] = build_service_environment
    bridge.__dict__["convert_result"] = convert_result
    bridge.__dict__["SecMindClient"] = V083SecMindClient
    bridge.__dict__["tempfile"] = SimpleNamespace(TemporaryDirectory=_RobustTemporaryDirectory)
    if callable(bridge.__dict__.get("_start_service")):

        def start_service(
            agent_root: Path,
            *,
            environment: Mapping[str, str],
            port: int,
        ) -> Any:
            return _safe_start_service(
                bridge,
                agent_root,
                environment=environment,
                port=port,
            )

        bridge.__dict__["_start_service"] = start_service


def _run_in_agent_environment(
    remaining: list[str],
    platform_bridge: Path,
    bridge_manifest: Path | None = None,
) -> int | None:
    """Pin evaluation to the candidate's installed dependency environment."""

    if os.environ.get("SECMIND_V083_PINNED_ENV") == "1":
        return None
    try:
        root_index = remaining.index("--agent-root") + 1
        agent_root = Path(remaining[root_index]).resolve(strict=True)
    except (ValueError, IndexError, OSError):
        return None
    candidates = (
        agent_root / ".venv" / "Scripts" / "python.exe",
        agent_root / ".venv" / "bin" / "python",
    )
    target = next((candidate for candidate in candidates if candidate.is_file()), None)
    if target is None:
        return None
    try:
        if target.samefile(Path(sys.executable)):
            return None
    except OSError:
        if target.resolve() == Path(sys.executable).resolve():
            return None
    environment = os.environ.copy()
    environment["SECMIND_V083_PINNED_ENV"] = "1"
    _pin_source_path(environment)
    child_arguments = [
        str(target),
        str(Path(__file__).resolve()),
        "--platform-bridge",
        str(platform_bridge),
    ]
    if bridge_manifest is not None:
        child_arguments.extend(("--bridge-manifest", str(bridge_manifest)))
    child_arguments.extend(remaining)
    completed = subprocess.run(  # noqa: S603 - fixed interpreter under the trusted agent root
        child_arguments,
        env=environment,
        check=False,
    )
    return int(completed.returncode)


def main(argv: list[str] | None = None) -> int:
    _pin_source_path(os.environ)
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--platform-bridge", type=Path, required=True)
    parser.add_argument("--bridge-manifest", type=Path)
    arguments, remaining = parser.parse_known_args(argv)
    bridge_path = arguments.platform_bridge.resolve(strict=True)
    bridge_snapshot = _verify_bridge_pin(
        bridge_path,
        arguments.bridge_manifest,
        require_pin=True,
        require_manifest=True,
        check_golden=True,
    )
    agent_root = _agent_root_from_args(remaining)
    agent_snapshot = _agent_snapshot(agent_root)
    bridge_snapshot = {
        **bridge_snapshot,
        **_validate_agent_snapshot(
            agent_snapshot,
            bridge_snapshot.get("agent_expected_git_sha"),
            bridge_snapshot.get("profile_expected"),
            bridge_snapshot.get("agent_expected_snapshot_digest"),
        ),
    }
    exit_code = _run_in_agent_environment(remaining, bridge_path, arguments.bridge_manifest)
    if exit_code is not None:
        return exit_code
    bridge_sha256 = str(bridge_snapshot["bridge_sha256"])
    bridge = _load_bridge(bridge_path, bridge_sha256)
    expected_version = bridge_snapshot.get("bridge_expected_version")
    if expected_version is not None and str(expected_version) != str(getattr(bridge, "BRIDGE_VERSION", "unknown")):
        raise RuntimeError("Test 3.0 bridge version does not match the pinned manifest")
    _install_contract_patches(
        bridge,
        bridge_sha256=bridge_sha256,
        bridge_snapshot=bridge_snapshot,
        agent_snapshot=agent_snapshot,
        agent_root=agent_root,
    )
    return int(bridge.main(remaining))


if __name__ == "__main__":
    raise SystemExit(main())
