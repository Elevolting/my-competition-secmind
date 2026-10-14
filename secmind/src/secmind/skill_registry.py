from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from secmind.schemas import AuditSkillManifest, RiskLevel, Scenario, ToolHealth
from secmind.skill_usage import record_skill_load
from secmind.source_triage import routing_terms_for_signals

BUILTIN_SKILL_ROOT = Path(__file__).with_name("builtin_skills")
BUILTIN_TRUST_ROOT = BUILTIN_SKILL_ROOT / "trust"
MANIFEST_NAME = "secmind-skill.json"
INSTRUCTIONS_NAME = "SKILL.md"
_SKILL_ID = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,2}(?:[-+][A-Za-z0-9.-]+)?$")
_TEXT_SUFFIXES = {".json", ".md", ".txt", ".yaml", ".yml"}


class SkillPackageError(ValueError):
    """A platform skill package is malformed, untrusted, or has been tampered with."""


@dataclass(frozen=True)
class SkillCatalogEntry:
    """Prompt-safe metadata loaded without materializing the skill instructions."""

    skill_id: str
    version: str
    description: str
    trigger_terms: tuple[str, ...]
    supported_languages: tuple[str, ...]
    scenarios: tuple[Scenario, ...]
    required_capabilities: tuple[str, ...]
    allowed_agent_profiles: tuple[str, ...]
    risk_ceiling: RiskLevel
    max_turns: int
    package_digest: str
    signer: str
    health: ToolHealth = ToolHealth.HEALTHY


@dataclass(frozen=True)
class LoadedAuditSkill:
    """A verified skill body materialized only after explicit selection."""

    manifest: AuditSkillManifest
    instructions: str
    references: dict[str, str]
    examples: dict[str, str]


@dataclass(frozen=True)
class _DiscoveredSkill:
    manifest: AuditSkillManifest
    package_dir: Path
    raw_manifest: dict[str, Any]


class SkillRegistry:
    """Registry for signed, platform-owned Audit Skill packages.

    Discovery reads and authenticates only ``secmind-skill.json``. The complete
    package digest, SKILL.md, references and examples are read only by ``load``.
    The registry never searches task workspaces, so repository-provided Skill,
    Hook or agent instruction files cannot register themselves.
    """

    def __init__(
        self,
        platform_root: Path,
        trusted_signers: dict[str, Ed25519PublicKey],
        *,
        approved_capabilities: set[str] | None = None,
        maximum_risk: RiskLevel = RiskLevel.R1,
        max_manifest_bytes: int = 128 * 1024,
        max_package_bytes: int = 4 * 1024 * 1024,
        max_package_files: int = 256,
    ) -> None:
        self.platform_root = _resolved_directory(platform_root, "skill platform root")
        if not trusted_signers:
            raise SkillPackageError("at least one trusted skill signer is required")
        self.trusted_signers = dict(trusted_signers)
        self.approved_capabilities = None if approved_capabilities is None else set(approved_capabilities)
        self.maximum_risk = maximum_risk
        self.max_manifest_bytes = max_manifest_bytes
        self.max_package_bytes = max_package_bytes
        self.max_package_files = max_package_files
        self._skills: dict[tuple[str, str], _DiscoveredSkill] = {}
        self._latest: dict[str, str] = {}

    @classmethod
    def builtin(cls, *, approved_capabilities: set[str] | None = None) -> SkillRegistry:
        return cls(
            BUILTIN_SKILL_ROOT,
            load_trust_roots(BUILTIN_TRUST_ROOT),
            approved_capabilities=approved_capabilities,
        )

    def discover(self) -> list[SkillCatalogEntry]:
        discovered: dict[tuple[str, str], _DiscoveredSkill] = {}
        latest: dict[str, str] = {}
        for package_dir in sorted(self.platform_root.iterdir(), key=lambda item: item.name):
            if package_dir.name.startswith("_") or package_dir == BUILTIN_TRUST_ROOT:
                continue
            if package_dir.is_symlink():
                raise SkillPackageError(f"skill package cannot be a symbolic link: {package_dir.name}")
            if not package_dir.is_dir():
                continue
            resolved = package_dir.resolve(strict=True)
            if resolved.parent != self.platform_root:
                raise SkillPackageError("skill package escaped the platform skill root")
            manifest_path = resolved / MANIFEST_NAME
            if not manifest_path.is_file():
                continue
            raw = _read_manifest(manifest_path, self.max_manifest_bytes)
            try:
                manifest = AuditSkillManifest.model_validate(raw)
            except Exception as exc:
                raise SkillPackageError(f"invalid skill manifest in {package_dir.name}") from exc
            self._validate_manifest(manifest, raw, package_dir.name)
            key = (manifest.skill_id, manifest.version)
            if key in discovered:
                raise SkillPackageError(f"duplicate skill version: {manifest.skill_id}@{manifest.version}")
            discovered[key] = _DiscoveredSkill(manifest, resolved, raw)
            current = latest.get(manifest.skill_id)
            if current is None or _version_key(manifest.version) > _version_key(current):
                latest[manifest.skill_id] = manifest.version
        self._skills = discovered
        self._latest = latest
        return self.catalog()

    def catalog(self) -> list[SkillCatalogEntry]:
        return [
            _catalog_entry(item.manifest)
            for _, item in sorted(self._skills.items(), key=lambda pair: (pair[0][0], _version_key(pair[0][1])))
        ]

    def select(
        self,
        *,
        objective: str,
        scenario: Scenario,
        languages: set[str] | None = None,
        agent_profile: str | None = None,
        required_capabilities: set[str] | None = None,
        risk_ceiling: RiskLevel = RiskLevel.R1,
        limit: int = 6,
        source_signals: Iterable[str] | None = None,
    ) -> list[SkillCatalogEntry]:
        if limit < 1:
            return []
        normalized_languages = {item.casefold() for item in languages or set()}
        required = set(required_capabilities or set())
        normalized_objective = objective.casefold()
        objective_terms = set(re.findall(r"[a-z0-9_+-]+", normalized_objective))
        routing_terms = routing_terms_for_signals(source_signals or ())
        ranked: list[tuple[tuple[int, int, int, int, str], SkillCatalogEntry]] = []
        for skill_id, version in self._latest.items():
            entry = _catalog_entry(self._skills[(skill_id, version)].manifest)
            if scenario not in entry.scenarios or entry.risk_ceiling > risk_ceiling:
                continue
            if agent_profile and entry.allowed_agent_profiles and agent_profile not in entry.allowed_agent_profiles:
                continue
            capabilities = set(entry.required_capabilities)
            if required and not required.issubset(capabilities):
                continue
            supported = {item.casefold() for item in entry.supported_languages}
            if normalized_languages and supported and not normalized_languages.intersection(supported):
                continue
            trigger_hits = sum(
                1
                for term in entry.trigger_terms
                if term.casefold() in objective_terms or term.casefold() in normalized_objective
            )
            language_hits = len(normalized_languages.intersection(supported))
            capability_hits = len(required.intersection(capabilities))
            # Source-derived hints break otherwise-equal signed-skill ties only.
            # Objective, language, capability and policy remain authoritative.
            signal_hits = sum(1 for term in entry.trigger_terms if term.casefold() in routing_terms)
            rank = (-trigger_hits, -language_hits, -capability_hits, -min(signal_hits, 2), entry.skill_id)
            ranked.append((rank, entry))
        return [entry for _, entry in sorted(ranked, key=lambda pair: pair[0])[:limit]]

    def load(self, skill_id: str, version: str | None = None) -> LoadedAuditSkill:
        try:
            loaded = self._load(skill_id, version)
        except Exception as exc:
            record_skill_load(skill_id, version or self._latest.get(skill_id), error=exc)
            raise
        record_skill_load(skill_id, loaded.manifest.version)
        return loaded

    def _load(self, skill_id: str, version: str | None = None) -> LoadedAuditSkill:
        selected_version = version or self._latest.get(skill_id)
        if selected_version is None:
            raise KeyError(skill_id)
        try:
            discovered = self._skills[(skill_id, selected_version)]
        except KeyError as exc:
            raise KeyError(f"unknown skill version: {skill_id}@{selected_version}") from exc
        actual_digest = _package_digest(
            discovered.package_dir,
            discovered.raw_manifest,
            max_bytes=self.max_package_bytes,
            max_files=self.max_package_files,
        )
        if not _constant_time_text(actual_digest, discovered.manifest.package_digest.lower()):
            raise SkillPackageError(f"skill package digest mismatch: {skill_id}@{selected_version}")
        instructions_path = discovered.package_dir / INSTRUCTIONS_NAME
        if not instructions_path.is_file() or instructions_path.is_symlink():
            raise SkillPackageError(f"skill instructions are missing: {skill_id}@{selected_version}")
        instructions = _read_text(instructions_path, self.max_package_bytes)
        references = _load_context_files(discovered.package_dir, "references", self.max_package_bytes)
        examples = _load_context_files(discovered.package_dir, "examples", self.max_package_bytes)
        return LoadedAuditSkill(discovered.manifest.model_copy(deep=True), instructions, references, examples)

    def _validate_manifest(self, manifest: AuditSkillManifest, raw: dict[str, Any], directory_name: str) -> None:
        if not _SKILL_ID.fullmatch(manifest.skill_id) or manifest.skill_id != directory_name:
            raise SkillPackageError("skill_id must be canonical and match its package directory")
        if not _VERSION.fullmatch(manifest.version):
            raise SkillPackageError(f"invalid skill version: {manifest.version}")
        if manifest.risk_ceiling > self.maximum_risk:
            raise SkillPackageError(f"skill exceeds platform risk ceiling: {manifest.skill_id}")
        if self.approved_capabilities is not None:
            unknown = set(manifest.required_capabilities) - self.approved_capabilities
            if unknown:
                raise SkillPackageError(
                    f"skill requests unapproved capabilities: {manifest.skill_id}: {', '.join(sorted(unknown))}"
                )
        public_key = self.trusted_signers.get(manifest.signer)
        if public_key is None:
            raise SkillPackageError(f"unknown skill signer: {manifest.signer}")
        signed_manifest = dict(raw)
        signature_text = signed_manifest.pop("signature", None)
        if not isinstance(signature_text, str):
            raise SkillPackageError("skill signature is missing")
        signature = _decode_signature(signature_text)
        try:
            public_key.verify(signature, _canonical_json(signed_manifest))
        except InvalidSignature as exc:
            raise SkillPackageError(f"invalid skill signature: {manifest.skill_id}") from exc


def load_trust_roots(directory: Path) -> dict[str, Ed25519PublicKey]:
    root = _resolved_directory(directory, "skill trust root")
    keys: dict[str, Ed25519PublicKey] = {}
    for path in sorted(root.glob("*.pub")):
        if path.is_symlink() or path.resolve(strict=True).parent != root:
            raise SkillPackageError("skill trust key escaped the trust root")
        signer = path.stem
        if not signer or signer in keys:
            raise SkillPackageError("duplicate or empty skill signer id")
        try:
            loaded = serialization.load_pem_public_key(path.read_bytes())
        except (ValueError, TypeError) as exc:
            raise SkillPackageError(f"invalid public key for skill signer: {signer}") from exc
        if not isinstance(loaded, Ed25519PublicKey):
            raise SkillPackageError(f"skill signer must use Ed25519: {signer}")
        keys[signer] = loaded
    if not keys:
        raise SkillPackageError("skill trust root contains no Ed25519 public keys")
    return keys


def compute_package_digest(package_dir: Path, manifest: dict[str, Any]) -> str:
    """Public helper used by the offline package signing/release process."""

    return _package_digest(package_dir.resolve(strict=True), manifest, max_bytes=4 * 1024 * 1024, max_files=256)


def manifest_signing_payload(manifest: dict[str, Any]) -> bytes:
    payload = dict(manifest)
    payload.pop("signature", None)
    return _canonical_json(payload)


def _package_digest(package_dir: Path, manifest: dict[str, Any], *, max_bytes: int, max_files: int) -> str:
    digest = hashlib.sha256()
    digest.update(b"secmind-audit-skill-package-v1\x00")
    metadata = dict(manifest)
    metadata.pop("package_digest", None)
    metadata.pop("signature", None)
    _digest_part(digest, MANIFEST_NAME, _canonical_json(metadata))
    total = 0
    files = 0
    for path in sorted(package_dir.rglob("*"), key=lambda item: item.relative_to(package_dir).as_posix()):
        if path.name == MANIFEST_NAME and path.parent == package_dir:
            continue
        if path.is_symlink():
            raise SkillPackageError("skill packages cannot contain symbolic links")
        if not path.is_file():
            continue
        resolved = path.resolve(strict=True)
        if package_dir not in resolved.parents:
            raise SkillPackageError("skill package content escaped its package root")
        relative = path.relative_to(package_dir).as_posix()
        if any(part in {"", ".", ".."} for part in Path(relative).parts):
            raise SkillPackageError("skill package contains a non-canonical path")
        content = path.read_bytes()
        files += 1
        total += len(content)
        if files > max_files or total > max_bytes:
            raise SkillPackageError("skill package exceeds platform limits")
        _digest_part(digest, relative, content)
    return digest.hexdigest()


def _digest_part(digest: Any, name: str, content: bytes) -> None:
    encoded_name = name.encode("utf-8")
    digest.update(len(encoded_name).to_bytes(4, "big"))
    digest.update(encoded_name)
    digest.update(len(content).to_bytes(8, "big"))
    digest.update(content)


def _catalog_entry(manifest: AuditSkillManifest) -> SkillCatalogEntry:
    return SkillCatalogEntry(
        skill_id=manifest.skill_id,
        version=manifest.version,
        description=manifest.description,
        trigger_terms=tuple(manifest.trigger_terms),
        supported_languages=tuple(manifest.supported_languages),
        scenarios=tuple(manifest.scenarios),
        required_capabilities=tuple(manifest.required_capabilities),
        allowed_agent_profiles=tuple(manifest.allowed_agent_profiles),
        risk_ceiling=manifest.risk_ceiling,
        max_turns=manifest.max_turns,
        package_digest=manifest.package_digest,
        signer=manifest.signer,
    )


def _load_context_files(package_dir: Path, section: str, max_bytes: int) -> dict[str, str]:
    root = package_dir / section
    if not root.exists():
        return {}
    if root.is_symlink() or not root.is_dir():
        raise SkillPackageError(f"skill {section} must be a regular directory")
    loaded: dict[str, str] = {}
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise SkillPackageError(f"skill {section} cannot contain symbolic links")
        if not path.is_file() or path.suffix.casefold() not in _TEXT_SUFFIXES:
            continue
        content = path.read_bytes()
        total += len(content)
        if total > max_bytes:
            raise SkillPackageError(f"skill {section} exceeds platform limits")
        try:
            loaded[path.relative_to(root).as_posix()] = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SkillPackageError(f"skill {section} must use UTF-8") from exc
    return loaded


def _read_manifest(path: Path, limit: int) -> dict[str, Any]:
    if path.is_symlink() or path.stat().st_size > limit:
        raise SkillPackageError("skill manifest exceeds platform limits or is a symbolic link")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SkillPackageError(f"invalid skill manifest: {path.parent.name}") from exc
    if not isinstance(value, dict):
        raise SkillPackageError("skill manifest must be a JSON object")
    return value


def _read_text(path: Path, limit: int) -> str:
    if path.stat().st_size > limit:
        raise SkillPackageError("skill instructions exceed platform limits")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise SkillPackageError("skill instructions must use UTF-8") from exc


def _resolved_directory(path: Path, description: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise SkillPackageError(f"{description} must be a regular directory")
    return path.resolve(strict=True)


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _decode_signature(value: str) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise SkillPackageError("skill signature is malformed") from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value:
        raise SkillPackageError("skill signature encoding is not canonical")
    return decoded


def _constant_time_text(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))


def _version_key(value: str) -> tuple[Any, ...]:
    core = re.split(r"[-+]", value, maxsplit=1)[0]
    suffix = value[len(core) :]
    numeric = tuple(int(part) for part in core.split("."))
    padded = (*numeric, *(0 for _ in range(3 - len(numeric))))
    return (*padded, 1 if not suffix.startswith("-") else 0, suffix)
