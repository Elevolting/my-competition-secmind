"""Minimal, secret-free release identity for trusted execution records.

The identity intentionally stores digests and Git provenance only.  It never
embeds configuration, prompts, rules, or bridge payloads in a release record;
callers can therefore publish the summary without making a raw bundle
available by default.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import shutil
import subprocess  # nosec B404
from collections.abc import Mapping, Sequence, Set
from pathlib import Path
from typing import Any

UNKNOWN = "UNKNOWN"
IDENTITY_SCHEMA_VERSION = "1.0"


class ReleaseIdentityError(ValueError):
    """Raised when a release component cannot be represented safely."""


def _canonicalize(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {"type": "bytes", "sha256": hashlib.sha256(value).hexdigest(), "size_bytes": len(value)}
    if isinstance(value, Path):
        return {"type": "path", "value": value.as_posix()}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _canonicalize(dataclasses.asdict(value))
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _canonicalize(model_dump(mode="json"))
    if isinstance(value, Mapping):
        pairs = [(_canonicalize(key), _canonicalize(item)) for key, item in value.items()]
        pairs.sort(key=lambda pair: json.dumps(pair[0], ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return {str(key): item for key, item in pairs}
    if isinstance(value, Set) and not isinstance(value, (str, bytes, bytearray)):
        items = [_canonicalize(item) for item in value]
        return sorted(
            items,
            key=lambda item: json.dumps(item, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_canonicalize(item) for item in value]
    raise ReleaseIdentityError(f"unsupported release component type: {type(value).__name__}")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _canonicalize(value),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _file_digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ReleaseIdentityError("release component path must be a regular file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _directory_digest(path: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(item for item in path.rglob("*") if item.is_file() and not item.is_symlink())
    for item in files:
        relative = item.relative_to(path).as_posix().encode("utf-8")
        content_digest = _file_digest(item).encode("ascii")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(content_digest)
    return digest.hexdigest()


def component_digest(value: Any) -> str:
    """Return a deterministic digest without retaining the component value."""

    if value is None:
        return UNKNOWN
    if isinstance(value, Path):
        if value.is_symlink():
            raise ReleaseIdentityError("release component path cannot be a symbolic link")
        path = value.resolve()
        if path.is_dir():
            return _directory_digest(path)
        return _file_digest(path)
    if isinstance(value, bytes):
        return hashlib.sha256(value).hexdigest()
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _git_value(root: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        raise ReleaseIdentityError("git executable is unavailable")
    completed = subprocess.run(  # noqa: S603  # nosec B603
        [executable, *arguments],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
        timeout=5,
    )
    if completed.returncode != 0:
        raise ReleaseIdentityError("git provenance is unavailable")
    return completed.stdout.strip()


def git_provenance(root: Path) -> tuple[str, str, bool]:
    """Return ``(commit, tree, dirty)`` and fail closed outside a Git worktree."""

    try:
        commit = _git_value(root, "rev-parse", "HEAD")
        tree = _git_value(root, "rev-parse", "HEAD^{tree}")
        status = _git_value(root, "status", "--porcelain=v1", "--untracked-files=all")
    except (OSError, ReleaseIdentityError, subprocess.SubprocessError):
        return UNKNOWN, UNKNOWN, True
    if not commit or not tree:
        return UNKNOWN, UNKNOWN, True
    return commit, tree, bool(status)


def _validate_text(value: str, field_name: str) -> str:
    if not value or len(value) > 256 or any(ord(char) < 32 for char in value):
        raise ReleaseIdentityError(f"invalid release identity {field_name}")
    return value


@dataclasses.dataclass(frozen=True, slots=True)
class ReleaseIdentity:
    """Public release summary; component material is represented by digests."""

    version: str = UNKNOWN
    git_commit: str = UNKNOWN
    git_tree: str = UNKNOWN
    dirty: bool = True
    config_digest: str = UNKNOWN
    prompt_digest: str = UNKNOWN
    rule_digest: str = UNKNOWN
    bridge_digest: str = UNKNOWN
    schema_version: str = IDENTITY_SCHEMA_VERSION
    identity_digest: str = dataclasses.field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.dirty, bool):
            raise ReleaseIdentityError("invalid release identity dirty flag")
        _validate_text(self.version, "version")
        _validate_text(self.git_commit, "git_commit")
        _validate_text(self.git_tree, "git_tree")
        for name in ("config_digest", "prompt_digest", "rule_digest", "bridge_digest"):
            value = getattr(self, name)
            if value != UNKNOWN and (len(value) != 64 or any(char not in "0123456789abcdef" for char in value.lower())):
                raise ReleaseIdentityError(f"invalid release identity {name}")
        payload = self.to_dict(include_identity_digest=False)
        identity = hashlib.sha256(b"secmind-release-identity\0" + _canonical_bytes(payload)).hexdigest()
        object.__setattr__(self, "identity_digest", identity)

    @classmethod
    def collect(
        cls,
        root: Path | str = ".",
        *,
        version: str = UNKNOWN,
        config: Any = None,
        prompt: Any = None,
        rule: Any = None,
        rules: Any = None,
        bridge: Any = None,
    ) -> ReleaseIdentity:
        repository = Path(root).resolve()
        commit, tree, dirty = git_provenance(repository)
        return cls(
            version=version,
            git_commit=commit,
            git_tree=tree,
            dirty=dirty,
            config_digest=component_digest(config),
            prompt_digest=component_digest(prompt),
            rule_digest=component_digest(rules if rules is not None else rule),
            bridge_digest=component_digest(bridge),
        )

    from_repository = collect

    @property
    def tree_digest(self) -> str:
        return self.git_tree

    @property
    def git_tree_digest(self) -> str:
        return self.git_tree

    @property
    def git_sha(self) -> str:
        return self.git_commit

    @property
    def agent_git_sha(self) -> str:
        return self.git_commit

    @property
    def agent_git_tree_sha(self) -> str:
        return self.git_tree

    @property
    def git_dirty(self) -> bool:
        return self.dirty

    @property
    def agent_git_dirty(self) -> bool:
        return self.dirty

    @property
    def bridge_sha(self) -> str:
        return self.bridge_digest

    def to_dict(self, *, include_identity_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "version": self.version,
            "git_commit": self.git_commit,
            "git_tree": self.git_tree,
            "dirty": self.dirty,
            "config_digest": self.config_digest,
            "prompt_digest": self.prompt_digest,
            "rule_digest": self.rule_digest,
            "bridge_digest": self.bridge_digest,
        }
        if include_identity_digest:
            payload["identity_digest"] = self.identity_digest
        return payload

    as_dict = to_dict

    def summary(self) -> dict[str, Any]:
        """Return the publishable, digest-only release summary."""

        return self.to_dict()


def build_release_identity(
    root: Path | str = ".",
    *,
    version: str = UNKNOWN,
    config: Any = None,
    prompt: Any = None,
    rule: Any = None,
    rules: Any = None,
    bridge: Any = None,
) -> ReleaseIdentity:
    return ReleaseIdentity.collect(
        root,
        version=version,
        config=config,
        prompt=prompt,
        rule=rule,
        rules=rules,
        bridge=bridge,
    )


compute_release_identity = build_release_identity


def publishable_release_summary(
    root: Path | str = ".",
    *,
    version: str = UNKNOWN,
    config: Any = None,
    prompt: Any = None,
    rule: Any = None,
    rules: Any = None,
    bridge: Any = None,
) -> dict[str, Any]:
    """Build the digest-only identity payload for API/evaluation records.

    This is the deliberate integration point for API, orchestrator, and
    Bridge identity assembly: callers add the returned mapping to their
    existing run identity without copying raw configuration or prompt data.
    """

    return build_release_identity(
        root,
        version=version,
        config=config,
        prompt=prompt,
        rule=rule,
        rules=rules,
        bridge=bridge,
    ).summary()


__all__ = [
    "IDENTITY_SCHEMA_VERSION",
    "UNKNOWN",
    "ReleaseIdentity",
    "ReleaseIdentityError",
    "build_release_identity",
    "component_digest",
    "compute_release_identity",
    "git_provenance",
    "publishable_release_summary",
]
