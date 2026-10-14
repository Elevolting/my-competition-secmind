"""Deterministic, evidence-bearing tool affinity routing.

The router does not execute repository code and does not ask a model to invent
tool names. It scores only approved manifests against bounded, hash-verified
source signals, then narrows an already policy-valid plan.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from secmind.java_semantic_sast import SEMANTIC_SIGNAL, has_security_relevant_weak_digest
from secmind.language_registry import language_for_path, normalize_languages
from secmind.schemas import InputArtifact, PlanStep, ToolManifest

_MAX_SIGNAL_BYTES = 512_000
_MAX_FILE_BYTES = 128_000
_DEPENDENCY_FILES = {
    "cargo.lock",
    "cargo.toml",
    "composer.json",
    "composer.lock",
    "go.mod",
    "go.sum",
    "gradle.lockfile",
    "package-lock.json",
    "package.json",
    "packages.lock.json",
    "pipfile",
    "pipfile.lock",
    "pnpm-lock.yaml",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
    "uv.lock",
    "yarn.lock",
}
_SECRET_FILE_NAMES = {
    ".env",
    ".env.local",
    ".npmrc",
    ".pypirc",
    "credentials.json",
}
_FLOW_MARKERS = {
    "command": ("os.system(", "os.popen(", "subprocess.", "shell=true"),
    "dynamic_code": ("eval(", "exec(", "compile("),
    "network": ("requests.", "httpx.", "urlopen(", "httpconnection", "httpsconnection"),
    "path": ("open(", "pathlib.", "os.path.join("),
    "sql": (".execute(", ".executemany(", ".objects.raw(", "select ", "insert ", "update "),
    "xml": ("parsestring(", "etree.parse", "etree.fromstring", "sax.parse"),
    "deserialization": ("pickle.load", "yaml.load", "marshal.load"),
    "randomness": ("random.", ".seed(", "secrets."),
    "web_input": (
        "request.get",
        "request.post",
        "request.args",
        "request.form",
        "user_input",
        "$_post",
        "$_get",
        "$_request",
    ),
    "web_state_change": ("mysqli_query(", "mysql_query(", "pg_query(", "->execute(", "->exec("),
}
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|private[_-]?key)\b"
    r"\s*[:=]\s*['\"][^'\"\r\n]{8,}['\"]"
)
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")


@dataclass(frozen=True)
class ToolAffinityResult:
    steps: tuple[PlanStep, ...]
    scores: dict[str, int]
    reasons: dict[str, str]
    signals: tuple[str, ...]
    coverage: dict[str, tuple[str, ...]] | None = None


def route_tools_by_affinity(
    *,
    workspace: Path,
    artifacts: list[InputArtifact],
    steps: list[PlanStep],
    manifests: dict[str, ToolManifest],
) -> ToolAffinityResult:
    text, filenames = _verified_source_view(workspace, artifacts)
    signals = _signals(text, filenames)
    languages = {language for name in filenames if (language := language_for_path(name)) is not None}
    scores = {
        tool_name: _score(tool_name, manifests.get(tool_name), signals)
        for step in steps
        for tool_name in step.tool_candidates
    }
    reasons: dict[str, str] = {}
    retained: list[PlanStep] = []
    removed_steps: set[str] = set()

    for step in steps:
        candidates = list(dict.fromkeys(step.tool_candidates))
        if not candidates:
            retained.append(step.model_copy(deep=True))
            continue
        ranked = sorted(
            candidates,
            key=lambda name: (
                -scores.get(name, 0),
                0 if _is_available(manifests.get(name)) else 1,
                _manifest_signature(manifests.get(name)),
                candidates.index(name),
            ),
        )
        configured_limit = step.context_requirements.get("tool_candidate_limit")
        candidate_limit = (
            configured_limit
            if isinstance(configured_limit, int) and not isinstance(configured_limit, bool) and configured_limit > 0
            else 3
            if step.capability == "sast"
            else 2
        )
        if step.capability == "inventory":
            selected = [name for name in ranked if _is_available(manifests.get(name))][:1]
        elif step.capability == "sast":
            selected = _select_sast_tools(
                ranked,
                scores=scores,
                manifests=manifests,
                languages=languages,
                candidate_limit=candidate_limit,
            )
            if not selected and ranked:
                fallback = next(
                    (
                        name
                        for name in ranked
                        if _is_available(manifests.get(name)) and _language_compatible(manifests.get(name), languages)
                    ),
                    None,
                )
                selected = [fallback] if fallback is not None else []
        elif step.capability == "secret_scan":
            # A secret scanner is cheap, deterministic and redacted.  Absence
            # of a lexical pre-signal is not evidence of absence; using the
            # pre-signal as a gate made the scout decide whether the deeper
            # scanner was allowed to observe the repository.
            selected = [name for name in ranked if _is_available(manifests.get(name))][:candidate_limit]
        elif step.capability in {"sbom", "dependency_audit"}:
            selected = [
                name for name in ranked if "dependency_manifest" in signals and _is_available(manifests.get(name))
            ][:candidate_limit]
        else:
            selected = [
                name for name in ranked if scores.get(name, 0) >= 40 and _is_available(manifests.get(name))
            ] or [next((name for name in ranked if _is_available(manifests.get(name))), "")]
            selected = [name for name in selected if name]
        for tool_name in candidates:
            if tool_name not in selected:
                reasons[tool_name] = (
                    "tool_unavailable"
                    if not _is_available(manifests.get(tool_name))
                    else "language_incompatible"
                    if step.capability == "sast" and not _language_compatible(manifests.get(tool_name), languages)
                    else "low_signal_affinity"
                    if scores.get(tool_name, 0) < 40
                    else "no_marginal_coverage"
                )
        if not selected and step.estimated_tool_calls:
            removed_steps.add(step.step_id)
            continue
        requirements = dict(step.context_requirements)
        requirements.update(
            {
                "tool_affinity_scores": {name: scores[name] for name in ranked},
                "tool_affinity_signals": sorted(signals),
                "tool_affinity_languages": sorted(languages),
                "tool_coverage": {
                    name: sorted(_coverage_for_tool(name, manifests.get(name), languages)) for name in selected
                },
                "candidate_policy": "execute_high_affinity",
            }
        )
        retained.append(
            step.model_copy(
                update={"tool_candidates": selected, "context_requirements": requirements},
                deep=True,
            )
        )

    if removed_steps:
        retained = [
            step.model_copy(
                update={
                    "dependencies": [item for item in step.dependencies if item not in removed_steps],
                    "dependency_bindings": [
                        item for item in step.dependency_bindings if item.upstream_step_id not in removed_steps
                    ],
                },
                deep=True,
            )
            for step in retained
        ]
    return ToolAffinityResult(
        tuple(retained),
        scores,
        reasons,
        tuple(sorted(signals)),
        {name: tuple(sorted(_coverage_for_tool(name, manifests.get(name), languages))) for name in sorted(scores)},
    )


def _verified_source_view(workspace: Path, artifacts: list[InputArtifact]) -> tuple[str, set[str]]:
    root = workspace.resolve()
    chunks: list[str] = []
    filenames: set[str] = set()
    remaining = _MAX_SIGNAL_BYTES
    for artifact in sorted(artifacts, key=lambda item: item.relative_path.casefold()):
        filenames.add(Path(artifact.relative_path).name.casefold())
        if remaining <= 0:
            break
        candidate = (root / artifact.relative_path).resolve()
        try:
            if not candidate.is_relative_to(root) or not candidate.is_file() or candidate.is_symlink():
                continue
            payload = candidate.read_bytes()
        except OSError:
            continue
        if hashlib.sha256(payload).hexdigest() != artifact.sha256.lower():
            continue
        bounded = payload[: min(len(payload), _MAX_FILE_BYTES, remaining)]
        remaining -= len(bounded)
        # Preserve source spelling for semantic analyzers: camel-case is part
        # of an identifier boundary (for example ``passwordFile``). Cheap
        # lexical markers are folded locally in ``_signals`` instead.
        chunks.append(bounded.decode("utf-8", errors="ignore"))
    # A sentinel prevents a bounded semantic signal from accidentally joining
    # identifiers from two unrelated files.
    return "\x00".join(chunks), filenames


def _signals(text: str, filenames: set[str]) -> set[str]:
    folded = text.casefold()
    signals = {signal for signal, markers in _FLOW_MARKERS.items() if any(marker in folded for marker in markers)}
    if _SECRET_ASSIGNMENT.search(text) or _PRIVATE_KEY.search(text):
        signals.add("secret_material")
    if filenames.intersection(_SECRET_FILE_NAMES) or any("secret" in name for name in filenames):
        signals.add("secret_candidate")
    if filenames.intersection(_DEPENDENCY_FILES):
        signals.add("dependency_manifest")
    if any(has_security_relevant_weak_digest(chunk) for chunk in text.split("\x00")):
        signals.add(SEMANTIC_SIGNAL)
    if any(language_for_path(name) in {"javascript", "typescript"} for name in filenames):
        from secmind.source_triage import triage_javascript_typescript

        js_analysis = triage_javascript_typescript(text)
        signals.update(js_analysis.signals)
        signals.update(f"flow:{flow.kind}" for flow in js_analysis.flows)
    return signals


def _score(_tool_name: str, manifest: ToolManifest | None, signals: set[str]) -> int:
    if manifest is None:
        return 0
    capabilities = {item.casefold() for item in manifest.capability_tags}
    languages = normalize_languages(manifest.supported_languages)
    evidence = {item.casefold() for item in manifest.evidence_types}
    description = manifest.description.casefold()
    if "inventory" in capabilities:
        return 100
    if "secret_scan" in capabilities:
        return 90 if signals.intersection({"secret_material", "secret_candidate"}) else 15
    if "dependency_audit" in capabilities or "sbom" in capabilities:
        return 90 if "dependency_manifest" in signals else 20
    if "java_semantic" in capabilities and "java" in languages:
        # This approved scanner contains bounded semantic rules whose sources
        # cannot be inferred safely from a shallow lexical pre-pass.  Java
        # compatibility is therefore sufficient to retain it; the scanner
        # itself remains the authority for whether a finding exists.
        return 100 if SEMANTIC_SIGNAL in signals else 75
    if "java" in languages and (SEMANTIC_SIGNAL in description or "weak" in description):
        return 100 if SEMANTIC_SIGNAL in signals else 10
    if "sast_flow" in evidence or "source-to-sink" in description:
        flow_signals = signals.intersection(set(_FLOW_MARKERS) - {"web_input"})
        return min(100, 25 + 55 * bool(flow_signals) + 10 * ("web_input" in signals))
    if "sast" in capabilities:
        return 65 + 15 * bool(signals.intersection(_FLOW_MARKERS))
    return 60


def _is_available(manifest: ToolManifest | None) -> bool:
    return manifest is not None and manifest.health_status.value != "unavailable"


def _language_compatible(manifest: ToolManifest | None, languages: set[str]) -> bool:
    if manifest is None:
        return False
    supported = normalize_languages(manifest.supported_languages)
    return not languages or not supported or bool(supported.intersection(languages))


def _manifest_signature(manifest: ToolManifest | None) -> tuple[str, ...]:
    if manifest is None:
        return ("missing",)
    return (
        ",".join(sorted(normalize_languages(manifest.supported_languages))),
        ",".join(sorted(item.casefold() for item in manifest.evidence_types)),
        ",".join(sorted(item.casefold() for item in manifest.capability_tags)),
        manifest.rule_bundle_digest or "",
        manifest.version,
        manifest.description,
    )


def _coverage_for_tool(
    _tool_name: str,
    manifest: ToolManifest | None,
    languages: set[str],
) -> set[str]:
    if manifest is None:
        return set()
    supported = normalize_languages(manifest.supported_languages)
    applicable = supported.intersection(languages) if languages and supported else supported or languages
    coverage: set[str] = {f"language:{language}" for language in applicable}
    coverage.update(f"evidence:{item.casefold()}" for item in manifest.evidence_types)
    capabilities = {item.casefold() for item in manifest.capability_tags}
    description = manifest.description.casefold()
    evidence = {item.casefold() for item in manifest.evidence_types}
    if "java" in supported and ("weak" in description or "messagedigest" in description):
        rule = "rule:java-semantic"
    elif "sast_flow" in evidence or "source-to-sink" in description:
        rule = "rule:source-to-sink"
    elif "bandit" in description:
        rule = "rule:python-broad"
    elif "semgrep" in description or "rule bundle" in description:
        rule = "rule:semgrep-reviewed"
    elif "secret_scan" in capabilities:
        rule = "rule:redacted-secret"
    elif "dependency_audit" in capabilities:
        rule = "rule:dependency-vulnerability"
    elif "sbom" in capabilities:
        rule = "rule:dependency-inventory"
    else:
        rule = "rule:generic"
    coverage.add(rule)
    return coverage


def _select_sast_tools(
    ranked: list[str],
    *,
    scores: dict[str, int],
    manifests: dict[str, ToolManifest],
    languages: set[str],
    candidate_limit: int,
) -> list[str]:
    """Greedily choose complementary coverage, with no name-based tie-break."""

    eligible = [
        name
        for name in ranked
        if scores.get(name, 0) >= 50
        and _is_available(manifests.get(name))
        and _language_compatible(manifests.get(name), languages)
    ]
    if not eligible:
        return []
    selected: list[str] = []
    covered: set[str] = set()
    while eligible and len(selected) < candidate_limit:
        choice = max(
            eligible,
            key=lambda name: (
                len(_coverage_for_tool(name, manifests.get(name), languages) - covered),
                scores.get(name, 0),
                -ranked.index(name),
            ),
        )
        marginal = _coverage_for_tool(choice, manifests.get(choice), languages) - covered
        # Two healthy SAST implementations remain useful independent
        # corroborators even when their declared lower-bound coverage is
        # identical.  After that minimum pair, stop duplicate work unless a
        # candidate adds new coverage.
        if len(selected) >= 2 and not marginal:
            break
        selected.append(choice)
        covered.update(_coverage_for_tool(choice, manifests.get(choice), languages))
        eligible.remove(choice)
    return selected


__all__ = ["ToolAffinityResult", "route_tools_by_affinity"]
