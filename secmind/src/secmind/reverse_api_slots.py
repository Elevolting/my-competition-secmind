"""Planning and migration primitives for independent DeepSeek API runs."""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from secmind.reverse_evaluation import verify_prediction_seal


@dataclass(frozen=True, slots=True)
class ApiRunSlot:
    arm: str
    case_id: str
    repeat_id: int
    evidence_sha256: str
    prompt_sha256: str

    @property
    def identity(self) -> tuple[str, str, int]:
        return (self.arm, self.case_id, self.repeat_id)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class EvidenceArmPaths:
    prediction_path: Path
    seal_path: Path


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _manifest_payload(manifest: Mapping[str, Any] | Path) -> Mapping[str, Any]:
    return _json(manifest) if isinstance(manifest, Path) else manifest


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validated_evidence(
    manifest: Mapping[str, Any], evidence_arms: Mapping[str, EvidenceArmPaths]
) -> dict[str, tuple[Path, dict[str, Any]]]:
    suite_id = manifest.get("suite_id")
    result: dict[str, tuple[Path, dict[str, Any]]] = {}
    if set(evidence_arms) != {"current", "optimized"}:
        raise ValueError("evidence arms must be exactly current and optimized")
    for arm in ("current", "optimized"):
        paths = evidence_arms[arm]
        if not isinstance(paths, EvidenceArmPaths):
            raise ValueError("each evidence arm must use EvidenceArmPaths")
        prediction, seal_path = paths.prediction_path, paths.seal_path
        try:
            seal = verify_prediction_seal(prediction, seal_path)
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid {arm} evidence seal: {exc}") from exc
        prediction_payload = _json(prediction)
        if prediction_payload.get("arm") != arm:
            raise ValueError(f"embedded arm for {arm} evidence does not match map key")
        if seal.get("suite_id") != suite_id:
            raise ValueError(f"{arm} evidence suite does not match manifest")
        result[arm] = (prediction, seal)
    return result


def plan_api_run_slots(
    manifest: Mapping[str, Any] | Path, evidence_arms: Mapping[str, EvidenceArmPaths]
) -> tuple[ApiRunSlot, ...]:
    """Validate the public 12-case manifest and produce the exact 48 slots."""

    payload = _manifest_payload(manifest)
    cases = payload.get("cases")
    if not isinstance(cases, list) or len(cases) != 12:
        raise ValueError("manifest must contain exactly 12 cases")
    case_ids: list[str] = []
    prompts: list[str] = []
    for case in cases:
        if not isinstance(case, Mapping) or not isinstance(case.get("id"), str) or not case["id"]:
            raise ValueError("manifest case IDs must be non-empty strings")
        case_ids.append(case["id"])
        prompt = case.get("prompt")
        if not isinstance(prompt, str) or not prompt:
            raise ValueError("manifest case prompts must be non-empty strings")
        prompts.append(prompt)
    if len(set(case_ids)) != 12:
        raise ValueError("manifest case IDs must be unique")
    evidence = _validated_evidence(payload, evidence_arms)
    slots: list[ApiRunSlot] = []
    for arm in ("current", "optimized"):
        prediction, seal = evidence[arm]
        prediction_payload = _json(prediction)
        prediction_ids = [case.get("id") for case in prediction_payload.get("cases", []) if isinstance(case, Mapping)]
        if prediction_ids != case_ids:
            raise ValueError(f"{arm} evidence case order does not match manifest")
        evidence_sha256 = str(seal["prediction_sha256"])
        for case_id, prompt in zip(case_ids, prompts, strict=True):
            for repeat_id in (1, 2):
                slots.append(ApiRunSlot(arm, case_id, repeat_id, evidence_sha256, _sha256_text(prompt)))
    if len(slots) != 48 or len({slot.identity for slot in slots}) != 48:
        raise ValueError("API run matrix must contain exactly 48 unique slots")
    return tuple(slots)


def migrate_sealed_evidence(
    evidence_arms: Mapping[str, EvidenceArmPaths], destination: Path
) -> dict[str, tuple[Path, Path]]:
    """Copy sealed predictions into the evidence tree without changing bytes."""

    if "gold" in str(destination).casefold():
        raise ValueError("evidence destination must not be a gold path")
    # Validate before creating or copying anything.
    if set(evidence_arms) != {"current", "optimized"}:
        raise ValueError("evidence arms must be exactly current and optimized")
    if any(not isinstance(value, EvidenceArmPaths) for value in evidence_arms.values()):
        raise ValueError("each evidence arm must use EvidenceArmPaths")
    for paths in evidence_arms.values():
        for source in (paths.prediction_path, paths.seal_path):
            resolved = source.resolve()
            if any(component.casefold() == "gold" for component in resolved.parts):
                raise ValueError("gold source paths are forbidden")
        if paths.prediction_path.name != "predictions.json":
            raise ValueError("prediction source must be named predictions.json")
        if paths.seal_path.name != "predictions.seal.json":
            raise ValueError("seal source must be named predictions.seal.json")
    validated = _validated_evidence(
        {"suite_id": _json(evidence_arms["current"].seal_path).get("suite_id")}, evidence_arms
    )
    copied: dict[str, tuple[Path, Path]] = {}
    for arm, (prediction, _seal_payload) in validated.items():
        seal = evidence_arms[arm].seal_path
        arm_root = destination / arm
        arm_root.mkdir(parents=True, exist_ok=True)
        prediction_copy = arm_root / prediction.name
        seal_copy = arm_root / seal.name
        shutil.copyfile(prediction, prediction_copy)
        shutil.copyfile(seal, seal_copy)
        verify_prediction_seal(prediction_copy, seal_copy)
        copied[arm] = (prediction_copy, seal_copy)
    return copied


__all__ = ["ApiRunSlot", "EvidenceArmPaths", "migrate_sealed_evidence", "plan_api_run_slots"]
