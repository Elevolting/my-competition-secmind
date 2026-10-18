from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secmind.live_source_review import SourceUnit

PROTOCOL = "secmind-blind-java-v1"
DEFAULT_SEED = "SecMind-v0.6-blind-20260715"
DEFAULT_SAMPLE_SIZE = 120
BATCH_SIZE = 12


def now() -> str:
    return datetime.now(UTC).isoformat()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_hash(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(raw)


def load_manifest(path: Path) -> dict[str, Any]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("protocol") != PROTOCOL:
        raise ValueError("unsupported blind benchmark manifest")
    expected = manifest.get("input_bundle_sha256")
    material = {
        "protocol": manifest["protocol"],
        "seed": manifest["seed"],
        "selection_algorithm": manifest["selection_algorithm"],
        "cases": manifest["cases"],
        "support_files": manifest["support_files"],
    }
    if canonical_hash(material) != expected:
        raise ValueError("blind benchmark manifest hash mismatch")
    return manifest


def load_units(input_root: Path, manifest: dict[str, Any]) -> tuple[list[SourceUnit], list[SourceUnit]]:
    def load(entry: dict[str, Any], *, case_id: str) -> SourceUnit:
        path = input_root / entry["path"]
        raw = path.read_bytes()
        if sha256_bytes(raw) != entry["sha256"] or len(raw) != entry["bytes"]:
            raise ValueError(f"blind input changed: {entry['path']}")
        return SourceUnit(case_id=case_id, path=entry["path"], content=raw.decode("utf-8"))

    cases = [load(item, case_id=item["case_id"]) for item in manifest["cases"]]
    support = [load(item, case_id=f"support:{item['path']}") for item in manifest["support_files"]]
    return cases, support


def batches(values: list[SourceUnit], size: int = BATCH_SIZE) -> Iterable[list[SourceUnit]]:
    for offset in range(0, len(values), size):
        yield values[offset : offset + size]


def prediction_commitment(runs: list[dict[str, Any]]) -> str:
    predictions = [{"repetition": run["repetition"], "predictions": run["predictions"]} for run in runs]
    return canonical_hash(predictions)
