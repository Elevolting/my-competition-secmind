import hashlib
import json
import os
from pathlib import Path

import pytest

from secmind.reverse_api_slots import (
    ApiRunSlot,
    EvidenceArmPaths,
    migrate_sealed_evidence,
    plan_api_run_slots,
)


def _manifest() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "suite_id": "suite-12",
        "cases": [{"id": f"case-{index:02d}", "prompt": f"Prompt {index}"} for index in range(12)],
    }


def _evidence(tmp_path: Path) -> dict[str, EvidenceArmPaths]:
    result: dict[str, EvidenceArmPaths] = {}
    for arm in ("current", "optimized"):
        source_dir = tmp_path / arm
        source_dir.mkdir()
        prediction = source_dir / "predictions.json"
        prediction.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "suite_id": "suite-12",
                    "arm": arm,
                    "cases": [{"id": f"case-{index:02d}"} for index in range(12)],
                }
            ),
            encoding="utf-8",
        )
        digest = hashlib.sha256(prediction.read_bytes()).hexdigest()
        seal = source_dir / "predictions.seal.json"
        seal.write_text(
            json.dumps({
                "schema_version": "1.0", "suite_id": "suite-12", "prediction_file": prediction.name,
                "prediction_sha256": digest, "case_count": 12,
                "case_ids": [f"case-{index:02d}" for index in range(12)],
                "case_ids_sha256": hashlib.sha256(
                    json.dumps([f"case-{index:02d}" for index in range(12)], separators=(",", ":")).encode()
                ).hexdigest(),
            }),
            encoding="utf-8",
        )
        result[arm] = EvidenceArmPaths(prediction_path=prediction, seal_path=seal)
    return result


def test_planner_builds_exactly_48_unique_slots(tmp_path: Path) -> None:
    slots = plan_api_run_slots(_manifest(), _evidence(tmp_path))
    assert len(slots) == 48
    assert len({slot.identity for slot in slots}) == 48
    assert {slot.arm for slot in slots} == {"current", "optimized"}
    assert {slot.repeat_id for slot in slots} == {1, 2}
    assert all(isinstance(slot, ApiRunSlot) for slot in slots)
    serialized = json.dumps([slot.to_dict() for slot in slots])
    for forbidden in ("gold", "score", "response", "repeat-1", "repeat-2"):
        assert forbidden not in serialized


def test_planner_rejects_invalid_matrix_and_seal(tmp_path: Path) -> None:
    evidence = _evidence(tmp_path)
    with pytest.raises(ValueError, match="arm"):
        plan_api_run_slots(_manifest(), {**evidence, "old": evidence["current"]})
    evidence["current"].prediction_path.write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="SHA256"):
        plan_api_run_slots(_manifest(), evidence)


def test_migration_preserves_bytes_and_seal_digest(tmp_path: Path) -> None:
    evidence = _evidence(tmp_path)
    destination = tmp_path / "evidence"
    copied = migrate_sealed_evidence(evidence, destination)
    assert set(copied) == {"current", "optimized"}
    for arm, paths in evidence.items():
        prediction, seal = paths.prediction_path, paths.seal_path
        migrated_prediction, migrated_seal = copied[arm]
        assert migrated_prediction.read_bytes() == prediction.read_bytes()
        assert migrated_seal.read_bytes() == seal.read_bytes()
        assert hashlib.sha256(migrated_prediction.read_bytes()).hexdigest() == json.loads(
            seal.read_text()
        )["prediction_sha256"]
        assert "gold" not in str(migrated_prediction).lower()


def test_planner_rejects_swapped_valid_evidence_arms(tmp_path: Path) -> None:
    evidence = _evidence(tmp_path)
    with pytest.raises(ValueError, match="embedded arm"):
        plan_api_run_slots(
            _manifest(), {"current": evidence["optimized"], "optimized": evidence["current"]}
        )


def test_migration_rejects_swapped_valid_evidence_arms(tmp_path: Path) -> None:
    evidence = _evidence(tmp_path)
    swapped = {"current": evidence["optimized"], "optimized": evidence["current"]}
    with pytest.raises(ValueError, match="embedded arm"):
        migrate_sealed_evidence(swapped, tmp_path / "evidence")


def test_migration_rejects_gold_source_before_copy(tmp_path: Path) -> None:
    evidence = _evidence(tmp_path)
    gold = tmp_path / "gold"
    gold.mkdir()
    paths = {}
    for arm, source in evidence.items():
        prediction = gold / f"{arm}-predictions.json"
        seal = gold / f"{arm}-predictions.seal.json"
        prediction.write_bytes(source.prediction_path.read_bytes())
        seal.write_bytes(source.seal_path.read_bytes())
        paths[arm] = EvidenceArmPaths(prediction, seal)
    with pytest.raises(ValueError, match="gold"):
        migrate_sealed_evidence(paths, tmp_path / "evidence")
    assert not (tmp_path / "evidence").exists()


def test_migration_rejects_symlink_to_gold_before_copy(tmp_path: Path) -> None:
    evidence = _evidence(tmp_path)
    gold = tmp_path / "gold"
    gold.mkdir()
    paths = {}
    for arm, source in evidence.items():
        prediction = gold / f"{arm}-predictions.json"
        seal = gold / f"{arm}-predictions.seal.json"
        prediction.write_bytes(source.prediction_path.read_bytes())
        seal.write_bytes(source.seal_path.read_bytes())
        link_dir = tmp_path / f"link-{arm}"
        link_dir.mkdir()
        prediction_link = link_dir / "predictions.json"
        seal_link = link_dir / "predictions.seal.json"
        try:
            os.symlink(prediction, prediction_link)
            os.symlink(seal, seal_link)
        except OSError as exc:
            if getattr(exc, "winerror", None) == 1314:
                pytest.skip("Windows symlink privilege is unavailable")
            raise
        paths[arm] = EvidenceArmPaths(prediction_link, seal_link)
    with pytest.raises(ValueError, match="gold"):
        migrate_sealed_evidence(paths, tmp_path / "evidence")


def test_migration_rejects_non_typed_values_without_attribute_or_file_access(tmp_path: Path) -> None:
    class Lookalike:
        @property
        def seal_path(self) -> Path:
            raise AssertionError("attribute accessed before type validation")

    with pytest.raises(ValueError, match="EvidenceArmPaths"):
        migrate_sealed_evidence(
            {"current": (tmp_path / "predictions.json", tmp_path / "predictions.seal.json"), "optimized": Lookalike()},
            tmp_path / "evidence",
        )


def test_planner_rejects_suite_and_case_order_mismatch(tmp_path: Path) -> None:
    evidence = _evidence(tmp_path)
    wrong_suite = _manifest()
    wrong_suite["suite_id"] = "other-suite"
    with pytest.raises(ValueError, match="suite"):
        plan_api_run_slots(wrong_suite, evidence)
    wrong_order = _manifest()
    wrong_order["cases"] = list(reversed(wrong_order["cases"]))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="case order"):
        plan_api_run_slots(wrong_order, evidence)


@pytest.mark.parametrize("keys", [{"current"}, {"current", "optimized", "extra"}])
def test_planner_rejects_missing_or_extra_arms_before_read(tmp_path: Path, keys: set[str]) -> None:
    evidence = _evidence(tmp_path)
    supplied = {key: evidence.get(key, object()) for key in keys}
    with pytest.raises(ValueError, match="exactly current and optimized"):
        plan_api_run_slots(_manifest(), supplied)


def test_closed_evidence_interface_rejects_ambiguous_tuple(tmp_path: Path) -> None:
    evidence = _evidence(tmp_path)
    with pytest.raises(ValueError, match="EvidenceArmPaths"):
        plan_api_run_slots(
            _manifest(),
            {
                "current": (
                    evidence["current"].prediction_path,
                    evidence["current"].seal_path,
                ),
                "optimized": evidence["optimized"],
            },
        )
