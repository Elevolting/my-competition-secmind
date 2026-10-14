from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ARM_NAMES = ("A", "B", "C", "D")
CORE_CWES = frozenset({22, 78, 79, 89})
EXTENDED_CWES = frozenset({22, 78, 79, 89, 90, 327, 328, 330, 501, 614})
PROTOCOL = "secmind-v0.7-abcd-offline-v1"
PASSING_STATUSES = frozenset({"complete", "completed", "success", "succeeded"})
RECOVERY_STATUS = "recovery_required"
PAIR_IDENTITY_FIELDS = (
    "input_manifest_digest",
    "audit_profile_digest",
    "unit_id",
    "primary_source_digest",
    "support_context_digests",
    "model_catalog_digest",
    "model_id",
    "base_url_policy_id",
    "prompt_template_version",
    "response_schema_version",
    "temperature",
    "seed",
    "max_input_tokens",
    "max_output_tokens",
    "timeout",
    "retry_policy",
    "request_digest",
    "system_prompt_digest",
    "user_prompt_digest",
    "reasoning_effort",
    "thinking_mode",
)


class V07EvaluationError(ValueError):
    pass


@dataclass(frozen=True)
class GoldCase:
    case_id: str
    vulnerable: bool
    cwe: int


@dataclass(frozen=True)
class Prediction:
    vulnerable: bool | None
    cwe: int | None
    schema_valid: bool = True

    @classmethod
    def missing(cls) -> Prediction:
        return cls(None, None, False)

    def material(self) -> dict[str, Any]:
        return {
            "vulnerable": self.vulnerable,
            "cwe": self.cwe,
            "schema_valid": self.schema_valid,
        }


@dataclass(frozen=True)
class Record:
    case_id: str
    prediction: Prediction
    baseline_prediction: Prediction
    public_prediction: Prediction
    identity: Mapping[str, Any]
    identity_valid: bool
    receipt_commitment: str
    receipt_valid: bool
    patches: tuple[Mapping[str, Any], ...]
    augmentation_status: str


@dataclass(frozen=True)
class Run:
    repetition: int
    execution_id: str
    status: str
    records: Mapping[str, Record]


@dataclass(frozen=True)
class Arm:
    name: str
    runs: Mapping[int, Run]


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _valid_sha256(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.removeprefix("sha256:")
    return (
        len(normalized) == 64
        and normalized != "0" * 64
        and all(character in "0123456789abcdef" for character in normalized)
    )


def _json_object(value: Any, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise V07EvaluationError(f"{label} must be a JSON object")
    return value


def _contains_gold(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if "gold" in normalized or normalized.startswith("expected_label"):
                return True
            if _contains_gold(item):
                return True
    elif isinstance(value, list):
        return any(_contains_gold(item) for item in value)
    return False


def _seal_material(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "sealing"}


def seal_experiment(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Commit predictions before a scorer is allowed to load labels."""

    material = dict(_seal_material(_json_object(payload, label="experiment")))
    material["protocol"] = PROTOCOL
    if _contains_gold(material):
        raise V07EvaluationError("prediction payload contains Gold/label material")
    arms = _json_object(material.get("arms"), label="experiment arms")
    missing = set(ARM_NAMES) - set(arms)
    extra = set(arms) - set(ARM_NAMES)
    if missing or extra:
        raise V07EvaluationError(f"A/B/C/D arms are required exactly; missing={sorted(missing)}, extra={sorted(extra)}")
    arm_commitments = {name: canonical_sha256(_json_object(arms[name], label=f"arm {name}")) for name in ARM_NAMES}
    sealed = json.loads(json.dumps(material, ensure_ascii=False))
    sealed["sealing"] = {
        "phase": "predictions_committed",
        "labels_loaded": False,
        "arm_commitments": arm_commitments,
        "prediction_commitment_sha256": canonical_sha256(material),
    }
    return sealed


def validate_sealed_experiment(payload: Mapping[str, Any]) -> None:
    raw = _json_object(payload, label="sealed experiment")
    sealing = _json_object(raw.get("sealing"), label="sealing")
    material = _seal_material(raw)
    if raw.get("protocol") != PROTOCOL or sealing.get("phase") != "predictions_committed":
        raise V07EvaluationError("unsupported or uncommitted v0.7 experiment")
    if sealing.get("labels_loaded") is not False or _contains_gold(material):
        raise V07EvaluationError("Gold isolation failed before prediction commitment")
    expected = canonical_sha256(material)
    if sealing.get("prediction_commitment_sha256") != expected:
        raise V07EvaluationError("experiment prediction commitment mismatch")
    arms = _json_object(material.get("arms"), label="experiment arms")
    commitments = _json_object(sealing.get("arm_commitments"), label="arm commitments")
    for name in ARM_NAMES:
        if name not in arms or commitments.get(name) != canonical_sha256(arms[name]):
            raise V07EvaluationError(f"arm {name} commitment mismatch")


def load_gold(path: Path) -> dict[str, GoldCase]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise V07EvaluationError("Gold must be readable UTF-8 JSON") from exc
    values = raw.get("cases", raw) if isinstance(raw, Mapping) else raw
    if isinstance(values, Mapping):
        entries: Iterable[tuple[str | None, Any]] = values.items()
    elif isinstance(values, list):
        entries = ((None, item) for item in values)
    else:
        raise V07EvaluationError("Gold must contain a cases object or list")
    result: dict[str, GoldCase] = {}
    for fallback, item in entries:
        row = _json_object(item, label="Gold case")
        case_id = str(row.get("case_id") or fallback or "")
        vulnerable = row.get("gold_vulnerable", row.get("vulnerable"))
        cwe = _integer(row.get("gold_cwe", row.get("cwe")))
        if not case_id or not isinstance(vulnerable, bool) or cwe is None:
            raise V07EvaluationError("each Gold case needs case_id, boolean vulnerability, and integer CWE")
        if case_id in result:
            raise V07EvaluationError(f"duplicate Gold case: {case_id}")
        result[case_id] = GoldCase(case_id, vulnerable, cwe)
    if not result:
        raise V07EvaluationError("Gold is empty")
    return result


def _integer(value: Any) -> int | None:
    if isinstance(value, bool) or value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _prediction(value: Any) -> Prediction:
    if not isinstance(value, Mapping):
        return Prediction.missing()
    vulnerable = value.get("vulnerable", value.get("predicted_vulnerable"))
    if vulnerable not in (True, False):
        return Prediction.missing()
    cwe = _integer(value.get("cwe", value.get("predicted_cwe")))
    if vulnerable and cwe is None:
        return Prediction.missing()
    return Prediction(vulnerable, cwe if vulnerable else None, True)


def _record_prediction(raw: Mapping[str, Any]) -> Prediction:
    nested = raw.get("prediction", raw.get("final_prediction"))
    return _prediction(nested if nested is not None else raw)


def _receipt_commitment(raw: Mapping[str, Any]) -> tuple[str, bool]:
    declared = raw.get(
        "provider_receipt_commitment_sha256",
        raw.get("provider_receipt_commitment", ""),
    )
    receipt = raw.get("provider_receipt")
    if isinstance(receipt, Mapping):
        material = {key: value for key, value in receipt.items() if key not in {"commitment", "commitment_sha256"}}
        computed = canonical_sha256(material)
        nested = receipt.get("commitment_sha256", receipt.get("commitment"))
        if nested is not None and nested != computed:
            return str(nested), False
        if not declared:
            declared = computed
        elif declared != computed:
            return str(declared), False
    return str(declared), _valid_sha256(declared)


def _identity(raw: Mapping[str, Any], case_id: str) -> tuple[Mapping[str, Any], bool]:
    value = raw.get("pair_identity")
    if not isinstance(value, Mapping):
        return {}, False
    identity = dict(value)
    if any(field not in identity for field in PAIR_IDENTITY_FIELDS):
        return identity, False
    digest_fields = (
        "input_manifest_digest",
        "audit_profile_digest",
        "primary_source_digest",
        "model_catalog_digest",
    )
    digests_valid = all(_valid_sha256(identity[field]) for field in digest_fields)
    support = identity["support_context_digests"]
    support_valid = isinstance(support, list) and all(_valid_sha256(item) for item in support)
    max_input_tokens = _integer(identity["max_input_tokens"])
    max_output_tokens = _integer(identity["max_output_tokens"])
    scalar_valid = bool(
        identity["unit_id"] == case_id
        and isinstance(identity["model_id"], str)
        and identity["model_id"]
        and isinstance(identity["base_url_policy_id"], str)
        and identity["base_url_policy_id"]
        and isinstance(identity["prompt_template_version"], str)
        and identity["prompt_template_version"]
        and isinstance(identity["response_schema_version"], str)
        and identity["response_schema_version"]
        and max_input_tokens is not None
        and max_input_tokens > 0
        and max_output_tokens is not None
        and max_output_tokens > 0
        and isinstance(identity["timeout"], (int, float))
        and not isinstance(identity["timeout"], bool)
        and identity["timeout"] > 0
        and isinstance(identity["retry_policy"], (str, Mapping))
        and bool(identity["retry_policy"])
        and (identity["temperature"] is None or isinstance(identity["temperature"], (int, float)))
        and (identity["seed"] is None or _integer(identity["seed"]) is not None)
    )
    return identity, digests_valid and support_valid and scalar_valid


def _parse_record(value: Any) -> Record:
    raw = _json_object(value, label="prediction record")
    case_id = str(raw.get("case_id") or raw.get("unit_id") or "")
    if not case_id:
        raise V07EvaluationError("every prediction record needs case_id/unit_id")
    prediction = _record_prediction(raw)
    baseline = _prediction(raw.get("baseline_prediction"))
    public = _prediction(raw.get("public_prediction"))
    identity, identity_valid = _identity(raw, case_id)
    receipt, receipt_valid = _receipt_commitment(raw)
    raw_patches = raw.get("patches")
    if raw_patches is None and raw.get("patch_key"):
        raw_patches = [
            {
                key: raw.get(key)
                for key in (
                    "patch_key",
                    "patch_kind",
                    "cwe",
                    "evidence_digest",
                    "rule_bundle_digest",
                    "parser_digest",
                )
            }
        ]
    patches = tuple(item for item in raw_patches or [] if isinstance(item, Mapping))
    return Record(
        case_id=case_id,
        prediction=prediction,
        baseline_prediction=baseline,
        public_prediction=public,
        identity=identity,
        identity_valid=identity_valid,
        receipt_commitment=receipt,
        receipt_valid=receipt_valid,
        patches=patches,
        augmentation_status=str(raw.get("augmentation_status", "completed")).lower(),
    )


def _parse_arm(name: str, value: Any) -> Arm:
    raw = _json_object(value, label=f"arm {name}")
    runs = raw.get("runs")
    if not isinstance(runs, list):
        raise V07EvaluationError(f"arm {name} must contain runs")
    result: dict[int, Run] = {}
    for index, item in enumerate(runs, 1):
        run = _json_object(item, label=f"arm {name} run")
        repetition = _integer(run.get("repetition", index))
        if repetition is None or repetition < 1 or repetition in result:
            raise V07EvaluationError(f"arm {name} has invalid/duplicate repetition")
        values = run.get("records", run.get("predictions", run.get("unit_decisions")))
        if not isinstance(values, list):
            raise V07EvaluationError(f"arm {name} repetition {repetition} lacks records")
        records: dict[str, Record] = {}
        for record_value in values:
            record = _parse_record(record_value)
            if record.case_id in records:
                raise V07EvaluationError(f"arm {name} repetition {repetition} duplicates {record.case_id}")
            records[record.case_id] = record
        result[repetition] = Run(
            repetition,
            str(run.get("execution_id", "")),
            str(run.get("status", "completed")).lower(),
            records,
        )
    return Arm(name, result)


def _parse_arms(sealed: Mapping[str, Any]) -> dict[str, Arm]:
    values = _json_object(sealed.get("arms"), label="experiment arms")
    return {name: _parse_arm(name, values[name]) for name in ARM_NAMES}


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _score(
    rows: Sequence[tuple[GoldCase, Prediction]],
    target_cwes: frozenset[int],
) -> dict[str, Any]:
    overall = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    exact = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    valid = 0
    for expected, predicted in rows:
        if not predicted.schema_valid:
            if expected.vulnerable:
                overall["fn"] += 1
            if expected.vulnerable and expected.cwe in target_cwes:
                exact["fn"] += 1
            continue
        valid += 1
        _classify(expected.vulnerable, predicted.vulnerable is True, overall)
        expected_target = expected.vulnerable and expected.cwe in target_cwes
        predicted_target = predicted.vulnerable is True and predicted.cwe in target_cwes
        exact_match = expected_target and predicted_target and predicted.cwe == expected.cwe
        if exact_match:
            exact["tp"] += 1
        elif expected_target:
            exact["fn"] += 1
            exact["fp"] += int(predicted_target)
        elif predicted_target:
            exact["fp"] += 1
        else:
            exact["tn"] += 1
    overall_f1 = _f1(overall)
    exact_f1 = _f1(exact)
    coverage = _ratio(valid, len(rows)) or 0.0
    return {
        "n": len(rows),
        "overall_binary_confusion": overall,
        "target_cwe_confusion": exact,
        "exact_cwe_confusion": exact,
        "overall_binary_precision": _ratio(overall["tp"], overall["tp"] + overall["fp"]),
        "overall_binary_recall": _ratio(overall["tp"], overall["tp"] + overall["fn"]),
        "overall_binary_f1": overall_f1,
        "target_cwe_precision": _ratio(exact["tp"], exact["tp"] + exact["fp"]),
        "target_cwe_recall": _ratio(exact["tp"], exact["tp"] + exact["fn"]),
        "target_cwe_f1": exact_f1,
        "exact_cwe_precision": _ratio(exact["tp"], exact["tp"] + exact["fp"]),
        "exact_cwe_recall": _ratio(exact["tp"], exact["tp"] + exact["fn"]),
        "exact_cwe_f1": exact_f1,
        "coverage": coverage,
        "effective_f1": overall_f1 * coverage,
        "target_effective_f1": exact_f1 * coverage,
        "exact_cwe_effective_f1": exact_f1 * coverage,
        "missing_as_failure": len(rows) - valid,
    }


def _classify(expected: bool, predicted: bool, counts: dict[str, int]) -> None:
    if expected and predicted:
        counts["tp"] += 1
    elif expected:
        counts["fn"] += 1
    elif predicted:
        counts["fp"] += 1
    else:
        counts["tn"] += 1


def _f1(counts: Mapping[str, int]) -> float:
    denominator = 2 * counts["tp"] + counts["fp"] + counts["fn"]
    return 2 * counts["tp"] / denominator if denominator else 0.0


def _arm_score(
    arm: Arm,
    gold: Mapping[str, GoldCase],
    repetitions: int,
    target_cwes: frozenset[int],
    *,
    view: str = "prediction",
) -> dict[str, Any]:
    rounds: list[dict[str, Any]] = []
    pooled: list[tuple[GoldCase, Prediction]] = []
    completed = recovery = 0
    for repetition in range(1, repetitions + 1):
        run = arm.runs.get(repetition)
        completed += int(run is not None and run.status in PASSING_STATUSES)
        recovery += int(run is not None and run.status == RECOVERY_STATUS)
        rows = [
            (
                expected,
                _view_prediction(run.records.get(case_id) if run else None, view),
            )
            for case_id, expected in sorted(gold.items())
        ]
        pooled.extend(rows)
        rounds.append(
            {
                "repetition": repetition,
                "status": run.status if run else "missing",
                **_score(rows, target_cwes),
            }
        )
    return {
        "name": arm.name,
        "expected_repetitions": repetitions,
        "completion_rate": completed / repetitions,
        "recovery_required": recovery,
        "rounds": rounds,
        "aggregate": _score(pooled, target_cwes),
    }


def _view_prediction(record: Record | None, view: str) -> Prediction:
    if record is None:
        return Prediction.missing()
    if view == "baseline":
        return record.baseline_prediction
    if view == "public":
        return record.public_prediction
    return record.prediction


def _same_prediction(left: Prediction, right: Prediction) -> bool:
    return left.material() == right.material()


def _gate_zero(
    arms: Mapping[str, Arm],
    case_ids: Sequence[str],
    repetitions: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    identity_match = receipt_match = baseline_match = case_universe_match = True
    execution_ids_unique = True
    repetitions_independent = True
    examples: list[dict[str, Any]] = []
    for name in ARM_NAMES:
        execution_ids = [
            arms[name].runs[item].execution_id for item in range(1, repetitions + 1) if item in arms[name].runs
        ]
        execution_ids_unique &= bool(
            len(execution_ids) == repetitions and all(execution_ids) and len(set(execution_ids)) == repetitions
        )
    for case_id in case_ids:
        for name in ARM_NAMES:
            receipts = [
                arms[name].runs[repetition].records[case_id].receipt_commitment
                for repetition in range(1, repetitions + 1)
                if repetition in arms[name].runs and case_id in arms[name].runs[repetition].records
            ]
            repetitions_independent &= len(receipts) == repetitions and len(set(receipts)) == repetitions
    for repetition in range(1, repetitions + 1):
        for name in ARM_NAMES:
            run = arms[name].runs.get(repetition)
            case_universe_match &= bool(run and set(run.records) == set(case_ids))
        for case_id in case_ids:
            records: dict[str, Record | None] = {}
            for name in ARM_NAMES:
                run = arms[name].runs.get(repetition)
                records[name] = run.records.get(case_id) if run else None
            present = all(records.values())
            identity_ok = bool(
                present
                and all(record and record.identity_valid for record in records.values())
                and len({canonical_sha256(record.identity) for record in records.values() if record}) == 1
            )
            receipt_ok = bool(
                present
                and all(record and record.receipt_valid for record in records.values())
                and len({record.receipt_commitment for record in records.values() if record}) == 1
            )
            direct = records["A"].prediction if records["A"] else Prediction.missing()
            baselines_ok = bool(
                present
                and all(
                    record and _same_prediction(record.baseline_prediction, direct)
                    for name, record in records.items()
                    if name != "A"
                )
            )
            identity_match &= identity_ok
            receipt_match &= receipt_ok
            baseline_match &= baselines_ok
            if len(examples) < 10 and not (identity_ok and receipt_ok and baselines_ok):
                examples.append(
                    {
                        "repetition": repetition,
                        "case_id": case_id,
                        "identity_match": identity_ok,
                        "receipt_match": receipt_ok,
                        "baseline_match": baselines_ok,
                    }
                )
    return (
        {
            "case_universe_matches_gold": case_universe_match,
            "pair_identity_all_fields_match": identity_match,
            "provider_receipt_commitments_match": receipt_match,
            "agent_baseline_bit_identical": baseline_match,
            "execution_ids_unique_per_repetition": execution_ids_unique,
            "receipt_commitments_independent_across_repetitions": repetitions_independent,
        },
        examples,
    )


def _gate_one(
    arms: Mapping[str, Arm], case_ids: Sequence[str], repetitions: int
) -> tuple[dict[str, bool], list[dict[str, Any]]]:
    public_match = structured_match = fallback_match = True
    public_valid = runtime_complete = True
    examples: list[dict[str, Any]] = []
    for repetition in range(1, repetitions + 1):
        a_run = arms["A"].runs.get(repetition)
        c_run = arms["C"].runs.get(repetition)
        d_run = arms["D"].runs.get(repetition)
        runtime_complete &= bool(d_run and d_run.status in PASSING_STATUSES)
        for case_id in case_ids:
            a = a_run.records.get(case_id) if a_run else None
            c = c_run.records.get(case_id) if c_run else None
            d = d_run.records.get(case_id) if d_run else None
            direct = a.prediction if a else Prediction.missing()
            public = d.public_prediction if d else Prediction.missing()
            structured = d.prediction if d else Prediction.missing()
            c_prediction = c.prediction if c else Prediction.missing()
            current_public = _same_prediction(public, direct)
            current_structured = _same_prediction(structured, c_prediction)
            current_valid = public.schema_valid
            current_fallback = bool(
                d is None
                or d.augmentation_status not in {"failed", "error", "timeout", RECOVERY_STATUS}
                or current_public
            )
            public_match &= current_public
            structured_match &= current_structured
            public_valid &= current_valid
            fallback_match &= current_fallback
            if len(examples) < 10 and not (
                current_public and current_structured and current_valid and current_fallback
            ):
                examples.append(
                    {
                        "repetition": repetition,
                        "case_id": case_id,
                        "public_matches_direct": current_public,
                        "runtime_matches_c": current_structured,
                        "public_schema_valid": current_valid,
                        "failure_fell_back": current_fallback,
                    }
                )
    return (
        {
            "public_output_equals_direct": public_match,
            "public_coverage_100_percent": public_valid,
            "runtime_completion_100_percent": runtime_complete,
            "d_structured_output_equals_c": structured_match,
            "augmentation_failure_falls_back": fallback_match,
        },
        examples,
    )


def _patch_report(
    arms: Mapping[str, Arm],
    gold: Mapping[str, GoldCase],
    repetitions: int,
    target_cwes: frozenset[int],
) -> tuple[list[dict[str, Any]], dict[str, bool], list[dict[str, Any]]]:
    counters: dict[str, dict[str, Any]] = {}
    untracked: list[dict[str, Any]] = []
    core_regressions = 0

    def register(patch: Mapping[str, Any]) -> dict[str, Any] | None:
        if not patch.get("patch_key"):
            return None
        key = str(patch["patch_key"])
        row = counters.setdefault(
            key,
            {
                "patch_key": key,
                "patch_kind": str(patch.get("patch_kind", "unknown")),
                "changes": 0,
                "tp_fixed": 0,
                "fp_introduced": 0,
                "fn_introduced": 0,
                "cwe_misclassified": 0,
                "digests_valid": True,
            },
        )
        row["digests_valid"] &= all(
            _valid_sha256(patch.get(field)) for field in ("evidence_digest", "rule_bundle_digest", "parser_digest")
        )
        return row

    for repetition in range(1, repetitions + 1):
        a_run = arms["A"].runs.get(repetition)
        c_run = arms["C"].runs.get(repetition)
        for case_id, expected in gold.items():
            a = a_run.records.get(case_id) if a_run else None
            c = c_run.records.get(case_id) if c_run else None
            baseline = a.prediction if a else Prediction.missing()
            candidate = c.prediction if c else Prediction.missing()
            patches = c.patches if c else ()
            if expected.cwe in CORE_CWES and _correct(expected, baseline) and not _correct(expected, candidate):
                core_regressions += 1
            if _same_prediction(baseline, candidate):
                for patch in patches:
                    register(patch)
                continue
            if len(patches) != 1 or not patches[0].get("patch_key"):
                untracked.append({"repetition": repetition, "case_id": case_id})
                continue
            patch = patches[0]
            row = register(patch)
            if row is None:
                untracked.append({"repetition": repetition, "case_id": case_id})
                continue
            row["changes"] += 1
            expected_positive = expected.vulnerable and expected.cwe in target_cwes
            baseline_correct = _correct(expected, baseline)
            candidate_correct = _correct(expected, candidate)
            candidate_positive = _target_positive(candidate, target_cwes)
            row["tp_fixed"] += int(expected_positive and not baseline_correct and candidate_correct)
            row["fp_introduced"] += int(
                candidate_positive
                and not candidate_correct
                and (not baseline.schema_valid or not _same_prediction(baseline, candidate))
            )
            row["fn_introduced"] += int(expected_positive and baseline_correct and not candidate_correct)
            row["cwe_misclassified"] += int(
                expected_positive and candidate.vulnerable is True and candidate.cwe != expected.cwe
            )
    reports: list[dict[str, Any]] = []
    for row in counters.values():
        denominator = row["tp_fixed"] + row["fp_introduced"]
        precision = _ratio(row["tp_fixed"], denominator)
        threshold = 0.98 if row["patch_kind"] in {"configuration", "automatic_deterministic"} else 0.95
        reports.append(
            {
                **row,
                "precision": precision,
                "required_precision": threshold,
                "net_gain": row["tp_fixed"] - row["fp_introduced"] - row["fn_introduced"],
                "qualified": bool(
                    row["digests_valid"]
                    and precision is not None
                    and precision >= threshold
                    and row["tp_fixed"] > row["fp_introduced"]
                    and row["fn_introduced"] == 0
                    and row["cwe_misclassified"] == 0
                ),
            }
        )
    reports.sort(key=lambda item: item["patch_key"])
    fixed = sum(row["tp_fixed"] for row in reports)
    introduced = sum(row["fp_introduced"] for row in reports)
    overall_precision = _ratio(fixed, fixed + introduced)
    checks = {
        "patches_present": bool(reports),
        "all_changes_attributed_to_one_patch": not untracked,
        "all_patch_digests_valid": bool(reports) and all(row["digests_valid"] for row in reports),
        "all_patches_qualified": bool(reports) and all(row["qualified"] for row in reports),
        "overall_new_candidate_precision_at_least_95_percent": bool(
            overall_precision is not None and overall_precision >= 0.95
        ),
        "core_four_no_new_errors": core_regressions == 0,
    }
    return reports, checks, untracked[:10]


def _target_positive(prediction: Prediction, target_cwes: frozenset[int]) -> bool:
    return bool(prediction.schema_valid and prediction.vulnerable is True and prediction.cwe in target_cwes)


def _correct(expected: GoldCase, prediction: Prediction) -> bool:
    if not prediction.schema_valid:
        return False
    if not expected.vulnerable:
        return prediction.vulnerable is False
    return prediction.vulnerable is True and prediction.cwe == expected.cwe


def _clustered_bootstrap(
    arms: Mapping[str, Arm],
    gold: Mapping[str, GoldCase],
    repetitions: int,
    target_cwes: frozenset[int],
    *,
    draws: int,
    seed: int,
) -> list[float]:
    if draws <= 0:
        return []
    ids = sorted(gold)
    rng = random.Random(seed)  # noqa: S311  # nosec B311
    deltas: list[float] = []
    for _ in range(draws):
        sampled = [ids[rng.randrange(len(ids))] for _ in ids]
        base_rows: list[tuple[GoldCase, Prediction]] = []
        candidate_rows: list[tuple[GoldCase, Prediction]] = []
        for case_id in sampled:
            for repetition in range(1, repetitions + 1):
                a_run = arms["A"].runs.get(repetition)
                d_run = arms["D"].runs.get(repetition)
                base_rows.append(
                    (gold[case_id], _view_prediction(a_run.records.get(case_id) if a_run else None, "prediction"))
                )
                candidate_rows.append(
                    (gold[case_id], _view_prediction(d_run.records.get(case_id) if d_run else None, "prediction"))
                )
        deltas.append(
            _score(candidate_rows, target_cwes)["exact_cwe_f1"] - _score(base_rows, target_cwes)["exact_cwe_f1"]
        )
    deltas.sort()
    return [deltas[int(draws * 0.025)], deltas[min(draws - 1, int(draws * 0.975))]]


def _gate_result(
    number: int,
    title: str,
    checks: Mapping[str, bool],
    *,
    prerequisite: bool,
) -> dict[str, Any]:
    blockers = [name for name, passed in checks.items() if not passed]
    if not prerequisite:
        blockers.insert(0, f"gate_{number - 1}_prerequisite_failed")
    return {
        "gate": number,
        "title": title,
        "prerequisite_passed": prerequisite,
        "checks": dict(checks),
        "passed": prerequisite and not blockers,
        "blockers": blockers,
    }


def evaluate_abcd_protocol(
    sealed: Mapping[str, Any],
    gold: Mapping[str, GoldCase],
    *,
    bootstrap_draws: int = 5000,
    bootstrap_seed: int = 20260719,
) -> dict[str, Any]:
    """Score a previously committed A/B/C/D experiment without any model access."""

    validate_sealed_experiment(sealed)
    arms = _parse_arms(sealed)
    repetitions = _integer(sealed.get("expected_repetitions", 3))
    if repetitions is None or repetitions < 1:
        raise V07EvaluationError("expected_repetitions must be positive")
    target_values = sealed.get("target_cwes", sorted(EXTENDED_CWES))
    if not isinstance(target_values, list) or not target_values:
        raise V07EvaluationError("target_cwes must be a non-empty integer list")
    parsed_target_cwes = [_integer(value) for value in target_values]
    if any(value is None for value in parsed_target_cwes):
        raise V07EvaluationError("target_cwes must contain unique integers")
    target_cwes = frozenset(value for value in parsed_target_cwes if value is not None)
    if len(target_cwes) != len(target_values):
        raise V07EvaluationError("target_cwes must contain unique integers")
    case_ids = sorted(gold)

    scores = {name: _arm_score(arms[name], gold, repetitions, target_cwes) for name in ARM_NAMES}
    scores["D_public"] = _arm_score(arms["D"], gold, repetitions, target_cwes, view="public")

    gate0_checks, gate0_examples = _gate_zero(arms, case_ids, repetitions)
    gate0 = _gate_result(0, "Direct parity", gate0_checks, prerequisite=True)
    gate1_checks, gate1_examples = _gate_one(arms, case_ids, repetitions)
    gate1 = _gate_result(
        1,
        "Shadow runtime preservation",
        gate1_checks,
        prerequisite=gate0["passed"],
    )
    patch_rows, gate2_checks, untracked = _patch_report(arms, gold, repetitions, target_cwes)
    gate2 = _gate_result(
        2,
        "Patch qualification",
        gate2_checks,
        prerequisite=gate1["passed"],
    )

    a_rounds = scores["A"]["rounds"]
    d_rounds = scores["D"]["rounds"]
    run_deltas = [
        {
            "repetition": repetition,
            "overall_binary_f1_delta": d_rounds[repetition - 1]["overall_binary_f1"]
            - a_rounds[repetition - 1]["overall_binary_f1"],
            "exact_cwe_f1_delta": d_rounds[repetition - 1]["exact_cwe_f1"] - a_rounds[repetition - 1]["exact_cwe_f1"],
            "effective_f1_delta": d_rounds[repetition - 1]["effective_f1"] - a_rounds[repetition - 1]["effective_f1"],
            "no_negative_gain": bool(
                d_rounds[repetition - 1]["exact_cwe_f1"] >= a_rounds[repetition - 1]["exact_cwe_f1"]
                and d_rounds[repetition - 1]["effective_f1"] >= a_rounds[repetition - 1]["effective_f1"]
            ),
        }
        for repetition in range(1, repetitions + 1)
    ]
    a_aggregate = scores["A"]["aggregate"]
    d_aggregate = scores["D"]["aggregate"]
    delta = d_aggregate["exact_cwe_f1"] - a_aggregate["exact_cwe_f1"]
    ci = _clustered_bootstrap(
        arms,
        gold,
        repetitions,
        target_cwes,
        draws=bootstrap_draws,
        seed=bootstrap_seed,
    )
    missing_runs = any(set(arm.runs) != set(range(1, repetitions + 1)) for arm in arms.values())
    gate3_checks = {
        "exactly_three_repetitions": repetitions == 3,
        "private_sample_at_least_40_cases": len(gold) >= 40,
        "bootstrap_draws_at_least_1000": bootstrap_draws >= 1000,
        "three_runs_no_negative_gain": repetitions == 3 and all(item["no_negative_gain"] for item in run_deltas),
        "aggregate_f1_gain_at_least_3pp": delta >= 0.03,
        "candidate_f1_at_least_direct_plus_3pp_and_0_73": d_aggregate["exact_cwe_f1"]
        >= max(a_aggregate["exact_cwe_f1"] + 0.03, 0.73),
        "recall_not_below_direct": (d_aggregate["exact_cwe_recall"] or 0.0) >= (a_aggregate["exact_cwe_recall"] or 0.0),
        "coverage_not_below_direct": d_aggregate["coverage"] >= a_aggregate["coverage"],
        "paired_bootstrap_95_lower_nonnegative": bool(ci) and ci[0] >= 0.0,
        "recovery_required_zero": scores["D"]["recovery_required"] == 0,
        "missing_runs_zero": not missing_runs,
        "candidate_completion_100_percent": scores["D"]["completion_rate"] == 1.0,
    }
    gate3 = _gate_result(
        3,
        "Canary superiority",
        gate3_checks,
        prerequisite=gate2["passed"],
    )
    gates = {"gate_0": gate0, "gate_1": gate1, "gate_2": gate2, "gate_3": gate3}
    highest = -1
    for number in range(4):
        if gates[f"gate_{number}"]["passed"]:
            highest = number
        else:
            break
    return {
        "schema_version": "1.0",
        "protocol": PROTOCOL,
        "offline_only": True,
        "provider_requests_made_by_scorer": 0,
        "gold_isolation": {
            "prediction_commitment_verified_before_scoring": True,
            "prediction_commitment_sha256": sealed["sealing"]["prediction_commitment_sha256"],
            "gold_sha256": canonical_sha256(
                {
                    case_id: {
                        "vulnerable": value.vulnerable,
                        "cwe": value.cwe,
                    }
                    for case_id, value in sorted(gold.items())
                }
            ),
        },
        "experiment": {
            "expected_repetitions": repetitions,
            "target_cwes": sorted(target_cwes),
            "case_count": len(gold),
        },
        "arms": scores,
        "patches": patch_rows,
        "paired": {
            "run_deltas": run_deltas,
            "aggregate_overall_binary_f1_delta": (d_aggregate["overall_binary_f1"] - a_aggregate["overall_binary_f1"]),
            "aggregate_exact_cwe_f1_delta": delta,
            "paired_cluster_bootstrap_f1_delta_95": ci,
        },
        "gates": gates,
        "highest_passed_gate": highest,
        "canary_superiority_passed": gate3["passed"],
        "diagnostics": {
            "gate_0_mismatch_examples": gate0_examples,
            "gate_1_mismatch_examples": gate1_examples,
            "untracked_patch_examples": untracked,
        },
    }


def score_files(
    sealed_path: Path,
    gold_path: Path,
    *,
    bootstrap_draws: int = 5000,
    bootstrap_seed: int = 20260719,
) -> dict[str, Any]:
    """Validate the prediction commitment before opening the Gold file."""

    try:
        sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise V07EvaluationError("sealed experiment must be readable UTF-8 JSON") from exc
    validate_sealed_experiment(sealed)
    gold = load_gold(gold_path)
    return evaluate_abcd_protocol(
        sealed,
        gold,
        bootstrap_draws=bootstrap_draws,
        bootstrap_seed=bootstrap_seed,
    )


def _write(path: Path | None, value: Mapping[str, Any]) -> None:
    rendered = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    if path is None:
        sys.stdout.write(rendered)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seal or score the SecMind v0.7 offline A/B/C/D protocol")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--seal-experiment", type=Path)
    mode.add_argument("--sealed-experiment", type=Path)
    parser.add_argument("--gold", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--bootstrap-draws", type=int, default=5000)
    parser.add_argument("--bootstrap-seed", type=int, default=20260719)
    args = parser.parse_args(argv)
    try:
        if args.seal_experiment:
            if args.gold:
                parser.error("Gold cannot be supplied during prediction sealing")
            raw = json.loads(args.seal_experiment.read_text(encoding="utf-8"))
            result = seal_experiment(raw)
            _write(args.output, result)
            return 0
        if not args.gold:
            parser.error("--gold is required only after --sealed-experiment")
        result = score_files(
            args.sealed_experiment,
            args.gold,
            bootstrap_draws=args.bootstrap_draws,
            bootstrap_seed=args.bootstrap_seed,
        )
        _write(args.output, result)
        return 0 if result["canary_superiority_passed"] else 1
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, V07EvaluationError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
