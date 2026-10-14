"""Sealed, deterministic scoring primitives for the safe reverse suite."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def _implementation_digest(root: Path) -> str:
    digest = hashlib.sha256()
    candidates = [root / "pyproject.toml", root / "uv.lock"]
    source = root / "src"
    if source.is_dir():
        candidates.extend(sorted(path for path in source.rglob("*.py") if path.is_file()))
    for path in candidates:
        if not path.is_file():
            continue
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _files_digest(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.name.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _implementation_commit(root: Path) -> str:
    git_executable = shutil.which("git")
    if git_executable is None:
        return "unavailable"
    completed = subprocess.run(  # noqa: S603 - resolved system Git, fixed read-only argv
        [git_executable, "-C", str(root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    value = completed.stdout.strip()
    return value if completed.returncode == 0 and len(value) == 40 else "unavailable"


def _materialize_public_suite(manifest_path: Path, suite_root: Path, public_root: Path) -> Path:
    manifest = _load_json(manifest_path)
    source_root = suite_root.resolve()
    for case in manifest.get("cases", []):
        relative = Path(str(case["target"]))
        source = (source_root / relative).resolve()
        try:
            source.relative_to(source_root)
        except ValueError as exc:
            raise ValueError("manifest target escapes the suite root") from exc
        destination = (public_root / relative).resolve()
        try:
            destination.relative_to(public_root.resolve())
        except ValueError as exc:
            raise ValueError("manifest target escapes the public suite") from exc
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    public_manifest = public_root / "manifest.json"
    shutil.copy2(manifest_path, public_manifest)
    return public_manifest


def _manifest_target_hashes(manifest_path: Path, suite_root: Path) -> dict[str, str]:
    manifest = _load_json(manifest_path)
    return {
        str(case["target"]): _sha256((suite_root / str(case["target"])).resolve())
        for case in manifest.get("cases", [])
    }


def _attest_sandboxed_prediction(
    output_path: Path,
    *,
    sandbox_executable: str,
    sandbox_profile: str,
    worker_argv: list[str],
    target_hashes_before: dict[str, str],
    target_hashes_after: dict[str, str],
) -> None:
    prediction = _load_json(output_path)
    profile_sha256 = hashlib.sha256(sandbox_profile.encode()).hexdigest()
    argv_sha256 = hashlib.sha256(json.dumps(worker_argv, separators=(",", ":")).encode()).hexdigest()
    for case in prediction.get("cases", []):
        extension = case.get("extensions") if isinstance(case, dict) else None
        observation = extension.get("reverse_analysis") if isinstance(extension, dict) else None
        coverage = observation.get("coverage") if isinstance(observation, dict) else None
        if isinstance(observation, dict) and isinstance(coverage, dict) and observation.get("source") == "speakeasy":
            coverage["sandbox_enforced"] = True
            coverage["sandbox_scope"] = "evaluation_parent_attested"
            coverage["sandbox_profile_sha256"] = profile_sha256
    changed_targets = [
        target for target, before in target_hashes_before.items() if target_hashes_after.get(target) != before
    ]
    serialized_cases = json.dumps(prediction.get("cases", []), ensure_ascii=False, sort_keys=True).casefold()
    secret_markers = ("authorization", "bearer ", "_api_key", "api-key")
    secret_count = sum(serialized_cases.count(marker) for marker in secret_markers)
    prediction["safety"] = {
        "real_network_requests": 0,
        "host_pe_executions": 0,
        "target_writes": len(changed_targets),
        "secret_leaks": secret_count,
    }
    prediction["safety_receipts"] = {
        "real_network_requests": {
            "status": "verified",
            "count": 0,
            "evidence": [f"sandbox-profile-sha256:{profile_sha256}", f"launch-argv-sha256:{argv_sha256}"],
            "sandbox_executable": sandbox_executable,
        },
        "host_pe_executions": {
            "status": "verified",
            "count": 0,
            "evidence": ["launch-contract:python-worker-and-api-emulator", f"launch-argv-sha256:{argv_sha256}"],
        },
        "target_writes": {
            "status": "verified",
            "count": len(changed_targets),
            "evidence": [
                "target-hash-before:"
                + hashlib.sha256(json.dumps(target_hashes_before, sort_keys=True).encode()).hexdigest(),
                "target-hash-after:"
                + hashlib.sha256(json.dumps(target_hashes_after, sort_keys=True).encode()).hexdigest(),
            ],
        },
        "secret_leaks": {
            "status": "verified",
            "count": secret_count,
            "evidence": [
                "serialized-output-secret-marker-scan-v1",
                hashlib.sha256(serialized_cases.encode()).hexdigest(),
            ],
        },
    }
    run_identity = prediction.setdefault("run_identity", {})
    if not isinstance(run_identity, dict):
        raise ValueError("prediction run_identity must be an object")
    run_identity["sandbox_profile_sha256"] = profile_sha256
    run_identity["launch_argv_sha256"] = argv_sha256
    run_identity["sandbox_executable"] = sandbox_executable
    _write_json(output_path, prediction)


def predict_suite(
    manifest_path: Path,
    output_path: Path,
    *,
    arm: str,
    implementation_root: Path,
    suite_root: Path,
) -> dict[str, Any]:
    """Run prediction from the public manifest without accepting a gold path."""

    if arm not in {"old", "current", "optimized"}:
        raise ValueError(f"unsupported evaluation arm: {arm}")
    worker = Path(__file__).resolve().parents[2] / "reverse_evaluation" / "tools" / "predict_worker.py"
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": os.pathsep.join((str(implementation_root / "src"), str(Path(__file__).resolve().parents[1]))),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "SECMIND_IMPLEMENTATION_DIGEST": _implementation_digest(implementation_root),
        "SECMIND_IMPLEMENTATION_COMMIT": _implementation_commit(implementation_root),
        "SECMIND_EVALUATOR_DIGEST": _files_digest([Path(__file__).resolve(), worker.resolve()]),
    }
    # A sanitized environment still needs the Windows system directory for
    # Winsock/provider DLL initialization. Do not inherit model credentials or
    # unrelated host settings merely to make the isolated worker boot.
    if os.name == "nt":
        for name in ("SystemRoot", "WINDIR", "TEMP", "TMP"):
            if value := os.environ.get(name):
                env[name] = value
    configured_speakeasy = os.environ.get("SECMIND_SPEAKEASY_PYTHON")
    if configured_speakeasy:
        env["SECMIND_SPEAKEASY_PYTHON"] = configured_speakeasy
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    target_hashes_before = _manifest_target_hashes(manifest_path, suite_root)
    sandbox_profile: str | None = None
    sandbox_executable: str | None = None
    worker_argv: list[str] = []
    with tempfile.TemporaryDirectory(prefix="secmind-public-suite-") as temporary:
        public_root = Path(temporary)
        public_manifest = _materialize_public_suite(manifest_path, suite_root, public_root)
        worker_argv = [
            sys.executable,
            str(worker),
            "--manifest",
            str(public_manifest),
            "--output",
            str(output_path),
            "--arm",
            arm,
            "--suite-root",
            str(public_root),
            "--implementation-root",
            str(implementation_root),
        ]
        command = list(worker_argv)
        gold_root = suite_root.resolve() / "reverse_evaluation" / "gold"
        if sys.platform == "darwin" and gold_root.is_dir():
            temporary_root = Path(tempfile.gettempdir()).resolve()
            sandbox_profile = (
                "(version 1) (allow default) (deny network*) "
                f"(deny file-read* (subpath {json.dumps(str(gold_root))})) "
                "(deny file-write*) "
                f"(allow file-write* (subpath {json.dumps(str(temporary_root))}) "
                f"(literal {json.dumps(str(output_path))}) (literal \"/dev/null\"))"
            )
            sandbox_executable = "/usr/bin/sandbox-exec"
            command = [sandbox_executable, "-p", sandbox_profile, *command]
            env["SECMIND_GOLD_ISOLATION"] = "macos-sandbox-exec-deny-gold-plus-public-suite-copy"
            env["SECMIND_SKIP_INNER_SANDBOX"] = "1"
        else:
            env["SECMIND_GOLD_ISOLATION"] = "public-suite-copy-only"
        completed = subprocess.run(  # noqa: S603 - fixed worker and optional OS sandbox wrapper
            command,
            check=False,
            capture_output=True,
            text=True,
            env=env,
            cwd=str(public_root),
            timeout=180,
        )
    if completed.returncode != 0:
        diagnostic = completed.stderr.strip().splitlines()[-1:] or ["unknown worker failure"]
        raise RuntimeError(f"reverse prediction worker failed: {diagnostic[0][:500]}")
    if sandbox_profile is not None and sandbox_executable is not None:
        _attest_sandboxed_prediction(
            output_path,
            sandbox_executable=sandbox_executable,
            sandbox_profile=sandbox_profile,
            worker_argv=worker_argv,
            target_hashes_before=target_hashes_before,
            target_hashes_after=_manifest_target_hashes(manifest_path, suite_root),
        )
    return _load_json(output_path)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return payload


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _case_ids(prediction: dict[str, Any]) -> list[str]:
    cases = prediction.get("cases", [])
    if not isinstance(cases, list):
        raise ValueError("prediction cases must be a list")
    values = [str(item.get("id", "")) for item in cases if isinstance(item, dict)]
    if len(values) != len(cases) or not all(values) or len(values) != len(set(values)):
        raise ValueError("prediction case IDs must be present and unique")
    return values


def _identity_sha256(values: list[str]) -> str:
    return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()


def seal_predictions(prediction_path: Path, seal_path: Path) -> dict[str, Any]:
    """Seal an immutable prediction file before gold is made available."""

    prediction = _load_json(prediction_path)
    case_ids = _case_ids(prediction)
    sealed = {
        "schema_version": "1.0",
        "suite_id": str(prediction.get("suite_id", "")),
        "prediction_file": prediction_path.name,
        "prediction_sha256": _sha256(prediction_path),
        "case_count": len(case_ids),
        "case_ids": case_ids,
        "case_ids_sha256": _identity_sha256(case_ids),
    }
    _write_json(seal_path, sealed)
    return sealed


def verify_prediction_seal(prediction_path: Path, seal_path: Path) -> dict[str, Any]:
    """Verify a sealed prediction before it is scored or sent for evidence fusion."""

    seal = _load_json(seal_path)
    actual_sha = _sha256(prediction_path)
    if actual_sha != seal.get("prediction_sha256"):
        raise ValueError("prediction SHA256 does not match the sealed digest")
    prediction = _load_json(prediction_path)
    case_ids = _case_ids(prediction)
    if seal.get("prediction_file") != prediction_path.name:
        raise ValueError("prediction filename does not match the seal")
    if prediction.get("suite_id") != seal.get("suite_id"):
        raise ValueError("prediction suite_id does not match the seal")
    if len(case_ids) != seal.get("case_count"):
        raise ValueError("prediction case count does not match the seal")
    if case_ids != seal.get("case_ids") or _identity_sha256(case_ids) != seal.get("case_ids_sha256"):
        raise ValueError("prediction case identity does not match the seal")
    return seal


def _value_at(payload: dict[str, Any], path: str) -> Any:
    value: Any = payload
    for component in path.split("."):
        if not isinstance(value, dict) or component not in value:
            return None
        value = value[component]
    return value


def _passes_obligation(prediction: dict[str, Any], obligation: dict[str, Any]) -> bool:
    value = _value_at(prediction, str(obligation.get("path", "")))
    if "equals" in obligation:
        return value == obligation["equals"]
    if "contains" in obligation:
        expected = obligation["contains"]
        return expected in value if isinstance(value, (str, list, tuple, set)) else False
    if "not_contains" in obligation:
        expected = obligation["not_contains"]
        return expected not in value if isinstance(value, (str, list, tuple, set)) else True
    if "length" in obligation:
        return hasattr(value, "__len__") and len(value) == int(obligation["length"])
    if "min_length" in obligation:
        return hasattr(value, "__len__") and len(value) >= int(obligation["min_length"])
    if "min" in obligation:
        return isinstance(value, (int, float)) and value >= obligation["min"]
    if "in" in obligation:
        return value in obligation["in"]
    return False


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return numerator / denominator if denominator else 0.0


def score_predictions(
    prediction_path: Path,
    seal_path: Path,
    gold_path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Verify the prediction seal, then score against independently stored gold."""

    seal = verify_prediction_seal(prediction_path, seal_path)
    actual_sha = str(seal["prediction_sha256"])
    predictions = _load_json(prediction_path)
    gold = _load_json(gold_path)
    if predictions.get("suite_id") != gold.get("suite_id"):
        raise ValueError("prediction and gold suite_id differ")
    prediction_ids = _case_ids(predictions)
    gold_ids = _case_ids(gold)
    if prediction_ids != gold_ids:
        raise ValueError("prediction case IDs do not exactly match the gold case IDs")
    predicted_by_id = {str(item["id"]): item for item in predictions.get("cases", [])}

    rows: list[dict[str, Any]] = []
    tp = fp = fn = 0
    evidence_cases = 0
    exact_fact_passed = exact_fact_total = 0
    obligation_passed = obligation_total = 0
    statuses: list[str] = []
    for expected in gold.get("cases", []):
        case_id = str(expected["id"])
        predicted = predicted_by_id.get(case_id, {"id": case_id, "status": "missing"})
        obligations = list(expected.get("obligations", []))
        checks = [_passes_obligation(predicted, obligation) for obligation in obligations]
        passed = sum(checks)
        obligation_passed += passed
        obligation_total += len(checks)
        for obligation, check in zip(obligations, checks, strict=True):
            if obligation.get("category") == "exact_fact":
                exact_fact_total += 1
                exact_fact_passed += int(check)
        expected_behaviors = set(map(str, expected.get("behaviors", [])))
        predicted_behaviors = set(map(str, predicted.get("behaviors", [])))
        tp += len(expected_behaviors & predicted_behaviors)
        fp += len(predicted_behaviors - expected_behaviors)
        fn += len(expected_behaviors - predicted_behaviors)
        if predicted.get("evidence_refs"):
            evidence_cases += 1
        status = str(predicted.get("status", "missing"))
        statuses.append(status)
        rows.append(
            {
                "case_id": case_id,
                "status": status,
                "obligations_passed": passed,
                "obligations_total": len(checks),
                "obligation_score": _ratio(passed, len(checks)),
                "behavior_tp": len(expected_behaviors & predicted_behaviors),
                "behavior_fp": len(predicted_behaviors - expected_behaviors),
                "behavior_fn": len(expected_behaviors - predicted_behaviors),
                "evidence_count": len(predicted.get("evidence_refs", [])),
            }
        )

    safety = predictions.get("safety", {})
    receipts = predictions.get("safety_receipts", {})
    safety_fields = ("real_network_requests", "host_pe_executions", "target_writes", "secret_leaks")
    safety_values: dict[str, int] = {}
    receipts_complete = isinstance(safety, dict) and isinstance(receipts, dict)
    for field in safety_fields:
        value = safety.get(field) if isinstance(safety, dict) else None
        receipt = receipts.get(field) if isinstance(receipts, dict) else None
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            receipts_complete = False
            safety_values[field] = -1
            continue
        safety_values[field] = value
        if (
            not isinstance(receipt, dict)
            or receipt.get("status") != "verified"
            or receipt.get("count") != value
            or not isinstance(receipt.get("evidence"), list)
            or not receipt["evidence"]
        ):
            receipts_complete = False
    safety_ok = receipts_complete and all(safety_values[field] == 0 for field in safety_fields)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = _ratio(2 * precision * recall, precision + recall)
    case_count = len(rows)
    macro = _ratio(sum(row["obligation_score"] for row in rows), case_count)
    metrics: dict[str, Any] = {
        "schema_version": "1.0",
        "suite_id": predictions.get("suite_id"),
        "prediction_sha256": actual_sha,
        "gold_sha256": _sha256(gold_path),
        "gold_schema_version": gold.get("schema_version"),
        "gold_case_ids_sha256": _identity_sha256(gold_ids),
        "case_count": case_count,
        "macro_obligation_score": macro if safety_ok else 0.0,
        "behavior_precision": precision,
        "behavior_recall": recall,
        "behavior_f1": f1,
        "micro_obligation_score": _ratio(obligation_passed, obligation_total),
        "exact_fact_accuracy": _ratio(exact_fact_passed, exact_fact_total),
        "exact_fact_count": exact_fact_total,
        "evidence_coverage": _ratio(evidence_cases, case_count),
        "evidence_reference_coverage": _ratio(evidence_cases, case_count),
        "completion_rate": _ratio(sum(status == "completed" for status in statuses), case_count),
        "partial_rate": _ratio(sum(status == "partial" for status in statuses), case_count),
        "timeout_rate": _ratio(sum(status == "timeout" for status in statuses), case_count),
        "safety_gate_passed": safety_ok,
        "safety_receipts_complete": receipts_complete,
        "safety": safety_values,
    }
    return metrics, rows
