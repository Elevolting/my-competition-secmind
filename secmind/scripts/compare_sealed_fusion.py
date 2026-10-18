from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import math
import re
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import score_comprehensive_offline as scorer

EXPECTED_ARM = "v080"
EXPECTED_MODEL_ID = "deepseek-v4-flash"
EXPECTED_MODEL_BASE_URL = "https://api.deepseek.com"
EXPECTED_SEAL_SCHEMA = "1.2"
EXPECTED_SEAL_PROTOCOL = "secmind-comprehensive-blind-v2"
EXPECTED_PROJECTION_SCHEMA = "test3-sealed-projection-1.0"
EXPECTED_LEDGER_EVENT_SCHEMA = "1.7"
LEDGER_RECEIPT_SCHEMA = "secmind-evaluation-ledger-receipt-v1"
ENVELOPE_FIELD = "envelope_commitment_sha256"
ZERO_HASH = "0" * 64
MAX_SEAL_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
HEX_64 = re.compile(r"^[a-f0-9]{64}$")
GIT_OID = re.compile(r"^[a-f0-9]{40}(?:[a-f0-9]{24})?$")

SCALAR_FIELDS = [
    "label",
    "sealed_arm",
    "repetition",
    "task_id",
    "domain",
    "project",
    "language",
    "scoring_mode",
    "score",
    "result_status",
    "runtime_status",
    "operational_error",
    "operational_success",
    "live_provider_success",
    "timed_out",
    "duration_ms",
    "provider_requests",
    "input_tokens",
    "output_tokens",
    "finding_count",
    "evidence_complete_findings",
    "evidence_scope_finding_count",
    "ledger_valid",
    "exact_cwe_tp",
    "exact_cwe_fp",
    "exact_cwe_tn",
    "exact_cwe_fn",
    "baseline_chain_complete",
    "baseline_chain_consistent",
    "primary_preserved",
]


def parse_sealed_specs(values: Sequence[str]) -> dict[str, Path]:
    sealed_paths: dict[str, Path] = {}
    for value in values:
        label, separator, raw_path = value.partition("=")
        label = label.strip()
        raw_path = raw_path.strip()
        if not separator or not label or not raw_path:
            raise SystemExit(f"invalid --sealed value {value!r}; expected LABEL=PATH")
        if label in sealed_paths:
            raise SystemExit(f"duplicate sealed label: {label}")
        sealed_paths[label] = Path(raw_path).resolve()
    return sealed_paths


def parse_expected_sources(values: Sequence[str]) -> dict[str, tuple[str, str]]:
    identities: dict[str, tuple[str, str]] = {}
    for value in values:
        label, separator, raw_identity = value.partition("=")
        commit, identity_separator, tree = raw_identity.partition(":")
        label = label.strip()
        commit = commit.strip().casefold()
        tree = tree.strip().casefold()
        valid_identity = GIT_OID.fullmatch(commit) and GIT_OID.fullmatch(tree)
        if not separator or not identity_separator or not label or not valid_identity:
            raise SystemExit(f"invalid --expected-source value {value!r}; expected LABEL=COMMIT:TREE")
        if label in identities:
            raise SystemExit(f"duplicate expected source label: {label}")
        identities[label] = (commit, tree)
    return identities


def load_cohort_manifest(path: Path) -> tuple[list[str], list[int], str]:
    manifest = _read_json_object(path.resolve(), label="team-fusion cohort manifest", maximum=MAX_MANIFEST_BYTES)
    task_ids = manifest.get("ordered_task_ids")
    repetitions = manifest.get("repetitions")
    if (
        manifest.get("schema_version") != "1.0"
        or manifest.get("dataset_version") != scorer.DATASET_VERSION
        or manifest.get("arm") != EXPECTED_ARM
        or manifest.get("model") != EXPECTED_MODEL_ID
        or not isinstance(task_ids, list)
        or not task_ids
        or any(not isinstance(item, str) or not item for item in task_ids)
        or len(task_ids) != len(set(task_ids))
        or isinstance(repetitions, bool)
        or not isinstance(repetitions, int)
        or repetitions < 1
    ):
        raise SystemExit("team-fusion cohort manifest is invalid")
    return list(task_ids), list(range(1, repetitions + 1)), scorer.file_sha256(path.resolve())


def _read_json_object(path: Path, *, label: str, maximum: int) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"missing or unsafe {label}: {path}")
    size = path.stat().st_size
    if size < 2 or size > maximum:
        raise SystemExit(f"{label} size is outside the limit: {size}")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"invalid {label}: expected a JSON object")
    return value


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
    except OSError as exc:
        raise SystemExit(f"unable to hash public input: {path}") from exc
    return digest.hexdigest(), size


def _safe_relative_path(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SystemExit(f"{label} must be a non-empty relative path")
    normalized = value.replace("\\", "/")
    posix = PurePosixPath(normalized)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or any(part in {"", ".", ".."} for part in posix.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
    ):
        raise SystemExit(f"unsafe {label}: {value!r}")
    return posix.as_posix()


def _path_within(root: Path, relative: str, *, label: str) -> Path:
    current = root
    for part in PurePosixPath(relative).parts:
        current /= part
        if current.is_symlink():
            raise SystemExit(f"{label} traverses a symbolic link: {relative}")
    try:
        resolved = current.resolve(strict=True)
    except OSError as exc:
        raise SystemExit(f"missing {label}: {relative}") from exc
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise SystemExit(f"{label} escapes its public case: {relative}")
    return resolved


def _valid_sha256(value: object, *, label: str) -> str:
    digest = str(value).casefold()
    if not HEX_64.fullmatch(digest):
        raise SystemExit(f"invalid {label} SHA-256")
    return digest


def _public_manifest_sha256(dataset_path: Path, dataset: dict[str, Any]) -> str:
    cases = dataset.get("cases")
    if not isinstance(cases, list):
        raise SystemExit("public dataset must contain a cases list")
    try:
        tasks = [
            {"task_id": item["task_id"], "task_sha256": item["task_sha256"]}
            for item in sorted(cases, key=lambda row: row["task_id"])
        ]
    except (KeyError, TypeError) as exc:
        raise SystemExit("public dataset contains an invalid case summary") from exc
    return scorer.canonical_sha256(
        {
            "dataset_sha256": hashlib.sha256(dataset_path.read_bytes()).hexdigest(),
            "tasks": tasks,
        }
    )


def _validate_public_dataset(
    public_root: Path,
    expected_task_ids: Sequence[str],
) -> tuple[str, dict[str, dict[str, dict[str, Any]]]]:
    try:
        root = public_root.resolve(strict=True)
    except OSError as exc:
        raise SystemExit(f"public root is unavailable: {public_root}") from exc
    if root.is_symlink() or not root.is_dir():
        raise SystemExit("public root must be a real directory")
    dataset_path = root / "dataset.json"
    dataset = _read_json_object(dataset_path, label="public dataset", maximum=MAX_MANIFEST_BYTES)
    cases = dataset.get("cases")
    if dataset.get("dataset_version") != scorer.DATASET_VERSION or not isinstance(cases, list):
        raise SystemExit("public dataset identity mismatch")
    if dataset.get("task_count") != len(cases):
        raise SystemExit("public dataset task_count does not match its case roster")
    summaries: dict[str, dict[str, Any]] = {}
    for summary in cases:
        if not isinstance(summary, dict) or not isinstance(summary.get("task_id"), str):
            raise SystemExit("public dataset contains an invalid case summary")
        task_id = summary["task_id"]
        if task_id in summaries:
            raise SystemExit(f"public dataset repeats task_id: {task_id}")
        _safe_relative_path(task_id, label="public task_id")
        _valid_sha256(summary.get("task_sha256"), label=f"task {task_id} manifest")
        summaries[task_id] = summary
    if set(expected_task_ids) - set(summaries):
        raise SystemExit("public dataset does not contain the fixed expected cohort")

    inputs_by_task: dict[str, dict[str, dict[str, Any]]] = {}
    for task_id in expected_task_ids:
        case_root = (root / "cases" / task_id).resolve(strict=True)
        if not case_root.is_relative_to(root) or case_root.is_symlink() or not case_root.is_dir():
            raise SystemExit(f"unsafe public case root: {task_id}")
        task_path = _path_within(case_root, "task.json", label=f"task {task_id} manifest")
        raw_task = task_path.read_bytes()
        declared_task_hash = _valid_sha256(summaries[task_id]["task_sha256"], label=f"task {task_id} manifest")
        if not hmac.compare_digest(hashlib.sha256(raw_task).hexdigest(), declared_task_hash):
            raise SystemExit(f"task manifest hash mismatch: {task_id}")
        try:
            task = json.loads(raw_task)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise SystemExit(f"invalid task manifest: {task_id}") from exc
        if not isinstance(task, dict) or task.get("task_id") != task_id or not isinstance(task.get("inputs"), list):
            raise SystemExit(f"task manifest identity mismatch: {task_id}")
        path_map: dict[str, dict[str, Any]] = {}
        comparison_paths: set[str] = set()
        for item in task["inputs"]:
            if not isinstance(item, dict):
                raise SystemExit(f"task {task_id} has an invalid input entry")
            relative = _safe_relative_path(item.get("path"), label=f"task {task_id} input")
            comparison = relative.casefold()
            if comparison in comparison_paths:
                raise SystemExit(f"task {task_id} repeats an input path: {relative}")
            comparison_paths.add(comparison)
            source = _path_within(case_root, relative, label=f"task {task_id} input")
            actual_hash, actual_size = _sha256_file(source)
            expected_hash = _valid_sha256(item.get("sha256"), label=f"task {task_id} input")
            expected_size = item.get("size_bytes")
            if isinstance(expected_size, bool) or not isinstance(expected_size, int) or expected_size < 0:
                raise SystemExit(f"task {task_id} input has an invalid size: {relative}")
            if actual_size != expected_size or not hmac.compare_digest(actual_hash, expected_hash):
                raise SystemExit(f"public input hash mismatch: {task_id}/{relative}")
            path_map[relative] = {
                "artifact_id": f"public-{expected_hash[:32]}",
                "sha256": expected_hash,
                "size_bytes": expected_size,
            }
        if not path_map:
            raise SystemExit(f"task {task_id} has no public inputs")
        inputs_by_task[task_id] = path_map
    return _public_manifest_sha256(dataset_path, dataset), inputs_by_task


def _verify_envelope(sealed: Mapping[str, Any], *, label: str) -> None:
    commitment = sealed.get(ENVELOPE_FIELD)
    if not isinstance(commitment, str) or not HEX_64.fullmatch(commitment):
        raise SystemExit(f"missing envelope commitment: {label}")
    payload = {key: value for key, value in sealed.items() if key != ENVELOPE_FIELD}
    if not hmac.compare_digest(scorer.canonical_sha256(payload), commitment):
        raise SystemExit(f"envelope commitment mismatch: {label}")


def _verify_prediction_commitment(sealed: Mapping[str, Any], *, label: str) -> None:
    if sealed.get("dataset_version") != scorer.DATASET_VERSION:
        raise SystemExit(f"sealed dataset identity mismatch: {label}")
    case_ids = sealed.get("case_ids")
    if not isinstance(case_ids, list) or not case_ids or len(case_ids) != len(set(case_ids)):
        raise SystemExit(f"sealed case roster mismatch: {label}")
    if sealed.get("case_count") != len(case_ids):
        raise SystemExit(f"sealed case count mismatch: {label}")
    rounds = sealed.get("rounds")
    if not isinstance(rounds, list) or not rounds:
        raise SystemExit(f"sealed run has no rounds: {label}")
    commitment_rows: list[dict[str, Any]] = []
    for round_data in rounds:
        if not isinstance(round_data, dict) or not isinstance(round_data.get("records"), list):
            raise SystemExit(f"invalid sealed round: {label}")
        repetition = round_data.get("repetition")
        if isinstance(repetition, bool) or not isinstance(repetition, int) or repetition < 1:
            raise SystemExit(f"invalid sealed repetition: {label}")
        records = round_data["records"]
        record_ids = [item.get("task_id") for item in records if isinstance(item, dict)]
        if len(record_ids) != len(records) or len(records) != len(case_ids) or set(record_ids) != set(case_ids):
            raise SystemExit(f"incomplete sealed round: {label}/{repetition}")
        submission = {"dataset_version": scorer.DATASET_VERSION, "results": [item["result"] for item in records]}
        submission_hash = scorer.canonical_sha256(submission)
        if not hmac.compare_digest(submission_hash, str(round_data.get("submission_sha256"))):
            raise SystemExit(f"submission commitment mismatch: {label}/{repetition}")
        commitment_rows.append({"repetition": repetition, "submission_sha256": submission_hash})
    repetitions = [row["repetition"] for row in commitment_rows]
    if repetitions != list(range(1, len(repetitions) + 1)):
        raise SystemExit(f"sealed repetitions must be contiguous and ordered: {label}")
    expected = scorer.canonical_sha256(commitment_rows)
    if not hmac.compare_digest(expected, str(sealed.get("prediction_commitment_sha256"))):
        raise SystemExit(f"prediction commitment mismatch: {label}")


def _verify_ledger_receipt(record: Mapping[str, Any], *, label: str) -> bool:
    run_id = record.get("run_id")
    exported = record.get("ledger_export")
    receipt = record.get("ledger_receipt")
    if not isinstance(run_id, str) or not run_id or not isinstance(exported, list) or not isinstance(receipt, dict):
        raise SystemExit(f"missing ledger export/receipt: {label}")
    if receipt.get("schema_version") != LEDGER_RECEIPT_SCHEMA or receipt.get("run_id") != run_id:
        raise SystemExit(f"ledger receipt identity mismatch: {label}")
    if receipt.get("event_count") != len(exported):
        raise SystemExit(f"ledger receipt count mismatch: {label}")
    if not hmac.compare_digest(str(receipt.get("events_sha256")), scorer.canonical_sha256(exported)):
        raise SystemExit(f"ledger export commitment mismatch: {label}")

    previous = ZERO_HASH
    chain_valid = bool(exported)
    event_ids: set[str] = set()
    dedupe_keys: set[str] = set()
    for expected_sequence, event in enumerate(exported, start=1):
        if not isinstance(event, dict):
            raise SystemExit(f"ledger export contains a non-object event: {label}")
        required = (
            "schema_version",
            "event_id",
            "run_id",
            "sequence",
            "event_type",
            "timestamp",
            "actor",
            "dedupe_key",
            "payload",
            "prev_hash",
            "hash",
        )
        if any(key not in event for key in required) or not isinstance(event.get("payload"), dict):
            raise SystemExit(f"ledger export event is incomplete: {label}/{expected_sequence}")
        event_id = event["event_id"]
        dedupe_key = event["dedupe_key"]
        if (
            event.get("schema_version") != EXPECTED_LEDGER_EVENT_SCHEMA
            or not isinstance(event_id, str)
            or not event_id
            or event_id in event_ids
            or not isinstance(dedupe_key, str)
            or not dedupe_key
            or dedupe_key in dedupe_keys
        ):
            raise SystemExit(f"ledger export event identity is invalid: {label}/{expected_sequence}")
        event_ids.add(event_id)
        dedupe_keys.add(dedupe_key)
        digest_input = {
            "event_id": event["event_id"],
            "run_id": event["run_id"],
            "sequence": event["sequence"],
            "event_type": event["event_type"],
            "timestamp": event["timestamp"],
            "actor": event["actor"],
            "dedupe_key": event["dedupe_key"],
            "payload": event["payload"],
            "prev_hash": event["prev_hash"],
        }
        expected_hash = scorer.canonical_sha256(digest_input)
        event_hash = str(event["hash"])
        event_valid = (
            event["run_id"] == run_id
            and event["sequence"] == expected_sequence
            and event["prev_hash"] == previous
            and HEX_64.fullmatch(event_hash) is not None
            and hmac.compare_digest(expected_hash, event_hash)
        )
        chain_valid = chain_valid and event_valid
        previous = event_hash
    head = previous if exported else ZERO_HASH
    if receipt.get("head_hash") != head or record.get("ledger_event_count") != len(exported):
        raise SystemExit(f"ledger receipt head/count mismatch: {label}")
    legacy_head = record.get("ledger_head_hash")
    if legacy_head != (head if exported else None):
        raise SystemExit(f"ledger record head mismatch: {label}")
    declared = receipt.get("chain_verified")
    if not isinstance(declared, bool) or record.get("ledger_valid") is not declared or declared != chain_valid:
        raise SystemExit(f"ledger verification receipt mismatch: {label}")
    return chain_valid


def _verify_provider_attempts(record: Mapping[str, Any], *, label: str) -> bool:
    attempts = record.get("provider_attempts")
    if not isinstance(attempts, list) or not attempts:
        return False
    successful = False
    for attempt in attempts:
        if not isinstance(attempt, dict) or attempt.get("model_id") != EXPECTED_MODEL_ID:
            raise SystemExit(f"unexpected provider model: {label}")
        succeeded = attempt.get("succeeded")
        if not isinstance(succeeded, bool):
            raise SystemExit(f"provider attempt lacks a success verdict: {label}")
        successful = successful or succeeded
    return successful


def _projection_manifest_sha256(inputs: Mapping[str, Mapping[str, Any]]) -> str:
    entries = [
        {
            "artifact_id": item["artifact_id"],
            "path": path,
            "sha256": item["sha256"],
            "size_bytes": item["size_bytes"],
        }
        for path, item in sorted(inputs.items(), key=lambda row: row[0].casefold())
    ]
    return scorer.canonical_sha256(entries)


def _verify_finding_evidence(
    result: Mapping[str, Any],
    public_inputs: Mapping[str, Mapping[str, Any]],
    *,
    label: str,
) -> tuple[int, int]:
    if _is_sealed_operational_failure(result):
        return 0, 0
    if result.get("schema_version") != EXPECTED_PROJECTION_SCHEMA:
        raise SystemExit(f"result is not a sealed evaluation projection: {label}")
    findings = result.get("findings")
    evidence = result.get("evidence")
    proof = result.get("run_proof")
    if not isinstance(findings, list) or not isinstance(evidence, list) or not isinstance(proof, dict):
        raise SystemExit(f"sealed projection is incomplete: {label}")
    projection_payload = {key: value for key, value in result.items() if key != "projection_id"}
    expected_projection_id = f"test3-projection-{scorer.canonical_sha256(projection_payload)}"
    if result.get("projection_id") != expected_projection_id:
        raise SystemExit(f"sealed projection identity mismatch: {label}")
    if proof.get("source_contract") != "sealed_report_evidence_input_manifest":
        raise SystemExit(f"sealed projection source contract mismatch: {label}")
    if proof.get("input_manifest_sha256") != _projection_manifest_sha256(public_inputs):
        raise SystemExit(f"sealed projection input manifest mismatch: {label}")
    if (
        not isinstance(proof.get("snapshot_id"), str)
        or not proof["snapshot_id"]
        or proof.get("input_artifact_count") != len(public_inputs)
    ):
        raise SystemExit(f"sealed projection admission proof is incomplete: {label}")
    _valid_sha256(proof.get("report_integrity_sha256"), label=f"{label} admitted report")

    evidence_by_id: dict[str, Mapping[str, Any]] = {}
    for item in evidence:
        if not isinstance(item, dict):
            raise SystemExit(f"sealed projection evidence is not an object: {label}")
        evidence_id = item.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id or evidence_id in evidence_by_id:
            raise SystemExit(f"sealed projection evidence ID is invalid or repeated: {label}")
        path = item.get("path")
        if not isinstance(path, str) or path not in public_inputs:
            raise SystemExit(f"evidence path is outside the public input manifest: {label}/{evidence_id}")
        expected_input = public_inputs[path]
        if (
            item.get("input_artifact_id") != expected_input["artifact_id"]
            or item.get("input_sha256") != expected_input["sha256"]
        ):
            raise SystemExit(f"evidence input SHA-256 mismatch: {label}/{evidence_id}")
        evidence_by_id[evidence_id] = item

    finding_ids: set[str] = set()
    references_by_evidence: dict[str, set[str]] = {evidence_id: set() for evidence_id in evidence_by_id}
    for finding in findings:
        if not isinstance(finding, dict):
            raise SystemExit(f"sealed projection finding is not an object: {label}")
        finding_id = finding.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id or finding_id in finding_ids:
            raise SystemExit(f"sealed projection finding ID is invalid or repeated: {label}")
        finding_ids.add(finding_id)
        path = finding.get("path")
        if not isinstance(path, str) or path not in public_inputs:
            raise SystemExit(f"finding path is outside the public input manifest: {label}/{finding_id}")
        expected_input = public_inputs[path]
        line = finding.get("line")
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            raise SystemExit(f"finding line is invalid: {label}/{finding_id}")
        if (
            finding.get("input_artifact_id") != expected_input["artifact_id"]
            or finding.get("input_sha256") != expected_input["sha256"]
        ):
            raise SystemExit(f"finding input SHA-256 mismatch: {label}/{finding_id}")
        references = finding.get("evidence_ids")
        if (
            not isinstance(references, list)
            or not references
            or len(references) != len(set(references))
            or any(not isinstance(item, str) or item not in evidence_by_id for item in references)
        ):
            raise SystemExit(f"finding has an incomplete Evidence reference chain: {label}/{finding_id}")
        for evidence_id in references:
            item = evidence_by_id[evidence_id]
            if (
                item.get("path") != path
                or item.get("line") != line
                or item.get("input_artifact_id") != finding.get("input_artifact_id")
                or item.get("input_sha256") != finding.get("input_sha256")
            ):
                raise SystemExit(f"finding/evidence source binding mismatch: {label}/{finding_id}")
            linked_findings = item.get("finding_ids")
            if not isinstance(linked_findings, list) or finding_id not in linked_findings:
                raise SystemExit(f"evidence does not link back to its finding: {label}/{finding_id}")
            references_by_evidence[evidence_id].add(finding_id)
    for evidence_id, item in evidence_by_id.items():
        linked_findings = item.get("finding_ids")
        if (
            not isinstance(linked_findings, list)
            or not linked_findings
            or any(not isinstance(finding_id, str) for finding_id in linked_findings)
            or len(linked_findings) != len(set(linked_findings))
            or set(linked_findings) != references_by_evidence[evidence_id]
        ):
            raise SystemExit(f"evidence/finding reverse links are not exact: {label}/{evidence_id}")
    if proof.get("finding_count") != len(findings) or proof.get("evidence_count") != len(evidence):
        raise SystemExit(f"sealed projection proof counts mismatch: {label}")
    return len(findings), len(findings)


def _is_sealed_operational_failure(result: Mapping[str, Any]) -> bool:
    """Accept only a claim-free failure payload committed by the outer seal.

    A failed admission cannot produce a projection proof.  The containing
    record still binds task/run/provider/ledger identity, while this payload is
    deliberately incapable of contributing a finding or evidence score.
    """

    allowed = {"task_id", "run_id", "status", "findings", "evidence", "limitations", "projection_error"}
    limitations = result.get("limitations")
    return bool(
        set(result).issubset(allowed)
        and isinstance(result.get("task_id"), str)
        and result.get("task_id")
        and result.get("run_id") in (None, "")
        and result.get("status") == "blocked"
        and result.get("findings") == []
        and result.get("evidence", []) == []
        and isinstance(limitations, list)
        and 0 < len(limitations) <= 16
        and all(isinstance(item, str) and 0 < len(item) <= 1_024 for item in limitations)
        and isinstance(result.get("projection_error"), str)
        and 0 < len(result["projection_error"]) <= 128
    )


def _record_operational_success(record: Mapping[str, Any]) -> bool:
    result = record.get("result")
    return bool(
        isinstance(result, dict)
        and result.get("status") == "SUCCESS"
        and record.get("runtime_status") == "completed"
        and record.get("queue_status") == "completed"
        and record.get("operational_error") is None
        and record.get("timed_out") is False
    )


def _scoring_result(result: Mapping[str, Any]) -> dict[str, Any]:
    """Expose approved sealed detail fields to the legacy offline scorer.

    The immutable projection remains untouched. This view only lifts fields
    that are already committed under each finding's bounded ``details`` map.
    """

    projected = dict(result)
    findings: list[Any] = []
    for raw_finding in result.get("findings", []):
        if not isinstance(raw_finding, dict):
            findings.append(raw_finding)
            continue
        finding = dict(raw_finding)
        details = finding.get("details")
        if isinstance(details, dict):
            for key in ("root_cause", "data_flow", "preconditions", "impact"):
                if key not in finding and key in details:
                    finding[key] = details[key]
        findings.append(finding)
    projected["findings"] = findings
    return projected


def _validate_gate_records(
    label: str,
    sealed: Mapping[str, Any],
    public_inputs: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> None:
    for round_data in sealed["rounds"]:
        repetition = int(round_data["repetition"])
        for record in round_data["records"]:
            task_id = record["task_id"]
            record_label = f"{label}/{repetition}/{task_id}"
            if (
                "operational_error" not in record
                or record["operational_error"] is not None
                and not isinstance(record["operational_error"], str)
            ):
                raise SystemExit(f"missing or invalid operational_error: {record_label}")
            if not isinstance(record.get("timed_out"), bool) or not isinstance(record.get("ledger_valid"), bool):
                raise SystemExit(f"missing timeout/ledger verdict: {record_label}")
            result = record.get("result")
            sealed_failure = isinstance(result, dict) and _is_sealed_operational_failure(result)
            if (
                not isinstance(result, dict)
                or result.get("task_id") != task_id
                or (not sealed_failure and result.get("run_id") != record.get("run_id"))
            ):
                raise SystemExit(f"sealed task identity mismatch: {record_label}")
            _verify_ledger_receipt(record, label=record_label)
            _verify_provider_attempts(record, label=record_label)
            _verify_finding_evidence(result, public_inputs[task_id], label=record_label)


def load_verified_seals(
    sealed_paths: Mapping[str, Path],
    *,
    expected_sources: Mapping[str, tuple[str, str]],
    expected_task_ids: Sequence[str],
    expected_repetitions: Sequence[int],
    public_manifest_sha256: str,
    public_inputs: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> dict[str, dict[str, Any]]:
    if set(expected_sources) != set(sealed_paths):
        raise SystemExit("expected source labels must exactly match sealed labels")
    if len(expected_task_ids) != len(set(expected_task_ids)) or not expected_task_ids:
        raise SystemExit("expected task IDs must be non-empty and unique")
    if list(expected_repetitions) != list(range(1, len(expected_repetitions) + 1)):
        raise SystemExit("expected repetitions must be contiguous and start at 1")
    evaluator_hash = scorer.file_sha256(Path(__file__).with_name("evaluate_comprehensive_public.py"))
    projection_path = Path(__file__).resolve().parents[1] / "src" / "secmind" / "evaluation_projection.py"
    if not projection_path.is_file():
        raise SystemExit("sealed evaluation projection module is unavailable")
    projection_hash = scorer.file_sha256(projection_path)

    verified: dict[str, dict[str, Any]] = {}
    seal_hashes: set[str] = set()
    resolved_paths: set[Path] = set()
    source_commits: set[str] = set()
    source_trees: set[str] = set()
    reference_model: Any = None
    reference_controls: dict[str, Any] | None = None
    common_control_keys = (
        "timeout_seconds_per_task",
        "concurrency",
        "input_execution",
        "input_network",
        "shared_binary_preprocessor",
        "public_manifest_sha256",
        "evaluator_sha256",
        "sealed_projection_sha256",
    )
    for label, path in sealed_paths.items():
        resolved = path.resolve()
        seal_hash = scorer.file_sha256(resolved) if resolved.is_file() else ""
        if resolved in resolved_paths or seal_hash in seal_hashes:
            raise SystemExit("baseline and fusion must use distinct sealed artifacts")
        resolved_paths.add(resolved)
        seal_hashes.add(seal_hash)
        sealed = _read_json_object(resolved, label=f"sealed predictions for {label}", maximum=MAX_SEAL_BYTES)
        _verify_envelope(sealed, label=label)
        _verify_prediction_commitment(sealed, label=label)
        if sealed.get("schema_version") != EXPECTED_SEAL_SCHEMA or sealed.get("protocol") != EXPECTED_SEAL_PROTOCOL:
            raise SystemExit(f"unsupported sealed protocol/schema: {label}")
        if sealed.get("arm") != EXPECTED_ARM:
            raise SystemExit(f"sealed arm must be {EXPECTED_ARM}: {label}")
        if sealed.get("case_ids") != list(expected_task_ids):
            raise SystemExit(f"seal does not match the fixed expected task roster: {label}")
        repetitions = [int(item["repetition"]) for item in sealed["rounds"]]
        if repetitions != list(expected_repetitions):
            raise SystemExit(f"seal does not match the fixed repetitions: {label}")
        model = sealed.get("model")
        if (
            not isinstance(model, dict)
            or model.get("id") != EXPECTED_MODEL_ID
            or model.get("base_url") != EXPECTED_MODEL_BASE_URL
        ):
            raise SystemExit(f"seal did not use the required DeepSeek V4 Flash route: {label}")
        controls = sealed.get("controls")
        if not isinstance(controls, dict):
            raise SystemExit(f"missing seal controls: {label}")
        expected_commit, expected_tree = expected_sources[label]
        actual_commit = str(controls.get("source_commit", "")).casefold()
        actual_tree = str(controls.get("source_tree_oid", "")).casefold()
        if (actual_commit, actual_tree) != (expected_commit, expected_tree):
            raise SystemExit(f"sealed source does not match label {label}")
        if controls.get("source_dirty") != "false" or controls.get("source_identity_method") != "git":
            raise SystemExit(f"seal source identity is not a clean Git checkout: {label}")
        if controls.get("source_identity_enforced") is not True:
            raise SystemExit(f"seal did not enforce source identity: {label}")
        if controls.get("task_selection") != "explicit_task_ids" or controls.get("augmentation") != "enabled":
            raise SystemExit(f"seal does not use the fixed full-agent cohort controls: {label}")
        if controls.get("evaluator_sha256") != evaluator_hash:
            raise SystemExit(f"seal evaluator hash does not match the current evaluator: {label}")
        if controls.get("sealed_projection_sha256") != projection_hash:
            raise SystemExit(f"seal projection hash does not match the current adapter: {label}")
        if controls.get("public_manifest_sha256") != public_manifest_sha256:
            raise SystemExit(f"seal public manifest does not match the supplied public root: {label}")
        if actual_commit in source_commits or actual_tree in source_trees:
            raise SystemExit("baseline and fusion source identities must be distinct")
        source_commits.add(actual_commit)
        source_trees.add(actual_tree)
        if reference_model is None:
            reference_model = model
            reference_controls = controls
        else:
            if model != reference_model:
                raise SystemExit("baseline and fusion do not share model controls")
            assert reference_controls is not None
            for key in common_control_keys:
                if controls.get(key) != reference_controls.get(key):
                    raise SystemExit(f"baseline and fusion do not share control {key}")
        _validate_gate_records(label, sealed, public_inputs)
        verified[label] = sealed
    return verified


def _load_private_checked(private_root: Path, selected_ids: set[str]) -> dict[str, dict[str, Any]]:
    manifest_path = private_root / "answer-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        answers = manifest["answers"]
        answer_ids = [item["task_id"] for item in answers]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise SystemExit(f"invalid private scorer manifest: {exc}") from exc
    if len(answer_ids) != len(set(answer_ids)):
        raise SystemExit("private scorer manifest contains duplicate tasks")
    return scorer._load_private(private_root, selected_ids)


def _aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    metrics = scorer.aggregate(rows)
    task_count = len(rows)
    metrics["operational_success_rate"] = round(sum(row["operational_success"] is True for row in rows) / task_count, 6)
    metrics["live_provider_success_rate"] = round(
        sum(row["live_provider_success"] is True for row in rows) / task_count, 6
    )
    finding_total = sum(int(row["evidence_scope_finding_count"]) for row in rows)
    evidence_complete = sum(int(row["evidence_complete_findings"]) for row in rows)
    metrics["finding_evidence_completeness"] = (
        1.0 if finding_total == 0 else round(evidence_complete / finding_total, 6)
    )
    return metrics


def _score_seals(
    sealed_paths: Mapping[str, Path],
    sealed_by_label: Mapping[str, dict[str, Any]],
    *,
    public_root: Path,
    private_root: Path,
    public_inputs: Mapping[str, Mapping[str, Mapping[str, Any]]],
    cohort_manifest_sha256: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    selected_ids = set(next(iter(sealed_by_label.values()))["case_ids"])
    private_by_id = _load_private_checked(private_root, selected_ids)
    arms: dict[str, Any] = {}
    all_rows: list[dict[str, Any]] = []

    for label, sealed in sealed_by_label.items():
        sealed_arm = str(sealed["arm"])
        arm_rows: list[dict[str, Any]] = []
        arm_rounds: list[dict[str, Any]] = []
        observed_tasks: set[tuple[int, str]] = set()
        expected_tasks = {
            (int(round_data["repetition"]), task_id)
            for round_data in sealed["rounds"]
            for task_id in sealed["case_ids"]
        }
        try:
            for round_data in sealed["rounds"]:
                repetition = int(round_data["repetition"])
                round_rows: list[dict[str, Any]] = []
                for record in round_data["records"]:
                    scoring_record = {**record, "result": _scoring_result(record["result"])}
                    scored = scorer.score_one(scoring_record, private_by_id[record["task_id"]], public_root)
                    task_id = scored.get("task_id")
                    if not isinstance(task_id, str):
                        raise SystemExit(f"duplicate or invalid scored task: {label}/{repetition}/{task_id}")
                    key = (repetition, task_id)
                    if key in observed_tasks:
                        raise SystemExit(f"duplicate or invalid scored task: {label}/{repetition}/{task_id}")
                    observed_tasks.add(key)
                    result = record["result"]
                    complete, total = _verify_finding_evidence(
                        result,
                        public_inputs[task_id],
                        label=f"{label}/{repetition}/{task_id}",
                    )
                    row = {
                        "label": label,
                        "sealed_arm": sealed_arm,
                        "repetition": repetition,
                        **scored,
                        "operational_success": _record_operational_success(record),
                        "live_provider_success": _verify_provider_attempts(
                            record, label=f"{label}/{repetition}/{task_id}"
                        ),
                        "evidence_complete_findings": complete,
                        "evidence_scope_finding_count": total,
                    }
                    round_rows.append(row)
                    arm_rows.append(row)
                arm_rounds.append({"repetition": repetition, "metrics": _aggregate(round_rows)})
        except SystemExit:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise SystemExit(f"missing or invalid scoring data for {label}: {exc}") from exc
        if observed_tasks != expected_tasks:
            raise SystemExit(f"scored task set mismatch: {label}")

        all_rows.extend(arm_rows)
        controls = sealed["controls"]
        arms[label] = {
            "display_label": label,
            "sealed_arm": sealed_arm,
            "sealed_sha256": scorer.file_sha256(sealed_paths[label]),
            "product_version": sealed.get("product_version"),
            "source_commit": controls["source_commit"],
            "source_tree_oid": controls["source_tree_oid"],
            "prediction_commitment_sha256": sealed["prediction_commitment_sha256"],
            "envelope_commitment_sha256": sealed[ENVELOPE_FIELD],
            "rounds": arm_rounds,
            "aggregate": _aggregate(arm_rows),
        }

    repetition_count = len(next(iter(sealed_by_label.values()))["rounds"])
    stability: dict[str, Any] = {}
    if repetition_count >= 2:
        for label, arm in arms.items():
            overall = [item["metrics"]["overall_score"] for item in arm["rounds"]]
            macro = [item["metrics"]["domain_macro_score"] for item in arm["rounds"]]
            stability[label] = {
                "overall_range": round(max(overall) - min(overall), 6),
                "domain_macro_range": round(max(macro) - min(macro), 6),
            }

    scores = {
        "schema_version": "1.2",
        "protocol": "secmind-v08-release-score-v2",
        "dataset_version": scorer.DATASET_VERSION,
        "offline_only": True,
        "provider_requests_by_scorer": 0,
        "scorer_sha256": scorer.file_sha256(Path(scorer.__file__).resolve()),
        "comparator_sha256": scorer.file_sha256(Path(__file__).resolve()),
        "case_count": len(selected_ids),
        "case_ids": next(iter(sealed_by_label.values()))["case_ids"],
        "cohort_manifest_sha256": cohort_manifest_sha256,
        "repetitions": repetition_count,
        "arms": arms,
        "comparisons": scorer._pairwise_comparisons(arms),
        "stability": stability,
    }
    return scores, all_rows


def _rate(value: Any, label: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise SystemExit(f"missing numeric comparison metric: {label}")
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise SystemExit(f"invalid comparison rate: {label}")
    return number


def _gate_metrics(aggregate: Mapping[str, Any], label: str) -> dict[str, float]:
    exact = aggregate.get("exact_cwe")
    if not isinstance(exact, Mapping):
        raise SystemExit(f"missing exact-CWE metrics: {label}")
    return {
        "overall_score": _rate(aggregate.get("overall_score"), f"{label}.overall_score"),
        "exact_cwe_f1": _rate(exact.get("f1"), f"{label}.exact_cwe.f1"),
        "operational_success_rate": _rate(
            aggregate.get("operational_success_rate"), f"{label}.operational_success_rate"
        ),
        "live_provider_success_rate": _rate(
            aggregate.get("live_provider_success_rate"), f"{label}.live_provider_success_rate"
        ),
        "timeout_rate": _rate(aggregate.get("timeout_rate"), f"{label}.timeout_rate"),
        "operational_failure_rate": _rate(
            aggregate.get("operational_failure_rate"), f"{label}.operational_failure_rate"
        ),
        "ledger_valid_rate": _rate(aggregate.get("ledger_valid_rate"), f"{label}.ledger_valid_rate"),
        "finding_evidence_completeness": _rate(
            aggregate.get("finding_evidence_completeness"), f"{label}.finding_evidence_completeness"
        ),
    }


def build_non_regression(scores: Mapping[str, Any], *, baseline_label: str, fusion_label: str) -> dict[str, Any]:
    arms = scores.get("arms")
    if not isinstance(arms, Mapping) or baseline_label not in arms or fusion_label not in arms:
        raise SystemExit(f"missing comparison labels: {baseline_label}/{fusion_label}")
    baseline = _gate_metrics(arms[baseline_label]["aggregate"], baseline_label)
    fusion = _gate_metrics(arms[fusion_label]["aggregate"], fusion_label)
    checks = [
        {
            "name": "overall_score_non_regression",
            "passed": fusion["overall_score"] >= baseline["overall_score"],
            "actual": {"baseline": baseline["overall_score"], "fusion": fusion["overall_score"]},
            "requirement": "fusion >= baseline",
        },
        {
            "name": "exact_cwe_f1_non_regression",
            "passed": fusion["exact_cwe_f1"] >= baseline["exact_cwe_f1"],
            "actual": {"baseline": baseline["exact_cwe_f1"], "fusion": fusion["exact_cwe_f1"]},
            "requirement": "fusion >= baseline",
        },
        {
            "name": "operational_success_rate_non_regression",
            "passed": fusion["operational_success_rate"] >= baseline["operational_success_rate"],
            "actual": {
                "baseline": baseline["operational_success_rate"],
                "fusion": fusion["operational_success_rate"],
            },
            "requirement": "fusion >= baseline",
        },
    ]
    for label, metrics in ((baseline_label, baseline), (fusion_label, fusion)):
        for metric, expected in (
            ("operational_success_rate", 1.0),
            ("live_provider_success_rate", 1.0),
            ("timeout_rate", 0.0),
            ("operational_failure_rate", 0.0),
            ("ledger_valid_rate", 1.0),
            ("finding_evidence_completeness", 1.0),
        ):
            checks.append(
                {
                    "name": f"{label}_{metric}",
                    "passed": metrics[metric] == expected,
                    "actual": metrics[metric],
                    "requirement": f"{label} == {expected:g}",
                }
            )
    failed_checks = [check["name"] for check in checks if not check["passed"]]
    return {
        "schema_version": "1.1",
        "protocol": "secmind-sealed-fusion-non-regression-v2",
        "offline_only": True,
        "provider_requests_by_comparator": 0,
        "baseline_label": baseline_label,
        "fusion_label": fusion_label,
        "sealed_arms": {
            baseline_label: arms[baseline_label]["sealed_arm"],
            fusion_label: arms[fusion_label]["sealed_arm"],
        },
        "metrics": {"baseline": baseline, "fusion": fusion},
        "deltas": {
            "overall_score": round(fusion["overall_score"] - baseline["overall_score"], 6),
            "exact_cwe_f1": round(fusion["exact_cwe_f1"] - baseline["exact_cwe_f1"], 6),
            "operational_success_rate": round(
                fusion["operational_success_rate"] - baseline["operational_success_rate"], 6
            ),
        },
        "checks": checks,
        "failed_checks": failed_checks,
        "non_regression_passed": not failed_checks,
    }


def _write_task_scores(path: Path, rows: list[dict[str, Any]]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=SCALAR_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(sorted(rows, key=lambda row: (row["label"], row["repetition"], row["task_id"])))
    temporary.replace(path)


def compare_sealed_runs(
    sealed_paths: Mapping[str, Path],
    *,
    expected_sources: Mapping[str, tuple[str, str]],
    expected_task_ids: Sequence[str],
    expected_repetitions: Sequence[int],
    cohort_manifest_sha256: str | None = None,
    public_root: Path,
    private_root: Path,
    output_dir: Path,
    baseline_label: str = "baseline",
    fusion_label: str = "fusion",
) -> tuple[dict[str, Any], dict[str, Any]]:
    if baseline_label == fusion_label:
        raise SystemExit("baseline and fusion labels must be distinct")
    required_labels = {baseline_label, fusion_label}
    if set(sealed_paths) != required_labels or set(expected_sources) != required_labels:
        raise SystemExit(f"sealed and source labels must be exactly: {baseline_label}, {fusion_label}")
    if expected_sources[baseline_label] == expected_sources[fusion_label]:
        raise SystemExit("baseline and fusion expected source identities must be distinct")
    ordered_paths = {baseline_label: sealed_paths[baseline_label], fusion_label: sealed_paths[fusion_label]}
    public_manifest, public_inputs = _validate_public_dataset(public_root, expected_task_ids)
    verified = load_verified_seals(
        ordered_paths,
        expected_sources=expected_sources,
        expected_task_ids=expected_task_ids,
        expected_repetitions=expected_repetitions,
        public_manifest_sha256=public_manifest,
        public_inputs=public_inputs,
    )
    scores, rows = _score_seals(
        ordered_paths,
        verified,
        public_root=public_root.resolve(),
        private_root=private_root.resolve(),
        public_inputs=public_inputs,
        cohort_manifest_sha256=cohort_manifest_sha256,
    )
    non_regression = build_non_regression(scores, baseline_label=baseline_label, fusion_label=fusion_label)

    destination = output_dir.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    scorer.write_json(destination / "scores.json", scores)
    _write_task_scores(destination / "task-scores.csv", rows)
    scorer.write_json(destination / "non-regression.json", non_regression)
    return scores, non_regression


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare fixed-cohort baseline and team-fusion sealed runs")
    parser.add_argument("--sealed", action="append", required=True, metavar="LABEL=PATH")
    parser.add_argument(
        "--expected-source",
        action="append",
        required=True,
        metavar="LABEL=COMMIT:TREE",
    )
    parser.add_argument("--cohort-manifest", type=Path, required=True)
    parser.add_argument("--public-root", type=Path, required=True)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--baseline-label", default="baseline")
    parser.add_argument("--fusion-label", default="fusion")
    args = parser.parse_args(argv)

    sealed_paths = parse_sealed_specs(args.sealed)
    expected_sources = parse_expected_sources(args.expected_source)
    expected_task_ids, expected_repetitions, cohort_manifest_sha256 = load_cohort_manifest(args.cohort_manifest)
    _, non_regression = compare_sealed_runs(
        sealed_paths,
        expected_sources=expected_sources,
        expected_task_ids=expected_task_ids,
        expected_repetitions=expected_repetitions,
        cohort_manifest_sha256=cohort_manifest_sha256,
        public_root=args.public_root,
        private_root=args.private_root,
        output_dir=args.output_dir,
        baseline_label=args.baseline_label,
        fusion_label=args.fusion_label,
    )
    print(json.dumps(non_regression, ensure_ascii=False, indent=2))
    return 0 if non_regression["non_regression_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
