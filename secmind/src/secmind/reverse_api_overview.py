"""Sealed DeepSeek API overview rendering and a narrow deletion gate."""

# ruff: noqa: E501

from __future__ import annotations

import base64
import csv
import ctypes
import errno
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import urllib.parse
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from html import escape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Literal, cast

if os.name == "nt":
    import msvcrt
    from ctypes import wintypes

from secmind.reverse_api_score import _validate_sealed_run_tree, _ValidatedSlot, score_api_runs

_ARMS: tuple[Literal["current", "optimized"], ...] = ("current", "optimized")
_REPEATS = (1, 2)
_ARTIFACT_NAMES = ("request.json", "response.json", "receipt.json", "report.json", "report.md", "report.html", "seal.json")
_TOP_LEVEL = frozenset({"index.html", "index.md", "api-metrics.json", "api-case-results.csv", "run-manifest.json", "artifact-inventory.json", "scoring-receipt.json"})
_RECEIPT_NAME = "deletion-gate-receipt.json"
_FINALIZATION_RECEIPT_NAME = "quarantine-finalization-receipt.json"
_QUARANTINE_RECEIPT_NAME = ".secmind-quarantine-receipt.json"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SCORING_VERSION = "1.0"
_DELETION_VERSION = "2.0"
_PUBLIC_DELETION_VERSION = "3.0"
_QUARANTINE_VERSION = "2.0"
_FINALIZATION_VERSION = "3.0"
_URL_RE = re.compile(r"""url\(\s*(['"]?)(.*?)\1\s*\)""", re.IGNORECASE | re.DOTALL)
_SCRIPT_NETWORK_RE = re.compile(r"\b(?:fetch|xmlhttprequest|websocket|eventsource|import|sendbeacon)\s*\(|\blocation\s*=", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class OverviewResult:
    output_dir: Path
    index_html: Path
    index_markdown: Path
    metrics_json: Path
    case_results_csv: Path
    run_manifest: Path
    inventory: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ScoringReceipt:
    schema_version: str
    run_tree_sha256: str
    gold_sha256: str
    source_inventory_sha256: str
    metrics_sha256: str
    rows_sha256: str
    receipt_sha256: str

    def unsigned_payload(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "run_tree_sha256": self.run_tree_sha256,
            "gold_sha256": self.gold_sha256,
            "source_inventory_sha256": self.source_inventory_sha256,
            "metrics_sha256": self.metrics_sha256,
            "rows_sha256": self.rows_sha256,
        }

    def to_dict(self) -> dict[str, str]:
        return {**self.unsigned_payload(), "receipt_sha256": self.receipt_sha256}


@dataclass(frozen=True, slots=True)
class DeletionGateReceipt:
    schema_version: str
    delivery_root: str
    delivery_sha256: str
    run_root: str
    gold_path: str
    gold_sha256: str
    scoring_receipt_path: str
    scoring_receipt_sha256: str
    suite_id: str
    slot_count: int
    artifact_count: int
    exact_secret_matches: int
    approved_deletion_targets: tuple[str, str]
    approved_target_sha256: tuple[tuple[str, str], tuple[str, str]]
    binding_sha256: str

    def unsigned_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("binding_sha256")
        return payload

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_payload(), "binding_sha256": self.binding_sha256}


@dataclass(frozen=True, slots=True)
class PublicDeletionGateReceipt:
    """The portable, delivery-visible projection of a pre-action gate."""

    schema_version: str
    delivery_root: str
    delivery_sha256: str
    run_root: str
    gold_path: str
    gold_sha256: str
    scoring_receipt_path: str
    scoring_receipt_sha256: str
    suite_id: str
    slot_count: int
    artifact_count: int
    exact_secret_matches: int
    approved_deletion_targets: tuple[str, str]
    approved_target_sha256: tuple[tuple[str, str], tuple[str, str]]
    pre_action_binding_sha256: str
    public_binding_sha256: str

    def unsigned_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("public_binding_sha256")
        return payload

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_payload(), "public_binding_sha256": self.public_binding_sha256}


@dataclass(frozen=True, slots=True)
class QuarantineTargetReceipt:
    original_path: str
    quarantine_path: str
    device: int
    inode: int
    tree_sha256: str


@dataclass(frozen=True, slots=True)
class QuarantineReceipt:
    """Recoverable location map. This workflow never purges quarantined bytes."""

    schema_version: str
    gate_binding_sha256: str
    targets: tuple[QuarantineTargetReceipt, QuarantineTargetReceipt]
    binding_sha256: str

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "gate_binding_sha256": self.gate_binding_sha256,
            "targets": [asdict(target) for target in self.targets],
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_payload(), "binding_sha256": self.binding_sha256}

    @property
    def quarantined_targets(self) -> dict[str, Path]:
        """Compatibility-only absolute map; it is never serialized."""

        workspace = _workspace_root().resolve()
        return {str(workspace / item.original_path): workspace / item.quarantine_path for item in self.targets}


@dataclass(frozen=True, slots=True)
class QuarantineFinalizationReceipt:
    schema_version: str
    gate_receipt_path: str
    gate_public_binding_sha256: str
    gate_receipt_sha256: str
    quarantine_receipt_path: str
    quarantine_receipt_binding_sha256: str
    quarantine_receipt_sha256: str
    source_inventory_sha256: str
    scoring_receipt_sha256: str
    pre_quarantine_core_delivery_sha256: str
    core_delivery_sha256: str
    previous_finalization_binding_sha256: str | None
    binding_sha256: str

    def unsigned_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("binding_sha256")
        return payload

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_payload(), "binding_sha256": self.binding_sha256}


class QuarantineRecoveryError(RuntimeError):
    """Rollback could not restore exact bytes; exposes only recovery locators."""

    def __init__(self, message: str, recovery_targets: Mapping[str, Path]) -> None:
        super().__init__(message)
        self.recovery_targets = dict(recovery_targets)


@dataclass(frozen=True, slots=True)
class _Quarantine:
    parent: Path
    parent_fd: int
    original_name: str
    quarantine_name: str
    device: int
    inode: int
    sha256: str


@dataclass(frozen=True, slots=True)
class _AnchorEntry:
    st_mode: int
    st_dev: int
    st_ino: int


def _json_bytes(payload: object) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _canonical_sha256(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(_SHA256.fullmatch(value.casefold()))


def _workspace_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _workspace_relative(path: Path | str, *, label: str) -> str:
    """Return one canonical workspace-relative identity for public receipts."""

    workspace = _workspace_root().resolve()
    try:
        resolved = Path(path).resolve(strict=False)
        relative = resolved.relative_to(workspace)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"{label} must remain inside the workspace") from exc
    if not relative.parts:
        raise ValueError(f"{label} must not be the workspace root")
    return relative.as_posix()


def _workspace_path(value: object, *, label: str) -> Path:
    relative = _safe_relative(value, label=label)
    workspace = _workspace_root().resolve()
    candidate = (workspace / relative).resolve(strict=False)
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"{label} escapes the workspace") from exc
    return candidate


def _canonical_gold_path() -> Path:
    """The deletion gate accepts exactly the workspace's scored gold file."""

    return _workspace_root().resolve() / "reverse_evaluation" / "gold" / "expected.json"


def _safe_relative(value: object, *, label: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{label} must be a non-empty relative path")
    path = Path(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts) or "\\" in value:
        raise ValueError(f"{label} must be a canonical relative path")
    return path


def _assert_regular_tree(path: Path, *, label: str, allow_gold: bool = False) -> Path:
    if not isinstance(path, Path) or not path.exists():
        raise ValueError(f"{label} must exist")
    if any(character in str(path) for character in "*?[]"):
        raise ValueError(f"{label} must not contain a glob")
    try:
        initial = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} cannot be inspected") from exc
    if stat.S_ISLNK(initial.st_mode) or not (stat.S_ISREG(initial.st_mode) or stat.S_ISDIR(initial.st_mode)):
        raise ValueError(f"{label} must be a regular non-symlink path")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label} cannot be resolved") from exc
    if resolved == Path(resolved.anchor) or (not allow_gold and any(part.casefold() == "gold" for part in resolved.parts)):
        raise ValueError(f"{label} is unsafe")
    current = Path(resolved.anchor)
    for part in resolved.parts[1:]:
        current /= part
        try:
            entry = current.lstat()
        except OSError as exc:
            raise ValueError(f"{label} cannot be inspected") from exc
        if stat.S_ISLNK(entry.st_mode):
            raise ValueError(f"{label} must not traverse a symlink")
    return resolved


def _walk_regular_files(root: Path, *, allow_gold: bool = False) -> list[Path]:
    resolved = _assert_regular_tree(root, label="tree", allow_gold=allow_gold)
    candidates: Iterable[Path] = (resolved,) if resolved.is_file() else sorted(resolved.rglob("*"))
    files: list[Path] = []
    for path in candidates:
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            raise ValueError("tree cannot be inspected") from exc
        if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError("tree contains a non-regular path")
        if path.is_file():
            files.append(path)
    return files


def _tree_digest(root: Path, *, exclude: frozenset[str] = frozenset()) -> str:
    resolved = _assert_regular_tree(root, label="tree")
    records = [
        {"path": path.relative_to(resolved).as_posix() if path != resolved else path.name, "sha256": _file_sha256(path), "size_bytes": path.stat().st_size}
        for path in _walk_regular_files(resolved)
        if path.relative_to(resolved).as_posix() not in exclude
    ]
    return _canonical_sha256(records)


def _require_active_secret(active_secret: str | None) -> str:
    if not isinstance(active_secret, str) or not active_secret:
        raise ValueError("an active non-empty DeepSeek secret is required for the deletion gate")
    return active_secret


def _secret_variants(secret: str) -> tuple[bytes, ...]:
    raw = secret.encode("utf-8")
    return tuple(dict.fromkeys((raw, json.dumps(secret, ensure_ascii=True).encode("utf-8"), json.dumps(secret, ensure_ascii=False).encode("utf-8"), urllib.parse.quote(secret, safe="").encode("ascii"), base64.b64encode(raw), base64.urlsafe_b64encode(raw))))


def _scan_exact_secret_tree(root: Path, *, active_secret: str, allow_gold: bool = False) -> None:
    variants = _secret_variants(_require_active_secret(active_secret))
    for path in _walk_regular_files(root, allow_gold=allow_gold):
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise ValueError("artifact cannot be scanned") from exc
        if any(variant and variant in content for variant in variants):
            raise ValueError("exact-secret scan failed")


def _source_inventory(slots: Sequence[_ValidatedSlot]) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for slot in slots:
        for name in _ARTIFACT_NAMES:
            source = slot.directory / name
            public = Path("reports") / slot.arm / f"run-{slot.repeat_id}" / slot.case_id / name
            entries.append({"arm": slot.arm, "case_id": slot.case_id, "repeat_id": slot.repeat_id, "path": public.as_posix(), "sha256": _file_sha256(source), "size_bytes": source.stat().st_size})
    entries.sort(key=lambda item: item["path"])
    if len(entries) != 336 or len({entry["path"] for entry in entries}) != 336:
        raise ValueError("source inventory must be an exact 48 by 7 artifact set")
    return {"schema_version": "1.0", "artifact_count": 336, "artifacts": entries}


def _load_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is unreadable") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return cast(dict[str, Any], value)


def _require_closed_fields(payload: Mapping[str, Any], fields: frozenset[str], *, label: str) -> None:
    if set(payload) != fields:
        raise ValueError(f"{label} schema is invalid")


def _scored_truth(
    *,
    run_root: Path,
    gold_path: Path,
    metrics: Mapping[str, Any] | None = None,
    case_rows: Sequence[Mapping[str, Any]] | None = None,
) -> tuple[list[_ValidatedSlot], dict[str, Any], list[dict[str, Any]], dict[str, Any], ScoringReceipt]:
    safe_run_root = _assert_regular_tree(run_root, label="run root")
    safe_gold_path = _assert_regular_tree(gold_path, label="gold path", allow_gold=True)
    if safe_gold_path.name != "expected.json" or "gold" not in {part.casefold() for part in safe_gold_path.parts}:
        raise ValueError("gold path must be the sealed expected.json")
    slots = _validate_sealed_run_tree(safe_run_root)
    scored_metrics, scored_rows = score_api_runs(safe_run_root, safe_gold_path)
    if metrics is not None and _canonical_sha256(metrics) != _canonical_sha256(scored_metrics):
        raise ValueError("supplied metrics do not equal the sealed score")
    if case_rows is not None and _canonical_sha256(list(case_rows)) != _canonical_sha256(scored_rows):
        raise ValueError("supplied case rows do not equal the sealed score")
    inventory = _source_inventory(slots)
    unsigned: dict[str, Any] = {
        "schema_version": _SCORING_VERSION,
        "run_tree_sha256": _tree_digest(safe_run_root, exclude=frozenset({".run-lease.lock"})),
        "gold_sha256": _file_sha256(safe_gold_path),
        "source_inventory_sha256": _canonical_sha256(inventory),
        "metrics_sha256": _canonical_sha256(scored_metrics),
        "rows_sha256": _canonical_sha256(scored_rows),
    }
    receipt = ScoringReceipt(**unsigned, receipt_sha256=_canonical_sha256(unsigned))
    return slots, scored_metrics, scored_rows, inventory, receipt


def _public_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    allowed = frozenset(
        {
            "arm", "case_id", "repeat_id", "execution_status", "obligations_passed", "obligations_total",
            "obligation_score", "behavior_tp", "behavior_fp", "behavior_fn", "behavior_precision",
            "behavior_recall", "behavior_f1", "exact_fact_passed", "exact_fact_total", "exact_fact_accuracy",
            "evidence_ref_coverage", "claimed_behaviors", "exact_fact_checks", "exact_fact_claims",
            "recommendation_priorities", "provider_requests", "input_tokens", "output_tokens", "total_tokens",
            "latency_ms", "retry_count", "estimated_cny", "unknown_usage_attempts", "cost_complete",
            "known_estimated_cny", "conservative_estimated_cny", "model_failure",
        }
    )
    public: list[dict[str, Any]] = []
    for raw in rows:
        if set(raw) - {"report_path"} != allowed:
            raise ValueError("scorer row schema is not closed")
        arm, case_id, repeat = raw["arm"], raw["case_id"], raw["repeat_id"]
        if arm not in _ARMS or not isinstance(case_id, str) or repeat not in _REPEATS:
            raise ValueError("scorer row identity is invalid")
        item = {key: raw[key] for key in allowed}
        item["report_path"] = (Path("reports") / str(arm) / f"run-{repeat}" / case_id / "report.html").as_posix()
        public.append(item)
    return sorted(public, key=lambda item: (str(item["arm"]), str(item["case_id"]), int(item["repeat_id"])))


def _csv_value(value: object) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    text = str(value)
    return f"'{text}" if text[:1] in {"=", "+", "-", "@"} else text


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    fields = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="raise")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(row.get(key, "")) for key in fields})


def _validate_manifest(manifest: Mapping[str, Any] | Path, slots: Sequence[_ValidatedSlot]) -> dict[str, Any]:
    value = _load_object(manifest, label="manifest") if isinstance(manifest, Path) else dict(manifest)
    cases = value.get("cases")
    if value.get("suite_id") != slots[0].task_identity.suite_id or not isinstance(cases, list):
        raise ValueError("manifest does not match the sealed API matrix")
    ids = [item.get("id") for item in cases if isinstance(item, Mapping)]
    if len(ids) != 12 or set(ids) != {slot.case_id for slot in slots}:
        raise ValueError("manifest does not match the sealed API matrix")
    return {"schema_version": "1.0", "suite_id": value["suite_id"], "cases": [{"id": item} for item in ids]}


class _ResourcePolicy(HTMLParser):
    def __init__(self, *, is_overview: bool, document: Path, root: Path, inventory_paths: frozenset[str]) -> None:
        super().__init__(convert_charrefs=True)
        self.is_overview = is_overview
        self.document = document
        self.root = root
        self.inventory_paths = inventory_paths
        self._in_script = False
        self._in_style = False

    def _safe_url(self, value: str, *, attr: str) -> bool:
        candidate = value.strip()
        if not candidate or candidate.startswith("#"):
            return True
        if candidate.startswith("//") or "\\" in candidate:
            return False
        scheme = urllib.parse.urlsplit(candidate).scheme.casefold()
        if scheme:
            return attr == "src" and scheme == "data" and candidate.casefold().startswith("data:image/")
        path = urllib.parse.urlsplit(candidate).path
        relative = Path(path)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            return False
        resolved = (self.document.parent / relative).resolve(strict=False)
        try:
            public = resolved.relative_to(self.root).as_posix()
        except ValueError:
            return False
        return public in self.inventory_paths

    def _validate_css(self, content: str) -> None:
        if "\\" in content:
            raise ValueError("HTML resource policy rejects CSS escapes")
        compact = re.sub(r"\\[0-9a-fA-F]{1,6}\s?", "", content)
        if "@import" in compact.casefold() or "url" in compact.casefold() and not _URL_RE.search(compact):
            raise ValueError("HTML resource policy rejects CSS imports")
        for match in _URL_RE.finditer(compact):
            if not self._safe_url(match.group(2), attr="src"):
                raise ValueError("HTML resource policy rejects CSS URL")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.casefold()
        values = {name.casefold(): value or "" for name, value in attrs}
        if tag in {"base", "iframe", "frame", "object", "embed", "link", "svg", "math"}:
            raise ValueError("HTML resource policy rejects embedded navigation")
        if any(name.startswith("on") or ":" in name for name in values):
            raise ValueError("HTML resource policy rejects executable URL attributes")
        if tag == "script":
            if not self.is_overview or "src" in values:
                raise ValueError("HTML resource policy rejects script resources")
            self._in_script = True
        if tag == "style":
            self._in_style = True
        if tag == "meta" and "http-equiv" in values and values["http-equiv"].casefold() != "content-security-policy":
            raise ValueError("HTML resource policy rejects meta navigation")
        for name, value in values.items():
            if name == "style":
                self._validate_css(value)
            elif name == "srcset":
                if any(not self._safe_url(part.strip().split()[0], attr="src") for part in value.split(",") if part.strip()):
                    raise ValueError("HTML resource policy rejects srcset")
            elif name in {"src", "href", "action", "formaction", "poster", "background", "data", "ping", "cite", "longdesc"}:
                if not self._safe_url(value, attr=name):
                    raise ValueError("HTML resource policy rejects external URL")

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "script":
            self._in_script = False
        if tag.casefold() == "style":
            self._in_style = False

    def handle_data(self, data: str) -> None:
        if self._in_style:
            self._validate_css(data)
        if self._in_script and _SCRIPT_NETWORK_RE.search(data):
            raise ValueError("HTML resource policy rejects script network access")


def _validate_html_policy(path: Path, *, is_overview: bool, inventory_paths: frozenset[str], root: Path) -> None:
    try:
        payload = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("HTML report is unreadable") from exc
    if "content-security-policy" not in payload.casefold() or "default-src 'none'" not in payload.casefold():
        raise ValueError("HTML resource policy requires restrictive CSP")
    parser = _ResourcePolicy(is_overview=is_overview, document=path, root=root, inventory_paths=inventory_paths)
    try:
        parser.feed(payload)
        parser.close()
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("HTML resource policy cannot parse report") from exc


def _copy_reports(slots: Sequence[_ValidatedSlot], root: Path) -> None:
    for slot in slots:
        destination = root / "reports" / slot.arm / f"run-{slot.repeat_id}" / slot.case_id
        destination.mkdir(parents=True, exist_ok=False)
        for name in _ARTIFACT_NAMES:
            shutil.copyfile(slot.directory / name, destination / name)


_PCT_FIELDS = frozenset(
    {
        "macro_obligation_score",
        "micro_obligation_score",
        "behavior_precision",
        "behavior_recall",
        "behavior_f1",
        "exact_fact_accuracy",
        "evidence_reference_coverage",
        "completion_rate",
        "partial_rate",
        "unavailable_rate",
        "status_agreement",
        "behavior_jaccard",
        "exact_fact_agreement",
        "recommendation_priority_agreement",
    }
)
_CNY_FIELDS = frozenset({"estimated_cny", "conservative_estimated_cny"})
_FIELD_LABELS = {
    "macro_obligation_score": "宏观义务分",
    "behavior_f1": "行为F1",
    "exact_fact_accuracy": "事实准确率",
    "evidence_reference_coverage": "证据引用覆盖",
    "completion_rate": "完成率",
    "partial_rate": "部分率",
    "unavailable_rate": "不可用率",
    "model_failure_count": "模型失败数",
    "provider_requests": "API请求",
    "total_tokens": "总Token",
    "latency_ms": "延迟(ms)",
    "retry_count": "重试数",
    "estimated_cny": "确认成本(¥)",
    "conservative_estimated_cny": "保守成本(¥)",
    "unknown_usage_attempts": "未知用量",
    "cost_complete": "成本完整",
}
_STATUS_LABELS = {"completed": "完成", "partial": "部分", "unavailable": "不可用"}
_COMPARISON_LABELS = {
    "macro_obligation_score": "宏观义务达成分",
    "behavior_f1": "行为 F1",
    "exact_fact_accuracy": "精确事实准确率",
    "evidence_reference_coverage": "证据引用覆盖率",
}


def _fmt_cell(field: str, value: object) -> tuple[str, str]:
    """Return (formatted text, css class) for one metric cell."""
    if field in _PCT_FIELDS:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return escape(str(value)), ""
        badge = "b-good" if number >= 0.9 else ("b-mid" if number >= 0.7 else "b-bad")
        return f"{number * 100:.1f}%", badge
    if field in _CNY_FIELDS:
        try:
            return f"¥{float(value):.4f}", ""
        except (TypeError, ValueError):
            return escape(str(value)), ""
    if isinstance(value, bool):
        return ("是" if value else "否"), ""
    if isinstance(value, (int, float)):
        try:
            number = float(value)
        except (TypeError, ValueError):
            return escape(str(value)), ""
        if number.is_integer():
            return f"{int(number):,}", ""
        return f"{number:,.2f}", ""
    return escape(str(value)), ""


def _fmt_pct(value: object) -> str:
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return escape(str(value))


def _lane_table(metrics: Mapping[str, Any]) -> str:
    fields = ("macro_obligation_score", "behavior_f1", "exact_fact_accuracy", "evidence_reference_coverage", "completion_rate", "partial_rate", "unavailable_rate", "model_failure_count", "provider_requests", "total_tokens", "latency_ms", "retry_count", "estimated_cny", "conservative_estimated_cny", "unknown_usage_attempts", "cost_complete")
    arms = cast(Mapping[str, Any], metrics["arms"])
    header = "".join(f"<th>{escape(_FIELD_LABELS.get(name, name))}<code class=\"fname\">{escape(name)}</code></th>" for name in fields)
    rows = []
    for arm in _ARMS:
        repeats = cast(Mapping[str, Any], cast(Mapping[str, Any], arms[arm])["repeats"])
        for repeat in _REPEATS:
            lane = cast(Mapping[str, Any], repeats[str(repeat)])
            cells = []
            for name in fields:
                text, badge = _fmt_cell(name, lane[name])
                cells.append(f'<td class="num {badge}">{text}</td>')
            rows.append(
                f'<tr class="lane-row" data-arm="{escape(arm)}" data-repeat="{repeat}">'
                f"<th>{escape(arm)} · repeat {repeat}</th>"
                + "".join(cells)
                + "</tr>"
            )
    return (
        '<div class="table-wrap"><table><thead><tr><th>lane</th>'
        + header
        + "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _stability_table(metrics: Mapping[str, Any]) -> str:
    arms = cast(Mapping[str, Any], metrics["arms"])
    fields = ("status_agreement", "behavior_jaccard", "exact_fact_agreement", "recommendation_priority_agreement")
    labels = {"status_agreement": "状态一致", "behavior_jaccard": "行为Jaccard", "exact_fact_agreement": "事实一致", "recommendation_priority_agreement": "建议优先级一致"}
    rows = []
    for arm in _ARMS:
        stability = cast(Mapping[str, Any], arms[arm]["stability"])
        cells = []
        for name in fields:
            text, badge = _fmt_cell(name, stability[name])
            try:
                width = max(2.0, float(stability[name]) * 100)
            except (TypeError, ValueError):
                width = 0.0
            cells.append(f'<td class="num {badge}"><span class="mini-bar"><span class="mini-fill" style="width:{width:.1f}%"></span></span>{text}</td>')
        rows.append(f"<tr><th>{escape(arm)}</th>{''.join(cells)}</tr>")
    header_cells = "".join(
        f'<th>{escape(labels[name])}<code class="fname">{escape(name)}</code></th>' for name in fields
    )
    return (
        '<div class="table-wrap"><table><thead><tr><th>arm</th>'
        + header_cells
        + "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _comparison_bars(metrics: Mapping[str, Any]) -> str:
    arms = cast(Mapping[str, Any], metrics["arms"])
    comparison = cast(Mapping[str, Any], cast(Mapping[str, Any], metrics["comparison"])["optimized_minus_current"])
    names = ("macro_obligation_score", "behavior_f1", "exact_fact_accuracy", "evidence_reference_coverage")
    rows = []
    for name in names:
        current_mean = float(arms["current"]["two_repeat_summary"][name]["mean"])
        optimized_mean = float(arms["optimized"]["two_repeat_summary"][name]["mean"])
        delta = float(comparison[name])
        current_width = max(2.0, min(100.0, current_mean * 100))
        optimized_width = max(2.0, min(100.0, optimized_mean * 100))
        delta_class = "pos" if delta >= 0 else "neg"
        sign = "+" if delta >= 0 else ""
        rows.append(
            f'<div class="cmp-row">'
            f'<div class="cmp-label">{escape(_COMPARISON_LABELS.get(name, name))}<code class="fname">{escape(name)}</code></div>'
            f'<div class="cmp-bars">'
            f'<div class="cmp-line"><span class="cmp-arm tag-current">current</span><div class="track"><div class="bar bar-cur" style="width:{current_width:.1f}%">{_fmt_pct(current_mean)}</div></div></div>'
            f'<div class="cmp-line"><span class="cmp-arm tag-optimized">optimized</span><div class="track"><div class="bar bar-opt" style="width:{optimized_width:.1f}%">{_fmt_pct(optimized_mean)}</div></div></div>'
            f'</div>'
            f'<div class="cmp-delta {delta_class}">{sign}{_fmt_pct(delta)}</div>'
            f'</div>'
        )
    return "".join(rows)


def _comparison_table(metrics: Mapping[str, Any]) -> str:
    controls = cast(Mapping[str, Any], metrics["model_control_plane"])
    control_fields = ("provider_requests", "input_tokens", "output_tokens", "total_tokens", "latency_ms", "retry_count", "estimated_cny", "conservative_estimated_cny", "unknown_usage_attempts", "model_failure_count", "cost_complete")
    control_labels = {"provider_requests": "API请求", "input_tokens": "输入Token", "output_tokens": "输出Token", "total_tokens": "总Token", "latency_ms": "总延迟(ms)", "retry_count": "重试数", "estimated_cny": "确认成本(¥)", "conservative_estimated_cny": "保守成本(¥)", "unknown_usage_attempts": "未知用量", "model_failure_count": "模型失败数", "cost_complete": "成本完整性"}
    items = []
    for name in control_fields:
        text, badge = _fmt_cell(name, controls[name])
        items.append(f'<li><span class="ctl-label">{escape(control_labels.get(name, name))}<code class="fname">{escape(name)}</code></span><span class="num {badge}">{text}</span></li>')
    return f"<h3>四维指标对比（双次重复均值）</h3>{_comparison_bars(metrics)}<h3>总体控制面成本</h3><ul class=\"control-plane\">{''.join(items)}</ul>"


def _ledger(slots: Sequence[_ValidatedSlot]) -> str:
    by_case: dict[str, dict[tuple[str, int], _ValidatedSlot]] = {
        case: {} for case in sorted({slot.case_id for slot in slots})
    }
    for slot in slots:
        by_case[slot.case_id][(slot.arm, slot.repeat_id)] = slot
    status_badge = {"completed": "b-good", "partial": "b-mid", "unavailable": "b-bad"}
    rows = []
    for case_id, lanes in by_case.items():
        cells = []
        for arm in _ARMS:
            for repeat in _REPEATS:
                slot = lanes[(arm, repeat)]
                status = slot.report.execution_status
                label = _STATUS_LABELS.get(status, status)
                badge = status_badge.get(status, "")
                href = f"reports/{slot.arm}/run-{slot.repeat_id}/{slot.case_id}/report.html"
                cells.append(f'<td data-slot="{escape(slot.arm)}-{repeat}-{escape(case_id)}" data-arm="{escape(slot.arm)}" data-repeat="{repeat}" data-status="{escape(status)}"><a class="status-link {badge}" href="{escape(href)}">{escape(label)}</a></td>')
        rows.append(f"<tr><th><code>{escape(case_id)}</code></th>{''.join(cells)}</tr>")
    return "".join(rows)


def _recommendations(slots: Sequence[_ValidatedSlot]) -> str:
    counts: dict[tuple[str, str], int] = {}
    for slot in slots:
        for recommendation in slot.report.human_decision_recommendations:
            key = recommendation.priority, recommendation.action
            counts[key] = counts.get(key, 0) + 1
    return "".join(f"<li><b>{escape(priority)}</b> {escape(action)} ×{count}</li>" for (priority, action), count in sorted(counts.items()))


def _failures(slots: Sequence[_ValidatedSlot]) -> str:
    records = []
    for slot in slots:
        if slot.report.execution_status != "completed" or slot.receipt.get("error_type"):
            status = slot.report.execution_status
            label = _STATUS_LABELS.get(status, status)
            error = slot.receipt.get("error_type") or "none"
            records.append(f'<li><code>{escape(slot.arm)}/run-{slot.repeat_id}/{escape(slot.case_id)}</code> · <span class="status-tag {status}">{escape(label)}</span> · <code>{escape(str(error))}</code></li>')
    return "".join(records) or "<li>无</li>"


_OVERVIEW_CSS = """
:root{--paper:#f5f7fa;--ink:#172033;--blue:#315b8a;--green:#2f8f5b;--red:#c0392b;--amber:#b7791f;--line:#d7dee8;--card:#fff}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.6 "PingFang SC",system-ui,sans-serif}
main{max-width:1280px;margin:auto;padding:40px 28px 64px}
h1{font:700 clamp(28px,4.5vw,46px)/1.15 "Songti SC",serif}
h2{font-size:19px;margin:0 0 10px}
h3{font-size:15px;margin:18px 0 8px;color:#3a4a63}
.hero{border-left:5px solid var(--blue);padding-left:24px;margin-bottom:8px}
.hero p{color:#5a6b85;margin:6px 0 0}
.panel{background:var(--card);border:1px solid var(--line);padding:20px;margin-top:16px;border-radius:8px}
.panel p,.panel li{overflow-wrap:anywhere;word-break:break-word}
.table-wrap{overflow:auto}
table{border-collapse:collapse;min-width:760px;width:100%}
th,td{padding:9px 10px;border-top:1px solid var(--line);text-align:left;vertical-align:top}
th{font-size:12px;white-space:nowrap}
code{overflow-wrap:anywhere}
.fname{display:block;font-size:10px;color:#8a97ab;font-weight:400;letter-spacing:.2px}
.num{font-variant-numeric:tabular-nums;white-space:nowrap}
.b-good{color:#1f7a43;font-weight:600}
.b-mid{color:#9a6a12;font-weight:600}
.b-bad{color:#b03a2e;font-weight:600}
.lane-row th{font-weight:600}
.mini-bar{display:inline-block;width:64px;height:8px;background:#eef1f6;border-radius:4px;vertical-align:middle;margin-right:8px;overflow:hidden}
.mini-fill{display:block;height:100%;background:var(--blue);border-radius:4px}
.cmp-row{display:flex;align-items:center;gap:14px;padding:10px 0;border-top:1px solid var(--line)}
.cmp-row:first-child{border-top:0}
.cmp-label{width:150px;flex:none;font-weight:600;font-size:13px}
.cmp-bars{flex:1;min-width:0}
.cmp-line{display:flex;align-items:center;gap:10px;margin:4px 0}
.cmp-arm{flex:none;width:64px;font-size:11px;text-align:right;color:#5a6b85}
.track{flex:1;background:#eef1f6;border-radius:4px;height:18px;overflow:hidden}
.bar{display:flex;align-items:center;justify-content:flex-end;height:100%;padding:0 6px;font-size:11px;font-weight:600;color:#fff;border-radius:4px;white-space:nowrap}
.bar-cur{background:#7f95b5}
.bar-opt{background:var(--blue)}
.cmp-delta{flex:none;width:74px;text-align:center;font-weight:700;font-size:14px;padding:4px 6px;border-radius:6px}
.cmp-delta.pos{color:#1f7a43;background:#e6f4ec}
.cmp-delta.neg{color:#b03a2e;background:#fbeceb}
.control-plane{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:8px 18px}
.control-plane li{display:flex;justify-content:space-between;gap:10px;padding:7px 10px;background:#f7f9fc;border:1px solid var(--line);border-radius:6px}
.ctl-label{font-size:13px;color:#3a4a63}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-top:14px}
.summary-card{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--blue);border-radius:8px;padding:16px 18px}
.summary-card .value{font:700 26px/1.2 "Songti SC",serif;margin:4px 0 2px}
.summary-card .label{font-size:13px;color:#5a6b85}
.summary-card .hint{font-size:12px;color:#8a97ab}
.status-link{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;text-decoration:none}
.status-link.b-good{color:#1f7a43;background:#e6f4ec}
.status-link.b-mid{color:#9a6a12;background:#fbf3e0}
.status-link.b-bad{color:#b03a2e;background:#fbeceb}
.status-tag{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600}
.status-tag.completed{color:#1f7a43;background:#e6f4ec}
.status-tag.partial{color:#9a6a12;background:#fbf3e0}
.status-tag.unavailable{color:#b03a2e;background:#fbeceb}
.filters{display:flex;gap:10px;flex-wrap:wrap}
.filters label{display:flex;align-items:center;gap:6px;font-size:13px;color:#3a4a63}
select{font:inherit;padding:6px;border:1px solid var(--line);border-radius:6px;background:#fff}
.hidden{display:none}
@media(max-width:720px){main{padding:24px 16px}.cmp-row{flex-wrap:wrap}.cmp-label{width:100%}.cmp-delta{width:auto}}
@media print{body{background:#fff}main{padding:0;max-width:none}.filters{display:none}.panel{break-inside:avoid}a{color:inherit;text-decoration:none}}
"""

_OVERVIEW_SCRIPT = """const f=['case','arm','repeat','status'];function apply(){const q=Object.fromEntries(f.map(x=>[x,document.getElementById(x).value]));document.querySelectorAll('#ledger tbody tr').forEach(r=>{const caseOk=q.case==='all'||r.querySelector('code').textContent===q.case;let anyLane=false;r.querySelectorAll('td[data-slot]').forEach(c=>{const ok=caseOk&&(q.arm==='all'||c.dataset.arm===q.arm)&&(q.repeat==='all'||c.dataset.repeat===q.repeat)&&(q.status==='all'||c.dataset.status===q.status);c.classList.toggle('hidden',!ok);anyLane||=ok;});r.classList.toggle('hidden',!caseOk||!anyLane)})}f.forEach(x=>document.getElementById(x).addEventListener('change',apply));"""


def _summary_cards(overall: Mapping[str, Any]) -> str:
    cards = [
        ("宏观义务分", _fmt_pct(overall["macro_obligation_score"]), "12 题宏观义务达成均值"),
        ("完成率", _fmt_pct(overall["completion_rate"]), "completed 槽位占比"),
        ("不可用率", _fmt_pct(overall["unavailable_rate"]), "设计内 API 失败占比"),
        ("确认成本", _fmt_cell("estimated_cny", overall["estimated_cny"])[0], "provider 完整计费"),
        ("总Token", _fmt_cell("total_tokens", overall["total_tokens"])[0], "全部 48 槽位"),
        ("模型失败", _fmt_cell("model_failure_count", overall["model_failure_count"])[0], "结构化输出失败数"),
    ]
    return '<div class="summary-grid">' + "".join(
        f'<div class="summary-card"><div class="label">{escape(label)}</div><div class="value">{text}</div><div class="hint">{escape(hint)}</div></div>'
        for label, text, hint in cards
    ) + "</div>"


def _overview_html(metrics: Mapping[str, Any], slots: Sequence[_ValidatedSlot]) -> str:
    safety = cast(Mapping[str, Any], metrics["safety"])
    overall = cast(Mapping[str, Any], metrics["overall"])
    csp = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; connect-src 'none'; object-src 'none'; frame-src 'none'"
    case_options = "".join(f'<option value="{escape(slot.case_id)}">{escape(slot.case_id)}</option>' for slot in sorted(slots, key=lambda slot: slot.case_id)[::4])
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="{csp}"><title>SecMind 逆向分析 · DeepSeek API 测评交付</title>
<style>{_OVERVIEW_CSS}</style></head>
<body><main>
<header class="hero"><p>SECMIND · 48 份独立 API 卷宗 · deepseek-v4-flash</p><h1>逆向分析决策台账（DeepSeek API 双重复运行）</h1><p>最终结论仅来自封存的 DeepSeek API 业务报告；本地逆向工具只提供有界证据，不构成并列结论。</p></header>
{_summary_cards(overall)}
<section class="panel"><h2>能力与网络边界</h2><p>PE/静态分析与受限模拟观测仅为证据输入，未断言宿主原生执行、Windows VM 或未观测运行路径。</p><p>DeepSeek 控制面流量单独核算。样本/工具安全账本：{escape(json.dumps(dict(safety), sort_keys=True))}</p></section>
<section class="panel"><h2>版本间比较（optimized − current）</h2>{_comparison_table(metrics)}</section>
<section class="panel"><h2>四个运行 lane 全量指标</h2>{_lane_table(metrics)}</section>
<section class="panel"><h2>重复稳定性（同题两次运行一致性）</h2>{_stability_table(metrics)}</section>
<section class="panel"><h2>12 题 × 4 lane 证据账本</h2><div class="filters"><label>题目 <select id="case"><option value="all">全部</option>{case_options}</select></label><label>版本 <select id="arm"><option value="all">全部</option><option value="current">Current</option><option value="optimized">Optimized</option></select></label><label>重复 <select id="repeat"><option value="all">全部</option><option value="1">1</option><option value="2">2</option></select></label><label>状态 <select id="status"><option value="all">全部</option><option value="completed">完成</option><option value="partial">部分</option><option value="unavailable">不可用</option></select></label></div><div class="table-wrap"><table id="ledger"><thead><tr><th>case</th><th>current · 重复1</th><th>current · 重复2</th><th>optimized · 重复1</th><th>optimized · 重复2</th></tr></thead><tbody>{_ledger(slots)}</tbody></table></div></section>
<section class="panel"><h2>失败与部分结论</h2><ul>{_failures(slots)}</ul><h2>人类决策建议（跨槽位汇总）</h2><ul>{_recommendations(slots)}</ul></section>
</main>
<script>{_OVERVIEW_SCRIPT}</script></body></html>"""


def _overview_markdown(metrics: Mapping[str, Any], slots: Sequence[_ValidatedSlot]) -> str:
    arms = cast(Mapping[str, Any], metrics["arms"])
    fields = ("macro_obligation_score", "behavior_f1", "exact_fact_accuracy", "evidence_reference_coverage", "completion_rate", "partial_rate", "unavailable_rate", "model_failure_count", "provider_requests", "total_tokens", "latency_ms", "retry_count", "estimated_cny", "conservative_estimated_cny", "unknown_usage_attempts", "cost_complete")
    lines = ["# SecMind DeepSeek API 逆向分析交付", "", "最终结论仅来自 48 份独立、封存的 DeepSeek API 业务报告。", "", "## 四个运行 lane", "", "| lane | " + " | ".join(fields) + " |", "| --- | " + " | ".join(["---:"] * len(fields)) + " |"]
    for arm in _ARMS:
        repeats = cast(Mapping[str, Any], cast(Mapping[str, Any], arms[arm])["repeats"])
        for repeat in _REPEATS:
            lane = cast(Mapping[str, Any], repeats[str(repeat)])
            lines.append(f"| {arm} / repeat {repeat} | " + " | ".join(str(lane[field]) for field in fields) + " |")
    stability_fields = ("status_agreement", "behavior_jaccard", "exact_fact_agreement", "recommendation_priority_agreement")
    lines.extend(["", "## 重复稳定性", "", "| arm | " + " | ".join(stability_fields) + " |", "| --- | " + " | ".join(["---:"] * len(stability_fields)) + " |"])
    for arm in _ARMS:
        stability = cast(Mapping[str, Any], arms[arm]["stability"])
        lines.append(f"| {arm} | " + " | ".join(str(stability[field]) for field in stability_fields) + " |")
    comparison = cast(Mapping[str, Any], cast(Mapping[str, Any], metrics["comparison"])["optimized_minus_current"])
    control = cast(Mapping[str, Any], metrics["model_control_plane"])
    lines.extend(["", "## 优化版本相对当前版本", ""])
    lines.extend(f"- optimized_minus_current.{name}: {value}" for name, value in sorted(comparison.items()))
    lines.extend(["", "## 总体控制面成本", ""])
    lines.extend(f"- {name}: {value}" for name, value in sorted(control.items()))
    lines.extend(["", "## 失败与人类决策", ""])
    for slot in slots:
        if slot.report.execution_status != "completed" or slot.receipt.get("error_type"):
            lines.append(f"- failure: {slot.arm}/run-{slot.repeat_id}/{slot.case_id} · {slot.report.execution_status}")
    recommendation_counts: dict[tuple[str, str], int] = {}
    for slot in slots:
        for item in slot.report.human_decision_recommendations:
            key = item.priority, item.action
            recommendation_counts[key] = recommendation_counts.get(key, 0) + 1
    lines.extend(f"- recommendation [{priority}] ×{count}: {action}" for (priority, action), count in sorted(recommendation_counts.items()))
    lines.extend(["", "## 边界", "", "- 工具输出是 API 报告的受限证据，不是并列结论。", "- 未声称宿主原生执行、Windows VM 或未观测运行路径。", "- DeepSeek 控制面流量与样本/工具安全网络计数分开。", "", "## 单次报告", ""])
    for slot in slots:
        lines.append(f"- [{slot.arm}/run-{slot.repeat_id}/{slot.case_id}](reports/{slot.arm}/run-{slot.repeat_id}/{slot.case_id}/report.html) · {slot.report.execution_status}")
    return "\n".join(lines) + "\n"


def render_api_overview(
    *,
    metrics: Mapping[str, Any],
    case_rows: Sequence[Mapping[str, Any]],
    run_root: Path,
    output_dir: Path,
    manifest: Mapping[str, Any] | Path,
    gold_path: Path,
) -> OverviewResult:
    """Render only a score recomputed from the sealed 48-run tree."""

    slots, scored_metrics, scored_rows, inventory, scoring_receipt = _scored_truth(
        run_root=run_root, gold_path=gold_path, metrics=metrics, case_rows=case_rows
    )
    public_manifest = _validate_manifest(manifest, slots)
    root = output_dir.resolve(strict=False)
    if root.exists() and any(root.iterdir()):
        raise ValueError("delivery root must be empty")
    if root.exists() and root.is_symlink():
        raise ValueError("delivery root must not be a symlink")
    root.mkdir(parents=True, exist_ok=True)
    _copy_reports(slots, root)
    public_rows = _public_rows(scored_rows)
    (root / "api-metrics.json").write_bytes(_json_bytes(scored_metrics))
    _write_csv(root / "api-case-results.csv", public_rows)
    (root / "run-manifest.json").write_bytes(_json_bytes(public_manifest))
    (root / "artifact-inventory.json").write_bytes(_json_bytes(inventory))
    (root / "scoring-receipt.json").write_bytes(_json_bytes(scoring_receipt.to_dict()))
    (root / "index.md").write_text(_overview_markdown(scored_metrics, slots), encoding="utf-8")
    (root / "index.html").write_text(_overview_html(scored_metrics, slots), encoding="utf-8")
    _verify_delivery(root, source_inventory=inventory, metrics=scored_metrics, scored_rows=scored_rows, scoring_receipt=scoring_receipt, active_secret=None)
    return OverviewResult(root, root / "index.html", root / "index.md", root / "api-metrics.json", root / "api-case-results.csv", root / "run-manifest.json", inventory)


def _verify_delivery(
    root: Path,
    *,
    source_inventory: Mapping[str, Any],
    metrics: Mapping[str, Any],
    scored_rows: Sequence[Mapping[str, Any]],
    scoring_receipt: ScoringReceipt,
    active_secret: str | None,
) -> None:
    root = _assert_regular_tree(root, label="delivery root")
    actual_files = {path.relative_to(root).as_posix() for path in _walk_regular_files(root)}
    actual_dirs = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_dir() and not path.is_symlink()
    }
    expected_reports = {str(entry["path"]) for entry in cast(list[dict[str, Any]], source_inventory["artifacts"])}
    expected_dirs = {
        parent.as_posix()
        for relative in expected_reports
        for parent in Path(relative).parents
        if parent.as_posix() != "."
    }
    allowed_receipts = {
        name for name in (_RECEIPT_NAME, _FINALIZATION_RECEIPT_NAME) if name in actual_files
    }
    if actual_files != set(_TOP_LEVEL) | expected_reports | allowed_receipts or actual_dirs != expected_dirs:
        raise ValueError("delivery contains extra or missing artifacts")
    if _load_object(root / "api-metrics.json", label="API metrics") != dict(metrics):
        raise ValueError("delivery metrics do not match the sealed score")
    inventory = _load_object(root / "artifact-inventory.json", label="artifact inventory")
    if _canonical_sha256(inventory) != _canonical_sha256(source_inventory):
        raise ValueError("delivery inventory does not match the source inventory")
    seen: set[str] = set()
    inventory_paths = frozenset(expected_reports)
    for entry in cast(list[dict[str, Any]], source_inventory["artifacts"]):
        relative = _safe_relative(entry["path"], label="inventory path")
        if relative.as_posix() in seen:
            raise ValueError("delivery inventory has duplicate paths")
        seen.add(relative.as_posix())
        artifact = root / relative
        if not artifact.is_file() or artifact.is_symlink() or artifact.stat().st_size != entry["size_bytes"] or _file_sha256(artifact) != entry["sha256"]:
            raise ValueError("delivery artifact does not equal its sealed source copy")
        if artifact.name == "report.html":
            _validate_html_policy(artifact, is_overview=False, inventory_paths=inventory_paths, root=root)
    _validate_html_policy(root / "index.html", is_overview=True, inventory_paths=inventory_paths, root=root)
    expected_rows = _public_rows(scored_rows)
    with (root / "api-case-results.csv").open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        actual_rows = list(reader)
        fields = tuple(reader.fieldnames or ())
    expected_fields = tuple(sorted({key for row in expected_rows for key in row}))
    expected_csv = [{key: _csv_value(row[key]) for key in expected_fields} for row in expected_rows]
    if fields != expected_fields or actual_rows != expected_csv:
        raise ValueError("delivery CSV does not match the sealed scoring rows")
    if _load_object(root / "scoring-receipt.json", label="scoring receipt") != scoring_receipt.to_dict():
        raise ValueError("delivery scoring receipt does not bind source truth")
    local_quarantine = _quarantine_receipt_path()
    finalization = root / _FINALIZATION_RECEIPT_NAME
    workspace_delivery = root.is_relative_to(_workspace_root().resolve())
    if workspace_delivery and (local_quarantine.exists() or local_quarantine.is_symlink()):
        if not finalization.is_file() or finalization.is_symlink():
            raise ValueError("delivery is missing quarantine finalization receipt")
    if finalization.is_file() or finalization.is_symlink():
        if finalization.is_symlink() or not (root / _RECEIPT_NAME).is_file():
            raise ValueError("delivery finalization receipt has no public gate")
        _load_quarantine_finalization_receipt(finalization, delivery=root)
    if active_secret is not None:
        _scan_exact_secret_tree(root, active_secret=active_secret)


def _allowed_legacy_targets() -> tuple[Path, Path]:
    root = _workspace_root().resolve()
    return (root / "docs" / "reports" / "reverse-analysis-audit-2026-08-24", root / "reverse_evaluation" / "results" / "audit-2026-08-24")


def _validated_legacy_targets() -> tuple[Path, Path]:
    root = _workspace_root().resolve()
    allowed = _allowed_legacy_targets()
    if any(not target.is_relative_to(root) for target in allowed):
        raise ValueError("legacy allowlist escapes workspace")
    resolved = tuple(_assert_regular_tree(target, label="approved legacy target") for target in allowed)
    if any(target.parent == root or target == root for target in resolved):
        raise ValueError("legacy target is too broad")
    return cast(tuple[Path, Path], resolved)


def _validated_canonical_gold(gold_path: Path) -> Path:
    canonical = _assert_regular_tree(_canonical_gold_path(), label="canonical gold path", allow_gold=True)
    supplied = _assert_regular_tree(gold_path, label="gold path", allow_gold=True)
    if supplied != canonical:
        raise ValueError("gold path is not the canonical workspace expected.json")
    return canonical


def build_deletion_gate_receipt(
    *,
    run_root: Path,
    delivery_root: Path,
    gold_path: Path,
    active_secret: str,
    metrics: Mapping[str, Any] | None = None,
    case_rows: Sequence[Mapping[str, Any]] | None = None,
) -> DeletionGateReceipt:
    """Issue a receipt only for recomputed truth and the closed legacy allowlist."""

    secret = _require_active_secret(active_secret)
    canonical_gold = _validated_canonical_gold(gold_path)
    slots, scored_metrics, scored_rows, inventory, scoring_receipt = _scored_truth(run_root=run_root, gold_path=canonical_gold, metrics=metrics, case_rows=case_rows)
    _scan_exact_secret_tree(run_root, active_secret=secret)
    _scan_exact_secret_tree(canonical_gold, active_secret=secret, allow_gold=True)
    delivery = _assert_regular_tree(delivery_root, label="delivery root")
    _verify_delivery(delivery, source_inventory=inventory, metrics=scored_metrics, scored_rows=scored_rows, scoring_receipt=scoring_receipt, active_secret=secret)
    targets = _validated_legacy_targets()
    digests = cast(tuple[tuple[str, str], tuple[str, str]], tuple((str(path), _tree_digest(path)) for path in targets))
    unsigned: dict[str, Any] = {
        "schema_version": _DELETION_VERSION,
        "delivery_root": str(delivery),
        "delivery_sha256": _tree_digest(delivery, exclude=frozenset({_RECEIPT_NAME})),
        "run_root": str(_assert_regular_tree(run_root, label="run root")),
        "gold_path": str(canonical_gold),
        "gold_sha256": _file_sha256(canonical_gold),
        "scoring_receipt_path": str((delivery / "scoring-receipt.json").resolve()),
        "scoring_receipt_sha256": scoring_receipt.receipt_sha256,
        "suite_id": str(scored_metrics["suite_id"]),
        "slot_count": len(slots),
        "artifact_count": 336,
        "exact_secret_matches": 0,
        "approved_deletion_targets": cast(tuple[str, str], tuple(str(path) for path in targets)),
        "approved_target_sha256": digests,
    }
    return DeletionGateReceipt(**unsigned, binding_sha256=_canonical_sha256(unsigned))


def _public_gate_receipt(receipt: DeletionGateReceipt) -> PublicDeletionGateReceipt:
    """Project the private pre-action receipt without a workstation path."""

    _validate_deletion_receipt(receipt)
    unsigned: dict[str, Any] = {
        "schema_version": _PUBLIC_DELETION_VERSION,
        "delivery_root": _workspace_relative(receipt.delivery_root, label="delivery root"),
        "delivery_sha256": receipt.delivery_sha256,
        "run_root": _workspace_relative(receipt.run_root, label="run root"),
        "gold_path": _workspace_relative(receipt.gold_path, label="gold path"),
        "gold_sha256": receipt.gold_sha256,
        "scoring_receipt_path": _workspace_relative(receipt.scoring_receipt_path, label="scoring receipt path"),
        "scoring_receipt_sha256": receipt.scoring_receipt_sha256,
        "suite_id": receipt.suite_id,
        "slot_count": receipt.slot_count,
        "artifact_count": receipt.artifact_count,
        "exact_secret_matches": receipt.exact_secret_matches,
        "approved_deletion_targets": tuple(
            _workspace_relative(path, label="approved deletion target") for path in receipt.approved_deletion_targets
        ),
        "approved_target_sha256": tuple(
            (_workspace_relative(path, label="approved deletion target"), digest)
            for path, digest in receipt.approved_target_sha256
        ),
        "pre_action_binding_sha256": receipt.binding_sha256,
    }
    return PublicDeletionGateReceipt(
        **unsigned, public_binding_sha256=_canonical_sha256(unsigned)
    )


def _validate_public_gate_receipt(receipt: PublicDeletionGateReceipt) -> None:
    if not isinstance(receipt, PublicDeletionGateReceipt) or receipt.schema_version != _PUBLIC_DELETION_VERSION:
        raise ValueError("public deletion receipt is invalid")
    if _canonical_sha256(receipt.unsigned_payload()) != receipt.public_binding_sha256:
        raise ValueError("public deletion receipt binding digest does not verify")
    relative_targets = tuple(_workspace_relative(path, label="approved legacy target") for path in _allowed_legacy_targets())
    expected_target_digests = tuple(item[0] for item in receipt.approved_target_sha256)
    if (
        receipt.approved_deletion_targets != relative_targets
        or expected_target_digests != relative_targets
        or len(receipt.approved_target_sha256) != 2
    ):
        raise ValueError("public deletion receipt does not use the closed legacy allowlist")
    delivery = _workspace_path(receipt.delivery_root, label="delivery root")
    if receipt.gold_path != _workspace_relative(_canonical_gold_path(), label="gold path"):
        raise ValueError("public deletion receipt does not bind canonical gold")
    if receipt.scoring_receipt_path != (Path(receipt.delivery_root) / "scoring-receipt.json").as_posix():
        raise ValueError("public deletion receipt does not bind scoring receipt")
    if not all(
        _is_sha256(value)
        for value in (
            receipt.delivery_sha256,
            receipt.gold_sha256,
            receipt.scoring_receipt_sha256,
            receipt.pre_action_binding_sha256,
            receipt.public_binding_sha256,
        )
    ):
        raise ValueError("public deletion receipt digest shape is invalid")
    if delivery.name == "" or receipt.slot_count != 48 or receipt.artifact_count != 336 or receipt.exact_secret_matches != 0:
        raise ValueError("public deletion receipt is incomplete")


def _load_public_gate_receipt(path: Path) -> PublicDeletionGateReceipt:
    payload = _load_object(path, label="public deletion receipt")
    _require_closed_fields(payload, frozenset(PublicDeletionGateReceipt.__dataclass_fields__), label="public deletion receipt")
    text_fields = {
        "schema_version", "delivery_root", "delivery_sha256", "run_root", "gold_path", "gold_sha256",
        "scoring_receipt_path", "scoring_receipt_sha256", "suite_id", "pre_action_binding_sha256",
        "public_binding_sha256",
    }
    if any(not isinstance(payload[name], str) for name in text_fields):
        raise ValueError("public deletion receipt schema is invalid")
    if any(type(payload[name]) is not int for name in ("slot_count", "artifact_count", "exact_secret_matches")):
        raise ValueError("public deletion receipt schema is invalid")
    targets_value = payload["approved_deletion_targets"]
    digests_value = payload["approved_target_sha256"]
    if (
        not isinstance(targets_value, list)
        or len(targets_value) != 2
        or any(not isinstance(item, str) for item in targets_value)
        or not isinstance(digests_value, list)
        or len(digests_value) != 2
        or any(
            not isinstance(item, list)
            or len(item) != 2
            or any(not isinstance(part, str) for part in item)
            for item in digests_value
        )
    ):
        raise ValueError("public deletion receipt schema is invalid")
    try:
        receipt = PublicDeletionGateReceipt(
            schema_version=payload["schema_version"],
            delivery_root=payload["delivery_root"],
            delivery_sha256=payload["delivery_sha256"],
            run_root=payload["run_root"],
            gold_path=payload["gold_path"],
            gold_sha256=payload["gold_sha256"],
            scoring_receipt_path=payload["scoring_receipt_path"],
            scoring_receipt_sha256=payload["scoring_receipt_sha256"],
            suite_id=payload["suite_id"],
            slot_count=payload["slot_count"],
            artifact_count=payload["artifact_count"],
            exact_secret_matches=payload["exact_secret_matches"],
            approved_deletion_targets=cast(tuple[str, str], tuple(payload["approved_deletion_targets"])),
            approved_target_sha256=cast(
                tuple[tuple[str, str], tuple[str, str]], tuple(tuple(item) for item in payload["approved_target_sha256"])
            ),
            pre_action_binding_sha256=payload["pre_action_binding_sha256"],
            public_binding_sha256=payload["public_binding_sha256"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("public deletion receipt schema is invalid") from exc
    _validate_public_gate_receipt(receipt)
    return receipt


def _validate_deletion_receipt(receipt: DeletionGateReceipt) -> None:
    if not isinstance(receipt, DeletionGateReceipt) or receipt.schema_version != _DELETION_VERSION:
        raise ValueError("deletion receipt is invalid")
    if _canonical_sha256(receipt.unsigned_payload()) != receipt.binding_sha256:
        raise ValueError("deletion receipt binding digest does not verify")
    allowed = tuple(str(path.resolve()) for path in _allowed_legacy_targets())
    if receipt.approved_deletion_targets != allowed or len(receipt.approved_target_sha256) != 2:
        raise ValueError("deletion receipt does not use the closed legacy allowlist")
    if receipt.gold_path != str(_validated_canonical_gold(Path(receipt.gold_path))) or receipt.scoring_receipt_path != str((Path(receipt.delivery_root) / "scoring-receipt.json").resolve()):
        raise ValueError("deletion receipt does not bind canonical proof paths")
    if not all(_is_sha256(value) for value in (receipt.delivery_sha256, receipt.gold_sha256, receipt.scoring_receipt_sha256, receipt.binding_sha256)):
        raise ValueError("deletion receipt digest shape is invalid")
    if receipt.slot_count != 48 or receipt.artifact_count != 336 or receipt.exact_secret_matches != 0:
        raise ValueError("deletion receipt is incomplete")


def _atomic_create_json(path: Path, payload: Mapping[str, Any]) -> None:
    """Create one receipt atomically; callers never overwrite an audit record."""

    parent = _assert_regular_tree(path.parent, label="receipt parent")
    if path.exists() or path.is_symlink():
        raise ValueError("receipt path is unsafe")
    temporary = parent / f".{path.name}.{secrets.token_hex(16)}.tmp"
    fd = -1
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        data = _json_bytes(payload)
        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        if path.exists() or path.is_symlink():
            raise ValueError("receipt path is unsafe")
        os.replace(temporary, path)
        if os.name == "posix":
            directory_fd = _open_parent_directory(parent)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except Exception:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)
        raise


def _atomic_replace_json(path: Path, payload: Mapping[str, Any]) -> None:
    """Replace a previously validated public projection without exposing partial JSON."""

    parent = _assert_regular_tree(path.parent, label="receipt parent")
    if not path.is_file() or path.is_symlink():
        raise ValueError("receipt path is unsafe")
    temporary = parent / f".{path.name}.{secrets.token_hex(16)}.tmp"
    fd = -1
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, _json_bytes(payload))
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, path)
        if os.name == "posix":
            directory_fd = _open_parent_directory(parent)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except Exception:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)
        raise


def write_deletion_gate_receipt(receipt: DeletionGateReceipt, *, active_secret: str) -> Path:
    """Persist the receipt at one fixed delivery location and scan it."""

    _validate_deletion_receipt(receipt)
    root = _assert_regular_tree(Path(receipt.delivery_root), label="delivery root")
    path = root / _RECEIPT_NAME
    public = _public_gate_receipt(receipt)
    _atomic_create_json(path, public.to_dict())
    try:
        _scan_exact_secret_tree(root, active_secret=_require_active_secret(active_secret))
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


def _open_parent_directory(path: Path) -> int:
    """Open a non-link parent with available descriptor-hardening flags."""

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(path, flags)
    except OSError as exc:
        unsupported = {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}
        if flags != os.O_RDONLY and exc.errno in unsupported:
            return os.open(path, os.O_RDONLY)
        raise


if os.name == "nt":
    class _WindowsFileInfo(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD), ("created", wintypes.FILETIME),
            ("accessed", wintypes.FILETIME), ("written", wintypes.FILETIME),
            ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD), ("links", wintypes.DWORD),
            ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD),
        ]

    class _WindowsRenameInfo(ctypes.Structure):
        _fields_ = [
            ("replace", ctypes.c_ubyte), ("root", wintypes.HANDLE),
            ("name_length", wintypes.DWORD), ("name", wintypes.WCHAR * 1),
        ]

    class _WindowsFileId(ctypes.Structure):
        _fields_ = [("volume", ctypes.c_ulonglong), ("file_id", ctypes.c_ubyte * 16)]

    class _WindowsUnicodeString(ctypes.Structure):
        _fields_ = [("length", wintypes.USHORT), ("maximum_length", wintypes.USHORT), ("buffer", wintypes.LPWSTR)]

    class _WindowsObjectAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.ULONG), ("root", wintypes.HANDLE),
            ("name", ctypes.POINTER(_WindowsUnicodeString)), ("attributes", wintypes.ULONG),
            ("security", wintypes.LPVOID), ("security_qos", wintypes.LPVOID),
        ]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(_WindowsFileInfo)]
    _kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    _kernel32.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    _kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    _ntdll.NtSetInformationFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, wintypes.ULONG, ctypes.c_int]
    _ntdll.NtSetInformationFile.restype = ctypes.c_long
    _ntdll.NtCreateFile.argtypes = [
        ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, ctypes.POINTER(_WindowsObjectAttributes),
        wintypes.LPVOID, wintypes.LPVOID, wintypes.ULONG, wintypes.ULONG,
        wintypes.ULONG, wintypes.ULONG, wintypes.LPVOID, wintypes.ULONG,
    ]
    _ntdll.NtCreateFile.restype = ctypes.c_long
    _ntdll.RtlNtStatusToDosError.argtypes = [ctypes.c_long]
    _ntdll.RtlNtStatusToDosError.restype = wintypes.ULONG


def _windows_open_directory(path: Path) -> int:
    handle = _kernel32.CreateFileW(str(path), 0x80, 0x7, None, 3, 0x02000000 | 0x00200000, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    info = _WindowsFileInfo()
    if not _kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
        error = ctypes.WinError(ctypes.get_last_error())
        _kernel32.CloseHandle(handle)
        raise error
    if not info.attributes & 0x10 or info.attributes & 0x400:
        _kernel32.CloseHandle(handle)
        raise ValueError("legacy directory is not a regular directory")
    return handle


def _windows_inode(handle: int) -> int:
    return _windows_file_id(handle)[1]


def _windows_file_id(handle: int) -> tuple[int, int]:
    info = _WindowsFileId()
    if not _kernel32.GetFileInformationByHandleEx(handle, 18, ctypes.byref(info), ctypes.sizeof(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    return info.volume, int.from_bytes(bytes(info.file_id), "little")


def _validate_anchor_name(name: str) -> None:
    if not name or name in {".", ".."} or "/" in name or "\\" in name or ":" in name:
        raise ValueError("anchored child name is invalid")


def _windows_open_child(parent_handle: int, name: str, *, rename: bool = False, create: bool = False) -> int:
    _validate_anchor_name(name)
    encoded = ctypes.create_unicode_buffer(name)
    unicode_name = _WindowsUnicodeString(len(name) * 2, (len(name) + 1) * 2, ctypes.cast(encoded, wintypes.LPWSTR))
    attributes = _WindowsObjectAttributes(
        ctypes.sizeof(_WindowsObjectAttributes), parent_handle, ctypes.pointer(unicode_name), 0x40, None, None,
    )
    handle = wintypes.HANDLE()
    io_status = (ctypes.c_void_p * 2)()
    access = (0x10000 | 0x80) if rename else (0x100000 | 0x10000 | 0x2 | 0x80 if create else 0x80)
    options = 0x00200000 | (0x40 if create else 0x1) | (0x20 if create else 0)
    status = _ntdll.NtCreateFile(
        ctypes.byref(handle), access, ctypes.byref(attributes), io_status,
        None, 0, 0x7, 2 if create else 1, options, None, 0,
    )
    if status < 0:
        raise ctypes.WinError(_ntdll.RtlNtStatusToDosError(status))
    if not create:
        info = _WindowsFileInfo()
        if not _kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            error = ctypes.WinError(ctypes.get_last_error())
            _kernel32.CloseHandle(handle)
            raise error
        if not info.attributes & 0x10 or info.attributes & 0x400:
            _kernel32.CloseHandle(handle)
            raise ValueError("legacy target is not a regular directory")
    return handle.value


def _open_quarantine_parent(path: Path) -> int:
    return _windows_open_directory(path) if os.name == "nt" else _open_parent_directory(path)


def _close_quarantine_parent(handle: int) -> None:
    if os.name == "nt":
        if not _kernel32.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())
    else:
        os.close(handle)


def _anchor_parent_stat(parent: Path, handle: int) -> os.stat_result:
    if os.name == "nt":
        entry = parent.lstat()
        if not stat.S_ISDIR(entry.st_mode) or (entry.st_dev, entry.st_ino) != _windows_file_id(handle):
            raise ValueError("legacy parent changed while anchored")
        return entry
    return os.fstat(handle)


def _anchor_stat(parent: Path, handle: int, name: str) -> _AnchorEntry:
    if os.name == "nt":
        child = _windows_open_child(handle, name)
        try:
            device, inode = _windows_file_id(child)
            return _AnchorEntry(stat.S_IFDIR, device, inode)
        finally:
            _kernel32.CloseHandle(child)
    entry = os.stat(name, dir_fd=handle, follow_symlinks=False)
    return _AnchorEntry(entry.st_mode, entry.st_dev, entry.st_ino)


def _anchor_rename(parent: Path, handle: int, source: str, destination: str, *, inode: int) -> None:
    if os.name != "nt":
        os.rename(source, destination, src_dir_fd=handle, dst_dir_fd=handle)
        return
    _validate_anchor_name(destination)
    source_handle = _windows_open_child(handle, source, rename=True)
    try:
        if _windows_file_id(source_handle) != (_windows_file_id(handle)[0], inode):
            raise ValueError("legacy target changed during quarantine")
        encoded = destination.encode("utf-16-le")
        size = _WindowsRenameInfo.name.offset + len(encoded) + 2
        buffer = ctypes.create_string_buffer(size)
        info = ctypes.cast(buffer, ctypes.POINTER(_WindowsRenameInfo)).contents
        info.replace = 0
        info.root = handle
        info.name_length = len(encoded)
        ctypes.memmove(ctypes.addressof(buffer) + _WindowsRenameInfo.name.offset, encoded, len(encoded))
        io_status = (ctypes.c_void_p * 2)()
        status = _ntdll.NtSetInformationFile(source_handle, io_status, buffer, size, 10)
        if status < 0:
            raise ctypes.WinError(_ntdll.RtlNtStatusToDosError(status))
    finally:
        _kernel32.CloseHandle(source_handle)


def _anchor_create(parent: Path, handle: int, name: str, payload: bytes) -> None:
    fd = -1
    child = -1
    try:
        if os.name == "nt":
            child = _windows_open_child(handle, name, create=True)
            fd = msvcrt.open_osfhandle(child, os.O_WRONLY | os.O_BINARY)
            child = -1  # The CRT descriptor owns this handle now.
        else:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=handle)
        remaining = memoryview(payload)
        while remaining:
            count = os.write(fd, remaining)
            if count <= 0:
                raise OSError("recovery record write made no progress")
            remaining = remaining[count:]
        os.fsync(fd)
    except Exception:
        if fd >= 0 or child >= 0:
            try:
                if os.name == "nt":
                    active_handle = msvcrt.get_osfhandle(fd) if fd >= 0 else child
                    deleted = ctypes.c_ubyte(1)
                    io_status = (ctypes.c_void_p * 2)()
                    _ntdll.NtSetInformationFile(active_handle, io_status, ctypes.byref(deleted), 1, 13)
                else:
                    os.unlink(name, dir_fd=handle)
            except OSError:
                pass
        raise
    finally:
        if fd >= 0:
            os.close(fd)
        elif child >= 0:
            _kernel32.CloseHandle(child)


def _persist_recovery_record(item: _Quarantine) -> Path | None:
    """Best-effort durable locator if an exact rollback cannot be completed."""

    name = f"{item.quarantine_name}.recovery.json"
    payload = _json_bytes({"schema_version": "1.0", "original": str(item.parent / item.original_name), "quarantine": str(item.parent / item.quarantine_name), "device": item.device, "inode": item.inode, "sha256": item.sha256})
    try:
        _anchor_create(item.parent, item.parent_fd, name, payload)
    except OSError:
        return None
    return item.parent / name


def _quarantine_receipt_path() -> Path:
    """One local, non-public locator covering both approved legacy targets."""

    return _workspace_root().resolve() / "docs" / "reports" / _QUARANTINE_RECEIPT_NAME


def _quarantine_receipt_from_items(
    *, gate_binding_sha256: str, items: Sequence[_Quarantine]
) -> QuarantineReceipt:
    if len(items) != 2:
        raise ValueError("quarantine receipt requires exactly two targets")
    targets = tuple(
        QuarantineTargetReceipt(
            original_path=_workspace_relative(item.parent / item.original_name, label="quarantine original"),
            quarantine_path=_workspace_relative(item.parent / item.quarantine_name, label="quarantine path"),
            device=item.device,
            inode=item.inode,
            tree_sha256=item.sha256,
        )
        for item in items
    )
    unsigned = {
        "schema_version": _QUARANTINE_VERSION,
        "gate_binding_sha256": gate_binding_sha256,
        "targets": [asdict(item) for item in targets],
    }
    return QuarantineReceipt(
        schema_version=_QUARANTINE_VERSION,
        gate_binding_sha256=gate_binding_sha256,
        targets=cast(tuple[QuarantineTargetReceipt, QuarantineTargetReceipt], targets),
        binding_sha256=_canonical_sha256(unsigned),
    )


def _validate_quarantine_receipt(receipt: QuarantineReceipt, *, verify_live_paths: bool) -> None:
    if not isinstance(receipt, QuarantineReceipt) or receipt.schema_version != _QUARANTINE_VERSION:
        raise ValueError("quarantine receipt is invalid")
    if _canonical_sha256(receipt.unsigned_payload()) != receipt.binding_sha256 or not _is_sha256(receipt.gate_binding_sha256):
        raise ValueError("quarantine receipt binding digest does not verify")
    expected = tuple(_workspace_relative(path, label="approved legacy target") for path in _allowed_legacy_targets())
    originals = tuple(item.original_path for item in receipt.targets)
    if originals != expected or len(receipt.targets) != 2:
        raise ValueError("quarantine receipt does not bind approved targets")
    for item in receipt.targets:
        quarantine = _workspace_path(item.quarantine_path, label="quarantine path")
        original = _workspace_path(item.original_path, label="quarantine original")
        if quarantine.parent != original.parent or not quarantine.name.startswith(".secmind-quarantine-"):
            raise ValueError("quarantine receipt path is invalid")
        if not isinstance(item.device, int) or not isinstance(item.inode, int) or item.device < 0 or item.inode < 0 or not _is_sha256(item.tree_sha256):
            raise ValueError("quarantine receipt identity is invalid")
        if verify_live_paths:
            entry = _assert_regular_tree(quarantine, label="quarantined legacy target")
            observed = entry.stat()
            if (observed.st_dev, observed.st_ino) != (item.device, item.inode) or _tree_digest(entry) != item.tree_sha256:
                raise ValueError("quarantined legacy target changed")


def _load_quarantine_receipt(path: Path, *, verify_live_paths: bool) -> QuarantineReceipt:
    payload = _load_object(path, label="quarantine receipt")
    _require_closed_fields(payload, frozenset(QuarantineReceipt.__dataclass_fields__), label="quarantine receipt")
    if any(not isinstance(payload[name], str) for name in ("schema_version", "gate_binding_sha256", "binding_sha256")):
        raise ValueError("quarantine receipt schema is invalid")
    try:
        target_values = payload["targets"]
        if not isinstance(target_values, list) or len(target_values) != 2:
            raise TypeError("targets")
        target_fields = frozenset(QuarantineTargetReceipt.__dataclass_fields__)
        if any(not isinstance(item, dict) or set(item) != target_fields for item in target_values):
            raise TypeError("target fields")
        if any(
            not isinstance(item["original_path"], str)
            or not isinstance(item["quarantine_path"], str)
            or not isinstance(item["tree_sha256"], str)
            or type(item["device"]) is not int
            or type(item["inode"]) is not int
            for item in target_values
        ):
            raise TypeError("target types")
        targets = tuple(
            QuarantineTargetReceipt(
                original_path=item["original_path"],
                quarantine_path=item["quarantine_path"],
                device=item["device"],
                inode=item["inode"],
                tree_sha256=item["tree_sha256"],
            )
            for item in target_values
        )
        receipt = QuarantineReceipt(
            schema_version=payload["schema_version"],
            gate_binding_sha256=payload["gate_binding_sha256"],
            targets=cast(tuple[QuarantineTargetReceipt, QuarantineTargetReceipt], targets),
            binding_sha256=payload["binding_sha256"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("quarantine receipt schema is invalid") from exc
    _validate_quarantine_receipt(receipt, verify_live_paths=verify_live_paths)
    return receipt


def _write_quarantine_receipt(receipt: QuarantineReceipt, *, active_secret: str) -> Path:
    _validate_quarantine_receipt(receipt, verify_live_paths=True)
    path = _quarantine_receipt_path()
    _atomic_create_json(path, receipt.to_dict())
    try:
        _scan_exact_secret_tree(path, active_secret=_require_active_secret(active_secret))
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


def _open_parent_anchor(target: Path, expected_sha256: str) -> _Quarantine:
    parent = _assert_regular_tree(target.parent, label="legacy parent")
    parent_fd = -1
    try:
        expected_parent = parent.lstat()
        parent_fd = _open_quarantine_parent(parent)
        opened_parent = _anchor_parent_stat(parent, parent_fd)
        if not stat.S_ISDIR(opened_parent.st_mode) or (opened_parent.st_dev, opened_parent.st_ino) != (expected_parent.st_dev, expected_parent.st_ino):
            raise ValueError("legacy parent changed while opening")
        entry = _anchor_stat(parent, parent_fd, target.name)
        if not stat.S_ISDIR(entry.st_mode):
            raise ValueError("legacy target must remain a directory")
        current = _anchor_stat(parent, parent_fd, target.name)
        if (current.st_dev, current.st_ino) != (entry.st_dev, entry.st_ino) or _tree_digest(target) != expected_sha256:
            raise ValueError("legacy target changed before quarantine")
    except Exception:
        if parent_fd >= 0:
            _close_quarantine_parent(parent_fd)
        raise
    quarantine_name = f".secmind-quarantine-{secrets.token_hex(16)}"
    item = _Quarantine(parent, parent_fd, target.name, quarantine_name, entry.st_dev, entry.st_ino, expected_sha256)
    renamed = False
    try:
        _anchor_rename(parent, parent_fd, target.name, quarantine_name, inode=entry.st_ino)
        renamed = True
        moved = _anchor_stat(parent, parent_fd, quarantine_name)
        quarantine = parent / quarantine_name
        if not stat.S_ISDIR(moved.st_mode) or (moved.st_dev, moved.st_ino) != (entry.st_dev, entry.st_ino):
            raise ValueError("legacy target changed during quarantine")
        if _tree_digest(quarantine) != expected_sha256:
            raise ValueError("legacy target changed during quarantine")
        return item
    except Exception:
        restored = False
        if renamed:
            try:
                moved = _anchor_stat(parent, parent_fd, quarantine_name)
                if (moved.st_dev, moved.st_ino) == (entry.st_dev, entry.st_ino):
                    _anchor_rename(parent, parent_fd, quarantine_name, target.name, inode=entry.st_ino)
                    restored = True
            except (OSError, ValueError):
                restored = False
            if not restored:
                _persist_recovery_record(item)
        _close_quarantine_parent(parent_fd)
        raise


def _rollback(quarantines: Sequence[_Quarantine]) -> dict[str, Path]:
    recovery: dict[str, Path] = {}
    for item in reversed(quarantines):
        original = str(item.parent / item.original_name)
        unresolved = False
        try:
            try:
                entry = _anchor_stat(item.parent, item.parent_fd, item.quarantine_name)
                if entry.st_dev == item.device and entry.st_ino == item.inode:
                    try:
                        _anchor_rename(item.parent, item.parent_fd, item.quarantine_name, item.original_name, inode=item.inode)
                    except (OSError, ValueError):
                        unresolved = True
                else:
                    unresolved = True
            except (OSError, ValueError):
                unresolved = True
            if unresolved:
                _persist_recovery_record(item)
                recovery[original] = item.parent / item.quarantine_name
        finally:
            _close_quarantine_parent(item.parent_fd)
    return recovery


def _reprove_gate_at_quarantine(
    receipt: DeletionGateReceipt, *, receipt_path: Path, active_secret: str
) -> tuple[Path, Path]:
    """Recompute the sealed score and delivery proof immediately before moving bytes."""

    _validate_deletion_receipt(receipt)
    secret = _require_active_secret(active_secret)
    delivery = _assert_regular_tree(Path(receipt.delivery_root), label="delivery root")
    if receipt_path.resolve(strict=True) != (delivery / _RECEIPT_NAME).resolve(strict=True):
        raise ValueError("deletion receipt path is not fixed")
    if _canonical_sha256(_load_object(receipt_path, label="persisted deletion receipt")) != _canonical_sha256(_public_gate_receipt(receipt).to_dict()):
        raise ValueError("persisted deletion receipt does not match")
    gold = _validated_canonical_gold(Path(receipt.gold_path))
    slots, metrics, rows, inventory, scoring = _scored_truth(run_root=Path(receipt.run_root), gold_path=gold)
    scoring_path = delivery / "scoring-receipt.json"
    if scoring_path.resolve() != Path(receipt.scoring_receipt_path) or _load_object(scoring_path, label="persisted scoring receipt") != scoring.to_dict():
        raise ValueError("sealed score does not re-prove source truth")
    if scoring.receipt_sha256 != receipt.scoring_receipt_sha256 or _file_sha256(gold) != receipt.gold_sha256:
        raise ValueError("gold or sealed score changed after receipt issuance")
    _verify_delivery(delivery, source_inventory=inventory, metrics=metrics, scored_rows=rows, scoring_receipt=scoring, active_secret=secret)
    if _tree_digest(delivery, exclude=frozenset({_RECEIPT_NAME})) != receipt.delivery_sha256:
        raise ValueError("delivery changed after receipt issuance")
    _scan_exact_secret_tree(Path(receipt.run_root), active_secret=secret)
    _scan_exact_secret_tree(gold, active_secret=secret, allow_gold=True)
    targets = _validated_legacy_targets()
    current_digests = cast(tuple[tuple[str, str], tuple[str, str]], tuple((str(target), _tree_digest(target)) for target in targets))
    if receipt.approved_target_sha256 != current_digests or len(slots) != 48:
        raise ValueError("legacy targets or sealed run tree changed after receipt issuance")
    return targets


def quarantine_approved_legacy_artifacts(
    receipt: DeletionGateReceipt,
    *,
    receipt_path: Path,
    active_secret: str,
) -> QuarantineReceipt:
    """Atomically quarantine both targets and retain all bytes for recovery.

    This intentionally exposes no automatic purge. The return value is a map
    from the original fixed target to its same-parent quarantine path.
    """

    targets = _reprove_gate_at_quarantine(receipt, receipt_path=receipt_path, active_secret=active_secret)
    digests = dict(receipt.approved_target_sha256)
    quarantines: list[_Quarantine] = []
    try:
        for target in targets:
            quarantines.append(_open_parent_anchor(target, digests[str(target.resolve())]))
        for item in quarantines:
            path = item.parent / item.quarantine_name
            entry = _anchor_stat(item.parent, item.parent_fd, item.quarantine_name)
            if entry.st_dev != item.device or entry.st_ino != item.inode or _tree_digest(path) != item.sha256:
                raise ValueError("quarantined legacy target changed")
        persisted = _quarantine_receipt_from_items(gate_binding_sha256=receipt.binding_sha256, items=quarantines)
        _write_quarantine_receipt(persisted, active_secret=active_secret)
        for item in quarantines:
            _close_quarantine_parent(item.parent_fd)
        return persisted
    except Exception as exc:
        recovery = _rollback(quarantines)
        if recovery:
            raise QuarantineRecoveryError("quarantine rollback requires recovery", recovery) from exc
        raise


def _internal_receipt_from_payload(payload: Mapping[str, Any]) -> DeletionGateReceipt:
    """Load the v2 private shape only to migrate an already-issued gate safely."""

    fields = frozenset(DeletionGateReceipt.__dataclass_fields__)
    if set(payload) != fields:
        raise ValueError("legacy deletion receipt has unregistered fields")
    text_fields = {
        "schema_version", "delivery_root", "delivery_sha256", "run_root", "gold_path", "gold_sha256",
        "scoring_receipt_path", "scoring_receipt_sha256", "suite_id", "binding_sha256",
    }
    if any(not isinstance(payload[name], str) for name in text_fields):
        raise ValueError("legacy deletion receipt schema is invalid")
    if any(type(payload[name]) is not int for name in ("slot_count", "artifact_count", "exact_secret_matches")):
        raise ValueError("legacy deletion receipt schema is invalid")
    targets_value = payload["approved_deletion_targets"]
    digests_value = payload["approved_target_sha256"]
    if (
        not isinstance(targets_value, list)
        or len(targets_value) != 2
        or any(not isinstance(item, str) for item in targets_value)
        or not isinstance(digests_value, list)
        or len(digests_value) != 2
        or any(
            not isinstance(item, list)
            or len(item) != 2
            or any(not isinstance(part, str) for part in item)
            for item in digests_value
        )
    ):
        raise ValueError("legacy deletion receipt schema is invalid")
    try:
        receipt = DeletionGateReceipt(
            schema_version=payload["schema_version"],
            delivery_root=payload["delivery_root"],
            delivery_sha256=payload["delivery_sha256"],
            run_root=payload["run_root"],
            gold_path=payload["gold_path"],
            gold_sha256=payload["gold_sha256"],
            scoring_receipt_path=payload["scoring_receipt_path"],
            scoring_receipt_sha256=payload["scoring_receipt_sha256"],
            suite_id=payload["suite_id"],
            slot_count=payload["slot_count"],
            artifact_count=payload["artifact_count"],
            exact_secret_matches=payload["exact_secret_matches"],
            approved_deletion_targets=cast(tuple[str, str], tuple(payload["approved_deletion_targets"])),
            approved_target_sha256=cast(
                tuple[tuple[str, str], tuple[str, str]], tuple(tuple(item) for item in payload["approved_target_sha256"])
            ),
            binding_sha256=payload["binding_sha256"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("legacy deletion receipt schema is invalid") from exc
    _validate_deletion_receipt(receipt)
    if _canonical_sha256(receipt.to_dict()) != _canonical_sha256(payload):
        raise ValueError("legacy deletion receipt binding shape is invalid")
    return receipt


def _internal_receipt_from_public(receipt: PublicDeletionGateReceipt) -> DeletionGateReceipt:
    _validate_public_gate_receipt(receipt)
    unsigned: dict[str, Any] = {
        "schema_version": _DELETION_VERSION,
        "delivery_root": str(_workspace_path(receipt.delivery_root, label="delivery root")),
        "delivery_sha256": receipt.delivery_sha256,
        "run_root": str(_workspace_path(receipt.run_root, label="run root")),
        "gold_path": str(_workspace_path(receipt.gold_path, label="gold path")),
        "gold_sha256": receipt.gold_sha256,
        "scoring_receipt_path": str(_workspace_path(receipt.scoring_receipt_path, label="scoring receipt path")),
        "scoring_receipt_sha256": receipt.scoring_receipt_sha256,
        "suite_id": receipt.suite_id,
        "slot_count": receipt.slot_count,
        "artifact_count": receipt.artifact_count,
        "exact_secret_matches": receipt.exact_secret_matches,
        "approved_deletion_targets": cast(
            tuple[str, str], tuple(str(_workspace_path(path, label="approved deletion target")) for path in receipt.approved_deletion_targets)
        ),
        "approved_target_sha256": cast(
            tuple[tuple[str, str], tuple[str, str]],
            tuple(
                (str(_workspace_path(path, label="approved deletion target")), digest)
                for path, digest in receipt.approved_target_sha256
            ),
        ),
    }
    internal = DeletionGateReceipt(
        **unsigned, binding_sha256=receipt.pre_action_binding_sha256
    )
    _validate_deletion_receipt(internal)
    return internal


def _load_gate_for_reconstruction(receipt_path: Path) -> tuple[DeletionGateReceipt, bool]:
    """Read either the old private publication or the current public projection."""

    payload = _load_object(receipt_path, label="persisted deletion receipt")
    if payload.get("schema_version") == _DELETION_VERSION:
        return _internal_receipt_from_payload(payload), True
    public = _load_public_gate_receipt(receipt_path)
    return _internal_receipt_from_public(public), False


def _find_reconstructable_quarantine(target: Path, expected_sha256: str) -> QuarantineTargetReceipt:
    parent = _assert_regular_tree(target.parent, label="legacy parent")
    matches: list[Path] = []
    for candidate in parent.iterdir():
        try:
            entry = candidate.lstat()
        except OSError as exc:
            raise ValueError("quarantine parent cannot be inspected") from exc
        if not candidate.name.startswith(".secmind-quarantine-") or stat.S_ISLNK(entry.st_mode):
            continue
        if not stat.S_ISDIR(entry.st_mode):
            continue
        checked = _assert_regular_tree(candidate, label="quarantined legacy target")
        if _tree_digest(checked) == expected_sha256:
            matches.append(checked)
    if len(matches) != 1:
        raise ValueError("existing quarantine reconstruction is ambiguous")
    quarantine = matches[0]
    observed = quarantine.stat()
    return QuarantineTargetReceipt(
        original_path=_workspace_relative(target, label="quarantine original"),
        quarantine_path=_workspace_relative(quarantine, label="quarantine path"),
        device=observed.st_dev,
        inode=observed.st_ino,
        tree_sha256=expected_sha256,
    )


def reconstruct_existing_quarantine(*, receipt_path: Path, active_secret: str) -> QuarantineReceipt:
    """Durably reconstruct only the approved, already-moved two-target state.

    This deliberately never renames, restores, deletes, or otherwise changes
    legacy bytes.  It is limited to the historical crash window where both
    closed-allowlist originals are absent and no durable locator exists.
    """

    secret = _require_active_secret(active_secret)
    internal, legacy_publication = _load_gate_for_reconstruction(receipt_path)
    delivery = _assert_regular_tree(Path(internal.delivery_root), label="delivery root")
    if receipt_path.resolve(strict=True) != (delivery / _RECEIPT_NAME).resolve(strict=True):
        raise ValueError("deletion receipt path is not fixed")
    targets = _allowed_legacy_targets()
    if any(target.exists() or target.is_symlink() for target in targets):
        raise ValueError("existing quarantine reconstruction requires exactly two missing originals")
    if legacy_publication:
        _atomic_replace_json(receipt_path, _public_gate_receipt(internal).to_dict())
    else:
        public = _load_public_gate_receipt(receipt_path)
        if public.to_dict() != _public_gate_receipt(internal).to_dict():
            raise ValueError("public deletion receipt does not bind the pre-action gate")
    local_path = _quarantine_receipt_path()
    if local_path.exists() or local_path.is_symlink():
        existing = _load_quarantine_receipt(local_path, verify_live_paths=True)
        if existing.gate_binding_sha256 != internal.binding_sha256:
            raise ValueError("existing quarantine receipt binds a different gate")
        return existing
    digests = dict(internal.approved_target_sha256)
    reconstructed_targets = tuple(
        _find_reconstructable_quarantine(target, digests[str(target.resolve())]) for target in targets
    )
    unsigned = {
        "schema_version": _QUARANTINE_VERSION,
        "gate_binding_sha256": internal.binding_sha256,
        "targets": [asdict(item) for item in reconstructed_targets],
    }
    reconstructed = QuarantineReceipt(
        schema_version=_QUARANTINE_VERSION,
        gate_binding_sha256=internal.binding_sha256,
        targets=cast(tuple[QuarantineTargetReceipt, QuarantineTargetReceipt], reconstructed_targets),
        binding_sha256=_canonical_sha256(unsigned),
    )
    _write_quarantine_receipt(reconstructed, active_secret=secret)
    return reconstructed


def write_quarantine_finalization(
    *, receipt_path: Path, quarantine_receipt: QuarantineReceipt, active_secret: str
) -> Path:
    """Bind the public gate, durable locator, source inventory, and sealed score."""

    secret = _require_active_secret(active_secret)
    public = _load_public_gate_receipt(receipt_path)
    internal = _internal_receipt_from_public(public)
    delivery = _assert_regular_tree(Path(internal.delivery_root), label="delivery root")
    if receipt_path.resolve(strict=True) != (delivery / _RECEIPT_NAME).resolve(strict=True):
        raise ValueError("deletion receipt path is not fixed")
    _validate_quarantine_receipt(quarantine_receipt, verify_live_paths=True)
    if quarantine_receipt.gate_binding_sha256 != internal.binding_sha256:
        raise ValueError("quarantine receipt binds a different gate")
    local_path = _quarantine_receipt_path()
    if _load_quarantine_receipt(local_path, verify_live_paths=True).to_dict() != quarantine_receipt.to_dict():
        raise ValueError("persisted quarantine receipt does not match")
    source_inventory = _load_object(delivery / "artifact-inventory.json", label="artifact inventory")
    scoring = _load_object(delivery / "scoring-receipt.json", label="scoring receipt")
    if source_inventory.get("artifact_count") != 336 or scoring.get("receipt_sha256") != internal.scoring_receipt_sha256:
        raise ValueError("delivery core receipts are invalid")
    core_sha256 = _tree_digest(delivery, exclude=frozenset({_RECEIPT_NAME, _FINALIZATION_RECEIPT_NAME}))
    if core_sha256 != internal.delivery_sha256:
        raise ValueError("delivery core changed after deletion gate")
    unsigned: dict[str, Any] = {
        "schema_version": _FINALIZATION_VERSION,
        "gate_receipt_path": _workspace_relative(receipt_path, label="gate receipt path"),
        "gate_public_binding_sha256": public.public_binding_sha256,
        "gate_receipt_sha256": _file_sha256(receipt_path),
        "quarantine_receipt_path": _workspace_relative(local_path, label="quarantine receipt path"),
        "quarantine_receipt_binding_sha256": quarantine_receipt.binding_sha256,
        "quarantine_receipt_sha256": _file_sha256(local_path),
        "source_inventory_sha256": _file_sha256(delivery / "artifact-inventory.json"),
        "scoring_receipt_sha256": _file_sha256(delivery / "scoring-receipt.json"),
        "pre_quarantine_core_delivery_sha256": public.delivery_sha256,
        "core_delivery_sha256": core_sha256,
        "previous_finalization_binding_sha256": None,
    }
    final = QuarantineFinalizationReceipt(
        **unsigned, binding_sha256=_canonical_sha256(unsigned)
    )
    path = delivery / _FINALIZATION_RECEIPT_NAME
    if path.exists() or path.is_symlink():
        # The first finalized delivery used v1.0 before exact receipt-byte
        # bindings existed.  Only that closed historical shape may be upgraded.
        existing = _load_object(path, label="existing finalization receipt")
        if existing.get("schema_version") != "1.0":
            raise ValueError("finalization receipt path is unsafe")
        _atomic_replace_json(path, final.to_dict())
    else:
        _atomic_create_json(path, final.to_dict())
    try:
        _scan_exact_secret_tree(delivery, active_secret=secret)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


def refresh_quarantine_finalization(*, receipt_path: Path, active_secret: str) -> Path:
    """Rebind a post-quarantine presentation correction without replacing its gate.

    The public gate and the durable quarantine locator are immutable records of
    the pre-action state.  This narrowly scoped operation only replaces the
    finalization receipt after proving those records and the sealed scoring
    artifacts are unchanged; it is intentionally unable to rewrite either
    pre-action receipt.
    """

    secret = _require_active_secret(active_secret)
    public = _load_public_gate_receipt(receipt_path)
    internal = _internal_receipt_from_public(public)
    delivery = _assert_regular_tree(Path(internal.delivery_root), label="delivery root")
    if receipt_path.resolve(strict=True) != (delivery / _RECEIPT_NAME).resolve(strict=True):
        raise ValueError("deletion receipt path is not fixed")
    local_path = _quarantine_receipt_path()
    quarantine = _load_quarantine_receipt(local_path, verify_live_paths=True)
    if quarantine.gate_binding_sha256 != internal.binding_sha256:
        raise ValueError("quarantine receipt binds a different gate")
    source_inventory = _load_object(delivery / "artifact-inventory.json", label="artifact inventory")
    scoring = _load_object(delivery / "scoring-receipt.json", label="scoring receipt")
    if source_inventory.get("artifact_count") != 336 or scoring.get("receipt_sha256") != internal.scoring_receipt_sha256:
        raise ValueError("delivery core receipts are invalid")
    path = delivery / _FINALIZATION_RECEIPT_NAME
    previous = _load_object(path, label="existing finalization receipt")
    version = previous.get("schema_version")
    if version == "2.0":
        legacy_fields = {
            "schema_version",
            "gate_receipt_path",
            "gate_public_binding_sha256",
            "gate_receipt_sha256",
            "quarantine_receipt_path",
            "quarantine_receipt_binding_sha256",
            "quarantine_receipt_sha256",
            "source_inventory_sha256",
            "scoring_receipt_sha256",
            "core_delivery_sha256",
            "binding_sha256",
        }
        if set(previous) != legacy_fields or any(not isinstance(value, str) for value in previous.values()):
            raise ValueError("existing finalization receipt is invalid")
        unsigned_previous = {key: value for key, value in previous.items() if key != "binding_sha256"}
        if (
            _canonical_sha256(unsigned_previous) != previous["binding_sha256"]
            or previous["core_delivery_sha256"] != public.delivery_sha256
        ):
            raise ValueError("existing finalization receipt is invalid")
    elif version == _FINALIZATION_VERSION:
        _require_closed_fields(
            previous, frozenset(QuarantineFinalizationReceipt.__dataclass_fields__), label="existing finalization receipt"
        )
        if any(not isinstance(value, str) for key, value in previous.items() if key != "previous_finalization_binding_sha256"):
            raise ValueError("existing finalization receipt is invalid")
        if previous.get("previous_finalization_binding_sha256") is not None and not isinstance(
            previous.get("previous_finalization_binding_sha256"), str
        ):
            raise ValueError("existing finalization receipt is invalid")
        unsigned_previous = {key: value for key, value in previous.items() if key != "binding_sha256"}
        if (
            _canonical_sha256(unsigned_previous) != previous["binding_sha256"]
            or previous.get("pre_quarantine_core_delivery_sha256") != public.delivery_sha256
        ):
            raise ValueError("existing finalization receipt is invalid")
    else:
        raise ValueError("existing finalization receipt is invalid")
    expected_static = {
        "gate_receipt_path": _workspace_relative(receipt_path, label="gate receipt path"),
        "gate_public_binding_sha256": public.public_binding_sha256,
        "gate_receipt_sha256": _file_sha256(receipt_path),
        "quarantine_receipt_path": _workspace_relative(local_path, label="quarantine receipt path"),
        "quarantine_receipt_binding_sha256": quarantine.binding_sha256,
        "quarantine_receipt_sha256": _file_sha256(local_path),
        "source_inventory_sha256": _file_sha256(delivery / "artifact-inventory.json"),
        "scoring_receipt_sha256": _file_sha256(delivery / "scoring-receipt.json"),
    }
    if any(previous.get(key) != value for key, value in expected_static.items()):
        raise ValueError("existing finalization receipt is not bound to immutable delivery facts")
    _scan_exact_secret_tree(delivery, active_secret=secret)
    core_sha256 = _tree_digest(delivery, exclude=frozenset({_RECEIPT_NAME, _FINALIZATION_RECEIPT_NAME}))
    unsigned = {
        "schema_version": _FINALIZATION_VERSION,
        **expected_static,
        "pre_quarantine_core_delivery_sha256": public.delivery_sha256,
        "core_delivery_sha256": core_sha256,
        "previous_finalization_binding_sha256": previous["binding_sha256"],
    }
    final = QuarantineFinalizationReceipt(**unsigned, binding_sha256=_canonical_sha256(unsigned))
    _atomic_replace_json(path, final.to_dict())
    return path


def _load_quarantine_finalization_receipt(path: Path, *, delivery: Path) -> QuarantineFinalizationReceipt:
    payload = _load_object(path, label="quarantine finalization receipt")
    _require_closed_fields(
        payload, frozenset(QuarantineFinalizationReceipt.__dataclass_fields__), label="quarantine finalization receipt"
    )
    if any(not isinstance(value, str) for key, value in payload.items() if key != "previous_finalization_binding_sha256"):
        raise ValueError("quarantine finalization receipt schema is invalid")
    if payload.get("previous_finalization_binding_sha256") is not None and not isinstance(
        payload.get("previous_finalization_binding_sha256"), str
    ):
        raise ValueError("quarantine finalization receipt schema is invalid")
    try:
        receipt = QuarantineFinalizationReceipt(**payload)
    except TypeError as exc:
        raise ValueError("quarantine finalization receipt schema is invalid") from exc
    if receipt.schema_version != _FINALIZATION_VERSION or _canonical_sha256(receipt.unsigned_payload()) != receipt.binding_sha256:
        raise ValueError("quarantine finalization receipt binding is invalid")
    if not all(
        _is_sha256(value)
        for value in (
            receipt.gate_public_binding_sha256,
            receipt.gate_receipt_sha256,
            receipt.quarantine_receipt_binding_sha256,
            receipt.quarantine_receipt_sha256,
            receipt.source_inventory_sha256,
            receipt.scoring_receipt_sha256,
            receipt.pre_quarantine_core_delivery_sha256,
            receipt.core_delivery_sha256,
            receipt.binding_sha256,
        )
    ):
        raise ValueError("quarantine finalization receipt digest shape is invalid")
    expected_gate = delivery / _RECEIPT_NAME
    expected_local = _quarantine_receipt_path()
    if (
        receipt.gate_receipt_path != _workspace_relative(expected_gate, label="gate receipt path")
        or receipt.quarantine_receipt_path != _workspace_relative(expected_local, label="quarantine receipt path")
        or not expected_gate.is_file()
        or not expected_local.is_file()
    ):
        raise ValueError("quarantine finalization receipt paths are invalid")
    public = _load_public_gate_receipt(expected_gate)
    quarantine = _load_quarantine_receipt(expected_local, verify_live_paths=True)
    core = _tree_digest(delivery, exclude=frozenset({_RECEIPT_NAME, _FINALIZATION_RECEIPT_NAME}))
    if (
        receipt.gate_public_binding_sha256 != public.public_binding_sha256
        or receipt.gate_receipt_sha256 != _file_sha256(expected_gate)
        or receipt.quarantine_receipt_binding_sha256 != quarantine.binding_sha256
        or receipt.quarantine_receipt_sha256 != _file_sha256(expected_local)
        or quarantine.gate_binding_sha256 != public.pre_action_binding_sha256
        or receipt.source_inventory_sha256 != _file_sha256(delivery / "artifact-inventory.json")
        or receipt.scoring_receipt_sha256 != _file_sha256(delivery / "scoring-receipt.json")
        or receipt.pre_quarantine_core_delivery_sha256 != public.delivery_sha256
        or receipt.core_delivery_sha256 != core
        or (
            receipt.previous_finalization_binding_sha256 is not None
            and not _is_sha256(receipt.previous_finalization_binding_sha256)
        )
    ):
        raise ValueError("quarantine finalization receipt does not bind finalized delivery state")
    return receipt


def delete_approved_legacy_artifacts(
    receipt: DeletionGateReceipt,
    *,
    receipt_path: Path,
    active_secret: str,
) -> QuarantineReceipt:
    """Deprecated compatibility alias; this performs recoverable quarantine only."""

    return quarantine_approved_legacy_artifacts(receipt, receipt_path=receipt_path, active_secret=active_secret)


__all__ = [
    "DeletionGateReceipt",
    "OverviewResult",
    "PublicDeletionGateReceipt",
    "QuarantineRecoveryError",
    "QuarantineReceipt",
    "QuarantineFinalizationReceipt",
    "ScoringReceipt",
    "build_deletion_gate_receipt",
    "delete_approved_legacy_artifacts",
    "quarantine_approved_legacy_artifacts",
    "refresh_quarantine_finalization",
    "reconstruct_existing_quarantine",
    "render_api_overview",
    "write_deletion_gate_receipt",
    "write_quarantine_finalization",
]
