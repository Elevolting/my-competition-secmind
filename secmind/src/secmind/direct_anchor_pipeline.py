"""Direct Anchor and append-only gain pipeline primitives.

The v0.8.2 product path has one deliberately narrow authority boundary:

``provider receipt -> sealed Anchor -> candidate store -> correlation ->
typed delta -> one adjudicator -> enhanced projection``.

This module is intentionally independent from the LangGraph orchestrator.  It
contains only deterministic data structures and policy helpers, which makes
replay and focused tests possible without another model call.  The older
projection and gate APIs remain available for compatibility; the orchestrator
opts into these primitives explicitly.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from secmind.schemas import AgentState, Evidence, Finding
from secmind.tool_assurance import verified_semantic_assurance

DIRECT_ANCHOR_PIPELINE_VERSION = "secmind-direct-anchor-gain-v1"
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_CWE_RE = re.compile(r"(?:CWE[-_ ]?)?(\d+)$", re.IGNORECASE)
_RELATED_CWE_FAMILIES = (
    frozenset({22, 23}),
    frozenset({77, 78}),
    frozenset({89, 564}),
    frozenset({94, 95}),
    frozenset({330, 337}),
    # CWE-840 is the broad business-logic category, CWE-841 is the precise
    # workflow-enforcement weakness, and CWE-602 captures the same trust flaw
    # from the client-side-enforcement perspective.  They are related labels,
    # not independent findings at one source location.
    frozenset({602, 693, 840, 841}),
)
_SEMANTIC_ASSURANCE = {"semantically_corroborated", "human_confirmed"}


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    return value


def stable_digest(value: Any) -> str:
    """Return the canonical digest used by all append-only identities."""

    return hashlib.sha256(
        json.dumps(_jsonable(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def valid_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.fullmatch(value))


def normalize_path(value: str) -> str:
    """Normalize a repository-relative path without resolving it on disk."""

    normalized = unicodedata.normalize("NFC", (value or ".").replace("\\", "/"))
    return PurePosixPath(normalized).as_posix().casefold()


def cwe_number(rule_id: str) -> int | None:
    match = _CWE_RE.search(rule_id.strip())
    return int(match.group(1)) if match else None


def cwe_family(rule_id: str) -> str:
    number = cwe_number(rule_id)
    if number is None:
        return rule_id.strip().casefold() or "unknown"
    for family in _RELATED_CWE_FAMILIES:
        if number in family:
            return "cwe-" + "-".join(str(item) for item in sorted(family))
    return f"cwe-{number}"


class CandidateState(StrEnum):
    PROPOSED = "proposed"
    CLUSTERED = "clustered"
    CORROBORATED = "corroborated"
    SHADOW = "shadow"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    QUARANTINED = "quarantined"


class DeltaAction(StrEnum):
    ADD = "added"
    CORRECT = "corrected"
    SUPPLEMENT = "supplement"
    REPLACE_FIELD = "replace_field"
    RETRACT = "retract"


class DeltaDisposition(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    QUARANTINED = "quarantined"
    SHADOW = "shadow"


class CandidateTransition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(ge=1)
    from_state: CandidateState | None = None
    to_state: CandidateState
    reason_code: str = Field(min_length=1, max_length=120)
    cluster_id: str | None = None
    policy_version: str = DIRECT_ANCHOR_PIPELINE_VERSION


@dataclass(frozen=True, slots=True)
class SemanticClusterKey:
    """The semantic identity used before gain/admission decisions."""

    cwe_family: str
    normalized_path: str
    line_window: tuple[int | None, int | None]
    sink: str
    dataflow: str

    @property
    def digest(self) -> str:
        return stable_digest(
            {
                "cwe_family": self.cwe_family,
                "normalized_path": self.normalized_path,
                "line_window": self.line_window,
                "sink": self.sink,
                "dataflow": self.dataflow,
            }
        )


class CandidateRecord(BaseModel):
    """One immutable version of a candidate's current state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    finding: Finding
    producer_ids: tuple[str, ...] = Field(default_factory=tuple)
    cwe_family: str
    normalized_path: str
    line_window: tuple[int | None, int | None]
    sink: str = ""
    dataflow: str = ""
    file_sha256: str | None = None
    rule_digest: str | None = None
    cluster_id: str | None = None
    state: CandidateState = CandidateState.PROPOSED
    version: int = Field(default=1, ge=1)
    transitions: tuple[CandidateTransition, ...] = Field(default_factory=tuple)
    content_digest: str = Field(min_length=64, max_length=64)


@dataclass(frozen=True, slots=True)
class CandidateCluster:
    cluster_id: str
    key: SemanticClusterKey
    records: tuple[CandidateRecord, ...]
    representative: Finding
    producer_ids: tuple[str, ...]

    @property
    def candidate_ids(self) -> tuple[str, ...]:
        return tuple(item.candidate_id for item in self.records)


class TypedDelta(BaseModel):
    """A typed, auditable change request; it is not itself a publication."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    delta_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    cluster_id: str = Field(min_length=1)
    candidate_ids: tuple[str, ...] = Field(min_length=1)
    action: DeltaAction
    disposition: DeltaDisposition
    target_finding_id: str | None = None
    finding: Finding | None = None
    evidence_ids: tuple[str, ...] = Field(default_factory=tuple)
    producer_ids: tuple[str, ...] = Field(default_factory=tuple)
    reason_code: str = Field(min_length=1, max_length=160)
    evidence_complete: bool = False
    semantic_checks: dict[str, bool] = Field(default_factory=dict)
    admission_ready: bool = False
    anchor_semantic_digest: str = Field(min_length=64, max_length=64)
    gate_digest: str = Field(min_length=64, max_length=64)
    policy_version: str = DIRECT_ANCHOR_PIPELINE_VERSION

    @property
    def accepted(self) -> bool:
        return self.disposition == DeltaDisposition.ACCEPTED


class AnchorReport(BaseModel):
    """Frozen report projection of the provider response.

    The raw receipt fields are retained alongside the projected findings.  A
    gain failure can therefore only change the Enhanced report, never this
    object or the bytes represented by ``response_artifact_id``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    receipt_id: str
    request_sha256: str
    response_sha256: str
    response_schema_sha256: str
    prompt_version: str
    prompt_artifact_id: str | None = None
    context_sha256: str
    response_artifact_id: str
    raw_response_sha256: str
    findings: tuple[Finding, ...] = Field(default_factory=tuple)
    evidence: tuple[Evidence, ...] = Field(default_factory=tuple)
    limitations: tuple[str, ...] = Field(default_factory=tuple)
    coverage: dict[str, Any] = Field(default_factory=dict)
    semantic_digest: str
    sealed: bool = True

    @property
    def report_digest(self) -> str:
        return stable_digest(
            {
                "run_id": self.run_id,
                "receipt_id": self.receipt_id,
                "request_sha256": self.request_sha256,
                "response_sha256": self.response_sha256,
                "response_schema_sha256": self.response_schema_sha256,
                "prompt_version": self.prompt_version,
                "prompt_artifact_id": self.prompt_artifact_id,
                "context_sha256": self.context_sha256,
                "response_artifact_id": self.response_artifact_id,
                "raw_response_sha256": self.raw_response_sha256,
                "findings": self.findings,
                "evidence": self.evidence,
                "limitations": self.limitations,
                "coverage": self.coverage,
                "semantic_digest": self.semantic_digest,
            }
        )


class EnhancedReport(BaseModel):
    """Auditable Anchor-plus-delta view produced after unified adjudication."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    anchor_report_digest: str
    anchor_semantic_digest: str
    findings: tuple[Finding, ...] = Field(default_factory=tuple)
    evidence: tuple[Evidence, ...] = Field(default_factory=tuple)
    deltas: tuple[TypedDelta, ...] = Field(default_factory=tuple)
    added_delta_ids: tuple[str, ...] = Field(default_factory=tuple)
    corrected_delta_ids: tuple[str, ...] = Field(default_factory=tuple)
    rejected_delta_ids: tuple[str, ...] = Field(default_factory=tuple)
    quarantined_delta_ids: tuple[str, ...] = Field(default_factory=tuple)
    precision_gate_met: bool = False
    publishable: bool = False
    anchor_preserved: bool = True
    coverage: dict[str, Any] = Field(default_factory=dict)


def _raw_value(finding: Finding, evidence_by_id: Mapping[str, Evidence], *keys: str) -> str:
    def normalized(value: object) -> str:
        if isinstance(value, str):
            return value.strip()
        if isinstance(value, (list, tuple)):
            parts = [item.strip() for item in value[:16] if isinstance(item, str) and item.strip()]
            return " -> ".join(parts)
        return ""

    for key in keys:
        value = normalized(finding.raw.get(key))
        if value:
            return value
    for evidence_id in finding.evidence_ids:
        evidence = evidence_by_id.get(evidence_id)
        if evidence is None:
            continue
        for key in keys:
            value = normalized(evidence.metadata.get(key))
            if value:
                return value
    return ""


def semantic_cluster_key(finding: Finding, evidence_by_id: Mapping[str, Evidence]) -> SemanticClusterKey:
    line = finding.line
    return SemanticClusterKey(
        cwe_family=cwe_family(finding.rule_id),
        normalized_path=normalize_path(finding.path),
        line_window=(line, line),
        sink=_raw_value(finding, evidence_by_id, "sink", "sink_symbol", "sink_name"),
        dataflow=_raw_value(finding, evidence_by_id, "data_flow", "dataflow", "flow_id", "source_to_sink"),
    )


def _producer_ids(finding: Finding, evidence_by_id: Mapping[str, Evidence]) -> tuple[str, ...]:
    # Producer independence is evidence-bound.  A scanner's own
    # ``corroborated_by_tools`` claim is deliberately not trusted as a second
    # producer, otherwise one tool could manufacture a rescue by relabeling
    # its metadata.
    producers: set[str] = set()
    for key in ("producer", "producer_id", "tool_name", "source"):
        value = finding.raw.get(key)
        if isinstance(value, str) and value.strip():
            producers.add(value.strip())
    evidence_sources: set[str] = set()
    for evidence_id in finding.evidence_ids:
        evidence = evidence_by_id.get(evidence_id)
        if evidence is None:
            continue
        for key in ("producer", "producer_id", "tool_name"):
            value = evidence.metadata.get(key)
            if isinstance(value, str) and value.strip():
                producers.add(value.strip())
        if evidence.source:
            evidence_sources.add(evidence.source)
    if not producers:
        producers.update(evidence_sources)
    return tuple(sorted(producers))


def _metadata_digest(finding: Finding, evidence_by_id: Mapping[str, Evidence], *keys: str) -> str | None:
    values: list[str] = []
    for key in keys:
        value = finding.raw.get(key)
        if isinstance(value, str) and valid_sha256(value):
            values.append(value.lower())
    for evidence_id in finding.evidence_ids:
        evidence = evidence_by_id.get(evidence_id)
        if evidence is None:
            continue
        for key in keys:
            value = evidence.metadata.get(key)
            if isinstance(value, str) and valid_sha256(value):
                values.append(value.lower())
            if key == "file_sha256" and isinstance(evidence.sha256, str) and valid_sha256(evidence.sha256):
                values.append(evidence.sha256.lower())
    return sorted(set(values))[0] if values else None


def _candidate_content_digest(
    finding: Finding,
    producer_ids: tuple[str, ...],
    key: SemanticClusterKey,
    file_sha256: str | None,
    rule_digest: str | None,
) -> str:
    return stable_digest(
        {
            "finding": finding,
            "producer_ids": producer_ids,
            "cluster_key": {
                "cwe_family": key.cwe_family,
                "normalized_path": key.normalized_path,
                "line_window": key.line_window,
                "sink": key.sink,
                "dataflow": key.dataflow,
            },
            "file_sha256": file_sha256,
            "rule_digest": rule_digest,
        }
    )


class CandidateStore:
    """Append-only candidate lifecycle with deterministic replay."""

    def __init__(
        self,
        run_id: str,
        records: Iterable[CandidateRecord] = (),
        events: Iterable[Mapping[str, Any]] = (),
    ) -> None:
        self.run_id = run_id
        self._records: dict[str, CandidateRecord] = {}
        self._events: list[dict[str, Any]] = []
        for record in records:
            self.append(record)
        self._events.extend(dict(item) for item in events)

    @classmethod
    def from_state(cls, state: AgentState) -> CandidateStore:
        payload = state.audit_coverage.get("candidate_store", {})
        if not isinstance(payload, Mapping):
            return cls(state.run_id)
        records: list[CandidateRecord] = []
        for raw in payload.get("records", []):
            try:
                records.append(CandidateRecord.model_validate(raw))
            except (TypeError, ValueError):
                continue
        events = payload.get("events", [])
        return cls(state.run_id, records, events if isinstance(events, list) else ())

    def append(self, record: CandidateRecord) -> CandidateRecord:
        if record.run_id != self.run_id:
            raise ValueError("candidate belongs to another run")
        existing = self._records.get(record.candidate_id)
        if existing is not None:
            if existing.content_digest != record.content_digest or record.version < existing.version:
                raise ValueError("candidate store is append-only and cannot overwrite a candidate version")
            if record.version == existing.version:
                return existing
        self._records[record.candidate_id] = record
        return record

    def register(
        self,
        finding: Finding,
        evidence_by_id: Mapping[str, Evidence],
        *,
        producer_id: str | None = None,
    ) -> CandidateRecord:
        key = semantic_cluster_key(finding, evidence_by_id)
        producer_ids = set(_producer_ids(finding, evidence_by_id))
        if producer_id:
            producer_ids.add(producer_id)
        normalized_producers = tuple(sorted(producer_ids or {"unknown-producer"}))
        file_sha256 = _metadata_digest(finding, evidence_by_id, "file_sha256", "source_sha256")
        rule_digest = _metadata_digest(finding, evidence_by_id, "rule_digest", "rule_bundle_digest")
        content_digest = _candidate_content_digest(
            finding,
            normalized_producers,
            key,
            file_sha256,
            rule_digest,
        )
        candidate_id = f"candidate-{stable_digest({'finding_id': finding.finding_id, 'content': content_digest})[:32]}"
        existing = self._records.get(candidate_id)
        if existing is not None:
            return existing
        initial = CandidateTransition(
            version=1,
            from_state=None,
            to_state=CandidateState.PROPOSED,
            reason_code="candidate_registered",
        )
        record = CandidateRecord(
            candidate_id=candidate_id,
            run_id=self.run_id,
            finding=finding.model_copy(deep=True),
            producer_ids=normalized_producers,
            cwe_family=key.cwe_family,
            normalized_path=key.normalized_path,
            line_window=key.line_window,
            sink=key.sink,
            dataflow=key.dataflow,
            file_sha256=file_sha256,
            rule_digest=rule_digest,
            transitions=(initial,),
            content_digest=content_digest,
        )
        self._events.append({"event": "registered", "candidate_id": candidate_id, "version": 1})
        return self.append(record)

    def transition(
        self,
        candidate_id: str,
        to_state: CandidateState,
        reason_code: str,
        *,
        cluster_id: str | None = None,
    ) -> CandidateRecord:
        current = self._records[candidate_id]
        if current.state == to_state and current.cluster_id == cluster_id:
            return current
        transition = CandidateTransition(
            version=current.version + 1,
            from_state=current.state,
            to_state=to_state,
            reason_code=reason_code,
            cluster_id=cluster_id or current.cluster_id,
        )
        updated = current.model_copy(
            update={
                "state": to_state,
                "cluster_id": cluster_id or current.cluster_id,
                "version": transition.version,
                "transitions": (*current.transitions, transition),
            }
        )
        self._records[candidate_id] = updated
        self._events.append(
            {
                "event": "transition",
                "candidate_id": candidate_id,
                "from_state": current.state.value,
                "to_state": to_state.value,
                "reason_code": reason_code,
                "version": updated.version,
                "cluster_id": updated.cluster_id,
            }
        )
        return updated

    def quarantine(self, candidate_id: str, reason_code: str = "quarantined_by_adjudicator") -> CandidateRecord:
        """Append a quarantine transition without removing the candidate."""

        return self.transition(candidate_id, CandidateState.QUARANTINED, reason_code)

    def add(
        self,
        finding: Finding,
        evidence_by_id: Mapping[str, Evidence],
        *,
        producer_id: str | None = None,
    ) -> CandidateRecord:
        """Compatibility alias emphasizing that registration is append-only."""

        return self.register(finding, evidence_by_id, producer_id=producer_id)

    def records(self) -> tuple[CandidateRecord, ...]:
        return tuple(sorted(self._records.values(), key=lambda item: item.candidate_id))

    def events(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(item) for item in self._events)

    def quarantined(self) -> tuple[CandidateRecord, ...]:
        return tuple(item for item in self.records() if item.state == CandidateState.QUARANTINED)

    def replay(self) -> tuple[CandidateRecord, ...]:
        """Return every current record, including quarantined records."""

        return self.records()

    def correlate(self) -> tuple[CandidateCluster, ...]:
        records = list(self.records())
        if not records:
            return ()
        components: list[list[CandidateRecord]] = []
        unseen = {item.candidate_id for item in records}
        by_id = {item.candidate_id: item for item in records}
        while unseen:
            seed_id = min(unseen)
            unseen.remove(seed_id)
            component_ids = [seed_id]
            frontier = [seed_id]
            while frontier:
                current = by_id[frontier.pop()]
                related = [
                    candidate_id for candidate_id in sorted(unseen) if self._related(current, by_id[candidate_id])
                ]
                for candidate_id in related:
                    unseen.remove(candidate_id)
                    frontier.append(candidate_id)
                    component_ids.append(candidate_id)
            components.append([by_id[candidate_id] for candidate_id in sorted(component_ids)])

        result: list[CandidateCluster] = []
        for component in components:
            key = self._cluster_key(component)
            cluster_payload = {
                "key": key.digest,
                "candidate_ids": [item.candidate_id for item in component],
            }
            cluster_id = f"cluster-{stable_digest(cluster_payload)[:32]}"
            clustered: list[CandidateRecord] = []
            for item in component:
                clustered.append(
                    self.transition(
                        item.candidate_id,
                        CandidateState.CLUSTERED,
                        "semantic_clustered",
                        cluster_id=cluster_id,
                    )
                )
            representative = self._representative(clustered, cluster_id)
            producers = tuple(sorted({producer for item in clustered for producer in item.producer_ids}))
            result.append(
                CandidateCluster(
                    cluster_id=cluster_id,
                    key=key,
                    records=tuple(clustered),
                    representative=representative,
                    producer_ids=producers,
                )
            )
        return tuple(sorted(result, key=lambda item: item.cluster_id))

    @staticmethod
    def _related(left: CandidateRecord, right: CandidateRecord) -> bool:
        if left.normalized_path != right.normalized_path or left.cwe_family != right.cwe_family:
            return False
        left_line = left.line_window[0]
        right_line = right.line_window[0]
        if left_line is not None and right_line is not None and abs(left_line - right_line) > 5:
            return False
        if left.sink and right.sink and left.sink.casefold() != right.sink.casefold():
            return False
        if left.dataflow and right.dataflow:
            left_tokens = set(re.findall(r"[a-z0-9_.$:-]+", left.dataflow.casefold()))
            right_tokens = set(re.findall(r"[a-z0-9_.$:-]+", right.dataflow.casefold()))
            if left_tokens and right_tokens and not left_tokens.intersection(right_tokens):
                return False
        return True

    @staticmethod
    def _cluster_key(records: list[CandidateRecord]) -> SemanticClusterKey:
        line_values = [item.line_window[0] for item in records if item.line_window[0] is not None]
        return SemanticClusterKey(
            cwe_family=records[0].cwe_family,
            normalized_path=records[0].normalized_path,
            line_window=(min(line_values) if line_values else None, max(line_values) if line_values else None),
            sink=next((item.sink for item in records if item.sink), ""),
            dataflow=next((item.dataflow for item in records if item.dataflow), ""),
        )

    @staticmethod
    def _representative(records: list[CandidateRecord], cluster_id: str) -> Finding:
        selected = min(
            records,
            key=lambda item: (
                -int(item.state == CandidateState.CORROBORATED),
                -int(str(item.finding.raw.get("assurance_level", "")) in _SEMANTIC_ASSURANCE),
                -int(bool(item.file_sha256)),
                -int(bool(item.rule_digest)),
                -len(item.producer_ids),
                item.candidate_id,
            ),
        ).finding
        evidence_ids = sorted({evidence_id for item in records for evidence_id in item.finding.evidence_ids})
        producer_ids = sorted({producer for item in records for producer in item.producer_ids})
        raw = {
            **selected.raw,
            "candidate_cluster_id": cluster_id,
            "candidate_ids": [item.candidate_id for item in records],
            "producer_ids": producer_ids,
            "correlation_stage": "before_gain_gate",
        }
        return selected.model_copy(
            deep=True,
            update={"evidence_ids": evidence_ids, "raw": raw},
        )

    def persist(self, state: AgentState) -> str:
        payload = {
            "version": DIRECT_ANCHOR_PIPELINE_VERSION,
            "run_id": self.run_id,
            "records": [item.model_dump(mode="json") for item in self.records()],
            "events": list(self.events()),
            "quarantined_candidate_ids": [item.candidate_id for item in self.quarantined()],
        }
        payload["store_digest"] = stable_digest(payload)
        state.audit_coverage["candidate_store"] = payload
        return str(payload["store_digest"])


def evidence_semantic_checks(
    finding: Finding,
    evidence_by_id: Mapping[str, Evidence],
) -> dict[str, bool]:
    evidence = [evidence_by_id.get(item) for item in finding.evidence_ids]
    evidence_complete = bool(finding.evidence_ids) and all(item is not None for item in evidence)
    assurance = str(finding.raw.get("assurance_level", ""))
    if assurance not in _SEMANTIC_ASSURANCE:
        assurance = next(
            (
                str(item.metadata.get("assurance_level", ""))
                for item in evidence
                if item is not None and str(item.metadata.get("assurance_level", "")) in _SEMANTIC_ASSURANCE
            ),
            "",
        )
    semantic = assurance in _SEMANTIC_ASSURANCE or any(
        item is not None and verified_semantic_assurance(item.metadata) for item in evidence
    )
    file_sha = _metadata_digest(finding, evidence_by_id, "file_sha256", "source_sha256")
    rule_digest = _metadata_digest(finding, evidence_by_id, "rule_digest", "rule_bundle_digest")
    return {
        "evidence_complete": evidence_complete,
        "path_complete": bool(finding.path and finding.path != "."),
        "line_complete": isinstance(finding.line, int) and finding.line >= 1,
        "file_sha256_complete": valid_sha256(file_sha),
        "rule_digest_complete": valid_sha256(rule_digest),
        "sink_or_dataflow_present": bool(
            _raw_value(finding, evidence_by_id, "sink", "sink_symbol", "sink_name")
            or _raw_value(finding, evidence_by_id, "data_flow", "dataflow", "source_to_sink")
        ),
        "semantic_assurance": semantic,
    }


def high_specificity_complete(finding: Finding, evidence_by_id: Mapping[str, Evidence]) -> bool:
    checks = evidence_semantic_checks(finding, evidence_by_id)
    return all(
        checks[key]
        for key in (
            "evidence_complete",
            "path_complete",
            "line_complete",
            "file_sha256_complete",
            "rule_digest_complete",
            "sink_or_dataflow_present",
            "semantic_assurance",
        )
    )


def _anchor_digest(findings: Iterable[Finding], evidence: Iterable[Evidence]) -> str:
    return stable_digest(
        {
            "findings": list(findings),
            "evidence": list(evidence),
        }
    )


class DeltaAdjudicator:
    """The one deterministic decision point after semantic correlation."""

    def adjudicate(
        self,
        *,
        run_id: str,
        clusters: Iterable[CandidateCluster],
        anchor_findings: Iterable[Finding],
        evidence_by_id: Mapping[str, Evidence],
        primary_degraded: bool,
        anchor_semantic_digest: str,
    ) -> tuple[TypedDelta, ...]:
        anchor = tuple(anchor_findings)
        deltas: list[TypedDelta] = []
        for cluster in sorted(clusters, key=lambda item: item.cluster_id):
            candidate = cluster.representative
            same = self._nearest(candidate, anchor, same_cwe=True)
            related = self._nearest_related(candidate, anchor)
            checks = evidence_semantic_checks(candidate, evidence_by_id)
            evidence_complete = checks["evidence_complete"]
            if same is not None:
                action = DeltaAction.SUPPLEMENT
                disposition = DeltaDisposition.ACCEPTED
                target = same.finding_id
                reason = "same_cwe_location_corroboration"
                ready = False
            elif related is not None and self._related_cwe(candidate.rule_id, related.rule_id):
                target = related.finding_id
                native_refinement = candidate.raw.get("deterministic_native_taxonomy_refinement") is True
                if native_refinement and high_specificity_complete(candidate, evidence_by_id):
                    # The closed native rule publishes a stable CWE family
                    # identity while retaining its precise weakness IDs in
                    # evidence. This correction is revalidated against the
                    # immutable manifest and CAS again at Admission.
                    action = DeltaAction.CORRECT
                    disposition = DeltaDisposition.ACCEPTED
                    reason = "bounded_native_taxonomy_normalization"
                    ready = True
                else:
                    action = DeltaAction.CORRECT
                    disposition = DeltaDisposition.ACCEPTED if evidence_complete else DeltaDisposition.QUARANTINED
                    reason = "bounded_related_cwe_correction" if evidence_complete else "correction_evidence_incomplete"
                    ready = evidence_complete and checks["semantic_assurance"]
            elif len(cluster.producer_ids) == 1 and high_specificity_complete(candidate, evidence_by_id):
                action = DeltaAction.ADD
                disposition = DeltaDisposition.ACCEPTED
                target = None
                reason = (
                    "single_producer_high_assurance_admission"
                    if not primary_degraded
                    else "single_producer_high_specificity_degraded_rescue"
                )
                ready = True
            elif (
                primary_degraded
                and len(cluster.producer_ids) >= 2
                and evidence_complete
                and all(
                    checks[key]
                    for key in (
                        "path_complete",
                        "line_complete",
                        "file_sha256_complete",
                        "rule_digest_complete",
                        "sink_or_dataflow_present",
                    )
                )
            ):
                action = DeltaAction.ADD
                disposition = DeltaDisposition.ACCEPTED
                target = None
                reason = "correlated_independent_degraded_rescue"
                ready = True
            elif len(cluster.producer_ids) >= 2 and evidence_complete and checks["semantic_assurance"]:
                action = DeltaAction.ADD
                disposition = DeltaDisposition.ACCEPTED
                target = None
                reason = "correlated_independent_producers"
                ready = True
            else:
                action = DeltaAction.ADD
                disposition = DeltaDisposition.QUARANTINED
                target = None
                reason = "primary_precision_holdout" if not primary_degraded else "insufficient_independent_specificity"
                ready = False
            gate_digest = stable_digest(
                {
                    "cluster_id": cluster.cluster_id,
                    "candidate_ids": cluster.candidate_ids,
                    "action": action.value,
                    "disposition": disposition.value,
                    "reason": reason,
                    "primary_degraded": primary_degraded,
                }
            )
            payload = {
                "run_id": run_id,
                "cluster_id": cluster.cluster_id,
                "candidate_ids": cluster.candidate_ids,
                "action": action.value,
                "disposition": disposition.value,
                "target_finding_id": target,
                "finding": candidate,
                "evidence_ids": tuple(sorted(set(candidate.evidence_ids))),
                "producer_ids": cluster.producer_ids,
                "reason_code": reason,
                "evidence_complete": evidence_complete,
                "semantic_checks": checks,
                "admission_ready": ready,
                "anchor_semantic_digest": anchor_semantic_digest,
                "gate_digest": gate_digest,
            }
            deltas.append(
                TypedDelta.model_validate(
                    {
                        "delta_id": f"delta-{stable_digest(payload)[:32]}",
                        **payload,
                    }
                )
            )
        return tuple(deltas)

    @staticmethod
    def _nearest(candidate: Finding, anchor: tuple[Finding, ...], *, same_cwe: bool) -> Finding | None:
        matches: list[tuple[int, str, Finding]] = []
        for item in anchor:
            if normalize_path(item.path) != normalize_path(candidate.path):
                continue
            if same_cwe and cwe_number(item.rule_id) != cwe_number(candidate.rule_id):
                continue
            distance = 0 if item.line is None or candidate.line is None else abs(item.line - candidate.line)
            if distance <= (5 if same_cwe else 2):
                matches.append((distance, item.finding_id, item))
        return min(matches, key=lambda value: (value[0], value[1]))[2] if matches else None

    @classmethod
    def _nearest_related(cls, candidate: Finding, anchor: tuple[Finding, ...]) -> Finding | None:
        """Return the nearest *related* Anchor instead of any nearby claim.

        A different, unrelated finding at the same line must not shadow a
        valid taxonomy correction merely because its stable ID sorts first.
        """

        matches: list[tuple[int, str, Finding]] = []
        for item in anchor:
            if normalize_path(item.path) != normalize_path(candidate.path):
                continue
            if not cls._related_cwe(candidate.rule_id, item.rule_id):
                continue
            distance = 0 if item.line is None or candidate.line is None else abs(item.line - candidate.line)
            if distance <= 2:
                matches.append((distance, item.finding_id, item))
        return min(matches, key=lambda value: (value[0], value[1]))[2] if matches else None

    @staticmethod
    def _related_cwe(left: str, right: str) -> bool:
        left_number = cwe_number(left)
        right_number = cwe_number(right)
        return (
            left_number is not None
            and right_number is not None
            and left_number != right_number
            and any({left_number, right_number} <= family for family in _RELATED_CWE_FAMILIES)
        )


def build_anchor_report(
    *,
    run_id: str,
    receipt_id: str,
    request_sha256: str,
    response_sha256: str,
    response_schema_sha256: str,
    prompt_version: str,
    prompt_artifact_id: str | None,
    context_sha256: str,
    response_artifact_id: str,
    findings: Iterable[Finding],
    evidence: Iterable[Evidence],
    limitations: Iterable[str],
    coverage: Mapping[str, Any],
    sealed: bool = True,
) -> AnchorReport:
    finding_tuple = tuple(item.model_copy(deep=True) for item in findings)
    evidence_tuple = tuple(item.model_copy(deep=True) for item in evidence)
    semantic_digest = _anchor_digest(finding_tuple, evidence_tuple)
    return AnchorReport(
        run_id=run_id,
        receipt_id=receipt_id,
        request_sha256=request_sha256,
        response_sha256=response_sha256,
        response_schema_sha256=response_schema_sha256,
        prompt_version=prompt_version,
        prompt_artifact_id=prompt_artifact_id,
        context_sha256=context_sha256,
        response_artifact_id=response_artifact_id,
        raw_response_sha256=response_sha256,
        findings=finding_tuple,
        evidence=evidence_tuple,
        limitations=tuple(dict.fromkeys(item for item in limitations if item)),
        coverage=dict(coverage),
        semantic_digest=semantic_digest,
        sealed=sealed,
    )


def build_enhanced_report(
    *,
    anchor: AnchorReport,
    deltas: Iterable[TypedDelta],
    findings: Iterable[Finding],
    evidence: Iterable[Evidence],
    coverage: Mapping[str, Any],
    precision_gate_met: bool,
    publishable: bool,
) -> EnhancedReport:
    delta_tuple = tuple(deltas)
    return EnhancedReport(
        run_id=anchor.run_id,
        anchor_report_digest=anchor.report_digest,
        anchor_semantic_digest=anchor.semantic_digest,
        findings=tuple(item.model_copy(deep=True) for item in findings),
        evidence=tuple(item.model_copy(deep=True) for item in evidence),
        deltas=delta_tuple,
        added_delta_ids=tuple(
            item.delta_id for item in delta_tuple if item.action == DeltaAction.ADD and item.accepted
        ),
        corrected_delta_ids=tuple(
            item.delta_id for item in delta_tuple if item.action == DeltaAction.CORRECT and item.accepted
        ),
        rejected_delta_ids=tuple(
            item.delta_id for item in delta_tuple if item.disposition == DeltaDisposition.REJECTED
        ),
        quarantined_delta_ids=tuple(
            item.delta_id for item in delta_tuple if item.disposition == DeltaDisposition.QUARANTINED
        ),
        precision_gate_met=precision_gate_met,
        publishable=publishable,
        anchor_preserved=True,
        coverage=dict(coverage),
    )


__all__ = [
    "AnchorReport",
    "CandidateCluster",
    "CandidateRecord",
    "CandidateState",
    "CandidateStore",
    "CandidateTransition",
    "DIRECT_ANCHOR_PIPELINE_VERSION",
    "DeltaAction",
    "DeltaAdjudicator",
    "DeltaDisposition",
    "EnhancedReport",
    "SemanticClusterKey",
    "TypedDelta",
    "build_anchor_report",
    "build_enhanced_report",
    "cwe_family",
    "evidence_semantic_checks",
    "high_specificity_complete",
    "normalize_path",
    "stable_digest",
    "valid_sha256",
]
