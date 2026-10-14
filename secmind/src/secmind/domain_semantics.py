"""Strict, source-bound semantic graphs for non-code security domains.

The public :mod:`secmind.domain_answers` models remain the single answer
protocol.  This module only provides their typed value objects and pure
normalizers.  Inputs are untrusted parser/model data: unknown properties are
retained under ``attributes`` and never interpreted as policy or instructions.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

_SHA256_PATTERN = r"^[a-fA-F0-9]{64}$"
_HTTP_METHODS = frozenset({"GET", "PUT", "POST", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"})
_SAFE_EVENT_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
_SAFE_EVENT_ID_RE = re.compile(_SAFE_EVENT_ID)


def _stable_id(namespace: str, value: Any) -> str:
    material = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return f"{namespace}-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:32]}"


def _text(value: Any, *, fallback: str = "") -> str:
    return str(value).strip() if value is not None and str(value).strip() else fallback


def _safe_event_identifier(value: Any, row: Any) -> str:
    """Return a stable graph-safe event ID without exposing source text."""

    candidate = _text(value)
    if candidate and _SAFE_EVENT_ID_RE.fullmatch(candidate) is not None:
        return candidate
    if isinstance(row, Mapping):
        # Do not hash the complete message/attributes payload: malformed IDs
        # are untrusted and may carry megabytes of display text.  Locator and
        # stable parser coordinates preserve deterministic uniqueness without
        # copying that text into the identifier calculation.
        material = {
            "raw_id": candidate,
            "source_locator": row.get("source_locator") or row.get("record_locator"),
            "record_number": row.get("record_number"),
            "line_number": row.get("line_number"),
            "byte_offset": row.get("byte_offset"),
            "timestamp": row.get("timestamp") or row.get("timestamp_utc"),
            "event_type": row.get("event_type") or row.get("fact_type"),
        }
    else:
        material = {"raw_id": candidate, "row": row}
    return _stable_id("event", material)


def canonicalize_timeline_event_rows(events: Sequence[Any]) -> list[dict[str, Any]]:
    """Canonicalize public event rows and their direct ID references.

    Parsers and providers sometimes use display labels such as ``4624/1`` or
    include control characters.  Those values are useful source text but are
    not safe graph identifiers.  Convert them to a deterministic opaque ID at
    the DomainAnswer boundary; the original value remains in ``attributes``
    only when the caller supplied one there, while evidence/source locators
    stay untouched.
    """

    rows = list(events[:2_000])
    aliases: dict[str, str] = {}
    normalized: list[dict[str, Any]] = []
    for raw in rows:
        if not isinstance(raw, Mapping):
            continue
        row = dict(raw)
        original = _text(row.get("event_id") or row.get("action_id") or row.get("id"))
        canonical = _safe_event_identifier(original, raw)
        if original:
            aliases.setdefault(original, canonical)
        row["event_id"] = canonical
        normalized.append(row)
    for row in normalized:
        for key in ("source_event_id", "target_event_id"):
            if key in row and row[key] is not None:
                row[key] = aliases.get(str(row[key]).strip(), str(row[key]).strip())
        if isinstance(row.get("event_ids"), Sequence) and not isinstance(row["event_ids"], (str, bytes, bytearray)):
            row["event_ids"] = [aliases.get(str(item), str(item)) for item in row["event_ids"]]
    return normalized


def _string_tuple(value: Any, *, limit: int = 2_000) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return ()
    return tuple(dict.fromkeys(_text(item) for item in value if _text(item)))[:limit]


class RecordLocator(BaseModel):
    """Replayable location in an immutable raw or derived artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_ref: str = Field(min_length=1, max_length=2_048)
    segment_id: str = Field(min_length=1, max_length=256)
    record_number: int = Field(default=0, ge=0)
    line_number: int = Field(default=0, ge=0)
    byte_offset: int = Field(default=0, ge=0)
    byte_length: int = Field(default=0, ge=0)
    locator_scope: Literal["record", "segment", "document", "whole_file", "unknown"] = "record"
    artifact_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def normalize_digest(self) -> Self:
        if self.artifact_sha256 is not None:
            object.__setattr__(self, "artifact_sha256", self.artifact_sha256.lower())
        return self


class SourceBinding(BaseModel):
    """Evidence and source coordinates shared by all semantic nodes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=2_000)
    source_locator: RecordLocator | None = None
    source_locators: tuple[RecordLocator, ...] = Field(default_factory=tuple, max_length=2_000)
    source_content_trust: Literal["untrusted_data", "deterministic_projection", "unknown"] = "untrusted_data"

    @model_validator(mode="after")
    def normalize_locators(self) -> Self:
        locators = list(self.source_locators)
        if self.source_locator is not None and self.source_locator not in locators:
            locators.insert(0, self.source_locator)
        primary = self.source_locator or (locators[0] if locators else None)
        object.__setattr__(self, "source_locator", primary)
        object.__setattr__(self, "source_locators", tuple(locators))
        object.__setattr__(self, "evidence_ids", tuple(dict.fromkeys(self.evidence_ids)))
        return self


class TimelineEntity(SourceBinding):
    entity_id: str = Field(min_length=1, max_length=256)
    kind: str = Field(min_length=1, max_length=128)
    value: str = Field(min_length=1, max_length=2_048)
    name: str | None = Field(default=None, max_length=512)
    role: str | None = Field(default=None, max_length=512)
    account: str | None = Field(default=None, max_length=512)
    event_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=2_000)
    attributes: dict[str, Any] = Field(default_factory=dict)


class TimelineEvent(SourceBinding):
    # Event IDs are cross-record references, not display text.  Keep them
    # printable and delimiter-safe so a parser cannot smuggle a path,
    # newline, or control character into graph links and replay cursors.
    event_id: str = Field(min_length=1, max_length=256, pattern=_SAFE_EVENT_ID)
    timestamp: str | None = Field(default=None, max_length=128)
    timestamp_quality: str | None = Field(default=None, max_length=64)
    event_type: str = Field(min_length=1, max_length=256)
    severity: str | None = Field(default=None, max_length=64)
    message: str | None = Field(default=None, max_length=4_000)
    entity_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=2_000)
    attributes: dict[str, Any] = Field(default_factory=dict)


class TimelineFlow(SourceBinding):
    flow_id: str = Field(min_length=1, max_length=256)
    source_id: str = Field(min_length=1, max_length=256)
    target_id: str = Field(min_length=1, max_length=256)
    relation: str = Field(min_length=1, max_length=128)
    attributes: dict[str, Any] = Field(default_factory=dict)


class TimelineGraph(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    events: tuple[TimelineEvent, ...] = Field(default_factory=tuple, max_length=2_000)
    entities: tuple[TimelineEntity, ...] = Field(default_factory=tuple, max_length=2_000)
    flows: tuple[TimelineFlow, ...] = Field(default_factory=tuple, max_length=4_000)
    unknowns: tuple[str, ...] = Field(default_factory=tuple, max_length=2_000)
    source_content_trust: Literal["untrusted_data"] = "untrusted_data"

    @model_validator(mode="after")
    def validate_graph(self) -> Self:
        event_ids = [item.event_id for item in self.events]
        entity_ids = [item.entity_id for item in self.entities]
        flow_ids = [item.flow_id for item in self.flows]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("timeline graph contains duplicate event IDs")
        if len(entity_ids) != len(set(entity_ids)):
            raise ValueError("timeline graph contains duplicate entity IDs")
        if len(flow_ids) != len(set(flow_ids)):
            raise ValueError("timeline graph contains duplicate flow IDs")
        node_ids = set(event_ids) | set(entity_ids)
        if any(item.source_id not in node_ids or item.target_id not in node_ids for item in self.flows):
            raise ValueError("timeline flow references an unknown event/entity")
        return self


class ApiOperation(SourceBinding):
    operation_id: str = Field(min_length=1, max_length=256)
    method: str = Field(min_length=1, max_length=16)
    path: str = Field(min_length=1, max_length=2_048)
    parameter_names: tuple[str, ...] = Field(default_factory=tuple, max_length=256)
    auth_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=128)
    resource_id: str = Field(min_length=1, max_length=256)
    request_schema: dict[str, Any] | None = None
    response_schema: dict[str, Any] | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def normalize_method(self) -> Self:
        method = self.method.strip().upper()
        if method not in _HTTP_METHODS:
            raise ValueError(f"unsupported API method: {self.method}")
        object.__setattr__(self, "method", method)
        return self


class ApiAuthScheme(SourceBinding):
    auth_id: str = Field(min_length=1, max_length=256)
    scheme: str = Field(min_length=1, max_length=256)
    operation_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=2_000)
    attributes: dict[str, Any] = Field(default_factory=dict)


class ApiResource(SourceBinding):
    resource_id: str = Field(min_length=1, max_length=256)
    path_template: str = Field(min_length=1, max_length=2_048)
    operation_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=2_000)
    attributes: dict[str, Any] = Field(default_factory=dict)


class ApiRelation(SourceBinding):
    relation_id: str = Field(min_length=1, max_length=256)
    source_id: str = Field(min_length=1, max_length=256)
    target_id: str = Field(min_length=1, max_length=256)
    relation: Literal["requires_auth", "accesses_resource"]


class ApiGraph(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    operations: tuple[ApiOperation, ...] = Field(default_factory=tuple, max_length=2_000)
    auth_schemes: tuple[ApiAuthScheme, ...] = Field(default_factory=tuple, max_length=1_000)
    resources: tuple[ApiResource, ...] = Field(default_factory=tuple, max_length=2_000)
    relations: tuple[ApiRelation, ...] = Field(default_factory=tuple, max_length=4_000)
    unknowns: tuple[str, ...] = Field(default_factory=tuple, max_length=2_000)
    source_content_trust: Literal["untrusted_data"] = "untrusted_data"

    @model_validator(mode="after")
    def validate_graph(self) -> Self:
        operation_ids = [item.operation_id for item in self.operations]
        auth_ids = [item.auth_id for item in self.auth_schemes]
        resource_ids = [item.resource_id for item in self.resources]
        if len(operation_ids) != len(set(operation_ids)):
            raise ValueError("API graph contains duplicate operation IDs")
        if len(auth_ids) != len(set(auth_ids)):
            raise ValueError("API graph contains duplicate auth IDs")
        if len(resource_ids) != len(set(resource_ids)):
            raise ValueError("API graph contains duplicate resource IDs")
        node_ids = set(operation_ids) | set(auth_ids) | set(resource_ids)
        if any(item.source_id not in node_ids or item.target_id not in node_ids for item in self.relations):
            raise ValueError("API relation references an unknown graph node")
        return self


class IncidentHypothesis(SourceBinding):
    hypothesis_id: str = Field(min_length=1, max_length=256)
    statement: str = Field(min_length=1, max_length=4_000)
    subject_ref: str | None = Field(default=None, max_length=2_048)
    status: Literal["verified", "conflicting", "unverified", "rejected", "unknown"] = "unknown"
    test: str | None = Field(default=None, max_length=4_000)
    attributes: dict[str, Any] = Field(default_factory=dict)


class IncidentAction(SourceBinding):
    action_id: str = Field(min_length=1, max_length=256)
    phase: Literal["investigation", "containment", "recovery", "validation", "unknown"]
    title: str = Field(min_length=1, max_length=1_000)
    subject_ref: str = Field(min_length=1, max_length=2_048)
    policy_action: str = Field(min_length=1, max_length=128)
    execution_enabled: bool = False
    expected_impact: str = Field(min_length=1, max_length=4_000)
    rollback_condition: str = Field(min_length=1, max_length=4_000)
    attributes: dict[str, Any] = Field(default_factory=dict)


class RollbackCondition(SourceBinding):
    rollback_id: str = Field(min_length=1, max_length=256)
    action_id: str = Field(min_length=1, max_length=256)
    condition: str = Field(min_length=1, max_length=4_000)
    validation_step: str | None = Field(default=None, max_length=4_000)


class IncidentResponsePlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hypotheses: tuple[IncidentHypothesis, ...] = Field(default_factory=tuple, max_length=1_000)
    actions: tuple[IncidentAction, ...] = Field(default_factory=tuple, max_length=2_000)
    rollback_conditions: tuple[RollbackCondition, ...] = Field(default_factory=tuple, max_length=2_000)
    unknowns: tuple[str, ...] = Field(default_factory=tuple, max_length=2_000)
    dry_run: Literal[True] = True
    source_content_trust: Literal["untrusted_data"] = "untrusted_data"

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        hypothesis_ids = [item.hypothesis_id for item in self.hypotheses]
        action_ids = [item.action_id for item in self.actions]
        rollback_ids = [item.rollback_id for item in self.rollback_conditions]
        if len(hypothesis_ids) != len(set(hypothesis_ids)):
            raise ValueError("incident plan contains duplicate hypothesis IDs")
        if len(action_ids) != len(set(action_ids)):
            raise ValueError("incident plan contains duplicate action IDs")
        if len(rollback_ids) != len(set(rollback_ids)):
            raise ValueError("incident plan contains duplicate rollback IDs")
        known_actions = set(action_ids)
        if any(item.action_id not in known_actions for item in self.rollback_conditions):
            raise ValueError("rollback condition references an unknown incident action")
        if any(item.execution_enabled for item in self.actions):
            raise ValueError("published incident plan must remain a non-executing dry run")
        return self


def _locator(value: Any) -> RecordLocator | None:
    if isinstance(value, RecordLocator):
        return value
    if not isinstance(value, Mapping):
        return None
    allowed = set(RecordLocator.model_fields)
    payload = {str(key): item for key, item in value.items() if str(key) in allowed}
    try:
        return RecordLocator.model_validate(payload)
    except ValueError:
        return None


def _binding(row: Mapping[str, Any], *, fallback: SourceBinding | None = None) -> dict[str, Any]:
    evidence_ids = _string_tuple(row.get("evidence_ids"))
    locators: list[RecordLocator] = []
    values = row.get("source_locators")
    if isinstance(values, Sequence) and not isinstance(values, (str, bytes, bytearray)):
        locators.extend(item for value in values if (item := _locator(value)) is not None)
    primary = _locator(row.get("source_locator") or row.get("record_locator"))
    if primary is not None and primary not in locators:
        locators.insert(0, primary)
    if fallback is not None:
        evidence_ids = tuple(dict.fromkeys((*evidence_ids, *fallback.evidence_ids)))
        if fallback.source_locator is not None and fallback.source_locator not in locators:
            locators.append(fallback.source_locator)
        for locator in fallback.source_locators:
            if locator not in locators:
                locators.append(locator)
    return {
        "evidence_ids": evidence_ids,
        "source_locator": primary or (fallback.source_locator if fallback is not None else None),
        "source_locators": tuple(locators),
        "source_content_trust": "untrusted_data",
    }


def _extras(row: Mapping[str, Any], known: set[str]) -> dict[str, Any]:
    explicit = row.get("attributes")
    values = dict(explicit) if isinstance(explicit, Mapping) else {}
    for key, value in row.items():
        name = str(key)
        if name not in known and name != "attributes":
            values[name] = value
    return values


_BINDING_FIELDS = {
    "evidence_ids",
    "source_locator",
    "source_locators",
    "record_locator",
    "source_content_trust",
}


def normalize_timeline_graph(
    events: Sequence[Any],
    actors: Sequence[Any] = (),
    flows: Sequence[Any] = (),
    *,
    unknowns: Sequence[str] = (),
) -> TimelineGraph:
    """Normalize event/entity/flow rows without creating causal claims."""

    event_nodes: list[TimelineEvent] = []
    entities: dict[str, TimelineEntity] = {}
    flow_nodes: list[TimelineFlow] = []
    raw_events = list(events[:2_000])
    event_id_aliases: dict[str, str] = {}
    normalized_event_ids: list[str | None] = []
    for raw in raw_events:
        if not isinstance(raw, Mapping):
            normalized_event_ids.append(None)
            continue
        original_id = _text(raw.get("event_id") or raw.get("action_id") or raw.get("id"))
        event_id = _safe_event_identifier(original_id, raw)
        normalized_event_ids.append(event_id)
        if original_id:
            event_id_aliases.setdefault(original_id, event_id)

    for raw_index, raw in enumerate(raw_events):
        if not isinstance(raw, Mapping):
            continue
        event_id = normalized_event_ids[raw_index] or _safe_event_identifier("", raw)
        event_type = _text(
            raw.get("event_type") or raw.get("phase") or raw.get("inference_type") or raw.get("fact_type"),
            fallback="unknown",
        )
        event_binding = SourceBinding.model_validate(_binding(raw))
        event_entity_ids: list[str] = []
        raw_entities = raw.get("entities")
        if isinstance(raw_entities, Sequence) and not isinstance(raw_entities, (str, bytes, bytearray)):
            for item in raw_entities[:256]:
                if not isinstance(item, Mapping):
                    continue
                kind = _text(item.get("kind") or item.get("type"), fallback="unknown")
                value = _text(item.get("value") or item.get("name") or item.get("account"))
                if not value:
                    continue
                entity_id = _text(item.get("entity_id"), fallback=_stable_id("entity", [kind, value]))
                entity_binding = _binding(item, fallback=event_binding)
                entity = TimelineEntity(
                    entity_id=entity_id,
                    kind=kind,
                    value=value,
                    name=_text(item.get("name")) or None,
                    role=_text(item.get("role")) or None,
                    account=_text(item.get("account")) or None,
                    event_ids=(event_id,),
                    attributes=_extras(
                        item,
                        _BINDING_FIELDS | {"entity_id", "kind", "type", "value", "name", "role", "account"},
                    ),
                    **entity_binding,
                )
                current = entities.get(entity_id)
                if current is not None:
                    entity = entity.model_copy(
                        update={
                            "event_ids": tuple(dict.fromkeys((*current.event_ids, event_id))),
                            "evidence_ids": tuple(dict.fromkeys((*current.evidence_ids, *entity.evidence_ids))),
                            "source_locators": tuple(
                                dict.fromkeys((*current.source_locators, *entity.source_locators))
                            ),
                        }
                    )
                entities[entity_id] = entity
                event_entity_ids.append(entity_id)
        known = _BINDING_FIELDS | {
            "event_id",
            "action_id",
            "id",
            "timestamp",
            "timestamp_utc",
            "timestamp_quality",
            "event_type",
            "phase",
            "inference_type",
            "fact_type",
            "severity",
            "message",
            "entities",
        }
        event_nodes.append(
            TimelineEvent(
                event_id=event_id,
                timestamp=_text(raw.get("timestamp") or raw.get("timestamp_utc")) or None,
                timestamp_quality=_text(raw.get("timestamp_quality")) or None,
                event_type=event_type,
                severity=_text(raw.get("severity")) or None,
                message=_text(raw.get("message")) or None,
                entity_ids=tuple(dict.fromkeys(event_entity_ids)),
                attributes=_extras(raw, known),
                **event_binding.model_dump(mode="python"),
            )
        )
        for entity_id in event_entity_ids:
            flow_nodes.append(
                TimelineFlow(
                    flow_id=_stable_id("flow", [event_id, entity_id, "observed_entity"]),
                    source_id=event_id,
                    target_id=entity_id,
                    relation="observed_entity",
                    attributes={},
                    **event_binding.model_dump(mode="python"),
                )
            )

    for raw in actors[:2_000]:
        if not isinstance(raw, Mapping):
            continue
        value = _text(raw.get("value") or raw.get("name") or raw.get("account") or raw.get("subject_ref"))
        if not value:
            continue
        kind = _text(raw.get("kind") or raw.get("role"), fallback="actor")
        entity_id = _text(raw.get("entity_id") or raw.get("actor_id"), fallback=_stable_id("entity", [kind, value]))
        binding = _binding(raw)
        event_ids = tuple(event_id_aliases.get(item, item) for item in _string_tuple(raw.get("event_ids")))
        entities[entity_id] = TimelineEntity(
            entity_id=entity_id,
            kind=kind,
            value=value,
            name=_text(raw.get("name")) or None,
            role=_text(raw.get("role")) or None,
            account=_text(raw.get("account")) or None,
            event_ids=event_ids,
            attributes=_extras(
                raw,
                _BINDING_FIELDS
                | {"entity_id", "actor_id", "kind", "value", "name", "role", "account", "subject_ref", "event_ids"},
            ),
            **binding,
        )

    node_ids = {item.event_id for item in event_nodes} | set(entities)
    for raw in flows[:4_000]:
        if not isinstance(raw, Mapping):
            continue
        source_id = _text(raw.get("source_id") or raw.get("source_event_id"))
        target_id = _text(raw.get("target_id") or raw.get("target_event_id"))
        source_id = event_id_aliases.get(source_id, source_id)
        target_id = event_id_aliases.get(target_id, target_id)
        relation = _text(raw.get("relation"), fallback="related")
        if not source_id or not target_id or source_id not in node_ids or target_id not in node_ids:
            raise ValueError("explicit timeline flow references an unknown event/entity")
        flow_nodes.append(
            TimelineFlow(
                flow_id=_text(raw.get("flow_id"), fallback=_stable_id("flow", [source_id, target_id, relation])),
                source_id=source_id,
                target_id=target_id,
                relation=relation,
                attributes=_extras(
                    raw,
                    _BINDING_FIELDS
                    | {"flow_id", "source_id", "source_event_id", "target_id", "target_event_id", "relation"},
                ),
                **_binding(raw),
            )
        )
    return TimelineGraph(
        events=tuple(event_nodes),
        entities=tuple(sorted(entities.values(), key=lambda item: item.entity_id)),
        flows=tuple(sorted({item.flow_id: item for item in flow_nodes}.values(), key=lambda item: item.flow_id)),
        unknowns=tuple(dict.fromkeys(_text(item) for item in unknowns if _text(item))),
    )


def normalize_api_graph(endpoints: Sequence[Any], *, unknowns: Sequence[str] = ()) -> ApiGraph:
    """Normalize operations and derive only structural auth/resource edges."""

    operations: dict[str, ApiOperation] = {}
    auth_operations: dict[str, set[str]] = {}
    auth_bindings: dict[str, dict[str, Any]] = {}
    resource_operations: dict[str, set[str]] = {}
    resource_paths: dict[str, str] = {}
    resource_bindings: dict[str, dict[str, Any]] = {}
    relations: list[ApiRelation] = []
    for raw in endpoints[:2_000]:
        if not isinstance(raw, Mapping):
            continue
        method = _text(raw.get("method")).upper()
        path = _text(raw.get("path") or raw.get("url_template"))
        if method not in _HTTP_METHODS or not path:
            raise ValueError("API operation requires a supported method and non-empty path")
        operation_id = _text(
            raw.get("operation_id") or raw.get("endpoint_id"),
            fallback=_stable_id("operation", [method, path]),
        )
        binding = _binding(raw)
        resource_id = _text(raw.get("resource_id"), fallback=_stable_id("resource", path))
        auth_schemes = _string_tuple(raw.get("auth_schemes") or raw.get("security"), limit=128)
        auth_ids = tuple(_stable_id("auth", scheme) for scheme in auth_schemes)
        operation = ApiOperation(
            operation_id=operation_id,
            method=method,
            path=path,
            parameter_names=_string_tuple(raw.get("parameter_names") or raw.get("parameters"), limit=256),
            auth_ids=auth_ids,
            resource_id=resource_id,
            request_schema=(dict(raw["request_schema"]) if isinstance(raw.get("request_schema"), Mapping) else None),
            response_schema=(dict(raw["response_schema"]) if isinstance(raw.get("response_schema"), Mapping) else None),
            attributes=_extras(
                raw,
                _BINDING_FIELDS
                | {
                    "operation_id",
                    "endpoint_id",
                    "method",
                    "path",
                    "url_template",
                    "resource_id",
                    "parameter_names",
                    "parameters",
                    "auth_schemes",
                    "security",
                    "request_schema",
                    "response_schema",
                },
            ),
            **binding,
        )
        existing = operations.get(operation_id)
        if existing is not None:
            if (
                existing.method,
                existing.path,
                existing.resource_id,
                existing.auth_ids,
            ) != (
                operation.method,
                operation.path,
                operation.resource_id,
                operation.auth_ids,
            ):
                raise ValueError("duplicate API operation ID has conflicting core semantics")
            operation = existing.model_copy(
                update={
                    "evidence_ids": tuple(dict.fromkeys((*existing.evidence_ids, *operation.evidence_ids))),
                    "source_locators": tuple(dict.fromkeys((*existing.source_locators, *operation.source_locators))),
                    "attributes": {**existing.attributes, **operation.attributes},
                }
            )
        operations[operation_id] = operation
        resource_operations.setdefault(resource_id, set()).add(operation_id)
        resource_paths[resource_id] = path
        resource_bindings.setdefault(resource_id, dict(binding))
        relations.append(
            ApiRelation(
                relation_id=_stable_id("api-relation", [operation_id, resource_id, "accesses_resource"]),
                source_id=operation_id,
                target_id=resource_id,
                relation="accesses_resource",
                **binding,
            )
        )
        for auth_id, scheme in zip(auth_ids, auth_schemes, strict=True):
            auth_operations.setdefault(auth_id, set()).add(operation_id)
            auth_bindings.setdefault(auth_id, dict(binding))
            relations.append(
                ApiRelation(
                    relation_id=_stable_id("api-relation", [operation_id, auth_id, "requires_auth"]),
                    source_id=operation_id,
                    target_id=auth_id,
                    relation="requires_auth",
                    **binding,
                )
            )
            auth_bindings[auth_id]["scheme"] = scheme
    auth_nodes = [
        ApiAuthScheme(
            auth_id=auth_id,
            scheme=str(auth_bindings[auth_id]["scheme"]),
            operation_ids=tuple(sorted(operation_ids)),
            attributes={},
            **{key: value for key, value in auth_bindings[auth_id].items() if key != "scheme"},
        )
        for auth_id, operation_ids in sorted(auth_operations.items())
    ]
    resource_nodes = [
        ApiResource(
            resource_id=resource_id,
            path_template=resource_paths[resource_id],
            operation_ids=tuple(sorted(operation_ids)),
            attributes={},
            **resource_bindings[resource_id],
        )
        for resource_id, operation_ids in sorted(resource_operations.items())
    ]
    return ApiGraph(
        operations=tuple(sorted(operations.values(), key=lambda item: item.operation_id)),
        auth_schemes=tuple(auth_nodes),
        resources=tuple(resource_nodes),
        relations=tuple(
            sorted({item.relation_id: item for item in relations}.values(), key=lambda item: item.relation_id)
        ),
        unknowns=tuple(dict.fromkeys(_text(item) for item in unknowns if _text(item))),
    )


def normalize_incident_plan(
    actions: Sequence[Any],
    hypotheses: Sequence[Any] = (),
    *,
    unknowns: Sequence[str] = (),
) -> IncidentResponsePlan:
    """Build a non-executing, evidence-bound hypothesis/action/rollback plan."""

    hypothesis_nodes: list[IncidentHypothesis] = []
    action_nodes: list[IncidentAction] = []
    rollback_nodes: list[RollbackCondition] = []
    for raw in hypotheses[:1_000]:
        if not isinstance(raw, Mapping):
            continue
        hypothesis_id = _text(raw.get("hypothesis_id") or raw.get("claim_id") or raw.get("id"))
        statement = _text(raw.get("statement") or raw.get("explanation") or raw.get("hypothesis"))
        if not hypothesis_id or not statement:
            raise ValueError("incident hypothesis requires an ID and statement")
        status = _text(raw.get("status")).casefold()
        if not status:
            status = "conflicting" if raw.get("treated_as_fact") is False else "unknown"
        if status not in {"verified", "conflicting", "unverified", "rejected", "unknown"}:
            status = "unknown"
        hypothesis_nodes.append(
            IncidentHypothesis(
                hypothesis_id=hypothesis_id,
                statement=statement,
                subject_ref=_text(raw.get("subject_ref")) or None,
                status=cast(
                    Literal["verified", "conflicting", "unverified", "rejected", "unknown"],
                    status,
                ),
                test=_text(raw.get("test") or raw.get("verification_step")) or None,
                attributes=_extras(
                    raw,
                    _BINDING_FIELDS
                    | {
                        "hypothesis_id",
                        "claim_id",
                        "id",
                        "statement",
                        "explanation",
                        "hypothesis",
                        "subject_ref",
                        "status",
                        "treated_as_fact",
                        "test",
                        "verification_step",
                    },
                ),
                **_binding(raw),
            )
        )
    for raw in actions[:2_000]:
        if not isinstance(raw, Mapping):
            continue
        action_id = _text(raw.get("action_id") or raw.get("id"))
        subject_ref = _text(raw.get("subject_ref"))
        rollback = _text(raw.get("rollback_condition"))
        if not action_id or not subject_ref or not rollback:
            raise ValueError("incident action requires action_id, subject_ref, and rollback_condition")
        phase = _text(raw.get("phase"), fallback="unknown").casefold()
        if phase not in {"investigation", "containment", "recovery", "validation", "unknown"}:
            phase = "unknown"
        binding = _binding(raw)
        action_nodes.append(
            IncidentAction(
                action_id=action_id,
                phase=cast(
                    Literal["investigation", "containment", "recovery", "validation", "unknown"],
                    phase,
                ),
                title=_text(raw.get("title"), fallback=f"{phase} dry-run action"),
                subject_ref=subject_ref,
                policy_action=_text(raw.get("policy_action"), fallback="unknown"),
                execution_enabled=bool(raw.get("execution_enabled", False)),
                expected_impact=_text(raw.get("expected_impact"), fallback="impact remains to be validated"),
                rollback_condition=rollback,
                attributes=_extras(
                    raw,
                    _BINDING_FIELDS
                    | {
                        "action_id",
                        "id",
                        "phase",
                        "title",
                        "subject_ref",
                        "policy_action",
                        "execution_enabled",
                        "expected_impact",
                        "rollback_condition",
                    },
                ),
                **binding,
            )
        )
        rollback_nodes.append(
            RollbackCondition(
                rollback_id=_stable_id("rollback", [action_id, rollback]),
                action_id=action_id,
                condition=rollback,
                validation_step=_text(raw.get("validation_step")) or None,
                **binding,
            )
        )
    return IncidentResponsePlan(
        hypotheses=tuple(sorted(hypothesis_nodes, key=lambda item: item.hypothesis_id)),
        actions=tuple(sorted(action_nodes, key=lambda item: item.action_id)),
        rollback_conditions=tuple(sorted(rollback_nodes, key=lambda item: item.rollback_id)),
        unknowns=tuple(dict.fromkeys(_text(item) for item in unknowns if _text(item))),
    )


__all__ = [
    "ApiAuthScheme",
    "ApiGraph",
    "ApiOperation",
    "ApiRelation",
    "ApiResource",
    "IncidentAction",
    "IncidentHypothesis",
    "IncidentResponsePlan",
    "RecordLocator",
    "RollbackCondition",
    "SourceBinding",
    "TimelineEntity",
    "TimelineEvent",
    "TimelineFlow",
    "TimelineGraph",
    "normalize_api_graph",
    "normalize_incident_plan",
    "normalize_timeline_graph",
]
