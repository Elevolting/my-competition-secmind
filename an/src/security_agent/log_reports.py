"""Typed display projection of the existing SecMind offline log answer."""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

Count = Annotated[int, Field(ge=0)]


class LogSourceLocator(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    source_ref: str
    line_number: Count | None
    record_number: Count | None
    byte_offset: Count | None
    byte_length: Count | None


class LogEvent(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    event_id: str
    timestamp: str | None
    event_type: str
    severity: str | None
    message: str
    evidence_ids: list[str]
    source_locator: LogSourceLocator | None


class LogIoc(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    ioc_type: str
    value: str
    event_id: str | None
    evidence_ids: list[str]


class LogRuleMatch(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    rule_id: str
    title: str
    severity: str
    event_ids: list[str]
    evidence_ids: list[str]


class LogStatistics(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    sources_processed: Count | None
    input_records: Count | None
    parsed_records: Count | None
    rejected_records: Count | None
    duplicates_removed: Count | None


class LogSource(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    evidence_id: str
    source_ref: str
    line_number: Count | None
    record_number: Count | None
    sha256: str | None


class LogAnalysisReport(BaseModel):
    """Required display arrays; unknown coverage counts remain null, never zero."""

    model_config = ConfigDict(extra="ignore", strict=True)

    events: list[LogEvent]
    iocs: list[LogIoc]
    rule_matches: list[LogRuleMatch]
    statistics: LogStatistics
    sources: list[LogSource]


class _EngineIoc(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    ioc_type: str
    normalized_value: str
    event_id: str | None
    evidence_ids: list[str]


class _EngineInference(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    inference_type: str
    rule_id: str | None = None
    title: str | None = None
    severity: str | None = None
    event_id: str | None = None
    evidence_ids: list[str] | None = None


class _EngineCoverage(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    source_count: Count | None = None
    sources_processed: Count | None = None
    records_seen: Count | None = None
    records_emitted: Count | None = None
    records_rejected: Count | None = None
    duplicates_removed: Count | None = None


class _EngineExtensions(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    coverage: _EngineCoverage = Field(default_factory=_EngineCoverage)


class _EngineTimeline(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    answer_kind: Literal["timeline"]
    events: list[LogEvent]
    iocs: list[_EngineIoc]
    inferences: list[_EngineInference]
    extensions: _EngineExtensions = Field(default_factory=_EngineExtensions)


class _EngineEvidenceMetadata(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    source_locator: LogSourceLocator | None = None


class _EngineEvidence(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    evidence_id: str
    sha256: str | None
    metadata: _EngineEvidenceMetadata


def project_log_analysis(
    answer_type: object, answer_payload: object, coverage: object, evidence: object,
) -> LogAnalysisReport | None:
    """Adapt only a real timeline answer; validate required fields at ingress."""
    if answer_type != "timeline":
        return None
    answer = _EngineTimeline.model_validate(answer_payload)
    report_coverage = _EngineCoverage.model_validate(coverage)
    counts = answer.extensions.coverage
    evidence_rows = TypeAdapter(list[_EngineEvidence]).validate_python(evidence)
    rules = [
        LogRuleMatch.model_validate({
            "rule_id": item.rule_id, "title": item.title, "severity": item.severity,
            "event_ids": [TypeAdapter(str).validate_python(item.event_id, strict=True)],
            "evidence_ids": item.evidence_ids,
        })
        for item in answer.inferences if item.inference_type == "rule_match"
    ]
    return LogAnalysisReport(
        events=answer.events,
        iocs=[LogIoc(ioc_type=item.ioc_type, value=item.normalized_value,
                     event_id=item.event_id, evidence_ids=item.evidence_ids) for item in answer.iocs],
        rule_matches=rules,
        statistics=LogStatistics(
            sources_processed=(report_coverage.sources_processed if report_coverage.sources_processed is not None
                               else counts.source_count),
            input_records=counts.records_seen,
            parsed_records=counts.records_emitted,
            rejected_records=counts.records_rejected,
            duplicates_removed=counts.duplicates_removed,
        ),
        sources=[LogSource(evidence_id=item.evidence_id, source_ref=locator.source_ref,
                           line_number=locator.line_number, record_number=locator.record_number,
                           sha256=item.sha256)
                 for item in evidence_rows if (locator := item.metadata.source_locator) is not None],
    )
