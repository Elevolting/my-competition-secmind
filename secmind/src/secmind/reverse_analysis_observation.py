"""Normalized evidence envelope shared by reverse-analysis lanes."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ReverseAnalysisObservation(BaseModel):
    """Bounded internal observation; published under answer extensions."""

    model_config = ConfigDict(extra="forbid")

    source: Literal["static_pe", "static_source", "speakeasy", "cape"]
    status: Literal["completed", "partial", "unavailable", "timeout", "error"]
    sample_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_identity: dict[str, str]
    profile_id: str | None = None
    coverage: dict[str, Any] = Field(default_factory=dict)
    events: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    artifacts: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list, max_length=500)
    error: dict[str, Any] | None = None


def static_pe_observation(report: dict[str, Any], evidence_refs: list[str]) -> ReverseAnalysisObservation:
    imports = sorted(
        {
            str(entry["name"])
            for library in report.get("imports", [])
            for entry in library.get("entries", [])
            if entry.get("name")
        }
    )
    return ReverseAnalysisObservation(
        source="static_pe",
        status="completed",
        sample_sha256=str(report["file"]["sha256"]),
        tool_identity={"name": "pe_reverse_analysis", "version": "1"},
        coverage={
            "format": report["file"].get("format"),
            "architecture": report["file"].get("architecture"),
            "section_count": report["pe"].get("section_count"),
            "import_library_count": report["pe"].get("import_library_count"),
            "import_semantics": report.get("import_semantics", "static_presence"),
        },
        artifacts={
            "imports": imports,
            "xor_decode_candidates": list(report.get("xor_decode_candidates", [])),
            "sections": list(report.get("sections", [])),
        },
        evidence_refs=evidence_refs,
    )


def fuse_reverse_facts(
    static_facts: dict[str, dict[str, Any]],
    dynamic_facts: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Merge fact candidates without silently preferring one evidence lane."""

    fused: dict[str, dict[str, Any]] = {}
    for key in sorted(set(static_facts) | set(dynamic_facts)):
        static = static_facts.get(key)
        dynamic = dynamic_facts.get(key)
        static_refs = list(static.get("evidence_refs", [])) if static else []
        dynamic_refs = list(dynamic.get("evidence_refs", [])) if dynamic else []
        evidence_refs = list(dict.fromkeys([*static_refs, *dynamic_refs]))
        if static is None and dynamic is not None:
            fused[key] = {
                "value": dynamic.get("value"),
                "provenance": "dynamic_only",
                "evidence_refs": evidence_refs,
            }
        elif dynamic is None and static is not None:
            fused[key] = {
                "value": static.get("value"),
                "provenance": "static_only",
                "evidence_refs": evidence_refs,
            }
        elif static is not None and dynamic is not None and static.get("value") == dynamic.get("value"):
            fused[key] = {
                "value": static.get("value"),
                "provenance": "observed_runtime",
                "evidence_refs": evidence_refs,
            }
        elif static is not None and dynamic is not None:
            fused[key] = {
                "value": {"static": static.get("value"), "dynamic": dynamic.get("value")},
                "provenance": "conflict",
                "evidence_refs": evidence_refs,
            }
    return fused
