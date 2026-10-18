"""Conservative admission policy for tool-produced audit deltas.

The canonical model review is the scoreable baseline.  Tools may corroborate
that baseline, propose a tightly located label correction, or add a finding
that has independent corroboration.  A single scanner is not allowed to turn
an empty Primary result into an unbounded list of authoritative findings.

This gate is deliberately deterministic.  It consumes only durable Findings
and Evidence, so recovery and replay produce the same report without another
model call.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from secmind.direct_anchor_pipeline import (
    DIRECT_ANCHOR_PIPELINE_VERSION,
    CandidateState,
    CandidateStore,
    DeltaAction,
    DeltaAdjudicator,
    DeltaDisposition,
    stable_digest,
)
from secmind.java_security_flows import LDAP_FILTER_CONCAT_RULE, SENSITIVE_LOG_VALUE_RULE
from secmind.java_semantic_sast import NATIVE_RULE_ID as JAVA_WEAK_DIGEST_RULE_ID
from secmind.java_semantic_sast import RULE_BUNDLE_DIGEST as JAVA_SEMANTIC_RULE_BUNDLE_DIGEST
from secmind.java_semantic_sast import SEMANTIC_SIGNAL as JAVA_WEAK_DIGEST_SIGNAL
from secmind.java_semantic_sast import TOOL_NAME as JAVA_SEMANTIC_TOOL_NAME
from secmind.quarantine import CapsuleConflictError, CapsuleIntegrityError, FailureCapsule, FailureCapsuleStore
from secmind.schemas import AgentState, DecisionRecord, Evidence, Finding
from secmind.tool_assurance import (
    finding_assurance_fingerprint,
    independently_rehash_evidence_set,
    verified_semantic_assurance,
)
from secmind.tooling.core import PYTHON_DATAFLOW_RULE_BUNDLE_DIGEST
from secmind.web_static_audit import CAPTCHA_STAGE_BYPASS_RULE as WEB_CAPTCHA_STAGE_BYPASS_RULE
from secmind.web_static_audit import PASSWORD_CHANGE_WITHOUT_REAUTH_RULE as WEB_PASSWORD_REAUTH_RULE
from secmind.web_static_audit import RULE_BUNDLE_DIGEST as WEB_WORKFLOW_RULE_BUNDLE_DIGEST
from secmind.web_static_audit import TOOL_NAME as WEB_WORKFLOW_TOOL_NAME
from secmind.web_static_audit import WEAK_PASSWORD_HASH_RULE as WEB_WEAK_PASSWORD_HASH_RULE

_CWE_PATTERN = re.compile(r"(?:CWE[-_ ]?)?(\d+)$", re.IGNORECASE)
_RELATED_CWE_FAMILIES = (
    frozenset({22, 23}),
    frozenset({77, 78}),
    frozenset({89, 564}),
    frozenset({94, 95}),
    frozenset({330, 337}),
    frozenset({602, 693, 840, 841}),
)
_HIGH_SPECIFICITY_FLOW_RULES = {
    "PYFLOW-DJANGO-RAW-SQL-001",
    "PYFLOW-SQL-001",
    "PYFLOW-SSRF-001",
    "PYFLOW-PREDICTABLE-PRNG-001",
    LDAP_FILTER_CONCAT_RULE,
    SENSITIVE_LOG_VALUE_RULE,
    WEB_CAPTCHA_STAGE_BYPASS_RULE,
    WEB_PASSWORD_REAUTH_RULE,
    WEB_WEAK_PASSWORD_HASH_RULE,
}
_SMALL_GAP_RESCUE_RULES = {"PYFLOW-CMD-001"}
_SMALL_GAP_MAX_BYTES = 16_384
_DETERMINISTIC_BUILTIN_RULE_CONTRACTS = {
    "PYFLOW-DJANGO-RAW-SQL-001": ("python_taint_audit", PYTHON_DATAFLOW_RULE_BUNDLE_DIGEST),
    "PYFLOW-SQL-001": ("python_taint_audit", PYTHON_DATAFLOW_RULE_BUNDLE_DIGEST),
    "PYFLOW-SSRF-001": ("python_taint_audit", PYTHON_DATAFLOW_RULE_BUNDLE_DIGEST),
    "PYFLOW-PREDICTABLE-PRNG-001": ("python_taint_audit", PYTHON_DATAFLOW_RULE_BUNDLE_DIGEST),
    LDAP_FILTER_CONCAT_RULE: (JAVA_SEMANTIC_TOOL_NAME, JAVA_SEMANTIC_RULE_BUNDLE_DIGEST),
    SENSITIVE_LOG_VALUE_RULE: (JAVA_SEMANTIC_TOOL_NAME, JAVA_SEMANTIC_RULE_BUNDLE_DIGEST),
    "PYFLOW-CMD-001": ("python_taint_audit", PYTHON_DATAFLOW_RULE_BUNDLE_DIGEST),
    WEB_CAPTCHA_STAGE_BYPASS_RULE: (WEB_WORKFLOW_TOOL_NAME, WEB_WORKFLOW_RULE_BUNDLE_DIGEST),
    WEB_PASSWORD_REAUTH_RULE: (WEB_WORKFLOW_TOOL_NAME, WEB_WORKFLOW_RULE_BUNDLE_DIGEST),
    WEB_WEAK_PASSWORD_HASH_RULE: (WEB_WORKFLOW_TOOL_NAME, WEB_WORKFLOW_RULE_BUNDLE_DIGEST),
}
_MANIFEST_PATH_CANONICALIZATION_VERSION = "manifest-path-canonicalization-1.1"


@dataclass(frozen=True)
class ToolGainSummary:
    candidates: int
    corroborated_into_primary: int
    accepted_corrections: int
    accepted_new: int
    quarantined: int
    quarantined_finding_ids: tuple[str, ...]
    typed_delta_ids: tuple[str, ...] = ()
    candidate_store_digest: str | None = None
    failure_capsule_ids: tuple[str, ...] = ()


class ToolGainGate:
    """Filter optional tool findings without weakening the Primary result."""

    @staticmethod
    def _resolve_capsule_store(state: AgentState, store: FailureCapsuleStore | None) -> FailureCapsuleStore | None:
        if store is not None:
            return store
        raw_root = state.audit_coverage.get("failure_capsule_root") or state.audit_coverage.get("capsule_root")
        if not isinstance(raw_root, (str, Path)) or not str(raw_root):
            return None
        return FailureCapsuleStore(Path(raw_root))

    @classmethod
    def apply(
        cls,
        state: AgentState,
        *,
        artifact_store: Any | None = None,
        capsule_store: FailureCapsuleStore | None = None,
    ) -> ToolGainSummary:
        primary_completed = bool(state.audit_coverage.get("canonical_primary_completed"))
        primary_attempted = bool(state.audit_coverage.get("canonical_primary_attempted"))
        strict_direct = (
            state.audit_coverage.get("direct_anchor_pipeline") is True
            and state.audit_coverage.get("direct_anchor_strict") is not False
        )
        # Pure offline/tool-only operation remains available.  Once a live
        # Primary was attempted, however, both its success and degradation
        # paths need the same precision boundary.
        if not primary_completed and not primary_attempted and not strict_direct:
            return ToolGainSummary(0, 0, 0, 0, 0, ())

        # Never mutate the immutable Anchor object through a shared Finding
        # instance when adding corroboration metadata to the working lane.
        primary = [item.model_copy(deep=True) for item in state.findings if item.raw.get("canonical_primary") is True]
        candidates = [
            item.model_copy(deep=True) for item in state.findings if item.raw.get("canonical_primary") is not True
        ]
        if not candidates:
            summary = ToolGainSummary(0, 0, 0, 0, 0, ())
            cls._record(state, summary, (), ())
            return summary

        capsule_store = cls._resolve_capsule_store(state, capsule_store)
        evidence_by_id = {item.evidence_id: item for item in state.evidence}
        rehashed_evidence_ids: set[str] | None = None
        cas_failures: dict[str, str] = {}
        if artifact_store is not None:
            verified, cas_failures = independently_rehash_evidence_set(
                evidence_by_id,
                artifact_store,
                run_id=state.run_id,
            )
            rehashed_evidence_ids = set(verified)
            state.audit_coverage["gain_gate_cas_rehash"] = {
                "verified_evidence_ids": sorted(verified),
                "failures": dict(sorted(cas_failures.items())),
                "source": "independent_cas_read",
            }
        if strict_direct:
            return cls._apply_direct_anchor(
                state,
                primary,
                candidates,
                evidence_by_id,
                rehashed_evidence_ids=rehashed_evidence_ids,
                cas_failures=cas_failures,
                capsule_store=capsule_store,
            )
        small_primary_gap = not primary and sum(item.size_bytes for item in state.input_artifacts) <= (
            _SMALL_GAP_MAX_BYTES
        )
        accepted: list[Finding] = []
        corroborated = 0
        corrections = 0
        accepted_new = 0
        quarantined: list[str] = []
        accepted_evidence: set[str] = set()
        java_weak_digest_gain_used = False
        candidate_lifecycle: list[dict[str, object]] = []

        for candidate in sorted(candidates, key=cls._sort_key):
            same_finding = cls._nearest_primary(candidate, primary, require_same_cwe=True)
            if same_finding is not None:
                if cls._has_authorized_assurance(
                    candidate,
                    evidence_by_id,
                    rehashed_evidence_ids=rehashed_evidence_ids,
                ):
                    cls._annotate_corroboration(same_finding, candidate, evidence_by_id)
                    corroborated += 1
                    accepted_evidence.update(candidate.evidence_ids)
                    candidate_lifecycle.append(
                        cls._candidate_record(candidate, "CORROBORATED", "same_location_same_cwe")
                    )
                    continue

            nearby = cls._nearest_related_primary(candidate, primary)
            if (
                nearby is not None
                and cls._related_cwe(candidate.rule_id, nearby.rule_id)
                and cls._has_authorized_assurance(
                    candidate,
                    evidence_by_id,
                    rehashed_evidence_ids=rehashed_evidence_ids,
                )
            ):
                # Same source location plus an independently executed scanner is
                # sufficient to expose a bounded label-correction candidate.
                accepted.append(candidate)
                corrections += 1
                accepted_evidence.update(candidate.evidence_ids)
                candidate_lifecycle.append(cls._candidate_record(candidate, "ACCEPTED", "related_cwe_same_location"))
                continue

            java_weak_digest_gain = (
                not java_weak_digest_gain_used
                and primary_completed
                and not primary
                and cls._java_weak_digest_prequalified(
                    state,
                    candidate,
                    evidence_by_id,
                    rehashed_evidence_ids=rehashed_evidence_ids,
                )
            )
            if java_weak_digest_gain or cls._prequalified(
                candidate,
                evidence_by_id,
                allow_small_gap_rescue=small_primary_gap,
                rehashed_evidence_ids=rehashed_evidence_ids,
            ):
                accepted.append(candidate)
                accepted_new += 1
                accepted_evidence.update(candidate.evidence_ids)
                java_weak_digest_gain_used = java_weak_digest_gain_used or java_weak_digest_gain
                candidate_lifecycle.append(
                    cls._candidate_record(
                        candidate,
                        "ACCEPTED",
                        "java_semantic_ticket" if java_weak_digest_gain else "prequalified_semantic",
                    )
                )
                continue

            producers = cls._producers(candidate, evidence_by_id)
            # Cross-tool agreement is an availability fallback when the live
            # Primary degraded.  When Primary completed, unrelated new labels
            # remain shadow findings unless the stricter v0.7 semantic gate
            # prequalified them; this prevents recall-oriented scanners from
            # reducing the scoreable baseline's precision.
            if (
                not primary_completed
                and len(producers) >= 2
                and cls._has_authorized_assurance(
                    candidate,
                    evidence_by_id,
                    rehashed_evidence_ids=rehashed_evidence_ids,
                )
            ):
                accepted.append(candidate)
                accepted_new += 1
                accepted_evidence.update(candidate.evidence_ids)
                candidate_lifecycle.append(cls._candidate_record(candidate, "ACCEPTED", "cross_tool_corroboration"))
                continue

            quarantined.append(candidate.finding_id)
            candidate_lifecycle.append(cls._candidate_record(candidate, "QUARANTINED", "not_authorized"))

        state.findings = sorted([*primary, *accepted], key=cls._sort_key)
        capsule_ids = cls._capture_failure_capsules(
            state,
            candidates,
            candidate_lifecycle,
            evidence_by_id,
            capsule_store=capsule_store,
            cas_failures=cas_failures,
        )
        summary = ToolGainSummary(
            candidates=len(candidates),
            corroborated_into_primary=corroborated,
            accepted_corrections=corrections,
            accepted_new=accepted_new,
            quarantined=len(quarantined),
            quarantined_finding_ids=tuple(sorted(quarantined)),
            failure_capsule_ids=tuple(capsule_ids),
        )
        cls._refresh_report_findings(state, state.findings)
        cls._record(state, summary, tuple(sorted(accepted_evidence)), tuple(candidate_lifecycle))
        return summary

    @classmethod
    def _apply_direct_anchor(
        cls,
        state: AgentState,
        primary: list[Finding],
        candidates: list[Finding],
        evidence_by_id: dict[str, Evidence],
        *,
        rehashed_evidence_ids: set[str] | None = None,
        cas_failures: Mapping[str, str] | None = None,
        capsule_store: FailureCapsuleStore | None = None,
    ) -> ToolGainSummary:
        """Run the v0.8.2 order: store -> correlate -> delta -> admission.

        ``state.findings`` is only a mutable working projection here.  The
        immutable Anchor lives in ``audit_coverage['anchor_report']`` and is
        never edited by corroboration or correction metadata.
        """

        primary_completed = bool(state.audit_coverage.get("canonical_primary_completed"))
        previous = state.audit_coverage.get("typed_deltas")
        if state.audit_coverage.get("direct_anchor_gain_applied") is True and isinstance(previous, list):
            gate = state.audit_coverage.get("tool_gain_gate", {})
            if isinstance(gate, dict):
                return ToolGainSummary(
                    int(gate.get("candidates", len(candidates))),
                    int(gate.get("corroborated_into_primary", 0)),
                    int(gate.get("accepted_corrections", 0)),
                    int(gate.get("accepted_new", 0)),
                    int(gate.get("quarantined", 0)),
                    tuple(str(item) for item in gate.get("quarantined_finding_ids", [])),
                    tuple(str(item.get("delta_id")) for item in previous if isinstance(item, dict)),
                    str(state.audit_coverage.get("candidate_store_digest"))
                    if state.audit_coverage.get("candidate_store_digest")
                    else None,
                    tuple(
                        str(item)
                        for item in state.audit_coverage.get("failure_capsule_ids", [])
                        if isinstance(item, str)
                    ),
                )

        primary, evidence_by_id, primary_path_diagnostics = cls._canonicalize_manifest_bound_paths(
            state,
            primary,
            evidence_by_id,
        )
        prepared_candidates, prepared_evidence = cls._prepare_direct_anchor_inputs(
            state,
            candidates,
            evidence_by_id,
            rehashed_evidence_ids=rehashed_evidence_ids,
        )
        candidate_path_diagnostics = state.audit_coverage.get("tool_path_canonicalization", {})
        primary_canonicalized = primary_path_diagnostics.get("canonicalized_count", 0)
        candidate_canonicalized = (
            candidate_path_diagnostics.get("canonicalized_count", 0)
            if isinstance(candidate_path_diagnostics, Mapping)
            else 0
        )
        state.audit_coverage["tool_path_canonicalization"] = {
            "version": _MANIFEST_PATH_CANONICALIZATION_VERSION,
            "primary": primary_path_diagnostics,
            "candidates": candidate_path_diagnostics,
            "canonicalized_count": (primary_canonicalized if isinstance(primary_canonicalized, int) else 0)
            + (candidate_canonicalized if isinstance(candidate_canonicalized, int) else 0),
        }
        store = CandidateStore.from_state(state)
        for candidate in sorted(prepared_candidates, key=cls._sort_key):
            store.register(candidate, prepared_evidence)
        clusters = store.correlate()
        anchor_digest = str(
            state.audit_coverage.get("anchor_semantic_digest")
            or stable_digest(
                {
                    "findings": [item.model_dump(mode="json") for item in primary],
                    "evidence": [
                        item.model_dump(mode="json")
                        for item in state.evidence
                        if item.evidence_id in {ref for finding in primary for ref in finding.evidence_ids}
                    ],
                }
            )
        )
        deltas = DeltaAdjudicator().adjudicate(
            run_id=state.run_id,
            clusters=clusters,
            anchor_findings=primary,
            evidence_by_id=prepared_evidence,
            primary_degraded=not primary_completed,
            anchor_semantic_digest=anchor_digest,
        )
        accepted: list[Finding] = []
        quarantined: list[str] = []
        corroborated = 0
        corrections = 0
        accepted_new = 0
        accepted_evidence: set[str] = set()
        original_by_finding_id = {item.finding_id: item for item in prepared_candidates}
        for delta in deltas:
            cluster = next(item for item in clusters if item.cluster_id == delta.cluster_id)
            target_state = {
                DeltaDisposition.ACCEPTED: (
                    CandidateState.CORROBORATED if delta.action == DeltaAction.SUPPLEMENT else CandidateState.ACCEPTED
                ),
                DeltaDisposition.SHADOW: CandidateState.SHADOW,
                DeltaDisposition.REJECTED: CandidateState.REJECTED,
                DeltaDisposition.QUARANTINED: CandidateState.QUARANTINED,
            }[delta.disposition]
            authorized_records = []
            for candidate_id in cluster.candidate_ids:
                record = next(item for item in cluster.records if item.candidate_id == candidate_id)
                original = original_by_finding_id.get(record.finding.finding_id, record.finding)
                candidate_authorized = cls._has_authorized_assurance(
                    original,
                    prepared_evidence,
                    rehashed_evidence_ids=rehashed_evidence_ids,
                )
                record_state = target_state
                if delta.disposition == DeltaDisposition.ACCEPTED and not candidate_authorized:
                    # A cluster can contain one valid and one forged scanner
                    # record.  The valid representative remains admissible,
                    # while the forged member receives its own quarantine
                    # transition instead of inheriting the cluster decision.
                    record_state = CandidateState.QUARANTINED
                    quarantined.append(record.finding.finding_id)
                else:
                    authorized_records.append(record)
                store.transition(candidate_id, record_state, delta.reason_code, cluster_id=cluster.cluster_id)
            if delta.disposition == DeltaDisposition.ACCEPTED:
                authorized_evidence_ids = {
                    evidence_id for record in authorized_records for evidence_id in record.finding.evidence_ids
                }
                accepted_evidence.update(authorized_evidence_ids)
                authorized_delta_finding = delta.finding
                if authorized_delta_finding is not None:
                    authorized_delta_finding = authorized_delta_finding.model_copy(
                        update={"evidence_ids": sorted(authorized_evidence_ids)}
                    )
                if delta.action == DeltaAction.SUPPLEMENT:
                    corroborated += 1
                elif delta.action == DeltaAction.CORRECT:
                    corrections += 1
                    if authorized_delta_finding is not None and authorized_records:
                        accepted.append(authorized_delta_finding)
                else:
                    accepted_new += 1
                    if authorized_delta_finding is not None and authorized_records:
                        accepted.append(authorized_delta_finding)
            else:
                quarantined.extend(item.finding.finding_id for item in cluster.records)

        store_digest = store.persist(state)
        typed_payload = [item.model_dump(mode="json") for item in deltas]
        state.audit_coverage["typed_deltas"] = typed_payload
        state.audit_coverage["candidate_store_digest"] = store_digest
        state.audit_coverage["direct_anchor_gain_applied"] = True
        state.audit_coverage["delta_adjudication"] = {
            "stage_order": [
                "scouts_tools",
                "semantic_cluster",
                "producer_merge",
                "gain_gate",
                "typed_delta",
                "admission",
            ],
            "cluster_count": len(clusters),
            "delta_count": len(deltas),
            "accepted": sum(item.disposition == DeltaDisposition.ACCEPTED for item in deltas),
            "quarantined": sum(item.disposition == DeltaDisposition.QUARANTINED for item in deltas),
            "anchor_semantic_digest": anchor_digest,
        }
        state.findings = sorted([*primary, *accepted], key=cls._sort_key)
        candidate_lifecycle = tuple(
            {
                "candidate_id": item.candidate_id,
                "finding_id": item.finding.finding_id,
                "rule_id": item.finding.rule_id,
                "path": item.finding.path,
                "line": item.finding.line,
                "evidence_ids": list(item.finding.evidence_ids),
                "disposition": item.state.value.upper(),
                "reason_code": item.transitions[-1].reason_code if item.transitions else "registered",
                "gate_version": DIRECT_ANCHOR_PIPELINE_VERSION,
            }
            for item in store.replay()
        )
        capsule_ids = cls._capture_failure_capsules(
            state,
            candidates,
            candidate_lifecycle,
            evidence_by_id,
            capsule_store=capsule_store,
            cas_failures=cas_failures or {},
            candidate_store=store,
        )
        summary = ToolGainSummary(
            candidates=len(candidates),
            corroborated_into_primary=corroborated,
            accepted_corrections=corrections,
            accepted_new=accepted_new,
            quarantined=len(quarantined),
            quarantined_finding_ids=tuple(sorted(set(quarantined))),
            typed_delta_ids=tuple(item.delta_id for item in deltas),
            candidate_store_digest=store_digest,
            failure_capsule_ids=tuple(capsule_ids),
        )
        cls._refresh_report_findings(state, state.findings)
        if state.report is not None and accepted_evidence:
            report_evidence = {item.evidence_id: item for item in [*state.report.evidence, *state.evidence]}
            state.report = state.report.model_copy(
                update={"evidence": [report_evidence[item] for item in sorted(report_evidence)]}
            )
        cls._record(state, summary, tuple(sorted(accepted_evidence)), candidate_lifecycle)
        return summary

    @classmethod
    def _prepare_direct_anchor_inputs(
        cls,
        state: AgentState,
        candidates: list[Finding],
        evidence_by_id: dict[str, Evidence],
        *,
        rehashed_evidence_ids: set[str] | None = None,
    ) -> tuple[list[Finding], dict[str, Evidence]]:
        """Make the direct pipeline consume only gate-authorized semantics.

        The legacy direct adjudicator still understands scanner-era
        ``assurance_level`` fields.  Before it sees a candidate, this gate
        removes those fields unless a signed contract or a closed native-rule
        proof has already authorized the candidate.  This keeps the change
        within the GainGate boundary and prevents a raw label from becoming a
        second producer or a high-specificity admission.
        """

        candidates, evidence_by_id, path_diagnostics = cls._canonicalize_manifest_bound_paths(
            state,
            candidates,
            evidence_by_id,
        )
        state.audit_coverage["tool_path_canonicalization"] = path_diagnostics
        canonical_evidence = {item.evidence_id: item for item in state.evidence}
        canonical_evidence.update(evidence_by_id)
        state.evidence = [canonical_evidence[item.evidence_id] for item in state.evidence]
        if state.report is not None:
            report_evidence = {item.evidence_id: item for item in state.report.evidence}
            for evidence_id, evidence in evidence_by_id.items():
                if evidence_id in report_evidence:
                    report_evidence[evidence_id] = evidence
            state.report = state.report.model_copy(
                update={"evidence": [report_evidence[item.evidence_id] for item in state.report.evidence]}
            )

        authorized_evidence_ids = {
            evidence_id
            for candidate in candidates
            if cls._has_authorized_assurance(
                candidate,
                evidence_by_id,
                rehashed_evidence_ids=rehashed_evidence_ids,
            )
            for evidence_id in candidate.evidence_ids
        }
        prepared_evidence = dict(evidence_by_id)
        for evidence_id, evidence in evidence_by_id.items():
            if evidence_id in authorized_evidence_ids:
                continue
            metadata = dict(evidence.metadata)
            metadata.pop("assurance_level", None)
            metadata.pop("tool_assurance", None)
            metadata.pop("tool_name", None)
            metadata.pop("producer", None)
            metadata.pop("producer_id", None)
            prepared_evidence[evidence_id] = evidence.model_copy(update={"metadata": metadata, "source": ""})

        prepared: list[Finding] = []
        builtin_failure_counts: dict[str, int] = {}
        for candidate in candidates:
            sanitized_raw = dict(candidate.raw)
            sanitized_raw.pop("deterministic_native_taxonomy_refinement", None)
            candidate = candidate.model_copy(update={"raw": sanitized_raw}, deep=True)
            builtin_rule, builtin_failure = cls._deterministic_builtin_rule_check(
                candidate,
                evidence_by_id,
                rehashed_evidence_ids=rehashed_evidence_ids,
            )
            if builtin_rule is None:
                builtin_failure_counts[builtin_failure] = builtin_failure_counts.get(builtin_failure, 0) + 1
            has_contract = any(
                cls._verified_evidence_contract(
                    candidate,
                    evidence_by_id[evidence_id],
                    rehashed_evidence_ids=rehashed_evidence_ids,
                )
                for evidence_id in candidate.evidence_ids
                if evidence_id in evidence_by_id
            )
            java_builtin = cls._java_weak_digest_prequalified(
                state,
                candidate,
                evidence_by_id,
                rehashed_evidence_ids=rehashed_evidence_ids,
            )
            if has_contract or builtin_rule is not None or java_builtin:
                raw = dict(candidate.raw)
                if builtin_rule is not None or java_builtin:
                    raw["assurance_level"] = "semantically_corroborated"
                    raw["assurance_source"] = (
                        f"deterministic_builtin_rule:{builtin_rule}"
                        if builtin_rule is not None
                        else "deterministic_builtin_rule:JAVA-WEAK-DIGEST-TICKET"
                    )
                if builtin_rule in _HIGH_SPECIFICITY_FLOW_RULES:
                    raw["deterministic_native_taxonomy_refinement"] = True
                prepared.append(candidate.model_copy(update={"raw": raw}))
                continue
            raw = dict(candidate.raw)
            for key in ("assurance_level", "gain_action", "tool_name", "producer", "producer_id"):
                raw.pop(key, None)
            # An unverified candidate may still be retained as a same-CWE
            # corroboration, but it cannot become a label correction or an
            # independent new finding through the direct adjudicator.
            prepared.append(candidate.model_copy(update={"raw": raw, "evidence_ids": []}))
        state.audit_coverage["deterministic_builtin_rule_diagnostics"] = {
            "checked_count": len(candidates),
            "authorized_count": len(candidates) - sum(builtin_failure_counts.values()),
            "failure_counts": dict(sorted(builtin_failure_counts.items())),
        }
        return prepared, prepared_evidence

    @classmethod
    def _canonicalize_manifest_bound_paths(
        cls,
        state: AgentState,
        candidates: list[Finding],
        evidence_by_id: dict[str, Evidence],
    ) -> tuple[list[Finding], dict[str, Evidence], dict[str, object]]:
        """Resolve tool paths to immutable manifest paths without prefix guessing.

        Tool containers commonly see ``input/foo.py`` while the Canonical
        Primary sees ``foo.py``.  Treating those as different sources prevents
        corroboration and turns bounded corrections into duplicate findings.
        A path is rewritten only when its declared file digest and a
        bidirectional suffix match identify exactly one immutable input row.
        Ambiguous or forged records remain unchanged and therefore cannot gain
        authority from this compatibility projection.
        """

        manifest: list[tuple[str, str, str]] = []
        invalid_manifest = False
        for artifact in state.input_artifacts:
            normalized = cls._safe_path_key(artifact.relative_path)
            if not normalized or not cls._valid_sha256(artifact.sha256):
                invalid_manifest = True
                break
            manifest.append((normalized, artifact.relative_path.replace("\\", "/"), artifact.sha256.lower()))
        if invalid_manifest or not manifest:
            return (
                candidates,
                evidence_by_id,
                {
                    "version": _MANIFEST_PATH_CANONICALIZATION_VERSION,
                    "canonicalized_count": 0,
                    "unchanged_count": len(candidates),
                    "ambiguous_count": 0,
                    "invalid_manifest": invalid_manifest,
                },
            )

        prepared_evidence = dict(evidence_by_id)
        prepared_candidates: list[Finding] = []
        canonicalized = 0
        ambiguous = 0
        for candidate in candidates:
            candidate_path = cls._safe_path_key(candidate.path)
            if candidate_path is None:
                prepared_candidates.append(candidate)
                ambiguous += int(bool(candidate.evidence_ids))
                continue
            bindings: set[tuple[str, str]] = set()
            for evidence_id in candidate.evidence_ids:
                evidence = evidence_by_id.get(evidence_id)
                if evidence is None:
                    continue
                metadata_path = evidence.metadata.get("path")
                file_sha256 = evidence.metadata.get("file_sha256")
                metadata_path_key = cls._safe_path_key(metadata_path)
                if metadata_path_key is None or not cls._valid_sha256(file_sha256):
                    continue
                digest = str(file_sha256).lower()
                matches = [
                    (canonical_path, canonical_digest)
                    for normalized, canonical_path, canonical_digest in manifest
                    if canonical_digest == digest
                    and cls._path_keys_equivalent(normalized, candidate_path)
                    and cls._path_keys_equivalent(normalized, metadata_path_key)
                ]
                bindings.update(matches)
            if len(bindings) != 1:
                ambiguous += int(bool(bindings) or bool(candidate.evidence_ids))
                prepared_candidates.append(candidate)
                continue

            canonical_path, canonical_digest = next(iter(bindings))
            if cls._safe_path_key(canonical_path) == candidate_path:
                prepared_candidates.append(candidate)
                continue
            raw = dict(candidate.raw)
            raw.setdefault("source_reported_path", candidate.path)
            canonical_candidate = candidate.model_copy(update={"path": canonical_path, "raw": raw}, deep=True)
            for evidence_id in candidate.evidence_ids:
                evidence = prepared_evidence.get(evidence_id)
                if evidence is None:
                    continue
                metadata = dict(evidence.metadata)
                metadata_path = metadata.get("path")
                file_sha256 = metadata.get("file_sha256")
                if (
                    isinstance(metadata_path, str)
                    and cls._path_keys_equivalent(
                        cls._safe_path_key(canonical_path),
                        cls._safe_path_key(metadata_path),
                    )
                    and isinstance(file_sha256, str)
                    and cls._valid_sha256(file_sha256)
                    and file_sha256.lower() == canonical_digest
                ):
                    metadata.setdefault("source_reported_path", metadata_path)
                    metadata["path"] = canonical_path
                    prepared_evidence[evidence_id] = evidence.model_copy(update={"metadata": metadata}, deep=True)
            prepared_candidates.append(canonical_candidate)
            canonicalized += 1

        return (
            prepared_candidates,
            prepared_evidence,
            {
                "version": _MANIFEST_PATH_CANONICALIZATION_VERSION,
                "canonicalized_count": canonicalized,
                "unchanged_count": len(prepared_candidates) - canonicalized,
                "ambiguous_count": ambiguous,
                "invalid_manifest": False,
            },
        )

    @classmethod
    def authorizes_deterministic_native_correction(
        cls,
        state: AgentState,
        candidate: Finding,
        target: Finding,
        evidence_by_id: dict[str, Evidence],
        *,
        rehashed_evidence_ids: set[str] | None,
    ) -> bool:
        """Revalidate a closed native taxonomy correction at Admission."""

        candidate_path = cls._manifest_bound_finding_path(state, candidate, evidence_by_id)
        target_path = cls._manifest_bound_finding_path(state, target, evidence_by_id)
        if (
            rehashed_evidence_ids is None
            or not candidate.evidence_ids
            or not set(candidate.evidence_ids).issubset(rehashed_evidence_ids)
            or candidate_path is None
            or candidate_path != target_path
            or not cls._related_cwe(candidate.rule_id, target.rule_id)
            or candidate.line is None
            or target.line is None
            or abs(candidate.line - target.line) > 2
            or cls._deterministic_builtin_rule(
                candidate,
                evidence_by_id,
                rehashed_evidence_ids=rehashed_evidence_ids,
            )
            not in _HIGH_SPECIFICITY_FLOW_RULES
        ):
            return False
        return True

    @classmethod
    def _manifest_bound_finding_path(
        cls,
        state: AgentState,
        finding: Finding,
        evidence_by_id: Mapping[str, Evidence],
    ) -> str | None:
        reported_path = cls._safe_path_key(finding.path)
        if reported_path is None:
            return None
        digests = {
            str(evidence_by_id[evidence_id].metadata.get("file_sha256", "")).lower()
            for evidence_id in finding.evidence_ids
            if evidence_id in evidence_by_id
            and cls._valid_sha256(evidence_by_id[evidence_id].metadata.get("file_sha256"))
        }
        raw_digest = finding.raw.get("file_sha256")
        if cls._valid_sha256(raw_digest):
            digests.add(str(raw_digest).lower())
        if len(digests) != 1:
            return None
        digest = next(iter(digests))
        matches = {
            cls._safe_path_key(artifact.relative_path)
            for artifact in state.input_artifacts
            if cls._valid_sha256(artifact.sha256)
            and artifact.sha256.lower() == digest
            and cls._safe_path_key(artifact.relative_path) is not None
            and (
                cls._safe_path_key(artifact.relative_path) == reported_path
                or str(cls._safe_path_key(artifact.relative_path)).endswith(f"/{reported_path}")
                or reported_path.endswith(f"/{cls._safe_path_key(artifact.relative_path)}")
            )
        }
        return next(iter(matches)) if len(matches) == 1 else None

    @staticmethod
    def _normal_path(path: str) -> str:
        return PurePosixPath(path.replace("\\", "/")).as_posix().casefold()

    @staticmethod
    def _safe_path_key(path: object) -> str | None:
        if not isinstance(path, str) or not path:
            return None
        normalized = path.replace("\\", "/")
        parsed = PurePosixPath(normalized)
        if (
            parsed.is_absolute()
            or (parsed.parts and parsed.parts[0].endswith(":"))
            or any(part in {"", ".", ".."} for part in parsed.parts)
            or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
        ):
            return None
        return parsed.as_posix().casefold()

    @staticmethod
    def _path_keys_equivalent(left: str | None, right: str | None) -> bool:
        """Match two already-safe paths only through a complete suffix.

        The immutable input manifest may contain an upload or runner namespace
        that is deliberately absent from a scanner record.  A content digest
        alone is not sufficient because duplicate files are possible, so both
        independently reported paths must resolve to the same unique manifest
        row.  Component-boundary suffix matching preserves that namespace
        compatibility without accepting basename substrings or traversal.
        """

        if left is None or right is None:
            return False
        return left == right or left.endswith(f"/{right}") or right.endswith(f"/{left}")

    @staticmethod
    def _cwe(rule_id: str) -> int | None:
        match = _CWE_PATTERN.search(rule_id.strip())
        return int(match.group(1)) if match else None

    @classmethod
    def _related_cwe(cls, left: str, right: str) -> bool:
        left_cwe = cls._cwe(left)
        right_cwe = cls._cwe(right)
        if left_cwe is None or right_cwe is None or left_cwe == right_cwe:
            return False
        return any({left_cwe, right_cwe} <= family for family in _RELATED_CWE_FAMILIES)

    @classmethod
    def _nearest_primary(
        cls,
        candidate: Finding,
        primary: list[Finding],
        *,
        require_same_cwe: bool,
    ) -> Finding | None:
        matches: list[tuple[int, str, Finding]] = []
        for item in primary:
            if cls._normal_path(item.path) != cls._normal_path(candidate.path):
                continue
            if require_same_cwe and cls._cwe(item.rule_id) != cls._cwe(candidate.rule_id):
                continue
            if item.line is None or candidate.line is None:
                distance = 0 if item.line == candidate.line else 3
            else:
                distance = abs(item.line - candidate.line)
            maximum = 5 if require_same_cwe else 2
            if distance <= maximum:
                matches.append((distance, item.finding_id, item))
        if not matches:
            return None
        return min(matches, key=lambda value: (value[0], value[1]))[2]

    @classmethod
    def _nearest_related_primary(cls, candidate: Finding, primary: list[Finding]) -> Finding | None:
        matches: list[tuple[int, str, Finding]] = []
        for item in primary:
            if cls._normal_path(item.path) != cls._normal_path(candidate.path):
                continue
            if not cls._related_cwe(candidate.rule_id, item.rule_id):
                continue
            if item.line is None or candidate.line is None:
                distance = 0 if item.line == candidate.line else 3
            else:
                distance = abs(item.line - candidate.line)
            if distance <= 2:
                matches.append((distance, item.finding_id, item))
        return min(matches, key=lambda value: (value[0], value[1]))[2] if matches else None

    @classmethod
    def _producers(cls, finding: Finding, evidence_by_id: dict[str, Evidence]) -> set[str]:
        # Producer identity is derived from durable evidence only.  Finding
        # ``raw`` is scanner-controlled and can otherwise manufacture a
        # two-tool quorum with one piece of evidence.
        producers: set[str] = set()
        for evidence_id in finding.evidence_ids:
            evidence = evidence_by_id.get(evidence_id)
            if evidence is None:
                continue
            tool_name = evidence.metadata.get("tool_name")
            if isinstance(tool_name, str) and tool_name:
                producers.add(tool_name)
        return producers

    @classmethod
    def _has_authorized_assurance(
        cls,
        finding: Finding,
        evidence_by_id: dict[str, Evidence],
        *,
        rehashed_evidence_ids: set[str] | None = None,
    ) -> bool:
        return (
            any(
                cls._verified_evidence_contract(
                    finding,
                    evidence_by_id[evidence_id],
                    rehashed_evidence_ids=rehashed_evidence_ids,
                )
                for evidence_id in finding.evidence_ids
                if evidence_id in evidence_by_id
            )
            or cls._deterministic_builtin_rule(
                finding,
                evidence_by_id,
                rehashed_evidence_ids=rehashed_evidence_ids,
            )
            is not None
        )

    @staticmethod
    def _verified_evidence_contract(
        finding: Finding,
        evidence: Evidence,
        *,
        rehashed_evidence_ids: set[str] | None = None,
    ) -> bool:
        if rehashed_evidence_ids is not None and evidence.evidence_id not in rehashed_evidence_ids:
            return False
        metadata = evidence.metadata
        declared_fingerprint = metadata.get("record_fingerprint")
        expected_fingerprint: str | None = None
        if isinstance(declared_fingerprint, str) and len(declared_fingerprint) == 64:
            expected_fingerprint = declared_fingerprint
        else:
            file_sha256 = metadata.get("file_sha256")
            expected_fingerprint = (
                finding_assurance_fingerprint(finding, file_sha256=file_sha256)
                if isinstance(file_sha256, str) and len(file_sha256) == 64
                else None
            )
        return verified_semantic_assurance(
            metadata,
            expected_finding_fingerprint=expected_fingerprint,
        )

    @classmethod
    def _prequalified(
        cls,
        finding: Finding,
        evidence_by_id: dict[str, Evidence],
        *,
        allow_small_gap_rescue: bool,
        rehashed_evidence_ids: set[str] | None = None,
    ) -> bool:
        # ``assurance_level`` and ``gain_action`` are scanner-controlled
        # presentation fields.  Neither can authorize a semantic delta.  The
        # only portable authorization is a platform-signed contract; the
        # exception is a small, closed set of deterministic native rules whose
        # parser and exact rule/tool pair are platform-owned.
        if cls._has_authorized_assurance(
            finding,
            evidence_by_id,
            rehashed_evidence_ids=rehashed_evidence_ids,
        ):
            return True
        built_in_rule = cls._deterministic_builtin_rule(
            finding,
            evidence_by_id,
            rehashed_evidence_ids=rehashed_evidence_ids,
        )
        if built_in_rule in _HIGH_SPECIFICITY_FLOW_RULES:
            return True
        return allow_small_gap_rescue and built_in_rule in _SMALL_GAP_RESCUE_RULES

    @classmethod
    def _deterministic_builtin_rule(
        cls,
        finding: Finding,
        evidence_by_id: dict[str, Evidence],
        *,
        rehashed_evidence_ids: set[str] | None = None,
    ) -> str | None:
        """Return a rule ID only for a closed, platform-owned rule contract.

        In particular, the finding's ``raw`` fields are not consulted.  A
        candidate must carry evidence from the exact trusted tool, with the
        native and normalized IDs, location, and immutable source digest bound
        to the candidate.  This keeps the built-in path deterministic without
        accepting an arbitrary ``assurance_level`` claim.
        """

        return cls._deterministic_builtin_rule_check(
            finding,
            evidence_by_id,
            rehashed_evidence_ids=rehashed_evidence_ids,
        )[0]

    @classmethod
    def _deterministic_builtin_rule_check(
        cls,
        finding: Finding,
        evidence_by_id: dict[str, Evidence],
        *,
        rehashed_evidence_ids: set[str] | None = None,
    ) -> tuple[str | None, str]:
        """Evaluate one native rule and return a content-free reason code.

        Isolated tools and the ingest manifest may expose the same file below
        different trusted namespace prefixes.  Exact path equality remains the
        default.  Component-boundary suffix equivalence is accepted only after
        the evidence artifact was independently reread from CAS; Admission
        still resolves both paths to one immutable manifest row before a delta
        can be published.
        """

        if not finding.evidence_ids:
            return None, "evidence_missing"
        failure = "evidence_missing"
        progress = -1

        def mark(stage: int, reason: str) -> None:
            nonlocal failure, progress
            if stage > progress:
                progress = stage
                failure = reason

        for evidence_id in finding.evidence_ids:
            evidence = evidence_by_id.get(evidence_id)
            if evidence is None:
                mark(0, "evidence_missing")
                continue
            if rehashed_evidence_ids is not None and evidence.evidence_id not in rehashed_evidence_ids:
                mark(1, "cas_unverified")
                continue
            metadata = evidence.metadata
            native_rule_id = metadata.get("native_rule_id")
            expected_contract = _DETERMINISTIC_BUILTIN_RULE_CONTRACTS.get(str(native_rule_id))
            if expected_contract is None or metadata.get("tool_name") != expected_contract[0]:
                mark(2, "tool_rule_pair")
                continue
            metadata_path = cls._safe_path_key(metadata.get("path"))
            finding_path = cls._safe_path_key(finding.path)
            exact_path = metadata.get("path") == finding.path
            cas_bound_equivalent_path = (
                rehashed_evidence_ids is not None
                and evidence.evidence_id in rehashed_evidence_ids
                and cls._path_keys_equivalent(metadata_path, finding_path)
            )
            if not (exact_path or cas_bound_equivalent_path):
                mark(3, "path_binding")
                continue
            if metadata.get("line") != finding.line:
                mark(4, "line_binding")
                continue
            if metadata.get("normalized_rule_id") != finding.rule_id:
                mark(5, "taxonomy_binding")
                continue
            if not cls._valid_sha256(metadata.get("file_sha256")):
                mark(6, "file_digest")
                continue
            declared_rule_bundle = metadata.get("rule_bundle_digest")
            if not cls._valid_sha256(declared_rule_bundle) or str(declared_rule_bundle).lower() != expected_contract[1]:
                mark(7, "rule_bundle_digest")
                continue
            if metadata.get("evidence_type") != "sast_flow":
                mark(8, "evidence_type")
                continue
            if metadata.get("semantic_corroboration") is not True or not metadata.get("data_flow"):
                mark(9, "semantic_flow")
                continue
            return str(native_rule_id), "authorized"
        return None, failure

    @classmethod
    def _java_weak_digest_prequalified(
        cls,
        state: AgentState,
        finding: Finding,
        evidence_by_id: dict[str, Evidence],
        *,
        rehashed_evidence_ids: set[str] | None = None,
    ) -> bool:
        """Authorize only the single ticketed, hash-bound Java semantic rule."""

        if (
            finding.rule_id != "CWE-328"
            or finding.raw.get("native_rule_id") != JAVA_WEAK_DIGEST_RULE_ID
            or finding.raw.get("tool_name") != JAVA_SEMANTIC_TOOL_NAME
            or finding.raw.get("semantic_signal") != JAVA_WEAK_DIGEST_SIGNAL
            or finding.raw.get("semantic_corroboration") is not True
            or not finding.evidence_ids
        ):
            return False
        tickets = [
            ticket
            for ticket in state.evidence_gap_tickets
            if ticket.tool_name == JAVA_SEMANTIC_TOOL_NAME
            and ticket.gap_code == "security_sensitive_weak_digest"
            and ticket.release_policy == "authoritative"
            and ticket.allowed_patch_class == "add_finding"
        ]
        if len(tickets) != 1:
            return False
        for evidence_id in finding.evidence_ids:
            evidence = evidence_by_id.get(evidence_id)
            if evidence is None:
                return False
            if rehashed_evidence_ids is not None and evidence.evidence_id not in rehashed_evidence_ids:
                return False
            metadata = evidence.metadata
            if (
                metadata.get("tool_name") != JAVA_SEMANTIC_TOOL_NAME
                or metadata.get("native_rule_id") != JAVA_WEAK_DIGEST_RULE_ID
                or metadata.get("normalized_rule_id") != "CWE-328"
                or metadata.get("semantic_signal") != JAVA_WEAK_DIGEST_SIGNAL
                or metadata.get("semantic_corroboration") is not True
                or metadata.get("path") != finding.path
                or metadata.get("line") != finding.line
                or not cls._valid_sha256(metadata.get("file_sha256"))
                or not cls._valid_sha256(metadata.get("rule_bundle_digest"))
            ):
                return False
        return True

    @classmethod
    def _capture_failure_capsules(
        cls,
        state: AgentState,
        candidates: Sequence[Finding],
        candidate_lifecycle: Sequence[Mapping[str, object]],
        evidence_by_id: Mapping[str, Evidence],
        *,
        capsule_store: FailureCapsuleStore | None,
        cas_failures: Mapping[str, str],
        candidate_store: CandidateStore | None = None,
    ) -> tuple[str, ...]:
        """Persist every non-admitted candidate as a bounded failure capsule."""

        candidate_by_finding = {item.finding_id: item for item in candidates}
        record_by_candidate = (
            {item.candidate_id: item for item in candidate_store.replay()} if candidate_store is not None else {}
        )
        existing_raw = state.audit_coverage.get("failure_capsules", [])
        existing: dict[str, FailureCapsule] = {}
        if isinstance(existing_raw, list):
            for raw in existing_raw:
                if not isinstance(raw, Mapping):
                    continue
                try:
                    capsule = FailureCapsule.model_validate(dict(raw))
                except (TypeError, ValueError) as exc:
                    raise CapsuleIntegrityError("failure capsule coverage is invalid") from exc
                existing[capsule.dedupe_key] = capsule

        capsule_ids: list[str] = []
        pending_capsules: list[FailureCapsule] = []
        for lifecycle in candidate_lifecycle:
            disposition = str(lifecycle.get("disposition", "")).upper()
            if disposition in {"ACCEPTED", "CORROBORATED"}:
                continue
            candidate_id = str(lifecycle.get("candidate_id") or lifecycle.get("finding_id") or "")
            finding_id = str(lifecycle.get("finding_id") or candidate_id)
            finding = candidate_by_finding.get(finding_id)
            record = record_by_candidate.get(candidate_id)
            if finding is None and record is not None:
                finding = record.finding
            if finding is None:
                # A transition can survive cleanup even when the full
                # candidate object has already been dropped.  Keep only the
                # identifier projection in that case.
                raw_line = lifecycle.get("line")
                raw_evidence_ids = lifecycle.get("evidence_ids", [])
                finding = Finding(
                    finding_id=finding_id or "unknown-finding",
                    rule_id=str(lifecycle.get("rule_id") or "unknown"),
                    path=str(lifecycle.get("path") or "."),
                    line=raw_line if isinstance(raw_line, int) and not isinstance(raw_line, bool) else None,
                    title="quarantined candidate",
                    description="",
                    evidence_ids=(
                        [str(item) for item in raw_evidence_ids if isinstance(item, str)]
                        if isinstance(raw_evidence_ids, (list, tuple, set, frozenset))
                        else []
                    ),
                )
            evidence_ids = tuple(str(item) for item in finding.evidence_ids)
            artifact_refs = tuple(
                str(evidence_by_id[item].artifact_ref)
                for item in evidence_ids
                if item in evidence_by_id and isinstance(evidence_by_id[item].artifact_ref, str)
            )
            tool_name: str | None = None
            tool_version: str | None = None
            rule_digest: str | None = None
            rule_version: str | None = None
            for evidence_id in evidence_ids:
                evidence = evidence_by_id.get(evidence_id)
                if evidence is None:
                    continue
                if tool_name is None and isinstance(evidence.metadata.get("tool_name"), str):
                    tool_name = evidence.metadata["tool_name"]
                if tool_version is None and isinstance(evidence.metadata.get("tool_version"), str):
                    tool_version = evidence.metadata["tool_version"]
                if rule_digest is None and isinstance(evidence.metadata.get("rule_bundle_digest"), str):
                    rule_digest = evidence.metadata["rule_bundle_digest"]
                if rule_version is None and isinstance(evidence.metadata.get("rule_version"), str):
                    rule_version = evidence.metadata["rule_version"]
            # These are provenance labels only; they never authorize a
            # candidate.  Retain them when Evidence was scrubbed during
            # cleanup so an offline capsule still identifies the attempted
            # tool/version.
            if tool_name is None and isinstance(finding.raw.get("tool_name"), str):
                tool_name = finding.raw["tool_name"]
            if tool_version is None and isinstance(finding.raw.get("tool_version"), str):
                tool_version = finding.raw["tool_version"]
            if rule_digest is None and isinstance(finding.raw.get("rule_bundle_digest"), str):
                rule_digest = finding.raw["rule_bundle_digest"]
            if rule_version is None and isinstance(finding.raw.get("rule_version"), str):
                rule_version = finding.raw["rule_version"]
            transition: dict[str, Any]
            if record is not None and record.transitions:
                transition = record.transitions[-1].model_dump(mode="json")
                lifecycle_state = disposition.casefold() or "quarantined"
                lifecycle_reason = str(lifecycle.get("reason_code") or "not_authorized")
                if (
                    str(transition.get("to_state", "")) != lifecycle_state
                    or str(transition.get("reason_code", "")) != lifecycle_reason
                ):
                    transition = {
                        "version": int(transition.get("version", record.version)) + 1,
                        "from_state": str(transition.get("to_state") or record.state.value),
                        "to_state": lifecycle_state,
                        "reason_code": lifecycle_reason,
                        "policy_version": str(lifecycle.get("gate_version") or "TOOL-GAIN-GATE-V2"),
                        "cluster_id": record.cluster_id,
                    }
            else:
                transition = {
                    "version": 1,
                    "from_state": "proposed",
                    "to_state": disposition.casefold() or "quarantined",
                    "reason_code": str(lifecycle.get("reason_code") or "not_authorized"),
                    "policy_version": str(lifecycle.get("gate_version") or "TOOL-GAIN-GATE-V2"),
                }
            fence: dict[str, int] = {"run": max(0, int(state.lease.fence))}
            matching_runtime = next(
                (
                    runtime
                    for runtime in state.step_runtime.values()
                    if tool_name is not None and runtime.actual_tool_name == tool_name
                ),
                next(iter(state.step_runtime.values()), None),
            )
            if matching_runtime is not None:
                fence.update(
                    {
                        "run_fence": matching_runtime.run_fence,
                        "step_fence": matching_runtime.step_fence,
                        "lease": matching_runtime.lease_fence,
                        "attempt": matching_runtime.attempt,
                    }
                )
            failures = [cas_failures[item] for item in evidence_ids if item in cas_failures]
            reason_code = str(lifecycle.get("reason_code") or "not_authorized")
            if failures:
                reason_code = f"{reason_code}:{','.join(sorted(set(failures)))}"
            capsule = FailureCapsule.from_candidate(
                finding,
                run_id=state.run_id,
                reason_code=reason_code,
                reason=f"candidate {disposition.casefold() or 'quarantined'}: {reason_code}",
                evidence_refs=evidence_ids,
                artifact_refs=artifact_refs,
                transition=transition,
                fence=fence,
                tool_name=tool_name,
                tool_version=tool_version,
                rule_version=rule_version,
                rule_digest=rule_digest,
                gate_version=str(lifecycle.get("gate_version") or "TOOL-GAIN-GATE-V2"),
                candidate_id=candidate_id,
            )
            prior = existing.get(capsule.dedupe_key)
            if prior is not None and prior.payload_digest != capsule.payload_digest:
                raise CapsuleConflictError("failure capsule payload conflict")
            if prior is not None:
                capsule = prior
            else:
                pending_capsules.append(capsule)
            existing[capsule.dedupe_key] = capsule
            capsule_ids.append(capsule.capsule_id)
            if isinstance(lifecycle, dict):
                lifecycle["capsule_id"] = capsule.capsule_id

        if capsule_store is not None and pending_capsules:
            for stored in capsule_store.append_many(pending_capsules):
                existing[stored.dedupe_key] = stored

        if existing:
            state.audit_coverage["failure_capsules"] = [
                item.to_dict() for item in sorted(existing.values(), key=lambda value: value.capsule_id)
            ]
            state.audit_coverage["failure_capsule_ids"] = sorted(item.capsule_id for item in existing.values())
        return tuple(sorted(set(capsule_ids)))

    @staticmethod
    def _valid_sha256(value: object) -> bool:
        return (
            isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)
        )

    @classmethod
    def _annotate_corroboration(
        cls,
        primary: Finding,
        candidate: Finding,
        evidence_by_id: dict[str, Evidence],
    ) -> None:
        raw = dict(primary.raw)
        tools = set(raw.get("corroborated_by_tools", []))
        tools.update(cls._producers(candidate, evidence_by_id))
        raw["corroborated_by_tools"] = sorted(str(item) for item in tools if item)
        raw["tool_corroboration_evidence_ids"] = sorted(
            set(raw.get("tool_corroboration_evidence_ids", [])) | set(candidate.evidence_ids)
        )
        primary.raw = raw

    @staticmethod
    def _sort_key(finding: Finding) -> tuple[str, int, str, str]:
        return (finding.path, finding.line or 0, finding.rule_id, finding.finding_id)

    @staticmethod
    def _candidate_record(finding: Finding, disposition: str, reason_code: str) -> dict[str, object]:
        """Persist every candidate disposition, not only quarantines.

        This record is intentionally plain JSON so a post-cleanup evaluator can
        reconstruct which candidate was corroborated, admitted or quarantined
        without replaying the tool process.
        """

        return {
            "candidate_id": finding.finding_id,
            "finding_id": finding.finding_id,
            "rule_id": finding.rule_id,
            "path": finding.path,
            "line": finding.line,
            "evidence_ids": list(finding.evidence_ids),
            "disposition": disposition,
            "reason_code": reason_code,
            "gate_version": "TOOL-GAIN-GATE-V2",
        }

    @staticmethod
    def _refresh_report_findings(state: AgentState, admitted: list[Finding]) -> None:
        if state.report is None:
            return
        # The mutable report is not an alternate publication lane.  Once a
        # candidate is quarantined it must disappear here as well as from
        # ``state.findings`` so terminal admission cannot accidentally ingest
        # the stale report copy.
        findings = [item.model_copy(deep=True) for item in admitted]
        state.report = state.report.model_copy(update={"findings": findings})

    @staticmethod
    def _record(
        state: AgentState,
        summary: ToolGainSummary,
        accepted_evidence_ids: tuple[str, ...],
        candidate_lifecycle: Sequence[Mapping[str, object]],
    ) -> None:
        payload = {
            "candidates": summary.candidates,
            "corroborated_into_primary": summary.corroborated_into_primary,
            "accepted_corrections": summary.accepted_corrections,
            "accepted_new": summary.accepted_new,
            "quarantined": summary.quarantined,
            "quarantined_finding_ids": list(summary.quarantined_finding_ids),
            "typed_delta_ids": list(summary.typed_delta_ids),
            "candidate_store_digest": summary.candidate_store_digest,
            "failure_capsule_ids": list(summary.failure_capsule_ids),
            "candidate_lifecycle": [
                dict(item)
                for item in sorted(
                    candidate_lifecycle,
                    key=lambda value: str(value.get("candidate_id", "")),
                )
            ],
            "quarantine_records": [
                dict(item) for item in candidate_lifecycle if item.get("disposition") == "QUARANTINED"
            ],
        }
        state.audit_coverage["tool_gain_gate"] = payload
        # The evaluation bridge removes the temporary DB/CAS after every task.
        # Preserve only aggregate, non-content diagnostics so a release run can
        # distinguish a semantic holdout from a broken CAS/assurance boundary.
        # Candidate IDs, paths, digests, excerpts and evidence IDs deliberately
        # remain in the private replay record above.
        reason_counts: dict[str, int] = {}
        for item in candidate_lifecycle:
            reason = str(item.get("reason_code") or "unknown")
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        failed_check_counts: dict[str, int] = {}
        raw_deltas = state.audit_coverage.get("typed_deltas", [])
        if isinstance(raw_deltas, list):
            for delta in raw_deltas:
                checks = delta.get("semantic_checks") if isinstance(delta, Mapping) else None
                if not isinstance(checks, Mapping):
                    continue
                for key, passed in checks.items():
                    if passed is False:
                        name = str(key)
                        failed_check_counts[name] = failed_check_counts.get(name, 0) + 1
        rehash_failure_counts: dict[str, int] = {}
        raw_rehash = state.audit_coverage.get("gain_gate_cas_rehash", {})
        failures = raw_rehash.get("failures") if isinstance(raw_rehash, Mapping) else None
        if isinstance(failures, Mapping):
            for code in failures.values():
                name = str(code or "CAS_REHASH_FAILED")
                rehash_failure_counts[name] = rehash_failure_counts.get(name, 0) + 1
        state.audit_coverage["tool_gain_gate_diagnostics"] = {
            "schema_version": "tool-gain-diagnostics-v1",
            "candidate_count": summary.candidates,
            "accepted_count": summary.accepted_corrections + summary.accepted_new,
            "corroborated_count": summary.corroborated_into_primary,
            "quarantined_count": summary.quarantined,
            "typed_delta_count": len(summary.typed_delta_ids),
            "reason_counts": dict(sorted(reason_counts.items())),
            "failed_semantic_check_counts": dict(sorted(failed_check_counts.items())),
            "cas_rehash_failure_counts": dict(sorted(rehash_failure_counts.items())),
            "builtin_rule_failure_counts": dict(
                sorted(
                    (
                        state.audit_coverage.get("deterministic_builtin_rule_diagnostics", {}).get(
                            "failure_counts",
                            {},
                        )
                        if isinstance(
                            state.audit_coverage.get("deterministic_builtin_rule_diagnostics"),
                            Mapping,
                        )
                        else {}
                    ).items()
                )
            ),
        }
        state.decisions.append(
            DecisionRecord(
                decision="tool_gain_adjudicated",
                rationale_summary=(
                    "Tool deltas were admitted only as local corroboration, bounded label corrections, "
                    "prequalified semantic gains, or cross-tool findings. "
                    f"Accepted {summary.accepted_corrections + summary.accepted_new}; "
                    f"corroborated {summary.corroborated_into_primary}; quarantined {summary.quarantined}."
                ),
                evidence_ids=list(accepted_evidence_ids),
                policy_ids=["TOOL-GAIN-GATE-V1", "PRIMARY-NON-REGRESSION-V1"],
                model_id="deterministic-tool-gain-gate",
                confidence=1.0,
            )
        )


__all__ = ["ToolGainGate", "ToolGainSummary"]
