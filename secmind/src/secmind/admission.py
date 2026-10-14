"""Single deterministic authority for public SecMind findings.

Workers, reducers, scanners, verifiers, and reporters produce candidates or
views.  This service is the only terminal boundary allowed to publish their
combined finding set.  It preserves an admitted Primary lane exactly and
admits only evidence-complete, verifier-visible deltas.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.audit_kernel.contracts import stable_unit_id
from secmind.direct_anchor_pipeline import (
    CandidateStore,
    DeltaAction,
    DeltaDisposition,
    TypedDelta,
    evidence_semantic_checks,
)
from secmind.final_validation import (
    build_exact_answer_attestation,
    build_final_validation,
    validate_final_validation_payload,
    verified_evidence_claims,
)
from secmind.java_semantic_sast import NATIVE_RULE_ID as JAVA_WEAK_DIGEST_RULE_ID
from secmind.java_semantic_sast import PROFILE_DIGEST as JAVA_WEAK_DIGEST_PROFILE_DIGEST
from secmind.java_semantic_sast import RULE_BUNDLE_DIGEST as JAVA_WEAK_DIGEST_RULE_BUNDLE_DIGEST
from secmind.java_semantic_sast import SEMANTIC_SIGNAL as JAVA_WEAK_DIGEST_SIGNAL
from secmind.java_semantic_sast import TOOL_NAME as JAVA_SEMANTIC_TOOL_NAME
from secmind.java_semantic_sast import TOOL_VERSION as JAVA_SEMANTIC_TOOL_VERSION
from secmind.primary_baseline import (
    baseline_semantic_digest,
    publish_primary_baseline,
    restore_published_baseline,
    validate_baseline_chain,
)
from secmind.public_coverage import INTERNAL_COVERAGE_KEYS, public_coverage_projection
from secmind.quarantine import FailureCapsuleStore
from secmind.schemas import (
    AgentReport,
    AgentState,
    Evidence,
    EvidenceGapTicket,
    Finding,
    PlanStep,
    PublishedBaselineProjection,
    SealedAdmissionSnapshot,
    Scenario,
    StepRuntime,
    StepStatus,
    ToolResult,
    ToolStatus,
)
from secmind.secret_scrubber import redact
from secmind.task_contract import validate_independence_proof
from secmind.tool_assurance import independently_rehash_evidence_set
from secmind.tool_gain_gate import ToolGainGate, ToolGainSummary


class AdmissionError(RuntimeError):
    """A candidate set cannot be published without weakening an invariant."""


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _report_integrity_digest(report: AgentReport) -> str:
    return _digest(report.model_dump(mode="json", exclude={"generated_at"}))


def _align_admitted_report(state: AgentState, report: AgentReport) -> AgentReport:
    """Make public prose describe the evidence admitted into this report."""

    if state.scenario == Scenario.CODE_AUDIT:
        summary = re.sub(
            r"\b\d+ evidence record\(s\)",
            f"{len(report.evidence)} evidence record(s)",
            report.executive_summary,
        )
        return report.model_copy(update={"executive_summary": summary})

    if state.scenario != Scenario.REVERSE_TRIAGE or report.answer_type != "reverse_behavior":
        return report
    pe_evidence = next(
        (
            item for item in report.evidence
            if item.source == "pe_reverse_analysis:1"
            and item.metadata.get("verification_status") == "verified_support"
            and item.metadata.get("sample_sha256") in {artifact.sha256 for artifact in state.input_artifacts}
        ),
        None,
    )
    if pe_evidence is None:
        return report

    metadata = pe_evidence.metadata
    dynamic_tool = state.audit_coverage.get("reverse_dynamic_tool")
    dynamic_completed = isinstance(dynamic_tool, dict) and "completed" in dynamic_tool.get("statuses", [])
    dynamic_scope = "Dynamic emulation was performed." if dynamic_completed else "Dynamic execution was not performed."
    summary = (
        f"Verified static PE analysis of {metadata.get('sample_name', 'the supplied sample')} "
        f"(SHA256 {metadata['sample_sha256']}): {metadata.get('architecture', 'unknown architecture')}, "
        f"{metadata.get('section_count', 'unknown')} section(s), "
        f"{metadata.get('import_libraries', 'unknown')} import library/libraries. "
        f"{dynamic_scope} Behavioral conclusions require their own evidence."
    )
    scenario_projection = state.audit_coverage.get("pre_primary_scenario_projection")
    scenario_answer = scenario_projection.get("answer_payload") if isinstance(scenario_projection, dict) else None
    payload = dict(report.answer_payload)
    payload["executive_summary"] = summary
    extensions = payload.get("extensions")
    if isinstance(extensions, dict):
        payload["extensions"] = {key: value for key, value in extensions.items() if key != "unknown_fields"}
    if isinstance(scenario_answer, dict) and scenario_answer.get("answer_kind") == "reverse_behavior":
        for field in ("unknowns", "limitations"):
            value = scenario_answer.get(field)
            if isinstance(value, list):
                payload[field] = value
    limitations = payload.get("limitations")
    return report.model_copy(update={
        "executive_summary": summary,
        "answer_payload": payload,
        "limitations": limitations if isinstance(limitations, list) else report.limitations,
    })


def _normalized_repository_path(value: object) -> str | None:
    """Return a cross-platform comparison key for a safe relative path."""

    if not isinstance(value, str):
        return None
    normalized = unicodedata.normalize("NFC", value.replace("\\", "/"))
    path = PurePosixPath(normalized)
    if (
        not normalized
        or path.is_absolute()
        or (path.parts and path.parts[0].endswith(":"))
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
    ):
        return None
    return path.as_posix().casefold()


def _valid_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


def _finding_payload(finding: Finding) -> dict[str, Any]:
    return finding.model_dump(mode="json")


class AdmissionService:
    """Admit the Primary once, adjudicate deltas, then seal one report view."""

    @staticmethod
    def _resolve_cas_store(state: AgentState, artifact_store: Any | None) -> Any | None:
        """Resolve an explicitly supplied CAS, or a durable state-bound root.

        Admission never treats a digest map emitted by a tool or an earlier
        verifier as a rehash.  A store object (or a state-bound CAS root) is
        required to perform the independent read.  The root fallback is kept
        for recovery workers that only have serialized state available.
        """

        if artifact_store is not None:
            return artifact_store
        raw_root = None
        for key in ("artifact_store_root", "cas_root", "artifact_root"):
            value = state.audit_coverage.get(key)
            if isinstance(value, (str, Path)) and str(value):
                raw_root = Path(value)
                break
        if raw_root is None:
            return None
        try:
            from secmind.artifact_store import ContentAddressedArtifactStore

            return ContentAddressedArtifactStore(raw_root)
        except (OSError, TypeError, ValueError):
            return None

    @staticmethod
    def _candidate_cas_status(
        candidate: Finding,
        *,
        rehashed_evidence_ids: set[str] | None,
        cas_failures: dict[str, str],
    ) -> bool:
        """Require every referenced Evidence object to pass the independent read."""

        if rehashed_evidence_ids is None:
            return True
        evidence_ids = set(candidate.evidence_ids)
        if not evidence_ids:
            return False
        if evidence_ids.intersection(cas_failures):
            return False
        return evidence_ids.issubset(rehashed_evidence_ids)

    @classmethod
    def _rehash_before_admission(
        cls,
        state: AgentState,
        evidence_by_id: dict[str, Evidence],
        artifact_store: Any | None,
    ) -> tuple[set[str] | None, dict[str, str]]:
        store = cls._resolve_cas_store(state, artifact_store)
        if store is None:
            return None, {}
        verified, failures = independently_rehash_evidence_set(
            evidence_by_id,
            store,
            run_id=state.run_id,
        )
        state.audit_coverage["admission_cas_rehash"] = {
            "verified_evidence_ids": sorted(verified),
            "failures": dict(sorted(failures.items())),
            "source": "independent_cas_read",
            "stage": "before_candidate_admission",
        }
        return set(verified), failures

    @staticmethod
    def admit_baseline(
        state: AgentState,
        *,
        artifact_store: ContentAddressedArtifactStore,
        capsule_store: FailureCapsuleStore,
        **values: Any,
    ) -> PublishedBaselineProjection:
        if not isinstance(artifact_store, ContentAddressedArtifactStore) or not isinstance(
            capsule_store, FailureCapsuleStore
        ):
            raise AdmissionError("baseline admission requires real ArtifactStore and CapsuleStore")
        response_artifact_id = values.get("response_artifact_id")
        response_sha256 = values.get("response_sha256")
        if not isinstance(response_artifact_id, str) or response_artifact_id != response_sha256:
            raise AdmissionError("baseline response receipt is not bound to its CAS artifact")
        try:
            artifact_store.read(response_artifact_id)
        except (OSError, ValueError) as exc:
            raise AdmissionError("baseline response CAS read failed") from exc
        state.audit_coverage["admission_store_status"] = {
            "status": "verified",
            "artifact_store": type(artifact_store).__name__,
            "capsule_store": type(capsule_store).__name__,
        }
        return publish_primary_baseline(state, **values)

    @staticmethod
    def adjudicate_deltas(
        state: AgentState,
        *,
        artifact_store: ContentAddressedArtifactStore,
        capsule_store: FailureCapsuleStore,
    ) -> ToolGainSummary:
        # ToolGainGate remains a compatibility policy implementation, but it
        # is no longer a public authority: only this service calls it on the
        # product path and its output is still a candidate until ``seal``.
        if not isinstance(artifact_store, ContentAddressedArtifactStore) or not isinstance(
            capsule_store, FailureCapsuleStore
        ):
            raise AdmissionError("delta admission requires real ArtifactStore and CapsuleStore")
        return ToolGainGate.apply(state, artifact_store=artifact_store, capsule_store=capsule_store)

    @classmethod
    def seal(
        cls,
        state: AgentState,
        report: AgentReport | None = None,
        *,
        artifact_store: ContentAddressedArtifactStore,
        capsule_store: FailureCapsuleStore,
    ) -> SealedAdmissionSnapshot:
        baseline = state.published_baseline
        if baseline is not None:
            valid, reason = validate_baseline_chain(state)
            if not valid:
                raise AdmissionError(f"Primary baseline chain is invalid: {reason}")
            if not restore_published_baseline(state):
                raise AdmissionError("Primary baseline could not be restored exactly")

        source_report = (report or state.report or cls._fallback_report(state)).model_copy(deep=True)
        if not isinstance(artifact_store, ContentAddressedArtifactStore) or not isinstance(
            capsule_store, FailureCapsuleStore
        ):
            raise AdmissionError("terminal admission requires real ArtifactStore and CapsuleStore")
        baseline_findings = {} if baseline is None else {item.finding_id: item for item in baseline.findings}
        baseline_evidence = {} if baseline is None else {item.evidence_id: item for item in baseline.evidence}
        # Durable state owns Evidence bytes.  A reporter projection may add a
        # claim-visible row, but must not replace a state row with a caller
        # supplied digest or artifact reference before the independent CAS
        # read.
        evidence_by_id = {item.evidence_id: item for item in state.evidence}
        for item in source_report.evidence:
            evidence_by_id.setdefault(item.evidence_id, item)
        rehashed_evidence_ids, cas_failures = cls._rehash_before_admission(
            state,
            evidence_by_id,
            artifact_store,
        )
        verified_subjects = {
            claim.subject_ref
            for claim in state.claims
            if str(getattr(claim.status, "value", claim.status)) == "verified"
        }
        evidence_origins: dict[str, set[tuple[str, int]]] = {}
        observed_evidence: dict[tuple[str, int, str], Evidence] = {}
        for step_id, runtime in state.step_runtime.items():
            for observation_index in runtime.observation_indexes:
                if observation_index < 0 or observation_index >= len(state.observations):
                    continue
                for item in state.observations[observation_index].evidence:
                    evidence_origins.setdefault(item.evidence_id, set()).add((step_id, observation_index))
                    observed_evidence[(step_id, observation_index, item.evidence_id)] = item
        tickets_by_step: dict[str, list[EvidenceGapTicket]] = {}
        for ticket in state.evidence_gap_tickets:
            tickets_by_step.setdefault(ticket.step_id, []).append(ticket)

        direct_mode = (
            state.audit_coverage.get("direct_anchor_pipeline") is True
            and state.audit_coverage.get("direct_anchor_strict") is not False
        )
        direct_deltas: tuple[TypedDelta, ...] = ()
        direct_by_finding_id: dict[str, TypedDelta] = {}
        direct_candidate_finding_ids: dict[str, str] = {}
        if direct_mode:
            raw_deltas = state.audit_coverage.get("typed_deltas", [])
            direct_deltas = tuple(
                TypedDelta.model_validate(raw_delta) for raw_delta in raw_deltas if isinstance(raw_delta, dict)
            )
            candidate_store = CandidateStore.from_state(state)
            direct_candidate_finding_ids = {
                record.candidate_id: record.finding.finding_id for record in candidate_store.records()
            }
            for delta in direct_deltas:
                if delta.finding is not None:
                    direct_by_finding_id[delta.finding.finding_id] = delta
                for candidate_id in delta.candidate_ids:
                    finding_id = direct_candidate_finding_ids.get(candidate_id)
                    if finding_id is not None:
                        direct_by_finding_id.setdefault(finding_id, delta)

        candidate_pool = {
            finding_item.finding_id: finding_item.model_copy(deep=True) for finding_item in state.findings
        }
        for report_finding in source_report.findings:
            candidate_pool.setdefault(report_finding.finding_id, report_finding.model_copy(deep=True))
        if direct_mode:
            for delta in direct_deltas:
                if delta.finding is not None:
                    candidate_pool.setdefault(delta.finding.finding_id, delta.finding.model_copy(deep=True))

        candidate_cas_ok = {
            finding_id: cls._candidate_cas_status(
                candidate,
                rehashed_evidence_ids=rehashed_evidence_ids,
                cas_failures=cas_failures,
            )
            for finding_id, candidate in candidate_pool.items()
        }

        admitted = {key: item.model_copy(deep=True) for key, item in baseline_findings.items()}
        rejected: set[str] = set()
        authorized_delta_ids: set[str] = set()
        correction_finding_ids: set[str] = set()
        if direct_mode and baseline is not None:
            for delta in sorted(direct_deltas, key=lambda item: item.delta_id):
                if delta.action not in {DeltaAction.CORRECT, DeltaAction.REPLACE_FIELD, DeltaAction.RETRACT}:
                    continue
                target_id = delta.target_finding_id
                current = admitted.get(target_id or "")
                references = set(delta.evidence_ids)
                if target_id is None or current is None or delta.disposition != DeltaDisposition.ACCEPTED:
                    continue
                authorized = False
                replacement = delta.finding
                if delta.action in {DeltaAction.CORRECT, DeltaAction.REPLACE_FIELD} and replacement is not None:
                    authorized = cls._direct_delta_authorizes(
                        state,
                        delta,
                        replacement,
                        references,
                        evidence_by_id,
                        rehashed_evidence_ids=rehashed_evidence_ids,
                    )
                elif delta.action == DeltaAction.RETRACT:
                    critic = state.audit_coverage.get("delta_critic", {})
                    critic_ids = (
                        {str(item) for item in critic.get("authorized_delta_ids", [])}
                        if isinstance(critic, dict) and critic.get("status") == "completed"
                        else set()
                    )
                    model_independent = (
                        isinstance(critic, dict)
                        and critic.get("status") == "completed"
                        and validate_independence_proof(critic.get("independence_proof"))[0]
                    )
                    deterministic_independent = len(set(delta.producer_ids)) >= 2
                    authorized = (
                        delta.admission_ready
                        and bool(references)
                        and references.issubset(evidence_by_id)
                        and delta.delta_id in critic_ids
                        and (model_independent or deterministic_independent)
                    )
                if not authorized:
                    continue
                if delta.action == DeltaAction.RETRACT:
                    admitted.pop(target_id, None)
                elif replacement is not None:
                    admitted[target_id] = replacement.model_copy(update={"finding_id": target_id}, deep=True)
                    correction_finding_ids.add(replacement.finding_id)
                authorized_delta_ids.add(delta.delta_id)
        for candidate in sorted(candidate_pool.values(), key=lambda item: item.finding_id):
            if candidate.finding_id in correction_finding_ids:
                continue
            if candidate.finding_id in admitted:
                continue
            if not candidate_cas_ok.get(candidate.finding_id, True):
                rejected.add(candidate.finding_id)
                continue
            references = set(candidate.evidence_ids)
            evidence_complete = bool(references) and references.issubset(evidence_by_id)
            candidate_delta: TypedDelta | None = None
            # When live Primary is disabled, deterministic tools are the only
            # audit lane and retain v0.7 compatibility authority.  Shadow is
            # a post-Primary concept, never a way to erase tool-only results.
            if direct_mode:
                candidate_delta = direct_by_finding_id.get(candidate.finding_id)
                if candidate_delta is not None and candidate_delta.action.value == "supplement":
                    # A corroboration delta enriches the Enhanced report and
                    # evidence set; it must never duplicate the Anchor finding
                    # in the public finding list.
                    if cls._direct_delta_authorizes(
                        state,
                        candidate_delta,
                        candidate,
                        references,
                        evidence_by_id,
                        rehashed_evidence_ids=rehashed_evidence_ids,
                    ):
                        authorized_delta_ids.add(candidate_delta.delta_id)
                        target_id = candidate_delta.target_finding_id
                        target = admitted.get(target_id or "")
                        if target is not None:
                            admitted[target.finding_id] = target.model_copy(
                                update={"evidence_ids": sorted({*target.evidence_ids, *references})},
                                deep=True,
                            )
                    else:
                        rejected.add(candidate.finding_id)
                    continue
                released_delta = cls._direct_delta_authorizes(
                    state,
                    candidate_delta,
                    candidate,
                    references,
                    evidence_by_id,
                    rehashed_evidence_ids=rehashed_evidence_ids,
                )
                verifier_visible = released_delta
            else:
                released_delta = baseline is None or cls._ticket_authorizes_new_finding(
                    state,
                    candidate,
                    references,
                    evidence_by_id=evidence_by_id,
                    evidence_origins=evidence_origins,
                    observed_evidence=observed_evidence,
                    tickets_by_step=tickets_by_step,
                )
                verifier_visible = (
                    baseline is None and (not state.claims or candidate.finding_id in verified_subjects)
                ) or (baseline is not None and candidate.finding_id in verified_subjects)
            if evidence_complete and verifier_visible and released_delta:
                admitted[candidate.finding_id] = candidate.model_copy(deep=True)
                if direct_mode and candidate_delta is not None:
                    authorized_delta_ids.add(candidate_delta.delta_id)
            else:
                rejected.add(candidate.finding_id)

        baseline_finding_ids = set(baseline_findings)
        gain_gate = state.audit_coverage.get("tool_gain_gate", {})
        quarantined: set[str] = set()
        if isinstance(gain_gate, dict):
            quarantined = {
                str(item) for item in gain_gate.get("quarantined_finding_ids", []) if isinstance(item, str) and item
            }
        if direct_mode:
            for delta in direct_deltas:
                if delta.disposition not in {DeltaDisposition.QUARANTINED, DeltaDisposition.REJECTED}:
                    continue
                if delta.finding is not None:
                    quarantined.add(delta.finding.finding_id)
                quarantined.update(
                    direct_candidate_finding_ids[item]
                    for item in delta.candidate_ids
                    if item in direct_candidate_finding_ids
                )
        if baseline_finding_ids & quarantined:
            raise AdmissionError("Tool quarantine cannot contradict the immutable Primary baseline")
        for finding_id in quarantined:
            admitted.pop(finding_id, None)
        rejected.update(quarantined)
        rejected.difference_update(baseline_finding_ids)

        # Admission is a second rejection boundary.  A candidate can pass the
        # gain gate and still fail a terminal evidence/authority check; keep a
        # bounded capsule for that transition as well.  This intentionally
        # happens before the public evidence projection is assembled.
        rejected_candidates = [
            candidate_pool[item]
            for item in sorted(rejected)
            if item in candidate_pool and item not in baseline_finding_ids
        ]
        if rejected_candidates:
            direct_store = CandidateStore.from_state(state) if direct_mode else None
            candidate_ids_by_finding = (
                {record.finding.finding_id: record.candidate_id for record in direct_store.records()}
                if direct_store is not None
                else {}
            )
            rejection_lifecycle: list[dict[str, object]] = []
            for candidate in rejected_candidates:
                candidate_delta = direct_by_finding_id.get(candidate.finding_id)
                rejection_lifecycle.append(
                    {
                        "candidate_id": candidate_ids_by_finding.get(candidate.finding_id, candidate.finding_id),
                        "finding_id": candidate.finding_id,
                        "rule_id": candidate.rule_id,
                        "path": candidate.path,
                        "line": candidate.line,
                        "evidence_ids": list(candidate.evidence_ids),
                        "disposition": "REJECTED",
                        "reason_code": (
                            candidate_delta.reason_code
                            if candidate_delta is not None
                            else (
                                "cas_rehash_failed"
                                if candidate_cas_ok.get(candidate.finding_id) is False
                                else "admission_rejected"
                            )
                        ),
                        "gate_version": (
                            candidate_delta.policy_version if candidate_delta is not None else "ADMISSION-V2"
                        ),
                    }
                )
            ToolGainGate._capture_failure_capsules(  # noqa: SLF001 - one capsule contract
                state,
                rejected_candidates,
                rejection_lifecycle,
                evidence_by_id,
                capsule_store=capsule_store,
                cas_failures=cas_failures,
                candidate_store=direct_store,
            )

        admitted_evidence_ids = set(baseline_evidence)
        admitted_evidence_ids.update(
            evidence_id for finding in admitted.values() for evidence_id in finding.evidence_ids
        )
        if direct_mode:
            admitted_evidence_ids.update(
                evidence_id
                for delta in direct_deltas
                if delta.delta_id in authorized_delta_ids
                for evidence_id in delta.evidence_ids
            )
        admitted_evidence_ids.update(
            cls._verified_report_evidence_ids(
                state,
                source_report,
                rehashed_evidence_ids=rehashed_evidence_ids,
            )
        )
        final_evidence = {
            evidence_id: evidence_by_id[evidence_id].model_copy(deep=True)
            for evidence_id in sorted(admitted_evidence_ids)
            if evidence_id in evidence_by_id
        }
        final_evidence.update({key: item.model_copy(deep=True) for key, item in baseline_evidence.items()})
        cls._project_verified_evidence_metadata(
            state,
            source_report,
            final_evidence,
            rehashed_evidence_ids=rehashed_evidence_ids,
        )
        final_findings = sorted(
            admitted.values(),
            key=lambda item: (item.path, item.line or 0, item.rule_id, item.finding_id),
        )
        final_evidence_list = sorted(final_evidence.values(), key=lambda item: item.evidence_id)
        final_semantic_digest = baseline_semantic_digest(final_findings, final_evidence_list)
        snapshot_payload = {
            "run_id": state.run_id,
            "baseline_projection_id": None if baseline is None else baseline.projection_id,
            "baseline_semantic_digest": None if baseline is None else baseline.semantic_digest,
            "final_semantic_digest": final_semantic_digest,
            "admitted_finding_ids": [item.finding_id for item in final_findings],
            "rejected_finding_ids": sorted(rejected),
            "status": state.status.value,
        }
        snapshot_id = f"admission-snapshot-{_digest(snapshot_payload)}"
        coverage = public_coverage_projection(
            {
                **source_report.coverage,
                **state.audit_coverage,
                "admission_snapshot_id": snapshot_id,
                "admitted_finding_count": len(final_findings),
                "accepted_delta_count": len(authorized_delta_ids),
                "accepted_delta_ids": sorted(authorized_delta_ids),
                "admitted_new_finding_count": sum(
                    item.finding_id not in baseline_finding_ids for item in final_findings
                ),
                "rejected_delta_count": sum(
                    delta.disposition in {DeltaDisposition.QUARANTINED, DeltaDisposition.REJECTED}
                    or delta.delta_id not in authorized_delta_ids
                    for delta in direct_deltas
                ),
                "rejected_finding_count": len(rejected),
                "final_semantic_digest": final_semantic_digest,
                "primary_preserved": baseline is not None,
                "direct_anchor_pipeline": direct_mode,
                "typed_delta_count": len(direct_deltas),
                "admission_authority": "unified-direct-delta" if direct_mode else "legacy-ticket-compatibility",
                "final_validation_required": True,
            }
        )
        if state.answer_revisions:
            raise AdmissionError("legacy answer revision chain is not authoritative")
        revised_answer_payload = dict(source_report.answer_payload)
        finding_answer = source_report.answer_type == "finding" or (
            state.resolved_task_contract is not None and state.resolved_task_contract.scoring_mode == "security_finding"
        )
        if finding_answer:
            revised_answer_payload["findings"] = [item.model_dump(mode="json") for item in final_findings]
        sealed_report = source_report.model_copy(
            deep=True,
            update={
                "status": state.status,
                "answer_type": "finding" if finding_answer else source_report.answer_type,
                "answer_payload": revised_answer_payload,
                "findings": final_findings,
                "evidence": final_evidence_list,
                "decisions": list(state.decisions),
                "coverage": coverage,
            },
        )
        sealed_report = _align_admitted_report(state, sealed_report)
        # Validation is a property of the admitted public view, not of the
        # reporter's pre-admission candidate projection.  Compute it only
        # after findings, evidence, and the typed answer have reached their
        # terminal shape so the receipt cannot describe rows that Admission
        # subsequently rejected.
        #
        # ``_project_verified_evidence_metadata`` deliberately annotates deep
        # copies in ``final_evidence`` with the runtime-owned support claim,
        # verification status, and exact-answer attestation.  The mutable
        # state still contains the pre-admission Evidence objects at this
        # point.  ``build_final_validation`` compares state/report evidence
        # byte-for-byte before accepting a SUPPORTS edge; leaving the two
        # views out of sync therefore makes every otherwise valid exact
        # observation appear unverified and forces the public scrubber to
        # redact its answer.  Synchronize the state to the already-admitted
        # terminal copies before validation.  This is a projection sync, not
        # a trust relaxation: all metadata was computed above from the
        # existing durable claim/evidence graph.
        state.evidence = [item.model_copy(deep=True) for item in final_evidence_list]
        validation = build_final_validation(
            state,
            sealed_report,
            rehashed_evidence_ids=rehashed_evidence_ids,
        )
        sealed_report = sealed_report.model_copy(
            update={
                "verification_summary": validation,
                "coverage": {
                    **sealed_report.coverage,
                    "final_validation_receipt_digest": validation["validation_digest"],
                    "final_validation_validator_id": validation["validator_id"],
                },
            }
        )
        snapshot = SealedAdmissionSnapshot(
            snapshot_id=snapshot_id,
            run_id=state.run_id,
            baseline_projection_id=None if baseline is None else baseline.projection_id,
            baseline_semantic_digest=None if baseline is None else baseline.semantic_digest,
            final_semantic_digest=final_semantic_digest,
            report_integrity_digest=_report_integrity_digest(sealed_report),
            admitted_finding_ids=[item.finding_id for item in final_findings],
            rejected_finding_ids=sorted(rejected),
            report=sealed_report,
        )
        if state.sealed_admission is not None:
            if state.sealed_admission.snapshot_id != snapshot.snapshot_id:
                raise AdmissionError("terminal admission snapshot is append-only")
            valid, reason = cls.validate_snapshot(state.sealed_admission)
            if not valid:
                raise AdmissionError(f"existing admission snapshot is invalid: {reason}")
            # A repeated terminal transition may arrive after mutable state was
            # changed or reconstructed.  The first valid snapshot remains the
            # authority, so heal every public projection before returning it.
            cls.restore_sealed_view(state)
            return state.sealed_admission
        state.sealed_admission = snapshot
        cls.restore_sealed_view(state)
        return snapshot

    @classmethod
    def restore_sealed_view(cls, state: AgentState) -> AgentReport:
        """Validate and restore the immutable terminal view into mutable state."""

        projected = cls.public_report(state)
        state.report = projected.model_copy(deep=True)
        state.findings = [item.model_copy(deep=True) for item in projected.findings]
        state.evidence = [item.model_copy(deep=True) for item in projected.evidence]
        state.decisions = [item.model_copy(deep=True) for item in projected.decisions]
        for key, value in projected.coverage.items():
            if key in INTERNAL_COVERAGE_KEYS and key in state.audit_coverage:
                continue
            state.audit_coverage[key] = value
        return projected

    @classmethod
    def public_report(cls, state: AgentState) -> AgentReport:
        """Project the only report that may cross a public or replay boundary."""

        if state.sealed_admission is None:
            raise AdmissionError("sealed admission snapshot is not available")
        return cls.project(state.sealed_admission)

    @classmethod
    def public_snapshot(cls, state: AgentState) -> SealedAdmissionSnapshot:
        """Return a validated deep copy so callers cannot mutate durable state."""

        snapshot = state.sealed_admission
        if snapshot is None:
            raise AdmissionError("sealed admission snapshot is not available")
        cls.project(snapshot)
        return snapshot.model_copy(deep=True)

    @classmethod
    def has_public_report(cls, state: AgentState) -> bool:
        try:
            cls.public_report(state)
        except AdmissionError:
            return False
        return True

    @staticmethod
    def project(snapshot: SealedAdmissionSnapshot) -> AgentReport:
        valid, reason = AdmissionService.validate_snapshot(snapshot)
        if not valid:
            raise AdmissionError(f"admission snapshot is invalid: {reason}")
        return snapshot.report.model_copy(deep=True)

    @staticmethod
    def validate_snapshot(snapshot: SealedAdmissionSnapshot) -> tuple[bool, str | None]:
        if snapshot.report.run_id != snapshot.run_id:
            return False, "admission report belongs to another run"
        if [item.finding_id for item in snapshot.report.findings] != snapshot.admitted_finding_ids:
            return False, "admitted finding references mismatch"
        admitted_ids = set(snapshot.admitted_finding_ids)
        rejected_ids = set(snapshot.rejected_finding_ids)
        if len(admitted_ids) != len(snapshot.admitted_finding_ids):
            return False, "admitted finding references are not unique"
        if len(rejected_ids) != len(snapshot.rejected_finding_ids):
            return False, "rejected finding references are not unique"
        if admitted_ids & rejected_ids:
            return False, "admitted and rejected findings overlap"
        semantic = baseline_semantic_digest(snapshot.report.findings, snapshot.report.evidence)
        if semantic != snapshot.final_semantic_digest:
            return False, "admission semantic digest mismatch"
        if snapshot.report.coverage.get("final_validation_required") is True:
            valid_validation, validation_reason = validate_final_validation_payload(
                snapshot.report.verification_summary
            )
            if not valid_validation:
                return False, f"terminal validation receipt is invalid: {validation_reason}"
            if snapshot.report.coverage.get(
                "final_validation_receipt_digest"
            ) != snapshot.report.verification_summary.get("validation_digest"):
                return False, "terminal validation receipt is not bound to report coverage"
        if _report_integrity_digest(snapshot.report) != snapshot.report_integrity_digest:
            return False, "admission report integrity mismatch"
        payload = {
            "run_id": snapshot.run_id,
            "baseline_projection_id": snapshot.baseline_projection_id,
            "baseline_semantic_digest": snapshot.baseline_semantic_digest,
            "final_semantic_digest": snapshot.final_semantic_digest,
            "admitted_finding_ids": snapshot.admitted_finding_ids,
            "rejected_finding_ids": snapshot.rejected_finding_ids,
            "status": snapshot.report.status.value,
        }
        if snapshot.snapshot_id != f"admission-snapshot-{_digest(payload)}":
            return False, "admission snapshot identity mismatch"
        return True, None

    @staticmethod
    def _direct_delta_authorizes(
        state: AgentState,
        delta: TypedDelta | None,
        candidate: Finding,
        evidence_ids: set[str],
        evidence_by_id: dict[str, Evidence],
        *,
        rehashed_evidence_ids: set[str] | None = None,
    ) -> bool:
        """Validate the v0.8.2 delta contract without consulting old tickets.

        A typed delta is still rechecked at the terminal boundary.  This is
        what removes the former contradiction where GainGate accepted a
        candidate and Admission silently rejected it under a different rule.
        """

        if delta is None or delta.disposition != DeltaDisposition.ACCEPTED:
            return False
        if not evidence_ids or not evidence_ids.issubset(evidence_by_id):
            return False
        if rehashed_evidence_ids is not None and not evidence_ids.issubset(rehashed_evidence_ids):
            return False
        if delta.evidence_ids and not set(delta.evidence_ids).issubset(evidence_by_id):
            return False
        checks = evidence_semantic_checks(candidate, evidence_by_id)
        verification = state.audit_coverage.get("delta_verification", {})
        verifier_mark = verification.get(candidate.finding_id) if isinstance(verification, dict) else None
        correlated_degraded_rescue = (
            delta.reason_code == "correlated_independent_degraded_rescue"
            and not state.audit_coverage.get("canonical_primary_completed", False)
            and len(set(delta.producer_ids)) >= 2
            and all(
                checks[key]
                for key in (
                    "evidence_complete",
                    "path_complete",
                    "line_complete",
                    "file_sha256_complete",
                    "rule_digest_complete",
                    "sink_or_dataflow_present",
                )
            )
        )
        semantically_verified = (
            verifier_mark is True
            or (checks["evidence_complete"] and checks["semantic_assurance"])
            or correlated_degraded_rescue
        )
        if delta.action.value == "supplement":
            return checks["evidence_complete"] and semantically_verified
        if delta.action.value == "added" and delta.reason_code == "deterministic_scenario_verified":
            # Scenario analyzers operate on immutable CAS bytes and their
            # claims already passed the sole EvidenceGraph verifier. They
            # still arrive as a typed delta, but do not need an unrelated
            # second scanner merely to publish a packet/log observation.
            scenario_verified = any(
                claim.subject_ref == candidate.finding_id
                and claim.producer == "deterministic-scenario-analyzer"
                and str(getattr(claim.status, "value", claim.status)) == "verified"
                for claim in state.claims
            )
            return scenario_verified and checks["evidence_complete"] and delta.admission_ready
        if not delta.admission_ready or not semantically_verified:
            return False
        if delta.action.value == "added":
            high_specific = all(
                checks[key]
                for key in (
                    "path_complete",
                    "line_complete",
                    "file_sha256_complete",
                    "rule_digest_complete",
                    "sink_or_dataflow_present",
                )
            )
            independent = len(set(delta.producer_ids)) >= 2
            calibrated_single = delta.reason_code == "single_producer_high_assurance_admission"
            return high_specific and (
                independent or calibrated_single or not state.audit_coverage.get("canonical_primary_completed", False)
            )
        if delta.action in {DeltaAction.CORRECT, DeltaAction.REPLACE_FIELD, DeltaAction.RETRACT}:
            target = next(
                (
                    item
                    for item in state.findings
                    if item.finding_id == delta.target_finding_id and item.raw.get("canonical_primary") is True
                ),
                None,
            )
            if (
                delta.action == DeltaAction.CORRECT
                and delta.reason_code == "bounded_native_taxonomy_normalization"
                and target is not None
                and ToolGainGate.authorizes_deterministic_native_correction(
                    state,
                    candidate,
                    target,
                    evidence_by_id,
                    rehashed_evidence_ids=rehashed_evidence_ids,
                )
            ):
                return True
            critic = state.audit_coverage.get("delta_critic", {})
            authorized = (
                {str(item) for item in critic.get("authorized_delta_ids", []) if isinstance(item, str)}
                if isinstance(critic, dict) and critic.get("status") == "completed"
                else set()
            )
            # Conflict corrections are the only provider-critic authority in
            # v0.8.2.  Failures, malformed IDs and unresolved/rejected reviews
            # all fail closed while the immutable Anchor remains untouched.
            model_independent = (
                isinstance(critic, dict)
                and critic.get("status") == "completed"
                and validate_independence_proof(critic.get("independence_proof"))[0]
            )
            deterministic_independent = len(set(delta.producer_ids)) >= 2
            return (
                delta.delta_id in authorized
                and (model_independent or deterministic_independent)
                and checks["evidence_complete"]
                and checks["semantic_assurance"]
            )
        return checks["evidence_complete"] and checks["semantic_assurance"]

    @classmethod
    def _ticket_authorizes_new_finding(
        cls,
        state: AgentState,
        candidate: Finding,
        evidence_ids: set[str],
        *,
        evidence_by_id: dict[str, Evidence],
        evidence_origins: dict[str, set[tuple[str, int]]],
        observed_evidence: dict[tuple[str, int, str], Evidence],
        tickets_by_step: dict[str, list[EvidenceGapTicket]],
    ) -> bool:
        """Validate the complete authority chain for one post-Primary addition."""

        baseline = state.published_baseline
        repository = state.repository_index
        sealed_snapshot_digest = state.audit_coverage.get("repository_snapshot_digest")
        if (
            baseline is None
            or repository is None
            or repository.run_id != state.run_id
            or not isinstance(sealed_snapshot_digest, str)
            or sealed_snapshot_digest != repository.digest
        ):
            return False

        origins: set[tuple[str, int]] = set()
        for evidence_id in evidence_ids:
            bound = evidence_origins.get(evidence_id, set())
            if len(bound) != 1:
                return False
            origins.update(bound)
        step_ids = {step_id for step_id, _ in origins}
        if len(step_ids) != 1:
            return False
        step_id = next(iter(step_ids))
        tickets = tickets_by_step.get(step_id, [])
        if len(tickets) != 1:
            return False
        ticket = tickets[0]
        if not cls._valid_ticket_identity(ticket):
            return False
        gap_authorized = ticket.gap_code == "empty_or_inconclusive_primary" or (
            ticket.gap_code == "security_sensitive_weak_digest" and ticket.tool_name == JAVA_SEMANTIC_TOOL_NAME
        )
        if (
            ticket.run_id != state.run_id
            or ticket.snapshot_digest != sealed_snapshot_digest
            or ticket.primary_semantic_digest != baseline.semantic_digest
            or ticket.release_policy != "authoritative"
            or ticket.allowed_patch_class != "add_finding"
            or not gap_authorized
            or ticket.target_finding_id is not None
            or not 1 <= ticket.max_tool_calls <= 2
        ):
            return False

        steps = [item for item in state.plan if item.step_id == step_id]
        runtime = state.step_runtime.get(step_id)
        if len(steps) != 1 or runtime is None or runtime.status != StepStatus.SUCCEEDED:
            return False
        step = steps[0]
        requirements = step.context_requirements
        if (
            step.capability != ticket.capability
            or not step.tool_candidates
            or step.tool_candidates[0] != ticket.tool_name
            or step.estimated_tool_calls < 1
            or step.estimated_tool_calls > ticket.max_tool_calls
            or requirements.get("evidence_gap_ticket_id") != ticket.ticket_id
            or requirements.get("allowed_patch_class") != ticket.allowed_patch_class
            or requirements.get("release_policy") != ticket.release_policy
            or requirements.get("primary_semantic_digest") != ticket.primary_semantic_digest
            or runtime.attempt < 1
            or runtime.attempt > ticket.max_tool_calls
            or runtime.actual_tool_calls < 1
            or runtime.actual_tool_calls > ticket.max_tool_calls
            or runtime.actual_tool_name != ticket.tool_name
            or len(runtime.tool_invocation_ids) != runtime.actual_tool_calls
            or len(set(runtime.tool_invocation_ids)) != runtime.actual_tool_calls
            or runtime.lease_fence != runtime.run_fence
            or (runtime.run_fence == 0) != (runtime.step_fence == 0)
        ):
            return False

        observation_indexes = sorted(set(runtime.observation_indexes))
        if not observation_indexes or len(observation_indexes) > ticket.max_tool_calls:
            return False
        observations = []
        successful_observations = []
        for index in observation_indexes:
            if index < 0 or index >= len(state.observations):
                return False
            observation = state.observations[index]
            if observation.duration_ms < 0 or observation.invocation_id not in runtime.tool_invocation_ids:
                return False
            observations.append(observation)
            if observation.status == ToolStatus.SUCCESS:
                successful_observations.append(observation)
        if not successful_observations:
            return False
        if sum(item.duration_ms for item in observations) > ticket.max_runtime_ms:
            return False
        allowed_origins = {(step_id, index) for index in observation_indexes}
        if origins - allowed_origins:
            return False

        successful_invocation_ids = {item.invocation_id for item in successful_observations}
        for evidence_id in evidence_ids:
            origin = next(iter(evidence_origins[evidence_id]))
            evidence = observed_evidence.get((*origin, evidence_id))
            if evidence is None or evidence.model_dump(mode="json") != evidence_by_id[evidence_id].model_dump(
                mode="json"
            ):
                return False
            if state.observations[origin[1]].invocation_id not in successful_invocation_ids:
                return False
            producer = evidence.metadata.get("tool_name")
            if not isinstance(producer, str) or producer != ticket.tool_name:
                return False
        declared_producer = candidate.raw.get("tool_name")
        if isinstance(declared_producer, str) and declared_producer != ticket.tool_name:
            return False
        if ticket.gap_code == "security_sensitive_weak_digest" and not cls._valid_java_weak_digest_delta(
            state,
            candidate,
            evidence_ids,
            evidence_by_id,
            observations,
            step,
            runtime,
        ):
            return False
        return candidate.finding_id not in {item.finding_id for item in baseline.findings}

    @staticmethod
    def _valid_java_weak_digest_delta(
        state: AgentState,
        candidate: Finding,
        evidence_ids: set[str],
        evidence_by_id: dict[str, Evidence],
        observations: list[ToolResult],
        step: PlanStep,
        runtime: StepRuntime,
    ) -> bool:
        """Bind the one promoted Java finding to the routed signal and tool bytes."""

        primary_signals = state.audit_coverage.get("primary_static_signals")
        affinity = state.audit_coverage.get("tool_affinity")
        affinity_signals = affinity.get("signals") if isinstance(affinity, dict) else None
        signal_present = (
            isinstance(primary_signals, list)
            and JAVA_WEAK_DIGEST_SIGNAL in primary_signals
            or isinstance(affinity_signals, list)
            and JAVA_WEAK_DIGEST_SIGNAL in affinity_signals
        )
        if not signal_present:
            return False
        if (
            candidate.rule_id != "CWE-328"
            or candidate.raw.get("native_rule_id") != JAVA_WEAK_DIGEST_RULE_ID
            or candidate.raw.get("tool_name") != JAVA_SEMANTIC_TOOL_NAME
            or candidate.raw.get("semantic_signal") != JAVA_WEAK_DIGEST_SIGNAL
            or candidate.raw.get("semantic_corroboration") is not True
            or len(evidence_ids) != 1
            or len(observations) != 1
        ):
            return False
        raw_findings = observations[0].data.get("findings")
        if not isinstance(raw_findings, list) or not raw_findings or len(raw_findings) > 9:
            return False
        candidate_payload = _finding_payload(candidate)
        observed_payloads: list[dict[str, Any]] = []
        for raw_finding in raw_findings:
            try:
                observed_payloads.append(_finding_payload(Finding.model_validate(raw_finding)))
            except (TypeError, ValueError):
                return False
        matching_payloads = [payload for payload in observed_payloads if payload == candidate_payload]
        if len(matching_payloads) != 1 or not hmac.compare_digest(
            _digest(candidate_payload),
            _digest(matching_payloads[0]),
        ):
            return False
        evidence = evidence_by_id[next(iter(evidence_ids))]
        metadata = evidence.metadata
        file_sha256 = metadata.get("file_sha256")
        flow_id = metadata.get("flow_id")
        input_manifest_digest = metadata.get("input_manifest_digest")
        unit_id = metadata.get("unit_id")
        manifest = AdmissionService._java_input_manifest(state, step)
        if manifest is None:
            return False
        expected_manifest_digest, expected_file_count = manifest
        files_scanned = observations[0].data.get("files_scanned")
        if (
            runtime.actual_tool_version != JAVA_SEMANTIC_TOOL_VERSION
            or not isinstance(files_scanned, int)
            or isinstance(files_scanned, bool)
            or files_scanned != expected_file_count
            or input_manifest_digest != expected_manifest_digest
            or not isinstance(file_sha256, str)
            or not _valid_sha256(file_sha256)
            or not isinstance(unit_id, str)
        ):
            return False
        try:
            expected_unit_id = stable_unit_id(
                input_manifest_digest=expected_manifest_digest,
                primary_path=candidate.path,
                source_sha256=file_sha256.lower(),
                target_cwes=(328,),
                profile_digest=JAVA_WEAK_DIGEST_PROFILE_DIGEST,
            )
        except ValueError:
            return False
        material_keys = (
            "tool_name",
            "tool_version",
            "native_rule_id",
            "normalized_rule_id",
            "path",
            "line",
            "file_sha256",
            "input_manifest_digest",
            "rule_bundle_digest",
            "flow_id",
            "unit_id",
            "algorithm",
            "sensitive_identifier",
            "method_name",
            "proof_kind",
            "sink",
            "data_flow",
        )
        canonical_material = {key: metadata.get(key) for key in material_keys}
        expected_evidence_digest = _digest(canonical_material)
        expected_metadata_keys = set(material_keys) | {
            "evidence_type",
            "assurance_level",
            "semantic_corroboration",
            "semantic_signal",
        }
        expected_summary = f"CWE-328 security-sensitive weak digest at {candidate.path}:{candidate.line}"
        expected_finding_digest = _digest(
            {
                "rule_id": "CWE-328",
                "path": candidate.path,
                "line": candidate.line,
                "evidence_id": evidence.evidence_id,
                "file_sha256": file_sha256,
            }
        )
        evidence_body = json.dumps(
            redact(
                {
                    "evidence_id": evidence.evidence_id,
                    "source": evidence.source,
                    "summary": evidence.summary,
                    "metadata": evidence.metadata,
                }
            ),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        persisted_evidence_digest = hashlib.sha256(evidence_body).hexdigest()
        valid_evidence_storage = (evidence.artifact_ref is None and evidence.sha256 == expected_evidence_digest) or (
            evidence.artifact_ref == persisted_evidence_digest and evidence.sha256 == persisted_evidence_digest
        )
        return bool(
            set(metadata) == expected_metadata_keys
            and metadata.get("tool_name") == JAVA_SEMANTIC_TOOL_NAME
            and metadata.get("tool_version") == JAVA_SEMANTIC_TOOL_VERSION
            and metadata.get("native_rule_id") == JAVA_WEAK_DIGEST_RULE_ID
            and metadata.get("normalized_rule_id") == "CWE-328"
            and metadata.get("semantic_signal") == JAVA_WEAK_DIGEST_SIGNAL
            and metadata.get("semantic_corroboration") is True
            and metadata.get("assurance_level") == "semantically_corroborated"
            and metadata.get("rule_bundle_digest") == JAVA_WEAK_DIGEST_RULE_BUNDLE_DIGEST
            and input_manifest_digest == expected_manifest_digest
            and unit_id == expected_unit_id
            and metadata.get("path") == candidate.path
            and metadata.get("line") == candidate.line
            and candidate.finding_id == f"java-semantic-finding-{expected_finding_digest}"
            and candidate.raw.get("tool_version") == JAVA_SEMANTIC_TOOL_VERSION
            and candidate.raw.get("normalized_rule_id") == "CWE-328"
            and candidate.raw.get("rule_bundle_digest") == JAVA_WEAK_DIGEST_RULE_BUNDLE_DIGEST
            and candidate.raw.get("data_flow") == metadata.get("data_flow")
            and isinstance(candidate.raw.get("file_sha256"), str)
            and hmac.compare_digest(candidate.raw["file_sha256"].lower(), file_sha256.lower())
            and AdmissionService._matches_immutable_input(state, candidate.path, file_sha256)
            and isinstance(flow_id, str)
            and flow_id.startswith("flow-")
            and candidate.raw.get("flow_id") == flow_id
            and evidence.source == f"{JAVA_SEMANTIC_TOOL_NAME}:{JAVA_SEMANTIC_TOOL_VERSION}"
            and evidence.summary == expected_summary
            and evidence.evidence_id == f"java-semantic-{expected_evidence_digest[:24]}"
            and valid_evidence_storage
        )

    @staticmethod
    def _project_verified_evidence_metadata(
        state: AgentState,
        source_report: AgentReport,
        evidence_by_id: dict[str, Evidence],
        *,
        rehashed_evidence_ids: set[str] | None = None,
    ) -> None:
        """Publish only durable EvidenceLink support and exact attestations.

        The CAS rehash set is a second, independent input to trust.  A
        verifier edge can explain *why* an evidence row supports a claim, but
        only the current Admission rehash proves that the bytes still exist
        and match their content address.  Failed rows remain in the report as
        evidence/coverage diagnostics; they simply cannot receive runtime
        verification metadata or an exact-answer attestation.
        """

        verified_claim_refs = verified_evidence_claims(
            state,
            source_report,
            allowed_evidence_ids=rehashed_evidence_ids,
        )
        input_manifest_digest = (
            state.resolved_task_contract.input_manifest_digest if state.resolved_task_contract is not None else None
        )
        for evidence_id, evidence in evidence_by_id.items():
            metadata = dict(evidence.metadata)
            claim_ids = verified_claim_refs.get(evidence_id)
            if not claim_ids:
                for key in (
                    "claim_id",
                    "claim_ids",
                    "claim_refs",
                    "verification_status",
                    "exact_answer_attestation",
                ):
                    metadata.pop(key, None)
                evidence.metadata = metadata
                continue
            metadata.update(
                {
                    "verification_status": "verified_support",
                    "claim_refs": list(claim_ids),
                    "claim_id": claim_ids[0],
                    "run_id": state.run_id,
                }
            )
            if input_manifest_digest:
                metadata["input_manifest_digest"] = input_manifest_digest
            if (
                input_manifest_digest
                and metadata.get("evidence_type") == "exact_value_observation"
                and isinstance(metadata.get("value_sha256"), str)
                and isinstance(metadata.get("source_artifact_sha256"), str)
            ):
                locator = metadata.get("source_locator")
                if isinstance(locator, dict):
                    attestation = build_exact_answer_attestation(
                        run_id=state.run_id,
                        input_manifest_digest=input_manifest_digest,
                        evidence_id=evidence_id,
                        value_sha256=metadata["value_sha256"],
                        artifact_sha256=metadata["source_artifact_sha256"],
                        locator=locator,
                    )
                    if attestation is not None:
                        metadata["exact_answer_attestation"] = attestation
            evidence.metadata = metadata

    @staticmethod
    def _verified_report_evidence_ids(
        state: AgentState,
        report: AgentReport,
        *,
        rehashed_evidence_ids: set[str] | None = None,
    ) -> set[str]:
        """Return only report-visible evidence backed by a verified support edge.

        Coverage claims are intentionally not Findings, so their evidence is
        not reachable through ``Finding.evidence_ids``.  The terminal boundary
        may retain that evidence only when the report exposes the claim and the
        durable graph records both a verified claim and a verified SUPPORTS
        edge.  Requiring byte-equivalent state/report evidence prevents a
        reporter candidate from replacing already-verified material.
        """

        return set(
            verified_evidence_claims(
                state,
                report,
                allowed_evidence_ids=rehashed_evidence_ids,
            )
        )

    @staticmethod
    def _java_input_manifest(state: AgentState, step: PlanStep) -> tuple[str, int] | None:
        """Reconstruct the bounded Java tool manifest from immutable ingest metadata."""

        raw_target = step.inputs.get("target", ".")
        target = _normalized_repository_path(raw_target)
        if target is None:
            return None
        candidates: list[tuple[str, str, int]] = []
        for artifact in state.input_artifacts:
            normalized = _normalized_repository_path(artifact.relative_path)
            if normalized is None or not _valid_sha256(artifact.sha256) or artifact.size_bytes < 0:
                return None
            canonical = PurePosixPath(
                unicodedata.normalize("NFC", artifact.relative_path.replace("\\", "/"))
            ).as_posix()
            if not canonical.casefold().endswith(".java"):
                continue
            if target != "." and normalized != target and not normalized.startswith(f"{target}/"):
                continue
            candidates.append((canonical, artifact.sha256.lower(), artifact.size_bytes))

        total_bytes = 0
        manifest_rows: list[dict[str, str]] = []
        for path, sha256, size_bytes in sorted(candidates, key=lambda item: item[0])[:512]:
            if size_bytes > 2 * 1024 * 1024 or total_bytes + size_bytes > 8 * 1024 * 1024:
                continue
            total_bytes += size_bytes
            manifest_rows.append({"path": path, "sha256": sha256})
        return _digest(manifest_rows), len(manifest_rows)

    @staticmethod
    def _matches_immutable_input(state: AgentState, path: str, file_sha256: str) -> bool:
        """Resolve one tool path to exactly one immutable input-manifest entry."""

        target = _normalized_repository_path(path)
        if target is None or not _valid_sha256(file_sha256) or not state.input_artifacts:
            return False

        manifest: list[tuple[str, str]] = []
        for artifact in state.input_artifacts:
            artifact_path = _normalized_repository_path(artifact.relative_path)
            if artifact_path is None or not _valid_sha256(artifact.sha256):
                return False
            manifest.append((artifact_path, artifact.sha256.lower()))

        exact = [item for item in manifest if item[0] == target]
        if len(exact) > 1:
            return False
        if exact:
            matched = exact
        else:
            matched = [item for item in manifest if item[0].endswith(f"/{target}")]
        if len(matched) != 1:
            return False
        return hmac.compare_digest(matched[0][1], file_sha256.lower())

    @staticmethod
    def _valid_ticket_identity(ticket: EvidenceGapTicket) -> bool:
        payload = ticket.model_dump(
            mode="json",
            exclude={"ticket_id", "schema_version", "created_at"},
        )
        return ticket.ticket_id == f"gap-ticket-{_digest(payload)}"

    @staticmethod
    def _fallback_report(state: AgentState) -> AgentReport:
        return AgentReport(
            run_id=state.run_id,
            status=state.status,
            executive_summary="SecMind completed deterministic admission over the available evidence.",
            findings=list(state.findings),
            decisions=list(state.decisions),
            evidence=list(state.evidence),
            limitations=list(state.completion_reasons),
            coverage=dict(state.audit_coverage),
            audit_kernel=state.audit_kernel,
            audit_units=list(state.audit_units),
        )


__all__ = ["AdmissionError", "AdmissionService"]
