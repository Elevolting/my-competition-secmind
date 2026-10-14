"""Deterministic evidence-gap compiler for bounded optional workers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass

from secmind.gap_plan import GAP_DOMAIN_CAPABILITIES, GapDomain, domain_for_capability
from secmind.java_semantic_sast import SEMANTIC_SIGNAL
from secmind.primary_baseline import baseline_semantic_digest, validate_baseline_chain
from secmind.schemas import AgentState, EvidenceGapTicket, Finding, PlanStep, RiskLevel, ToolHealth, ToolManifest


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _non_negative_int(value: object) -> int | None:
    """Parse persisted coverage counters without letting malformed state crash recovery."""

    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value)
        except (ValueError, OverflowError):
            return None
    else:
        return None
    return parsed if parsed >= 0 else None


@dataclass(frozen=True, slots=True)
class GapCompilation:
    gap_codes: tuple[str, ...]
    tickets: tuple[EvidenceGapTicket, ...]
    steps: tuple[PlanStep, ...]
    scout_mode: bool = False
    domains: tuple[GapDomain, ...] = ()


def cross_domain_capability_catalog() -> dict[GapDomain, tuple[str, ...]]:
    """Return the immutable cross-domain capability catalog for pure planners.

    The returned mapping is copied so callers cannot mutate the server-owned
    capability boundary.  Tool execution still requires a matching
    ``ToolManifest``; this function only describes legal observation lanes.
    """

    return {domain: tuple(capabilities) for domain, capabilities in GAP_DOMAIN_CAPABILITIES.items()}


class EvidenceGapCompiler:
    """Release at most four bounded observation workers.

    Authority is decided from verified evidence at Admission, not from the
    order in which this planner happened to enumerate tools. R2 manifests may
    be planned, but they still have to pass the atomic Broker guardrail and
    therefore interrupt for operator approval. R3 manifests are never
    released by this compiler.
    """

    _TOOL_PREFERENCE = {
        "java_semantic_sast": 0,
        "python_taint_audit": 1,
        "web_workflow_audit": 2,
        "semgrep_sast": 3,
        "bandit_python_audit": 4,
    }
    _GAP_CAPABILITIES = {
        # Inventory is a bounded supporting worker for a missing Primary
        # baseline.  It never receives release authority; the compiler keeps
        # that authority restricted to a SAST-capability worker below.
        "empty_or_inconclusive_primary": frozenset({"inventory", "sast"}),
        "security_sensitive_weak_digest": frozenset({"sast"}),
        "cwe_uncertain": frozenset({"sast"}),
        "sink_location_missing": frozenset({"sast"}),
        "source_sink_trace_missing": frozenset({"sast"}),
        "primary_tool_conflict": frozenset({"sast"}),
        "missing_secret_coverage": frozenset({"secret_scan"}),
        "missing_dependency_coverage": frozenset({"sbom", "dependency_audit"}),
        "missing_web_workflow_coverage": frozenset({"sast"}),
        "missing_java_semantic_coverage": frozenset({"sast"}),
    }

    def gap_codes(self, state: AgentState) -> tuple[str, ...]:
        """Return stable public gap codes without constructing any worker."""

        return tuple(dict.fromkeys(item[0] for item in self._detect(state)))

    def compile(
        self,
        state: AgentState,
        steps: list[PlanStep],
        manifests: Iterable[ToolManifest],
        *,
        force_scouts: bool = False,
    ) -> GapCompilation:
        baseline = state.published_baseline
        if state.repository_index is None:
            return GapCompilation((), (), ())
        detected = self._detect(state)
        scout_mode = force_scouts and not detected
        if not detected and not scout_mode:
            return GapCompilation((), (), ())

        manifest_by_name = {
            manifest.name: manifest
            for manifest in manifests
            if manifest.health_status == ToolHealth.HEALTHY
            and manifest.risk_level <= RiskLevel.R2
            and (manifest.platform_risk is None or manifest.platform_risk <= RiskLevel.R2)
        }
        healthy = set(manifest_by_name)
        candidates = [step for step in steps if step.tool_candidates and step.tool_candidates[0] in healthy]
        candidates.sort(
            key=lambda step: (
                self._TOOL_PREFERENCE.get(step.tool_candidates[0], 100),
                step.step_id,
            )
        )
        selected: list[PlanStep] = []
        tickets: list[EvidenceGapTicket] = []
        authoritative_used = False
        shadow_count = 0
        for step in candidates:
            if len(tickets) >= 4:
                break
            tool_name = step.tool_candidates[0]
            manifest = manifest_by_name[tool_name]
            relevant: tuple[str, str | None, str] | None
            if scout_mode:
                scout_gaps = {
                    "sast": ("primary_tool_conflict", None, "add_finding"),
                    "secret_scan": ("missing_secret_coverage", None, "add_finding"),
                    "sbom": ("missing_dependency_coverage", None, "add_finding"),
                    "dependency_audit": ("missing_dependency_coverage", None, "add_finding"),
                    "inventory": ("empty_or_inconclusive_primary", None, "attach_coverage"),
                }
                relevant = scout_gaps.get(step.capability)
            else:
                relevant = self._gap_for_tool(tool_name, step.capability, detected)
            if relevant is None:
                continue
            gap_code, target_id, patch_class = relevant
            can_authorize = (
                not scout_mode
                and not authoritative_used
                and step.capability == "sast"
                and (
                    (baseline is None and gap_code == "empty_or_inconclusive_primary")
                    or (
                        tool_name == "python_taint_audit"
                        and patch_class == "add_finding"
                        and "python" in state.repository_index.languages
                    )
                    or (
                        tool_name == "java_semantic_sast"
                        and gap_code == "security_sensitive_weak_digest"
                        and patch_class == "add_finding"
                        and "java" in state.repository_index.languages
                        and self._has_java_weak_digest_signal(state)
                    )
                )
            )
            if can_authorize:
                release_policy = "authoritative"
                authoritative_used = True
            elif shadow_count < 4:
                release_policy = "shadow"
                shadow_count += 1
            else:
                continue
            payload = {
                "run_id": state.run_id,
                "snapshot_digest": state.repository_index.digest,
                "primary_semantic_digest": (
                    baseline.semantic_digest if baseline is not None else baseline_semantic_digest([], [])
                ),
                "gap_code": gap_code,
                "target_finding_id": target_id,
                "allowed_patch_class": patch_class,
                "capability": step.capability,
                "tool_name": tool_name,
                "step_id": step.step_id,
                "release_policy": release_policy,
                "max_tool_calls": 2 if manifest.idempotent else 1,
                "max_runtime_ms": 120_000,
            }
            ticket = EvidenceGapTicket.model_validate({"ticket_id": f"gap-ticket-{_digest(payload)}", **payload})
            requirements = {
                **step.context_requirements,
                "evidence_gap_ticket_id": ticket.ticket_id,
                "evidence_gap_code": ticket.gap_code,
                "allowed_patch_class": ticket.allowed_patch_class,
                "release_policy": ticket.release_policy,
                "primary_semantic_digest": ticket.primary_semantic_digest,
            }
            selected.append(step.model_copy(deep=True, update={"context_requirements": requirements}))
            tickets.append(ticket)
        # Gap workers consume the already sealed repository snapshot. Generic
        # strategy plans often depend on an inventory step, but the compiler
        # releases only the selected post-Primary workers. Keeping a dependency
        # on a step that was not released makes the bounded plan invalid and
        # silently turns every gap tool into dead code.
        selected_ids = {step.step_id for step in selected}
        selected = [
            step.model_copy(
                deep=True,
                update={
                    "dependencies": [item for item in step.dependencies if item in selected_ids],
                    "dependency_bindings": [
                        item for item in step.dependency_bindings if item.upstream_step_id in selected_ids
                    ],
                    "context_requirements": {
                        **step.context_requirements,
                        "repository_snapshot_prerequisite": "sealed",
                    },
                },
            )
            for step in selected
        ]
        domains = tuple(
            dict.fromkeys(domain for step in selected if (domain := domain_for_capability(step.capability)) is not None)
        )
        return GapCompilation(
            tuple(dict.fromkeys(item[0] for item in detected)),
            tuple(tickets),
            tuple(selected),
            scout_mode,
            domains,
        )

    @staticmethod
    def _gap_for_tool(
        tool_name: str,
        capability: str,
        detected: list[tuple[str, str | None, str]],
    ) -> tuple[str, str | None, str] | None:
        compatible = [
            item for item in detected if capability in EvidenceGapCompiler._GAP_CAPABILITIES.get(item[0], frozenset())
        ]
        if tool_name == "java_semantic_sast":
            return next(
                (
                    item
                    for item in compatible
                    if item[0] in {"security_sensitive_weak_digest", "missing_java_semantic_coverage"}
                ),
                None,
            )
        if tool_name == "web_workflow_audit":
            workflow_gap = next((item for item in compatible if item[0] == "missing_web_workflow_coverage"), None)
            if workflow_gap is not None:
                return workflow_gap
        if capability == "sast":
            compatible = [
                item
                for item in compatible
                if item[0]
                not in {
                    "security_sensitive_weak_digest",
                    "missing_java_semantic_coverage",
                    "missing_web_workflow_coverage",
                }
            ]
        return compatible[0] if compatible else None

    @staticmethod
    def _has_java_weak_digest_signal(state: AgentState) -> bool:
        primary_signals = state.audit_coverage.get("primary_static_signals")
        if isinstance(primary_signals, list) and SEMANTIC_SIGNAL in primary_signals:
            return True
        affinity = state.audit_coverage.get("tool_affinity")
        if not isinstance(affinity, dict):
            return False
        signals = affinity.get("signals")
        return isinstance(signals, list) and SEMANTIC_SIGNAL in signals

    @classmethod
    def _detect(cls, state: AgentState) -> list[tuple[str, str | None, str]]:
        baseline = state.published_baseline
        if baseline is None:
            return cls._sorted_gaps(
                [("empty_or_inconclusive_primary", None, "add_finding")] + cls._coverage_gaps(state, [])
            )
        valid, _reason = validate_baseline_chain(state)
        if not valid:
            return cls._sorted_gaps(
                [("empty_or_inconclusive_primary", None, "add_finding")] + cls._coverage_gaps(state, [])
            )
        findings = baseline.findings
        status = str(baseline.coverage.get("primary_answer_status", baseline.status.value))
        gaps: list[tuple[str, str | None, str]] = []
        input_count = _non_negative_int(baseline.coverage.get("input_count"))
        viewed_count = _non_negative_int(baseline.coverage.get("viewed_count"))
        omitted_count = _non_negative_int(baseline.coverage.get("omitted_count"))
        unbound_count = _non_negative_int(baseline.coverage.get("unbound_primary_candidate_count"))
        negative_coverage_complete = bool(
            not findings
            and status == "completed"
            and baseline.coverage.get("negative_coverage_complete") is True
            and input_count is not None
            and input_count > 0
            and omitted_count == 0
            and viewed_count == input_count
            and unbound_count == 0
        )
        if not findings and status == "completed" and cls._has_java_weak_digest_signal(state):
            gaps.append(("security_sensitive_weak_digest", None, "add_finding"))
        if (not findings and not negative_coverage_complete) or status in {
            "partial",
            "insufficient_evidence",
            "blocked",
        }:
            gaps.append(("empty_or_inconclusive_primary", None, "add_finding"))
        gaps.extend(cls._coverage_gaps(state, findings))
        for finding in findings:
            raw = finding.raw
            if finding.rule_id in {"", "UNKNOWN", "MODEL-SECURITY-FINDING"}:
                gaps.append(("cwe_uncertain", finding.finding_id, "correct_cwe"))
            if finding.path in {"", "."} or finding.line is None:
                gaps.append(("sink_location_missing", finding.finding_id, "attach_trace"))
            if not str(raw.get("data_flow") or "").strip() or not str(raw.get("root_cause") or "").strip():
                gaps.append(("source_sink_trace_missing", finding.finding_id, "attach_trace"))
        return cls._sorted_gaps(gaps)

    @classmethod
    def _coverage_gaps(
        cls,
        state: AgentState,
        findings: list[Finding],
    ) -> list[tuple[str, str | None, str]]:
        signals = cls._coverage_signals(state)
        gaps: list[tuple[str, str | None, str]] = []
        if "secret_material" in signals or "secret_candidate" in signals:
            if not any(cls._is_secret_finding(finding) for finding in findings):
                gaps.append(("missing_secret_coverage", None, "add_finding"))
        if "dependency_manifest" in signals:
            if not any(cls._is_dependency_finding(finding) for finding in findings):
                gaps.append(("missing_dependency_coverage", None, "add_finding"))
        if cls._needs_web_workflow_coverage(state, findings):
            gaps.append(("missing_web_workflow_coverage", None, "add_finding"))
        if cls._needs_java_semantic_coverage(state):
            gaps.append(("missing_java_semantic_coverage", None, "add_finding"))
        return gaps

    @staticmethod
    def _needs_java_semantic_coverage(state: AgentState) -> bool:
        """Run the approved Java semantic checker once per Java audit.

        A model finding or a shallow lexical pass is not an execution receipt.
        The specialized checker is bounded, deterministic, R1, and enforces
        its own source-to-sink proof before emitting any candidate.
        """

        repository = state.repository_index
        if repository is None or "java" not in {item.casefold() for item in repository.languages}:
            return False
        if EvidenceGapCompiler._has_java_weak_digest_signal(state):
            # The more specific authoritative gap already dispatches the same
            # tool and must not be shadowed by this generic coverage ticket.
            return False
        routing = state.audit_coverage.get("tool_routing")
        succeeded = routing.get("succeeded", []) if isinstance(routing, dict) else []
        if isinstance(succeeded, list) and "java_semantic_sast" in {str(item) for item in succeeded}:
            return False
        affinity = state.audit_coverage.get("tool_affinity")
        if not isinstance(affinity, dict):
            return False
        scores = affinity.get("scores")
        if not isinstance(scores, dict):
            return False
        score = _non_negative_int(scores.get("java_semantic_sast"))
        return score is not None and score >= 70

    @staticmethod
    def _needs_web_workflow_coverage(state: AgentState, _findings: list[Finding]) -> bool:
        """Release the approved PHP workflow analyzer independently of model self-status.

        A completed Primary response is not evidence that a client-controlled
        state transition was examined.  The router has already inspected only
        bounded, hash-verified input bytes; a high affinity score therefore
        authorizes one cheap R1 observation, not a finding.  The analyzer and
        Admission still have to prove the workflow and its evidence closure.
        """

        repository = state.repository_index
        if repository is None or "php" not in {item.casefold() for item in repository.languages}:
            return False
        # A model-proposed label is not an execution receipt.  Only a real,
        # successful deterministic observation closes this coverage gap;
        # otherwise Primary can suppress the very checker meant to validate
        # or correct it by simply asserting CWE-840 itself.
        routing = state.audit_coverage.get("tool_routing")
        succeeded = routing.get("succeeded", []) if isinstance(routing, dict) else []
        if isinstance(succeeded, list) and "web_workflow_audit" in {str(item) for item in succeeded}:
            return False
        affinity = state.audit_coverage.get("tool_affinity")
        if not isinstance(affinity, dict):
            return False
        scores = affinity.get("scores")
        if not isinstance(scores, dict):
            return False
        score = _non_negative_int(scores.get("web_workflow_audit"))
        return score is not None and score >= 80

    @staticmethod
    def _sorted_gaps(
        gaps: list[tuple[str, str | None, str]],
    ) -> list[tuple[str, str | None, str]]:
        return sorted(set(gaps), key=lambda item: (item[0], item[1] or "", item[2]))

    @staticmethod
    def _coverage_signals(state: AgentState) -> set[str]:
        signals: set[str] = set()
        affinity = state.audit_coverage.get("tool_affinity")
        if isinstance(affinity, dict):
            raw_signals = affinity.get("signals")
            if isinstance(raw_signals, list):
                signals.update(str(item) for item in raw_signals)
        if state.repository_index is not None and state.repository_index.dependency_files:
            signals.add("dependency_manifest")
        return signals

    @staticmethod
    def _is_secret_finding(finding: object) -> bool:
        rule_id = str(getattr(finding, "rule_id", ""))
        raw = getattr(finding, "raw", {})
        return rule_id == "CWE-798" or (isinstance(raw, dict) and raw.get("finding_type") == "secret_exposure")

    @staticmethod
    def _is_dependency_finding(finding: object) -> bool:
        rule_id = str(getattr(finding, "rule_id", ""))
        raw = getattr(finding, "raw", {})
        return rule_id == "CWE-1104" or (
            isinstance(raw, dict) and raw.get("finding_type") in {"dependency_vulnerability", "dependency_audit"}
        )


__all__ = [
    "EvidenceGapCompiler",
    "GapCompilation",
    "cross_domain_capability_catalog",
    "domain_for_capability",
]
