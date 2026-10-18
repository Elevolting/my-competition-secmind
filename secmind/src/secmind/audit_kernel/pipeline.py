from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime

from secmind.audit_kernel.contracts import (
    AuditUnit,
    CandidateFlow,
    CriticVerdict,
    FlowVerdict,
    GainAction,
    GainPolicy,
    PrimaryVerdict,
    ReviewVerdict,
    UnitDecision,
    content_digest,
)
from secmind.audit_kernel.gain_gate import GainGate
from secmind.audit_kernel.java_configuration import (
    JavaConfigurationEvidenceExtractor,
)
from secmind.audit_kernel.java_context import dependency_closed_support
from secmind.audit_kernel.java_evidence import (
    JavaEvidenceExtractor,
    validate_structural_correction,
    validate_structural_flow,
)
from secmind.audit_kernel.patch_release import (
    EmpiricalGate,
    PatchIdentity,
    PatchReleaseRecord,
    PatchReleaseRegistry,
)
from secmind.audit_kernel.persistence import (
    AuditLane,
    AuditPersistence,
    ReviewShardReceipt,
    ShardStatus,
)
from secmind.audit_kernel.profiles import CORE_TARGET_CWES
from secmind.audit_kernel.reviewer import (
    CRITIC_PROMPT_VERSION,
    PRIMARY_PROMPT_VERSION,
    ConditionalConflictCritic,
    DirectFirstPrimaryReviewer,
    PreparedSource,
    PrimaryReviewResult,
)
from secmind.audit_kernel.snapshot import WorkspaceSnapshot
from secmind.live_source_review import SourceUnit
from secmind.schemas import ModelUsage

JAVA_EVIDENCE_TOOL = "secmind-java-flow"
JAVA_EVIDENCE_VERSION = "1.1.0"
JAVA_RULE_BUNDLE_DIGEST = hashlib.sha256(b"secmind-java-flow-rules-v2").hexdigest()
JAVA_CONFIGURATION_TOOL = "secmind-java-configuration"
JAVA_CONFIGURATION_VERSION = "1.0.0"
JAVA_CONFIGURATION_RULE_BUNDLE_DIGEST = hashlib.sha256(b"secmind-java-configuration-rules-v1").hexdigest()
JAVA_PARSER_DIGEST = hashlib.sha256(b"secmind-java-structural-candidate-parser-v1").hexdigest()
DEFAULT_CRITIC_MODEL_POLICY_DIGEST = hashlib.sha256(b"secmind-v0.7-approved-model-policy-max-tier-5.4").hexdigest()
DEFAULT_TARGET_CWES = CORE_TARGET_CWES


@dataclass(frozen=True, slots=True)
class AuditKernelResult:
    mode: str
    snapshot: WorkspaceSnapshot
    units: tuple[AuditUnit, ...]
    primary_verdicts: dict[str, PrimaryVerdict]
    decisions: tuple[UnitDecision, ...]
    shadow_decisions: tuple[UnitDecision, ...]
    candidate_flows: dict[str, tuple[CandidateFlow, ...]]
    sink_lines: dict[str, int | None]
    rationales: dict[str, str]
    source_by_unit_id: dict[str, PreparedSource]
    shard_errors: dict[str, str]
    response_hashes: tuple[str, ...]
    model_calls_used: int
    usage: ModelUsage

    @property
    def coverage(self) -> dict[str, int | float]:
        total = len(self.units)
        reviewed = sum(decision.final_verdict != ReviewVerdict.INCONCLUSIVE for decision in self.decisions)
        scoreable = reviewed
        positives = sum(decision.final_verdict == ReviewVerdict.VULNERABLE for decision in self.decisions)
        negatives = sum(decision.final_verdict == ReviewVerdict.NOT_VULNERABLE for decision in self.decisions)
        promoted = sum(decision.action == GainAction.ACCEPT_ENHANCEMENT for decision in self.decisions)
        corrected = sum(decision.action == GainAction.ACCEPT_CORRECTION for decision in self.decisions)
        return {
            "total_units": total,
            "covered_units": reviewed,
            "scoreable_units": scoreable,
            "positive_units": positives,
            "negative_units": negatives,
            "inconclusive_units": total - reviewed,
            "promoted_units": promoted,
            "corrected_units": corrected,
            "coverage": 1.0 if total == 0 else scoreable / total,
            "review_coverage": 1.0 if total == 0 else reviewed / total,
        }


@dataclass(slots=True)
class _CallBudget:
    remaining: int
    deadline_at: datetime
    minimum_dispatch_seconds: float
    used: int = 0
    usage: ModelUsage = field(default_factory=ModelUsage)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def claim(self) -> bool:
        async with self._lock:
            remaining_seconds = (self.deadline_at - datetime.now(UTC)).total_seconds()
            if self.remaining <= 0 or remaining_seconds < self.minimum_dispatch_seconds:
                return False
            self.remaining -= 1
            self.used += 1
            return True

    async def record_usage(self, usage: ModelUsage) -> None:
        async with self._lock:
            self.usage.provider_requests += usage.provider_requests
            self.usage.input_tokens += usage.input_tokens
            self.usage.output_tokens += usage.output_tokens
            self.usage.cache_hit_input_tokens += usage.cache_hit_input_tokens
            self.usage.cache_miss_input_tokens += usage.cache_miss_input_tokens
            self.usage.cost_units += usage.cost_units

    def timeout_seconds(self) -> float:
        """Return the remaining root wall-clock budget for an in-flight call."""

        return max(0.0, (self.deadline_at - datetime.now(UTC)).total_seconds())


class JavaAuditKernel:
    """Five-stage v0.7 audit facade with Direct-first monotonic semantics."""

    def __init__(
        self,
        primary: DirectFirstPrimaryReviewer,
        critic: ConditionalConflictCritic,
        *,
        repository: AuditPersistence | None = None,
        target_cwes: tuple[int, ...] = DEFAULT_TARGET_CWES,
        gain_cwes: tuple[int, ...] | None = None,
        primary_concurrency: int = 3,
        critic_concurrency: int = 2,
        max_units_per_shard: int = 6,
        minimum_dispatch_seconds: float = 1.0,
        patch_registry: PatchReleaseRegistry | None = None,
        critic_model_policy_digest: str = DEFAULT_CRITIC_MODEL_POLICY_DIGEST,
    ) -> None:
        if primary_concurrency < 1 or critic_concurrency < 1:
            raise ValueError("audit model concurrency must be positive")
        if not 1 <= max_units_per_shard <= 6:
            raise ValueError("v0.7 shards must contain 1-6 units")
        self._primary = primary
        self._critic = critic
        self._repository = repository
        self._target_cwes = tuple(sorted(set(target_cwes)))
        self._gain_cwes = tuple(sorted(set(self._target_cwes if gain_cwes is None else gain_cwes)))
        if not set(self._gain_cwes).issubset(self._target_cwes):
            raise ValueError("gain CWEs must be a subset of the immutable target scope")
        self._primary_concurrency = primary_concurrency
        self._critic_concurrency = critic_concurrency
        self._max_units_per_shard = max_units_per_shard
        self._minimum_dispatch_seconds = minimum_dispatch_seconds
        self._extractor = JavaEvidenceExtractor(
            tool_name=JAVA_EVIDENCE_TOOL,
            tool_version=JAVA_EVIDENCE_VERSION,
            rule_bundle_digest=JAVA_RULE_BUNDLE_DIGEST,
        )
        self._configuration_extractor = JavaConfigurationEvidenceExtractor(
            tool_name=JAVA_CONFIGURATION_TOOL,
            tool_version=JAVA_CONFIGURATION_VERSION,
            rule_bundle_digest=JAVA_CONFIGURATION_RULE_BUNDLE_DIGEST,
        )
        self._patch_registry = patch_registry or PatchReleaseRegistry()
        if self._repository is not None:
            for release in self._repository.load_patch_releases():
                self._patch_registry.put(release)
        self._gain_gate = GainGate(EmpiricalGate(self._patch_registry))
        self._critic_model_policy_digest = critic_model_policy_digest
        self._policy = GainPolicy.create(
            policy_id="SECMIND-V07-MONOTONIC-GAIN",
            version="1",
            approved_tool_names=(JAVA_EVIDENCE_TOOL, JAVA_CONFIGURATION_TOOL),
            approved_rule_bundle_digests=(
                JAVA_RULE_BUNDLE_DIGEST,
                JAVA_CONFIGURATION_RULE_BUNDLE_DIGEST,
            ),
            allowed_cwes=self._gain_cwes,
            minimum_tool_confidence=0.85,
            minimum_critic_confidence=0.85,
        )

    async def run(
        self,
        *,
        run_id: str,
        case_files: list[SourceUnit],
        support_files: list[SourceUnit],
        deadline_at: datetime,
        max_model_calls: int,
        mode: str = "shadow",
        authorized_scope: tuple[str, ...] = (".",),
    ) -> AuditKernelResult:
        if mode not in {"baseline", "shadow", "authoritative"}:
            raise ValueError("audit kernel mode must be baseline, shadow or authoritative")
        snapshot, prepared = self._prepare(
            run_id,
            case_files,
            support_files,
            authorized_scope=authorized_scope,
        )
        if self._repository is not None:
            for item in prepared:
                self._repository.register_unit(item.unit)
        budget = _CallBudget(max_model_calls, deadline_at, self._minimum_dispatch_seconds)
        context_files = [*case_files, *support_files]
        (
            primary,
            sink_lines,
            rationales,
            response_hashes,
            shard_errors,
        ) = await self._review_primary(
            run_id,
            prepared,
            context_files,
            budget,
        )
        # Every unit gets a durable baseline truth, including explicit
        # inconclusive outcomes for exhausted/failed shards.
        for item in prepared:
            if item.unit.unit_id in primary:
                continue
            primary[item.unit.unit_id] = PrimaryVerdict(
                unit_id=item.unit.unit_id,
                verdict=ReviewVerdict.INCONCLUSIVE,
                confidence=0,
                sink_line=None,
                reason_codes=("primary_unavailable",),
                limitations=("The bounded primary review did not return a valid unit verdict.",),
                receipt_id=f"unavailable:{item.unit.unit_id}",
            )
            if self._repository is not None:
                self._repository.commit_primary_verdict(
                    run_id=run_id,
                    lane=AuditLane.BASELINE,
                    verdict=primary[item.unit.unit_id],
                )
            sink_lines[item.unit.unit_id] = None
            rationales[item.unit.unit_id] = "Primary review unavailable; no label was inferred."

        baseline_decisions = tuple(
            self._gain_gate.decide(item.unit, primary[item.unit.unit_id], policy=None)
            for item in sorted(prepared, key=lambda value: value.unit.unit_id)
        )
        if self._repository is not None:
            for decision in baseline_decisions:
                self._repository.commit_unit_decision(
                    run_id=run_id,
                    lane=AuditLane.BASELINE,
                    decision=decision,
                )

        # The Direct baseline is now durable. Evidence extraction is optional
        # and isolated per unit so parser/tool failure can never erase it.
        flows: dict[str, tuple[CandidateFlow, ...]] = {item.unit.unit_id: () for item in prepared}
        if mode != "baseline":
            for item in prepared:
                try:
                    candidates = {
                        flow.flow_id: flow
                        for flow in (
                            *self._extractor.extract(item.unit, item.content),
                            *self._configuration_extractor.extract(item.unit, item.content),
                        )
                    }
                    flows[item.unit.unit_id] = tuple(sorted(candidates.values(), key=lambda value: value.flow_id))
                except Exception as exc:
                    shard_errors[f"evidence:{item.unit.unit_id}"] = type(exc).__name__
        augmented = baseline_decisions
        if mode == "authoritative":
            augmented = await self._adjudicate(
                run_id,
                prepared,
                primary,
                flows,
                context_files,
                budget,
                lane=AuditLane.FINAL,
            )
        elif mode == "shadow":
            augmented = await self._adjudicate(
                run_id,
                prepared,
                primary,
                flows,
                context_files,
                budget,
                lane=AuditLane.SHADOW,
            )
        selected = augmented if mode == "authoritative" else baseline_decisions
        if self._repository is not None and mode != "authoritative":
            for decision in selected:
                self._repository.commit_unit_decision(
                    run_id=run_id,
                    lane=AuditLane.FINAL,
                    decision=decision,
                )
        return AuditKernelResult(
            mode=mode,
            snapshot=snapshot,
            units=tuple(item.unit for item in prepared),
            primary_verdicts=primary,
            decisions=selected,
            shadow_decisions=augmented if mode == "shadow" else (),
            candidate_flows=flows,
            sink_lines=sink_lines,
            rationales=rationales,
            source_by_unit_id={item.unit.unit_id: item for item in prepared},
            shard_errors=shard_errors,
            response_hashes=tuple(sorted(response_hashes)),
            model_calls_used=budget.used,
            usage=budget.usage.model_copy(deep=True),
        )

    def _prepare(
        self,
        run_id: str,
        case_files: list[SourceUnit],
        support_files: list[SourceUnit],
        *,
        authorized_scope: tuple[str, ...],
    ) -> tuple[WorkspaceSnapshot, list[PreparedSource]]:
        snapshot = WorkspaceSnapshot.build([*case_files, *support_files], authorized_scope=authorized_scope)
        manifest_digest = snapshot.input_manifest_digest
        profile_digest = content_digest(
            {
                "kernel": "v0.7-direct-first",
                "target_cwes": self._target_cwes,
                "gain_cwes": self._gain_cwes,
                "rule_bundle_digests": (
                    JAVA_RULE_BUNDLE_DIGEST,
                    JAVA_CONFIGURATION_RULE_BUNDLE_DIGEST,
                ),
            }
        )
        support_by_path = dependency_closed_support(case_files, support_files)
        prepared: list[PreparedSource] = []
        for source in sorted(case_files, key=lambda item: (item.path, item.sha256)):
            unit = AuditUnit.create(
                run_id=run_id,
                input_manifest_digest=manifest_digest,
                profile_digest=profile_digest,
                primary_path=source.path,
                source_sha256=source.sha256,
                target_cwes=self._target_cwes,
                support_paths=support_by_path.get(source.path, ()),
                authorized_scope=authorized_scope,
                snapshot_id=snapshot.snapshot_id,
            )
            prepared.append(PreparedSource(unit=unit, content=source.content))
        return snapshot, prepared

    async def _review_primary(
        self,
        run_id: str,
        prepared: list[PreparedSource],
        support_files: list[SourceUnit],
        budget: _CallBudget,
    ) -> tuple[
        dict[str, PrimaryVerdict],
        dict[str, int | None],
        dict[str, str],
        set[str],
        dict[str, str],
    ]:
        prepared_ids = {item.unit.unit_id for item in prepared}
        cached = (
            ()
            if self._repository is None
            else self._repository.load_primary_verdicts(
                run_id=run_id,
                lane=AuditLane.BASELINE,
            )
        )
        primary = {record.unit_id: record.verdict for record in cached if record.unit_id in prepared_ids}
        prepared_by_id = {item.unit.unit_id: item for item in prepared}
        sink_lines: dict[str, int | None] = {unit_id: verdict.sink_line for unit_id, verdict in primary.items()}
        rationales: dict[str, str] = {unit_id: "Recovered immutable Direct-first verdict." for unit_id in primary}
        response_hashes: set[str] = set()
        errors: dict[str, str] = {}
        if self._repository is not None:
            can_project_receipt = callable(getattr(self._primary, "project_receipt", None))
            for receipt in self._repository.load_provider_receipts(run_id):
                if not set(receipt.unit_ids).issubset(prepared_ids):
                    continue
                # Crash recovery reuses the paid provider receipt and must also
                # restore its usage projection.  ``model_calls_used`` remains
                # zero because no new logical call is dispatched on replay.
                await budget.record_usage(receipt.usage)
                if set(receipt.unit_ids).issubset(primary):
                    response_hashes.add(receipt.response_digest)
                    continue
                if not can_project_receipt:
                    continue
                receipt_sources = [prepared_by_id[item] for item in receipt.unit_ids]
                try:
                    replayed = self._primary.project_receipt(receipt, receipt_sources)
                except (TypeError, ValueError):
                    errors[f"receipt:{receipt.receipt_id}"] = "receipt_projection_failed"
                    continue
                self._accept_primary(run_id, replayed, primary, sink_lines, rationales)
                response_hashes.add(receipt.response_digest)
        semaphore = asyncio.Semaphore(self._primary_concurrency)
        shards = [
            prepared[index : index + self._max_units_per_shard]
            for index in range(0, len(prepared), self._max_units_per_shard)
        ]

        async def review_shard(
            shard: list[PreparedSource],
        ) -> tuple[list[PreparedSource], PrimaryReviewResult | None, str | None]:
            missing = [item for item in shard if item.unit.unit_id not in primary]
            if not missing:
                return missing, None, None
            try:
                async with semaphore:
                    if not await budget.claim():
                        return missing, None, "deadline_or_model_budget"
                    async with asyncio.timeout(budget.timeout_seconds()):
                        result = await self._primary.review(
                            missing,
                            support_files=support_files,
                            run_id=run_id,
                            deadline_at=budget.deadline_at,
                        )
                if self._repository is not None and result.receipt is not None:
                    self._repository.commit_provider_receipt(result.receipt)
                await budget.record_usage(result.meta.usage)
                return missing, result, None
            except TimeoutError:
                return missing, None, "deadline_exhausted"
            except Exception as exc:  # Each shard is an intentional fault domain.
                return missing, None, type(exc).__name__

        shard_results = await asyncio.gather(*(review_shard(shard) for shard in shards))
        repair_units: dict[str, PreparedSource] = {}
        for dispatched, result, error in shard_results:
            if not dispatched:
                continue
            shard_key = self._shard_key(dispatched)
            attempted = tuple(item.unit.unit_id for item in dispatched)
            if not attempted:
                continue
            if error is not None:
                errors[shard_key] = error
                repair_units.update({item.unit.unit_id: item for item in dispatched})
                self._record_shard(
                    run_id,
                    dispatched,
                    completed_unit_ids=(),
                    response_sha256=None,
                    error_type=error,
                )
                continue
            if result is None:
                continue
            response_hashes.add(result.meta.response_sha256)
            self._accept_primary(run_id, result, primary, sink_lines, rationales)
            unresolved = set(result.missing_unit_ids) | set(result.rejected_unit_ids)
            repair_units.update({item.unit.unit_id: item for item in dispatched if item.unit.unit_id in unresolved})
            self._record_shard(
                run_id,
                dispatched,
                completed_unit_ids=tuple(result.verdicts),
                response_sha256=result.meta.response_sha256,
                error_type=None if not unresolved else "item_validation",
            )

        async def repair(
            item: PreparedSource,
        ) -> tuple[PreparedSource, PrimaryReviewResult | None, str | None]:
            if item.unit.unit_id in primary:
                return item, None, None
            try:
                async with semaphore:
                    if not await budget.claim():
                        return item, None, "deadline_or_model_budget"
                    async with asyncio.timeout(budget.timeout_seconds()):
                        result = await self._primary.review(
                            [item],
                            support_files=support_files,
                            run_id=run_id,
                            deadline_at=budget.deadline_at,
                        )
                if self._repository is not None and result.receipt is not None:
                    self._repository.commit_provider_receipt(result.receipt)
                await budget.record_usage(result.meta.usage)
                return item, result, None
            except TimeoutError:
                return item, None, "deadline_exhausted"
            except Exception as exc:
                return item, None, type(exc).__name__

        repairs = await asyncio.gather(
            *(repair(item) for item in sorted(repair_units.values(), key=lambda v: v.unit.unit_id))
        )
        for item, result, error in repairs:
            repair_key = self._shard_key([item])
            if error is not None:
                errors[repair_key] = error
                self._record_shard(
                    run_id,
                    [item],
                    completed_unit_ids=(),
                    response_sha256=None,
                    error_type=error,
                )
                continue
            if result is not None:
                response_hashes.add(result.meta.response_sha256)
                self._accept_primary(run_id, result, primary, sink_lines, rationales)
                has_verdict = bool(result.verdicts)
                self._record_shard(
                    run_id,
                    [item],
                    completed_unit_ids=tuple(result.verdicts),
                    response_sha256=result.meta.response_sha256,
                    error_type=None if has_verdict else "item_validation",
                )
        return primary, sink_lines, rationales, response_hashes, errors

    def _accept_primary(
        self,
        run_id: str,
        result: PrimaryReviewResult,
        primary: dict[str, PrimaryVerdict],
        sink_lines: dict[str, int | None],
        rationales: dict[str, str],
    ) -> None:
        if self._repository is not None and result.receipt is not None:
            self._repository.commit_provider_receipt(result.receipt)
        for unit_id, verdict in result.verdicts.items():
            primary[unit_id] = verdict
            sink_lines[unit_id] = verdict.sink_line
            rationales[unit_id] = result.rationales.get(unit_id, "Bounded primary verdict.")
            if self._repository is not None:
                self._repository.commit_primary_verdict(
                    run_id=run_id,
                    lane=AuditLane.BASELINE,
                    verdict=verdict,
                )

    async def _adjudicate(
        self,
        run_id: str,
        prepared: list[PreparedSource],
        primary: dict[str, PrimaryVerdict],
        flows: dict[str, tuple[CandidateFlow, ...]],
        support_files: list[SourceUnit],
        budget: _CallBudget,
        *,
        lane: AuditLane,
    ) -> tuple[UnitDecision, ...]:
        semaphore = asyncio.Semaphore(self._critic_concurrency)
        cached = (
            {}
            if self._repository is None
            else {
                record.unit_id: record.decision
                for record in self._repository.load_unit_decisions(
                    run_id=run_id,
                    lane=lane,
                )
            }
        )

        async def decide(item: PreparedSource) -> UnitDecision:
            if item.unit.unit_id in cached:
                return cached[item.unit.unit_id]
            baseline = primary[item.unit.unit_id]
            candidate_verdict = (
                FlowVerdict.CANDIDATE_POSITIVE
                if baseline.verdict == ReviewVerdict.NOT_VULNERABLE
                else FlowVerdict.CANDIDATE_NEGATIVE
                if baseline.verdict == ReviewVerdict.VULNERABLE
                else None
            )
            candidates = [
                flow
                for flow in flows.get(item.unit.unit_id, ())
                if candidate_verdict is not None
                and flow.verdict == candidate_verdict
                and flow.cwe in self._gain_cwes
                and (
                    baseline.cwe is None
                    or candidate_verdict == FlowVerdict.CANDIDATE_POSITIVE
                    or flow.cwe == baseline.cwe
                )
            ]
            if not candidates:
                decision = self._gain_gate.decide(item.unit, baseline, policy=self._policy)
            else:
                flow = sorted(candidates, key=lambda value: (-value.confidence, value.flow_id))[0]
                certificate = (
                    validate_structural_flow(item.unit, flow)
                    if flow.verdict == FlowVerdict.CANDIDATE_POSITIVE
                    else validate_structural_correction(item.unit, flow)
                )
                critic: CriticVerdict | None = None
                if certificate.valid:
                    try:
                        async with semaphore:
                            if not await budget.claim():
                                raise TimeoutError("deadline_or_model_budget")
                            async with asyncio.timeout(budget.timeout_seconds()):
                                critic_result = await self._critic.review(
                                    item,
                                    baseline,
                                    flow,
                                    support_files=support_files,
                                    run_id=run_id,
                                )
                        critic = critic_result.verdict
                        await budget.record_usage(critic_result.meta.usage)
                    except Exception:
                        critic = None
                decision = self._gain_gate.decide(
                    item.unit,
                    baseline,
                    policy=self._policy,
                    flow=flow,
                    certificate=certificate,
                    critic=critic,
                    patch_identity=self.patch_identity(item.unit, flow),
                )
            if self._repository is not None:
                self._repository.commit_unit_decision(
                    run_id=run_id,
                    lane=lane,
                    decision=decision,
                )
            return decision

        decisions = await asyncio.gather(
            *(decide(item) for item in sorted(prepared, key=lambda value: value.unit.unit_id))
        )
        return tuple(decisions)

    def patch_identity(self, unit: AuditUnit, flow: CandidateFlow) -> PatchIdentity:
        """Return the exact release key required for one candidate class."""

        patch_kind = "configuration" if flow.tool_name == JAVA_CONFIGURATION_TOOL else "dataflow"
        return PatchIdentity.create(
            target_profile_digest=unit.profile_digest,
            cwe=flow.cwe,
            patch_kind=patch_kind,
            tool_name=flow.tool_name,
            tool_version=flow.tool_version,
            rule_bundle_digest=flow.rule_bundle_digest,
            parser_name="secmind-java-structural-candidate",
            parser_digest=JAVA_PARSER_DIGEST,
            critic_prompt_version=CRITIC_PROMPT_VERSION,
            critic_model_policy_digest=self._critic_model_policy_digest,
        )

    def patch_releases(self) -> tuple[PatchReleaseRecord, ...]:
        return self._patch_registry.list_records()

    def publish_patch_release(
        self,
        evaluation_run_id: str,
        release: PatchReleaseRecord,
    ) -> PatchReleaseRecord:
        persisted = release
        if self._repository is not None:
            persisted = self._repository.publish_patch_release(
                evaluation_run_id,
                release,
            )
        return self._patch_registry.put(persisted)

    def revoke_patch_release(
        self,
        patch_release_id: str,
        reason: str,
    ) -> PatchReleaseRecord:
        if self._repository is None:
            return self._patch_registry.revoke(patch_release_id, reason)
        current = self._patch_registry.get(patch_release_id)
        if current is None:
            raise KeyError(patch_release_id)
        revoked = self._repository.revoke_patch_release(
            patch_release_id,
            reason,
        )
        return self._patch_registry.put(
            revoked,
            expected_release_digest=current.release_digest,
        )

    @staticmethod
    def _shard_key(shard: list[PreparedSource]) -> str:
        return "shard-" + content_digest(
            {
                "unit_ids": sorted(item.unit.unit_id for item in shard),
                "profile_digests": sorted({item.unit.profile_digest for item in shard}),
                "prompt": PRIMARY_PROMPT_VERSION,
            }
        )

    def _record_shard(
        self,
        run_id: str,
        shard: list[PreparedSource],
        *,
        completed_unit_ids: tuple[str, ...],
        response_sha256: str | None,
        error_type: str | None,
    ) -> None:
        if self._repository is None or not shard:
            return
        unit_ids = tuple(sorted(item.unit.unit_id for item in shard))
        completed = tuple(sorted(set(completed_unit_ids).intersection(unit_ids)))
        if completed == unit_ids:
            status = ShardStatus.SUCCEEDED
            normalized_error = None
        elif completed:
            status = ShardStatus.PARTIAL
            normalized_error = error_type or "item_validation"
        else:
            status = ShardStatus.FAILED
            normalized_error = error_type or "item_validation"
        input_digest = content_digest({"unit_ids": unit_ids})
        profile_digest = content_digest({"profile_digests": sorted({item.unit.profile_digest for item in shard})})
        prompt_digest = hashlib.sha256(PRIMARY_PROMPT_VERSION.encode("utf-8")).hexdigest()
        draft = ReviewShardReceipt.create(
            run_id=run_id,
            lane=AuditLane.BASELINE,
            unit_ids=unit_ids,
            input_digest=input_digest,
            profile_digest=profile_digest,
            prompt_digest=prompt_digest,
            status=status,
            completed_unit_ids=completed,
            response_sha256=response_sha256,
            error_type=normalized_error,
        )
        existing = self._repository.load_shard_receipts(
            run_id=run_id,
            lane=AuditLane.BASELINE,
        )
        attempt = 1 + max(
            (receipt.attempt for receipt in existing if receipt.shard_key == draft.shard_key),
            default=0,
        )
        receipt = (
            draft
            if attempt == 1
            else ReviewShardReceipt.create(
                run_id=run_id,
                lane=AuditLane.BASELINE,
                unit_ids=unit_ids,
                input_digest=input_digest,
                profile_digest=profile_digest,
                prompt_digest=prompt_digest,
                status=status,
                attempt=attempt,
                completed_unit_ids=completed,
                response_sha256=response_sha256,
                error_type=normalized_error,
            )
        )
        self._repository.commit_shard_receipt(receipt)
