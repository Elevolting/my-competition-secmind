from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.audit_kernel.contracts import CriticVerdict, PrimaryVerdict, ReviewVerdict
from secmind.audit_kernel.persistence import AuditPersistence
from secmind.audit_kernel.pipeline import JavaAuditKernel
from secmind.audit_kernel.projection import AuditResultProjector
from secmind.audit_kernel.receipts import ProviderReceipt
from secmind.audit_kernel.reviewer import (
    ConditionalConflictCritic,
    CriticReviewResult,
    PrimaryReviewResult,
)
from secmind.investigation.store import InvestigationStore
from secmind.live_source_review import SourceUnit
from secmind.llm import ModelCallMeta
from secmind.schemas import ModelUsage


def _meta(identity: str) -> ModelCallMeta:
    return ModelCallMeta(
        model_id="mock-5.4",
        prompt_version="v07-test",
        response_sha256=hashlib.sha256(identity.encode()).hexdigest(),
        duration_ms=1,
        used_fallback=False,
        usage=ModelUsage(provider_requests=1, input_tokens=10, output_tokens=2, cost_units=0.01),
    )


class _Primary:
    def __init__(self, *, fail_group: str | None = None, omit_once: str | None = None) -> None:
        self.fail_group = fail_group
        self.omit_once = omit_once
        self.calls: list[tuple[str, ...]] = []

    async def review(self, sources, **_kwargs) -> PrimaryReviewResult:
        paths = tuple(item.unit.primary_path for item in sources)
        self.calls.append(paths)
        if self.fail_group is not None and len(sources) > 1 and any(self.fail_group in path for path in paths):
            raise RuntimeError("injected shard failure")
        selected = list(sources)
        if self.omit_once is not None and len(sources) > 1:
            selected = [item for item in sources if self.omit_once not in item.unit.primary_path]
            self.omit_once = None
        verdicts = {
            item.unit.unit_id: PrimaryVerdict(
                unit_id=item.unit.unit_id,
                verdict=ReviewVerdict.NOT_VULNERABLE,
                confidence=0.91,
                reason_codes=("mock_direct",),
                receipt_id=f"model:{hashlib.sha256(item.unit.unit_id.encode()).hexdigest()}",
                model_id="primary-mock-5.4",
                prompt_version="primary-v2",
                evidence_ids=(f"primary-{item.unit.unit_id}",),
            )
            for item in selected
        }
        returned = set(verdicts)
        expected = {item.unit.unit_id for item in sources}
        meta = _meta("\n".join(paths))
        return PrimaryReviewResult(
            verdicts=verdicts,
            sink_lines={unit_id: None for unit_id in returned},
            rationales={unit_id: "No proven source-to-sink flow." for unit_id in returned},
            missing_unit_ids=tuple(sorted(expected - returned)),
            rejected_unit_ids=(),
            meta=meta,
        )


class _NeverPrimary:
    calls: list[tuple[str, ...]] = []

    async def review(self, sources, **_kwargs):
        self.calls.append(tuple(item.unit.primary_path for item in sources))
        raise AssertionError("recovery must reuse persisted primary verdicts")


class _Critic:
    def __init__(self, *, confirm: bool = False) -> None:
        self.confirm = confirm
        self.calls = 0

    async def review(self, source, _baseline, flow, **_kwargs) -> CriticReviewResult:
        self.calls += 1
        verdict = ReviewVerdict.VULNERABLE if self.confirm else ReviewVerdict.NOT_VULNERABLE
        critic = CriticVerdict(
            unit_id=source.unit.unit_id,
            verdict=verdict,
            cwe=flow.cwe if self.confirm else None,
            source_node_id=flow.source_site.node_id if self.confirm and flow.source_site else None,
            sink_node_id=flow.sink_site.node_id if self.confirm else None,
            confidence=0.95,
            receipt_id=f"critic:{flow.flow_id}",
            lineage_id="critic:mock-5.4:v07-test",
            model_id="critic-mock-5.4",
            prompt_version="critic-v2",
            evidence_ids=(f"critic-evidence-{flow.flow_id}",),
        )
        return CriticReviewResult(verdict=critic, rationale="Bounded conflict decision.", meta=_meta(flow.flow_id))


class _CaptureCriticGateway:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def structured(self, **kwargs):
        self.calls.append(kwargs)
        prompt = json.loads(str(kwargs["user_prompt"]))
        output_model = kwargs["output_model"]
        return output_model.model_validate(
            {
                "unit_id": prompt["unit_id"],
                "verdict": "vulnerable",
                "cwe": prompt["candidate_flow"]["cwe"],
                "confidence": 0.96,
                "rationale_summary": "The bounded candidate remains reachable across the supplied context.",
            }
        ), _meta("critic-support-context")


class _SlowCritic:
    def __init__(self) -> None:
        self.started = 0

    async def review(self, *_args, **_kwargs):
        self.started += 1
        await asyncio.sleep(5)
        raise AssertionError("the root deadline must cancel an in-flight critic")


def _sources(count: int, *, failed_group: range | None = None) -> list[SourceUnit]:
    failed = set(failed_group or ())
    return [
        SourceUnit(
            case_id=f"case-{index}",
            path=f"src/{'failed' if index in failed else 'normal'}/Case{index}.java",
            content=f"class Case{index} {{ void safe() {{}} }}\n",
        )
        for index in range(count)
    ]


def _kernel(primary, critic, *, store: AuditPersistence | None = None) -> JavaAuditKernel:
    return JavaAuditKernel(
        primary,  # type: ignore[arg-type]
        critic,  # type: ignore[arg-type]
        repository=store,
        max_units_per_shard=6,
        primary_concurrency=3,
        critic_concurrency=2,
        minimum_dispatch_seconds=0.01,
    )


@pytest.mark.asyncio
async def test_failed_shard_is_repaired_without_erasing_later_shards() -> None:
    primary = _Primary(fail_group="failed")
    kernel = _kernel(primary, _Critic())
    result = await kernel.run(
        run_id="run-shards",
        case_files=_sources(13, failed_group=range(6, 12)),
        support_files=[],
        deadline_at=datetime.now(UTC) + timedelta(seconds=30),
        max_model_calls=20,
        mode="baseline",
    )

    assert result.coverage["covered_units"] == 13
    assert result.coverage["inconclusive_units"] == 0
    assert result.shard_errors
    assert any("Case12.java" in path for call in primary.calls for path in call)
    assert any(len(call) == 1 for call in primary.calls)


@pytest.mark.asyncio
async def test_missing_item_gets_singleton_repair_only() -> None:
    primary = _Primary(omit_once="Case2.java")
    result = await _kernel(primary, _Critic()).run(
        run_id="run-item-repair",
        case_files=_sources(6),
        support_files=[],
        deadline_at=datetime.now(UTC) + timedelta(seconds=30),
        max_model_calls=10,
        mode="baseline",
    )

    assert result.coverage["coverage"] == 1
    assert [len(call) for call in primary.calls] == [6, 1]
    assert primary.calls[-1] == ("src/normal/Case2.java",)


@pytest.mark.asyncio
async def test_baseline_mode_is_critic_free_and_bit_preserving() -> None:
    primary = _Primary()
    critic = _Critic(confirm=True)
    result = await _kernel(primary, critic).run(
        run_id="run-baseline",
        case_files=_sources(3),
        support_files=[],
        deadline_at=datetime.now(UTC) + timedelta(seconds=30),
        max_model_calls=5,
        mode="baseline",
    )

    assert critic.calls == 0
    assert all(
        decision.final_verdict == result.primary_verdicts[decision.unit_id].verdict for decision in result.decisions
    )
    assert result.coverage["promoted_units"] == 0


@pytest.mark.asyncio
async def test_audit_projection_persists_primary_agent_evidence(tmp_path: Path) -> None:
    result = await _kernel(_Primary(), _Critic()).run(
        run_id="run-projection",
        case_files=_sources(1),
        support_files=[],
        deadline_at=datetime.now(UTC) + timedelta(seconds=30),
        max_model_calls=2,
        mode="baseline",
    )
    artifacts = ContentAddressedArtifactStore(tmp_path / "artifacts")
    projection = AuditResultProjector(artifacts, None).project(
        result,
        run_id="run-projection",
        step_id="model-source-review",
        planner_model_id="primary-mock-5.4",
        severity_for=lambda _cwe, _assurance: "MEDIUM",
    )

    assert len(projection.units) == len(projection.evidence) == 1
    assert projection.evidence[0].source == "secmind:v0.7-primary-agent"
    assert artifacts.read(projection.evidence[0].artifact_ref)


@pytest.mark.asyncio
async def test_authoritative_mode_still_requires_empirical_patch_release() -> None:
    source = SourceUnit(
        case_id="cmd",
        path="src/Command.java",
        content=(
            "class Command { void run(Request request) throws Exception {\n"
            'String value = request.getParameter("cmd");\n'
            "Runtime runtime = Runtime.getRuntime();\n"
            "runtime.exec(value);\n"
            "}}\n"
        ),
    )
    critic = _Critic(confirm=True)
    result = await _kernel(_Primary(), critic).run(
        run_id="run-gain",
        case_files=[source],
        support_files=[],
        deadline_at=datetime.now(UTC) + timedelta(seconds=30),
        max_model_calls=5,
        mode="authoritative",
    )

    decision = result.decisions[0]
    assert critic.calls == 1
    assert decision.baseline_verdict == ReviewVerdict.NOT_VULNERABLE
    assert decision.final_verdict == ReviewVerdict.NOT_VULNERABLE
    assert decision.action.value == "keep_baseline"
    assert "patch_release_missing" in decision.reason_codes
    assert result.coverage["promoted_units"] == 0


@pytest.mark.asyncio
async def test_critic_receives_bounded_sorted_support_without_mutating_baseline() -> None:
    source = SourceUnit(
        case_id="generic-command",
        path="src/CommandEndpoint.java",
        content=(
            "class CommandEndpoint { void run(Request request) throws Exception {\n"
            'String value = request.getParameter("cmd");\n'
            "Runtime runtime = Runtime.getRuntime();\n"
            "runtime.exec(value);\n"
            "}}\n"
        ),
    )
    support_files = [
        SourceUnit(
            case_id="support-late",
            path="src/support/CUnused.java",
            content='class CUnused { String marker = "late-support-marker"; }\n',
        ),
        SourceUnit(
            case_id="support-large",
            path="src/support/BOversized.java",
            content="class BOversized {}\n" + ("x" * (128 * 1024)),
        ),
        SourceUnit(
            case_id="support-interface",
            path="src/support/ACommandFactory.java",
            content=(
                "interface CommandFactory { String build(String userInput); }\n"
                "final class ForwardingFactory implements CommandFactory {\n"
                "  public String build(String userInput) { return userInput; }\n"
                "}\n"
            ),
        ),
    ]
    gateway = _CaptureCriticGateway()
    critic = ConditionalConflictCritic(gateway)  # type: ignore[arg-type]
    result = await _kernel(_Primary(), critic).run(
        run_id="run-support-context",
        case_files=[source],
        support_files=support_files,
        deadline_at=datetime.now(UTC) + timedelta(seconds=30),
        max_model_calls=5,
        mode="authoritative",
    )

    assert len(gateway.calls) == 1
    call = gateway.calls[0]
    prompt = json.loads(str(call["user_prompt"]))
    support_context = prompt["support_sources"]
    assert [item["path"] for item in support_context] == [
        "src/support/ACommandFactory.java",
        "src/support/CUnused.java",
    ]
    assert sum(item["content_bytes"] for item in support_context) <= 128 * 1024
    assert "interface CommandFactory" in support_context[0]["numbered_source"]
    assert "late-support-marker" in str(call["user_prompt"])
    assert "untrusted data" in str(call["system_prompt"])

    decision = result.decisions[0]
    baseline = result.primary_verdicts[decision.unit_id]
    assert baseline.verdict == ReviewVerdict.NOT_VULNERABLE
    assert decision.baseline_verdict == ReviewVerdict.NOT_VULNERABLE
    assert decision.baseline_receipt_id == baseline.receipt_id
    assert decision.final_verdict == ReviewVerdict.NOT_VULNERABLE
    assert "patch_release_missing" in decision.reason_codes
    assert decision.action.value == "keep_baseline"


@pytest.mark.asyncio
async def test_root_deadline_bounds_critic_queue_and_inflight_call() -> None:
    sources = [
        SourceUnit(
            case_id=f"deadline-command-{index}",
            path=f"src/DeadlineCommand{index}.java",
            content=(
                f"class DeadlineCommand{index} {{ void run(Request request) throws Exception {{\n"
                'String value = request.getParameter("cmd");\n'
                "Runtime runtime = Runtime.getRuntime();\n"
                "runtime.exec(value);\n"
                "}}\n"
            ),
        )
        for index in range(2)
    ]
    critic = _SlowCritic()
    kernel = JavaAuditKernel(
        _Primary(),  # type: ignore[arg-type]
        critic,  # type: ignore[arg-type]
        max_units_per_shard=6,
        primary_concurrency=1,
        critic_concurrency=1,
        minimum_dispatch_seconds=0.001,
    )
    clock = asyncio.get_running_loop()
    started_at = clock.time()
    result = await kernel.run(
        run_id="run-absolute-deadline",
        case_files=sources,
        support_files=[],
        deadline_at=datetime.now(UTC) + timedelta(seconds=0.15),
        max_model_calls=5,
        mode="authoritative",
    )
    elapsed = clock.time() - started_at

    assert critic.started == 1
    assert elapsed < 1
    assert all(
        decision.baseline_verdict == ReviewVerdict.NOT_VULNERABLE
        and decision.final_verdict == ReviewVerdict.NOT_VULNERABLE
        and decision.action.value == "keep_baseline"
        for decision in result.decisions
    )


@pytest.mark.asyncio
async def test_new_kernel_instance_recovers_without_second_provider_call() -> None:
    investigation = InvestigationStore("sqlite:///:memory:")
    persistence = AuditPersistence(investigation)
    sources = _sources(4)
    deadline = datetime.now(UTC) + timedelta(seconds=30)
    try:
        first = await _kernel(_Primary(), _Critic(), store=persistence).run(
            run_id="run-recovery",
            case_files=sources,
            support_files=[],
            deadline_at=deadline,
            max_model_calls=5,
            mode="baseline",
        )
        digest = hashlib.sha256(b"durable-provider-receipt").hexdigest()
        persistence.commit_provider_receipt(
            ProviderReceipt.create(
                run_id="run-recovery",
                logical_call_id="logical-recovery",
                provider_request_id="provider-recovery",
                request_digest=digest,
                response_digest=digest,
                pair_digest=digest,
                unit_ids=tuple(sorted(item.unit_id for item in first.units)),
                model_id="mock-5.4",
                prompt_version="v07-test",
                response_schema_digest=digest,
                parsed_response={},
                usage=first.usage,
                latency_ms=1,
            )
        )
        never = _NeverPrimary()
        second = await _kernel(never, _Critic(), store=AuditPersistence(investigation)).run(
            run_id="run-recovery",
            case_files=sources,
            support_files=[],
            deadline_at=deadline,
            max_model_calls=5,
            mode="baseline",
        )
    finally:
        investigation.close()

    assert never.calls == []
    assert [item.decision_digest for item in first.decisions] == [item.decision_digest for item in second.decisions]
    assert second.model_calls_used == 0
    assert second.usage == first.usage
