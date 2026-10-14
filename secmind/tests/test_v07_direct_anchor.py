from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from secmind.audit_kernel.contracts import AuditUnit, ReviewVerdict
from secmind.audit_kernel.pipeline import JavaAuditKernel
from secmind.audit_kernel.receipts import ProviderReceipt
from secmind.audit_kernel.reviewer import (
    DirectFirstPrimaryReviewer,
    PreparedSource,
    PrimaryReviewResult,
)
from secmind.audit_kernel.snapshot import WorkspaceSnapshot
from secmind.live_source_review import SourceUnit
from secmind.llm import ModelCallMeta
from secmind.schemas import ModelUsage


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _prepared() -> PreparedSource:
    content = "class Safe { void run() {} }\n"
    unit = AuditUnit.create(
        run_id="run-direct",
        input_manifest_digest=_digest("manifest"),
        profile_digest=_digest("profile"),
        primary_path="src/Safe.java",
        source_sha256=_digest(content),
        target_cwes=(22, 78, 79, 89),
        authorized_scope=("src",),
    )
    return PreparedSource(unit, content)


def test_provider_receipt_replays_direct_baseline_without_gateway() -> None:
    prepared = _prepared()
    parsed = {
        "verdicts": [
            {
                "unit_id": prepared.unit.unit_id,
                "verdict": "not_vulnerable",
                "cwe": None,
                "sink_line": None,
                "confidence": 0.91,
                "reason_codes": ["reviewed"],
                "rationale_summary": "No target-CWE evidence was found.",
                "limitations": [],
            }
        ]
    }
    receipt = ProviderReceipt.create(
        run_id="run-direct",
        logical_call_id="logical-direct-1",
        provider_request_id="logical-direct-1",
        request_digest=_digest("request"),
        response_digest=_digest("response"),
        pair_digest=_digest("pair"),
        unit_ids=(prepared.unit.unit_id,),
        model_id="gpt-5.4",
        prompt_version="secmind-v0.7-direct-first-primary-v2",
        response_schema_digest=_digest("schema"),
        parsed_response=parsed,
        usage=ModelUsage(provider_requests=1, input_tokens=80, output_tokens=20),
        latency_ms=30,
        attempt_count=1,
    )

    reviewer = object.__new__(DirectFirstPrimaryReviewer)
    result = reviewer.project_receipt(receipt, [prepared])

    verdict = result.verdicts[prepared.unit.unit_id]
    assert verdict.verdict == ReviewVerdict.NOT_VULNERABLE
    assert verdict.receipt_id == receipt.receipt_id
    assert result.meta.usage.provider_requests == 1
    assert result.receipt == receipt


def test_workspace_snapshot_binds_scope_and_manifest() -> None:
    source = SourceUnit("safe", "src/Safe.java", "class Safe {}\n")
    snapshot = WorkspaceSnapshot.build([source], authorized_scope=("src",))

    assert snapshot.authorized_scope == ("src",)
    assert snapshot.files[0].sha256 == source.sha256
    assert snapshot.snapshot_id == f"snapshot-{snapshot.snapshot_digest}"


class _Primary:
    async def review(self, sources: list[PreparedSource], **_: object) -> PrimaryReviewResult:
        from secmind.audit_kernel.contracts import PrimaryVerdict

        verdicts = {
            item.unit.unit_id: PrimaryVerdict(
                unit_id=item.unit.unit_id,
                verdict=ReviewVerdict.NOT_VULNERABLE,
                confidence=0.9,
                receipt_id=f"mock:{item.unit.unit_id}",
            )
            for item in sources
        }
        return PrimaryReviewResult(
            verdicts=verdicts,
            sink_lines={item.unit.unit_id: None for item in sources},
            rationales={item.unit.unit_id: "baseline" for item in sources},
            missing_unit_ids=(),
            rejected_unit_ids=(),
            meta=ModelCallMeta(
                model_id="gpt-5.4",
                prompt_version="test",
                response_sha256=_digest("mock-response"),
                duration_ms=1,
                used_fallback=False,
                usage=ModelUsage(provider_requests=1),
            ),
        )


class _Critic:
    async def review(self, *_: object, **__: object) -> object:
        raise AssertionError("critic must not run when evidence extraction failed")


class _ExplodingExtractor:
    def extract(self, *_: object) -> tuple[()]:
        raise RuntimeError("optional parser failed")


@pytest.mark.asyncio
async def test_optional_evidence_failure_cannot_erase_direct_baseline() -> None:
    kernel = JavaAuditKernel(_Primary(), _Critic())  # type: ignore[arg-type]
    kernel._extractor = _ExplodingExtractor()  # type: ignore[assignment]
    result = await kernel.run(
        run_id="run-fallback",
        case_files=[SourceUnit("safe", "src/Safe.java", "class Safe {}\n")],
        support_files=[],
        deadline_at=datetime.now(UTC) + timedelta(seconds=5),
        max_model_calls=2,
        mode="shadow",
        authorized_scope=("src",),
    )

    assert result.coverage["coverage"] == 1
    assert result.decisions[0].final_verdict == ReviewVerdict.NOT_VULNERABLE
    assert result.decisions[0].decision_digest
    assert result.shard_errors
