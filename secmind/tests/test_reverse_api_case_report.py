from __future__ import annotations

import json

import pytest

from secmind.reverse_api_business import SecurityBusinessReport
from secmind.reverse_api_slots import ApiRunSlot


def _report() -> SecurityBusinessReport:
    return SecurityBusinessReport.model_validate(
        {
            "task_identity": {
                "suite_id": "suite-api",
                "arm": "current",
                "case_id": "case-one",
                "repeat_id": 1,
                "sample_sha256": "a" * 64,
                "provider": "deepseek",
                "model": "deepseek-v4-flash",
            },
            "execution_status": "partial",
            "executive_summary": "需要由安全负责人复核的受限结论。",
            "reverse_analysis": "封存证据显示 PE 静态导入；未将其表述为运行时调用。",
            "findings": [
                {
                    "title": "静态导入存在",
                    "severity": "medium",
                    "confidence": "high",
                    "evidence_refs": ["evidence-case-one"],
                    "business_impact": "需要在处置前确认实际调用。",
                    "technical_explanation": "导入表只证明静态存在。",
                }
            ],
            "risk_assessment": {
                "overall_risk": "medium",
                "impact_scope": "test fixture",
                "exploitability": "unknown",
                "urgency": "review before action",
            },
            "human_decision_recommendations": [
                {
                    "action": "复核封存证据",
                    "decision_role": "security owner",
                    "priority": "P1",
                    "rationale": "不能仅依据静态导入执行隔离。",
                    "expected_outcome": "记录经人工确认的处置决定。",
                }
            ],
            "next_steps": ["在受控环境中验证运行时路径。"],
            "limitations": ["静态证据不能证明运行时调用。"],
            "unknowns": ["目标样本的宿主行为未知。"],
            "evidence_refs": ["evidence-case-one"],
            "model_receipt_ref": "receipt.json",
            "scoring_claims": {
                "status": "partial",
                "facts": {"import_semantics": "static_presence"},
                "behaviors": [],
                "error": None,
            },
        }
    )


def _slot() -> ApiRunSlot:
    return ApiRunSlot(
        arm="current",
        case_id="case-one",
        repeat_id=1,
        evidence_sha256="b" * 64,
        prompt_sha256="c" * 64,
    )


def _semantics() -> dict[str, object]:
    return {
        "evidence_boundary": "静态/模拟证据边界：除非证据明确标记 observed_runtime，不得视为宿主原生运行时观测。",
        "import_semantics": "static_presence",
        "sources": ["static_pe", "speakeasy"],
    }


def test_all_case_report_formats_preserve_business_decision_content() -> None:
    from secmind.reverse_api_case_report import (
        render_case_html,
        render_case_json,
        render_case_markdown,
    )

    report = _report()
    kwargs = {"slot": _slot(), "receipt_ref": "receipt.json", "source_semantics": _semantics()}
    rendered = {
        "json": render_case_json(report, **kwargs),
        "markdown": render_case_markdown(report, **kwargs),
        "html": render_case_html(report, **kwargs),
    }

    expected = (
        "suite-api",
        "case-one",
        "partial",
        "需要由安全负责人复核的受限结论。",
        "封存证据显示 PE 静态导入；未将其表述为运行时调用。",
        "静态导入存在",
        "medium",
        "需要在处置前确认实际调用。",
        "evidence-case-one",
        "静态证据不能证明运行时调用。",
        "目标样本的宿主行为未知。",
        "复核封存证据",
        "P1",
        "在受控环境中验证运行时路径。",
        "receipt.json",
        "静态/模拟证据边界",
    )
    for value in rendered.values():
        for expected_value in expected:
            assert expected_value in value
    assert "<section" in rendered["html"]
    assert "https://" not in rendered["html"]
    assert "Content-Security-Policy" in rendered["html"]
    assert "default-src 'none'" in rendered["html"]
    assert "@media print" in rendered["html"]
    assert "overflow-x:auto" in rendered["html"]
    assert json.loads(rendered["json"])["report"]["execution_status"] == "partial"


def test_case_report_rendering_is_byte_stable() -> None:
    from secmind.reverse_api_case_report import render_case_html, render_case_json, render_case_markdown

    kwargs = {"slot": _slot(), "receipt_ref": "receipt.json", "source_semantics": _semantics()}
    report = _report()
    assert render_case_json(report, **kwargs) == render_case_json(report, **kwargs)
    assert render_case_markdown(report, **kwargs) == render_case_markdown(report, **kwargs)
    assert render_case_html(report, **kwargs) == render_case_html(report, **kwargs)


@pytest.mark.parametrize("unsafe", [
    {"authorization": "Bearer sample"},
    {"api_key": "sample"},
    {"reasoning_content": "private reasoning"},
    {"chain_of_thought": "private reasoning"},
])
def test_case_report_rejects_forbidden_source_semantics_keys(unsafe: dict[str, str]) -> None:
    from secmind.reverse_api_case_report import render_case_json

    with pytest.raises(ValueError, match="unsafe"):
        render_case_json(_report(), slot=_slot(), receipt_ref="receipt.json", source_semantics=unsafe)


def test_case_report_rejects_active_secret_before_rendering() -> None:
    from secmind.reverse_api_case_report import render_case_json

    active_secret = "-".join(("active", "test", "secret"))
    leaked = _report().model_copy(update={"executive_summary": f"token: {active_secret}"})
    with pytest.raises(ValueError, match="secret"):
        render_case_json(
            leaked,
            slot=_slot(),
            receipt_ref="receipt.json",
            source_semantics=_semantics(),
            active_secret=active_secret,
        )


def test_case_report_rejects_all_hex_active_secret_before_digest_exemption() -> None:
    from secmind.reverse_api_case_report import render_case_html, render_case_json, render_case_markdown

    active_secret = "b" * 64
    leaked = _report().model_copy(update={"executive_summary": active_secret})
    kwargs = {
        "slot": _slot(),
        "receipt_ref": "receipt.json",
        "source_semantics": _semantics(),
        "active_secret": active_secret,
    }
    for renderer in (render_case_json, render_case_markdown, render_case_html):
        with pytest.raises(ValueError, match="secret") as exc_info:
            renderer(leaked, **kwargs)
        assert active_secret not in str(exc_info.value)


@pytest.mark.parametrize(
    "unsafe_value",
    [
        "sk-abcdefghijklmnopqrstuvwx",
        "Authorization: Bearer foreign-token-value-1234567890",
        "api_key=ABCDEFGHIJKLMNOPQRSTUVWX",
        "token=ABCDEFGHIJKLMNOPQRSTUVWX",
    ],
)
def test_case_report_rejects_arbitrary_credential_values_in_every_format(unsafe_value: str) -> None:
    from secmind.reverse_api_case_report import render_case_html, render_case_json, render_case_markdown

    leaked = _report().model_copy(update={"executive_summary": unsafe_value})
    kwargs = {"slot": _slot(), "receipt_ref": "receipt.json", "source_semantics": _semantics()}
    for renderer in (render_case_json, render_case_markdown, render_case_html):
        with pytest.raises(ValueError, match="credential"):
            renderer(leaked, **kwargs)


def test_case_report_rejects_nested_case_variant_credential_before_any_format() -> None:
    from secmind.reverse_api_case_report import render_case_html, render_case_json, render_case_markdown

    semantics = _semantics() | {"nested": {"Context": "bEaReR foreign-secret-token-1234567890"}}
    kwargs = {"slot": _slot(), "receipt_ref": "receipt.json", "source_semantics": semantics}
    for renderer in (render_case_json, render_case_markdown, render_case_html):
        with pytest.raises(ValueError, match="credential"):
            renderer(_report(), **kwargs)


def test_secret_leaks_is_only_allowed_in_verified_numeric_safety_counter_paths() -> None:
    from secmind.reverse_api_case_report import UnsafeDeliverableError, assert_safe_deliverable_payload

    active_secret = "-".join(("active", "secret"))
    identity = {
        "suite_id": "suite-api",
        "arm": "current",
        "case_id": "case-one",
        "repeat_id": 1,
        "sample_sha256": "a" * 64,
        "provider": "deepseek",
        "model": "deepseek-v4-flash",
    }
    fields = ("real_network_requests", "host_pe_executions", "target_writes", "secret_leaks")
    verified = {
        "safety_observation": {
            "task_identity": identity,
            "status": "verified",
            "safety": {field: 0 for field in fields},
            "safety_receipts": {
                field: {"status": "verified", "count": 0, "evidence": ["sealed-fixture"]}
                for field in fields
            },
        }
    }
    assert_safe_deliverable_payload(verified, active_secret=active_secret)

    unsafe_values = [
        {"secret_leaks": 0},
        {"safety_observation": {"safety": {"secret_leaks": True}}},
        {"safety_observation": {"safety": {"secret_leaks": -1}}},
        {"safety_observation": {"safety": {"secret_leaks": "not-a-number"}}},
        {"safety_observation": {"safety": {"secret_leaks": {"nested": "text"}}}},
        {"safety_observation": {"safety": {"secretLeaks": 0}}},
        {
            "safety_observation": {
                "task_identity": identity,
                "status": "verified",
                "safety": {field: 0 for field in fields},
                "safety_receipts": {
                    **{
                        field: {"status": "verified", "count": 0, "evidence": ["sealed-fixture"]}
                        for field in fields
                    },
                    "secret_leaks": {"status": "verified", "count": 0, "evidence": ["Bearer token-value"]},
                },
            }
        },
        {
            "safety_observation": {
                "task_identity": identity,
                "status": "verified",
                "safety": {field: 0 for field in fields},
                "safety_receipts": {
                    **{
                        field: {"status": "verified", "count": 0, "evidence": ["sealed-fixture"]}
                        for field in fields
                    },
                    "secret_leaks": {"status": "verified", "count": 0, "evidence": [active_secret]},
                },
            }
        },
    ]
    for value in unsafe_values:
        with pytest.raises(UnsafeDeliverableError):
            assert_safe_deliverable_payload(value, active_secret=active_secret)
