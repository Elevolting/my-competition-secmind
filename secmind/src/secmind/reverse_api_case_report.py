"""Deterministic, public-safe per-run reverse-analysis business reports.

The model supplies a validated :class:`SecurityBusinessReport`; this module
only lays that conclusion out for people.  It does not summarize, infer, or
otherwise rewrite model content, so the three report formats stay auditable.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from html import escape
from typing import Any

from secmind.reverse_api_business import SecurityBusinessReport, TaskIdentity
from secmind.reverse_api_slots import ApiRunSlot
from secmind.secret_scrubber import ArtifactLeakageError, assert_no_secret_leak, is_sensitive_key

_HIDDEN_REASONING_KEYS = frozenset({"reasoningcontent", "chainofthought"})
_HIDDEN_REASONING_MARKERS = ("reasoning_content", "chain_of_thought")
_PUBLIC_DIGEST = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{96}|[0-9a-fA-F]{128})$")
_PUBLIC_DIGEST_FIELDS = frozenset(
    {
        "evidencesha256",
        "modelrequestsha256",
        "modelresponsesha256",
        "predictionsha256",
        "promptsha256",
        "publicrequestsha256",
        "questionsha256",
        "requestdigest",
        "receiptsha256",
        "reporthtmlsha256",
        "reportjsonsha256",
        "reportmdsha256",
        "requestsha256",
        "responsesha256",
        "responsedigest",
        "samplesha256",
        "sealedevidencecasesha256",
        "promptartifactid",
        "promptselectiondigest",
    }
)
_STATUS_LABELS = {
    "completed": "已完成",
    "partial": "部分完成",
    "unavailable": "不可用",
}
_PUBLIC_EVIDENCE_SOURCES = frozenset({"static", "emulated", "cape_fixture", "source", "unknown"})
_SEVERITY_CLASS = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}
_CASE_REPORT_CSS = """
:root {
  --paper:#F5F7FA; --ink:#172033; --blue:#315B8A; --teal:#16736B;
  --rust:#A54835; --slate:#667085; --line:#D7DEE8; --card:#FFFFFF;
}
* { box-sizing:border-box; }
body {
  margin:0; color:var(--ink); background:var(--paper);
  font:15px/1.65 "PingFang SC",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}
main { max-width:1120px; margin:0 auto; padding:42px 28px 64px; }
h1,h2,h3,p { margin-top:0; }
h1 {
  font:700 clamp(30px,5vw,48px)/1.12 "Songti SC",ui-serif,serif;
  letter-spacing:.02em; margin-bottom:12px;
}
h2 { font-size:18px; margin-bottom:14px; }
h3 { font-size:16px; margin-bottom:8px; }
.eyebrow {
  color:var(--blue); font:700 12px/1 ui-monospace,SFMono-Regular,Menlo,monospace;
  letter-spacing:.08em; text-transform:uppercase;
}
.hero { padding:0 0 26px 24px; border-left:4px solid var(--blue); }
.hero-row { display:flex; gap:18px; align-items:flex-start; justify-content:space-between; }
.status {
  flex:none; border:1px solid var(--line); border-radius:999px; padding:6px 11px;
  color:var(--teal); background:#F0FAF8; font-weight:700;
}
.status.partial { color:#825C0A; background:#FFF8E4; }
.status.unavailable { color:var(--rust); background:#FFF0ED; }
.meta { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:10px; margin-top:20px; }
.meta div,.panel { background:var(--card); border:1px solid var(--line); border-radius:4px; }
.meta div { padding:10px 12px; }
.label {
  display:block; color:var(--slate); font-size:11px; font-weight:700;
  letter-spacing:.06em; text-transform:uppercase;
}
code { font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace; overflow-wrap:anywhere; }
.spine { position:relative; margin-top:28px; padding-left:31px; }
.spine:before {
  content:""; position:absolute; top:7px; bottom:7px; left:7px; width:1px;
  background:var(--line);
}
section {
  position:relative; margin:0 0 22px; padding:21px 22px; background:var(--card);
  border:1px solid var(--line); border-radius:4px;
}
section:before {
  content:""; position:absolute; left:-30px; top:25px; width:12px; height:12px;
  border:3px solid var(--paper); border-radius:50%; background:var(--blue);
  box-shadow:0 0 0 1px var(--blue);
}
section.decision:before { background:var(--teal); box-shadow:0 0 0 1px var(--teal); }
section.caution:before { background:var(--rust); box-shadow:0 0 0 1px var(--rust); }
.boundary { color:#213A5B; background:#EEF3F9; border-left:3px solid var(--blue); padding:12px 14px; }
.grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:10px; }
.metric { padding:11px; border:1px solid var(--line); }
.metric b { display:block; font-size:14px; }
.finding,.recommendation { padding:14px 0; border-top:1px solid var(--line); }
.finding:first-child,.recommendation:first-child { border-top:0; padding-top:0; }
.finding-head,.rec-head { display:flex; align-items:center; flex-wrap:wrap; gap:8px; }
.finding-head h3,.rec-head h3 { margin:0 auto 0 0; }
.stamp,.priority,.confidence,.chip {
  display:inline-block; font:700 11px/1 ui-monospace,SFMono-Regular,Menlo,monospace;
  padding:5px 7px; border-radius:2px;
}
.severity-critical,.severity-high { background:#FCE8E4; color:#822F22; }
.severity-medium { background:#FFF4DC; color:#825C0A; }
.severity-low,.severity-info { background:#EAF5F3; color:#11625B; }
.confidence { color:var(--slate); background:#F0F2F5; }
.priority { color:#FFF; background:var(--blue); }
.chips { display:flex; gap:6px; flex-wrap:wrap; }
.chip { color:#28496D; background:#EDF3FA; font-weight:500; overflow-wrap:anywhere; }
ul { margin:0; padding-left:20px; }
.table-wrap { overflow-x:auto; }
table { width:100%; border-collapse:collapse; min-width:620px; }
th,td { padding:9px 10px; border-top:1px solid var(--line); text-align:left; vertical-align:top; }
th { color:var(--slate); font-size:12px; }
.receipt,.empty { color:var(--slate); }
@media (max-width:720px) {
  main { padding:25px 16px 44px; } .meta,.grid { grid-template-columns:1fr; }
  .hero-row { display:block; } .status { display:inline-block; margin-top:12px; }
  .spine { padding-left:22px; } section { padding:17px; } section:before { left:-22px; }
}
@media print {
  body { background:#fff; font-size:11pt; } main { max-width:none; padding:0; }
  .meta div,section { break-inside:avoid; } .spine:before { background:#AAB4C2; }
}
""".strip()


class UnsafeDeliverableError(ValueError):
    """A public artifact would expose a credential or hidden reasoning."""


def build_source_semantics(*, import_semantics: object, observation_type: object) -> dict[str, object]:
    """Build source semantics from the closed EvidenceDTO observation enum.

    Callers must supply the validated public observation type rather than a
    sealed evidence object.  That prevents unregistered evidence branches or
    raw source labels from reaching a public report.
    """

    if not isinstance(import_semantics, str) or not import_semantics:
        import_semantics = "unspecified"
    if not isinstance(observation_type, str) or observation_type not in _PUBLIC_EVIDENCE_SOURCES:
        raise ValueError("source semantics must use the closed public vocabulary")
    return {
        "evidence_boundary": (
            "静态/模拟证据边界：除非封存证据明确标记 observed_runtime，"
            "本报告不得将事实视为宿主原生运行时观测。"
        ),
        "import_semantics": import_semantics,
        "sources": [observation_type],
    }


def _canonical_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).casefold())


def _verified_secret_leak_paths(value: Any) -> frozenset[str]:
    """Return the two exact paths for one structurally verified audit count."""

    if not isinstance(value, Mapping):
        return frozenset()
    observation = value.get("safety_observation")
    if (
        not isinstance(observation, Mapping)
        or set(observation) != {"task_identity", "status", "safety", "safety_receipts"}
        or observation.get("status") != "verified"
    ):
        return frozenset()
    try:
        TaskIdentity.model_validate(observation.get("task_identity"))
    except ValueError:
        return frozenset()
    safety = observation.get("safety")
    receipts = observation.get("safety_receipts")
    if not isinstance(safety, Mapping) or not isinstance(receipts, Mapping):
        return frozenset()
    fields = {"real_network_requests", "host_pe_executions", "target_writes", "secret_leaks"}
    if set(safety) != fields or set(receipts) != fields:
        return frozenset()
    for field in fields:
        field_count = safety.get(field)
        field_receipt = receipts.get(field)
        if (
            not isinstance(field_count, int)
            or isinstance(field_count, bool)
            or field_count < 0
            or not isinstance(field_receipt, Mapping)
            or field_receipt.get("status") != "verified"
            or field_receipt.get("count") != field_count
            or not isinstance(field_receipt.get("evidence"), list)
            or not field_receipt["evidence"]
        ):
            return frozenset()
    count = safety.get("secret_leaks")
    receipt = receipts.get("secret_leaks")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0 or not isinstance(receipt, Mapping):
        return frozenset()
    evidence = receipt.get("evidence")
    if (
        receipt.get("status") != "verified"
        or receipt.get("count") != count
        or not isinstance(evidence, list)
        or not evidence
        or not all(isinstance(item, str) and item for item in evidence)
    ):
        return frozenset()
    return frozenset(
        {
            "deliverable.safety_observation.safety.secret_leaks",
            "deliverable.safety_observation.safety_receipts.secret_leaks",
        }
    )


def _reject_unsafe_value(
    value: Any,
    *,
    active_secret: str | None,
    path: str = "report",
    allow_public_digest: bool = False,
    allowed_sensitive_paths: frozenset[str] = frozenset(),
) -> None:
    """Fail closed before content is handed to a report writer.

    This deliberately rejects rather than redacts: a published report must be
    traceable to one validated business object, not a silently altered copy.
    """

    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            canonical = _canonical_key(key_text)
            child_path = f"{path}.{key_text}"
            if canonical in _HIDDEN_REASONING_KEYS or (
                is_sensitive_key(key_text) and child_path not in allowed_sensitive_paths
            ):
                raise UnsafeDeliverableError("unsafe deliverable key")
            _reject_unsafe_value(
                item,
                active_secret=active_secret,
                path=child_path,
                allow_public_digest=canonical in _PUBLIC_DIGEST_FIELDS,
                allowed_sensitive_paths=allowed_sensitive_paths,
            )
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            _reject_unsafe_value(
                item,
                active_secret=active_secret,
                path=f"{path}[{index}]",
                allowed_sensitive_paths=allowed_sensitive_paths,
            )
        return
    if isinstance(value, str):
        lower = value.casefold()
        if active_secret and active_secret in value:
            raise UnsafeDeliverableError("unsafe secret value")
        if allow_public_digest and _PUBLIC_DIGEST.fullmatch(value):
            return
        if any(marker in lower for marker in _HIDDEN_REASONING_MARKERS):
            raise UnsafeDeliverableError("unsafe hidden-reasoning value")
        try:
            assert_no_secret_leak(value)
        except ArtifactLeakageError as exc:
            raise UnsafeDeliverableError("unsafe credential value") from exc


def assert_safe_deliverable_payload(value: Any, *, active_secret: str | None = None) -> None:
    """Reject secrets and hidden reasoning in every public artifact payload."""

    _reject_unsafe_value(
        value,
        active_secret=active_secret,
        path="deliverable",
        allowed_sensitive_paths=_verified_secret_leak_paths(value),
    )


def _validated_context(
    report: SecurityBusinessReport,
    *,
    slot: ApiRunSlot | None,
    receipt_ref: str | None,
    source_semantics: Mapping[str, Any] | None,
    active_secret: str | None,
) -> tuple[SecurityBusinessReport, dict[str, Any], str]:
    if not isinstance(report, SecurityBusinessReport):
        report = SecurityBusinessReport.model_validate(report)
    if slot is not None:
        identity = report.task_identity
        if (slot.arm, slot.case_id, slot.repeat_id) != (identity.arm, identity.case_id, identity.repeat_id):
            raise ValueError("slot identity does not match the business report")
    receipt = receipt_ref if receipt_ref is not None else report.model_receipt_ref
    if not isinstance(receipt, str) or not receipt or receipt != report.model_receipt_ref:
        raise ValueError("receipt reference does not match the business report")
    if source_semantics is None:
        source_semantics = {
            "evidence_boundary": "静态/模拟证据边界：未提供额外的已观测运行时证据。",
            "import_semantics": "unspecified",
            "sources": ["sealed_evidence"],
        }
    if not isinstance(source_semantics, Mapping):
        raise ValueError("source semantics must be a mapping")
    semantics = dict(source_semantics)
    _reject_unsafe_value(semantics, active_secret=active_secret, path="source_semantics")
    boundary = semantics.get("evidence_boundary")
    if not isinstance(boundary, str) or not boundary:
        raise ValueError("source semantics must state the evidence boundary")
    report_payload = report.model_dump(mode="json")
    assert_safe_deliverable_payload(report_payload, active_secret=active_secret)
    _reject_unsafe_value(receipt, active_secret=active_secret, path="receipt_ref")
    return report, semantics, receipt


def _payload(
    report: SecurityBusinessReport,
    *,
    slot: ApiRunSlot | None = None,
    receipt_ref: str | None = None,
    source_semantics: Mapping[str, Any] | None = None,
    active_secret: str | None = None,
) -> dict[str, Any]:
    validated, semantics, receipt = _validated_context(
        report,
        slot=slot,
        receipt_ref=receipt_ref,
        source_semantics=source_semantics,
        active_secret=active_secret,
    )
    return {
        "schema_version": "1.0",
        "artifact_type": "reverse_api_case_business_report",
        "task_identity": validated.task_identity.model_dump(mode="json"),
        "execution_status": validated.execution_status,
        "model_receipt_ref": receipt,
        "source_semantics": semantics,
        "report": validated.model_dump(mode="json"),
    }


def render_case_json(
    report: SecurityBusinessReport,
    *,
    slot: ApiRunSlot | None = None,
    receipt_ref: str | None = None,
    source_semantics: Mapping[str, Any] | None = None,
    active_secret: str | None = None,
) -> str:
    """Render a canonical JSON envelope for a single logical API run."""

    return json.dumps(
        _payload(
            report,
            slot=slot,
            receipt_ref=receipt_ref,
            source_semantics=source_semantics,
            active_secret=active_secret,
        ),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def _bullet_list(values: Sequence[str]) -> str:
    return "\n".join(f"- {value}" for value in values) if values else "- 无"


def render_case_markdown(
    report: SecurityBusinessReport,
    *,
    slot: ApiRunSlot | None = None,
    receipt_ref: str | None = None,
    source_semantics: Mapping[str, Any] | None = None,
    active_secret: str | None = None,
) -> str:
    """Render the same conclusion as a concise Chinese business-security dossier."""

    payload = _payload(
        report,
        slot=slot,
        receipt_ref=receipt_ref,
        source_semantics=source_semantics,
        active_secret=active_secret,
    )
    report_data = payload["report"]
    identity = payload["task_identity"]
    semantics = payload["source_semantics"]
    findings = report_data["findings"]
    recommendations = report_data["human_decision_recommendations"]
    finding_text = "\n\n".join(
        "\n".join(
            [
                f"### {item['title']}（{item['severity']} / 置信度：{item['confidence']}）",
                f"- 业务影响：{item['business_impact']}",
                f"- 技术说明：{item['technical_explanation']}",
                f"- 证据：{', '.join(item['evidence_refs']) or '无'}",
            ]
        )
        for item in findings
    ) or "无发现。"
    recommendation_text = "\n\n".join(
        "\n".join(
            [
                f"### [{item['priority']}] {item['action']}",
                f"- 决策角色：{item['decision_role']}",
                f"- 理由：{item['rationale']}",
                f"- 预期结果：{item['expected_outcome']}",
            ]
        )
        for item in recommendations
    )
    risk = report_data["risk_assessment"]
    status_label = _STATUS_LABELS[report_data["execution_status"]]
    return "\n".join(
        [
            f"# 逆向分析业务报告：{identity['case_id']}",
            "",
            f"> **运行状态：{status_label} ({report_data['execution_status']})**",
            "",
            "## 任务身份与回执",
            "",
            f"- 题集：`{identity['suite_id']}`",
            f"- 版本：`{identity['arm']}`；独立重复：`{identity['repeat_id']}`",
            f"- 样本 SHA256：`{identity['sample_sha256']}`",
            f"- 模型：`{identity['provider']}` / `{identity['model']}`",
            f"- 模型回执：`{payload['model_receipt_ref']}`",
            "",
            "## 管理摘要",
            "",
            report_data["executive_summary"],
            "",
            "## 逆向分析",
            "",
            report_data["reverse_analysis"],
            "",
            "## 证据边界",
            "",
            str(semantics["evidence_boundary"]),
            "",
            f"- 导入语义：`{semantics.get('import_semantics', 'unspecified')}`",
            f"- 证据来源：{', '.join(str(item) for item in semantics.get('sources', [])) or '未声明'}",
            "",
            "## 发现与风险",
            "",
            finding_text,
            "",
            f"- 总体风险：{risk['overall_risk']}",
            f"- 影响范围：{risk['impact_scope']}",
            f"- 可利用性：{risk['exploitability']}",
            f"- 紧迫度：{risk['urgency']}",
            "",
            "## 给决策者的建议",
            "",
            recommendation_text,
            "",
            "## 后续步骤",
            "",
            _bullet_list(report_data["next_steps"]),
            "",
            "## 局限与未知项",
            "",
            "### 局限",
            _bullet_list(report_data["limitations"]),
            "",
            "### 未知项",
            _bullet_list(report_data["unknowns"]),
            "",
            "## 证据引用",
            "",
            _bullet_list(report_data["evidence_refs"]),
            "",
        ]
    )


def _html_list(values: Sequence[str], *, css_class: str = "") -> str:
    content = "".join(f"<li>{escape(value)}</li>" for value in values) or "<li>无</li>"
    return f'<ul class="{css_class}">{content}</ul>'


def _severity_class(value: str) -> str:
    return _SEVERITY_CLASS.get(value.casefold(), "info")


def render_case_html(
    report: SecurityBusinessReport,
    *,
    slot: ApiRunSlot | None = None,
    receipt_ref: str | None = None,
    source_semantics: Mapping[str, Any] | None = None,
    active_secret: str | None = None,
) -> str:
    """Render a self-contained, printable security-leadership dossier."""

    payload = _payload(
        report,
        slot=slot,
        receipt_ref=receipt_ref,
        source_semantics=source_semantics,
        active_secret=active_secret,
    )
    data = payload["report"]
    identity = payload["task_identity"]
    semantics = payload["source_semantics"]
    status = data["execution_status"]
    findings = "".join(
        "<article class=\"finding\">"
        f"<div class=\"finding-head\"><h3>{escape(item['title'])}</h3>"
        f"<span class=\"stamp severity-{_severity_class(item['severity'])}\">{escape(item['severity'])}</span>"
        f"<span class=\"confidence\">置信度 {escape(item['confidence'])}</span></div>"
        f"<p><b>业务影响</b> {escape(item['business_impact'])}</p>"
        f"<p><b>技术说明</b> {escape(item['technical_explanation'])}</p>"
        "<div class=\"chips\">"
        + "".join(f"<span class=\"chip\">{escape(ref)}</span>" for ref in item["evidence_refs"])
        + "</div></article>"
        for item in data["findings"]
    ) or "<p class=\"empty\">本次运行未输出可供决策的发现。</p>"
    recommendations = "".join(
        "<article class=\"recommendation\">"
        f"<div class=\"rec-head\"><span class=\"priority\">{escape(item['priority'])}</span>"
        f"<h3>{escape(item['action'])}</h3></div>"
        f"<p><b>适用角色</b> {escape(item['decision_role'])}</p>"
        f"<p><b>理由</b> {escape(item['rationale'])}</p>"
        f"<p><b>预期结果</b> {escape(item['expected_outcome'])}</p>"
        "</article>"
        for item in data["human_decision_recommendations"]
    )
    risk = data["risk_assessment"]
    source_names = ", ".join(str(item) for item in semantics.get("sources", [])) or "未声明"
    meta_cards = "\n".join(
        [
            f'<div><span class="label">题集</span><code>{escape(identity["suite_id"])}</code></div>',
            (
                '<div><span class="label">样本 SHA256</span>'
                f'<code>{escape(identity["sample_sha256"])}</code></div>'
            ),
            (
                '<div><span class="label">模型回执</span>'
                f'<code>{escape(payload["model_receipt_ref"])}</code></div>'
            ),
        ]
    )
    risk_cards = "\n".join(
        f'<div class="metric"><span class="label">{label}</span><b>{escape(value)}</b></div>'
        for label, value in (
            ("总体风险", risk["overall_risk"]),
            ("影响范围", risk["impact_scope"]),
            ("可利用性", risk["exploitability"]),
            ("紧迫度", risk["urgency"]),
        )
    )
    evidence_rows = "".join(
        f"<tr><td>封存证据</td><td><code>{escape(ref)}</code></td></tr>"
        for ref in data["evidence_refs"]
    ) or "<tr><td>封存证据</td><td>无</td></tr>"
    evidence_rows += (
        '<tr><td>模型回执</td><td class="receipt"><code>'
        f'{escape(payload["model_receipt_ref"])}</code></td></tr>'
    )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy"
content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none';
form-action 'none'; connect-src 'none'; object-src 'none'; frame-src 'none'">
<title>SecMind 逆向分析业务报告 · {escape(identity['case_id'])}</title>
<style>{_CASE_REPORT_CSS}</style>
</head>
<body>
<main>
  <header class="hero">
    <div class="eyebrow">SECMIND · REVERSE ANALYSIS DOSSIER</div>
    <div class="hero-row"><div><h1>单次逆向分析业务报告</h1>
      <p>题目 <code>{escape(identity['case_id'])}</code> · 版本 <code>{escape(identity['arm'])}</code>
      · 独立重复 <code>{identity['repeat_id']}</code></p></div>
      <span class="status {escape(status)}">{escape(_STATUS_LABELS[status])} / {escape(status)}</span>
    </div>
    <div class="meta">{meta_cards}</div>
  </header>
  <div class="spine">
    <section><h2>管理摘要</h2><p>{escape(data['executive_summary'])}</p></section>
    <section><h2>逆向分析</h2><p>{escape(data['reverse_analysis'])}</p>
      <h2>证据边界</h2><p class="boundary">{escape(str(semantics['evidence_boundary']))}</p>
      <p><b>导入语义：</b><code>{escape(str(semantics.get('import_semantics', 'unspecified')))}</code>
     　<b>来源：</b>{escape(source_names)}</p>
    </section>
    <section><h2>发现与风险</h2>{findings}<div class="grid">{risk_cards}</div></section>
    <section class="decision"><h2>给人类决策者的建议</h2>{recommendations}</section>
    <section class="decision"><h2>后续步骤</h2>{_html_list(data['next_steps'])}</section>
    <section class="caution"><h2>局限与未知项</h2><div class="grid">
      <div><h3>局限</h3>{_html_list(data['limitations'])}</div>
      <div><h3>未知项</h3>{_html_list(data['unknowns'])}</div>
    </div></section>
    <section><h2>审计证据与回执</h2><div class="table-wrap"><table>
      <thead><tr><th>对象</th><th>引用</th></tr></thead><tbody>{evidence_rows}</tbody>
    </table></div></section>
  </div>
</main>
</body>
</html>
"""


__all__ = [
    "build_source_semantics",
    "assert_safe_deliverable_payload",
    "UnsafeDeliverableError",
    "render_case_html",
    "render_case_json",
    "render_case_markdown",
]
