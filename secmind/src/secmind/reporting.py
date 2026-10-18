from __future__ import annotations

from typing import Any

from secmind import PUBLIC_VERSION
from secmind.schemas import AgentReport


def render_markdown(report: AgentReport) -> str:
    lines = [
        f"# SecMind security report: {report.run_id}",
        "",
        f"Status: **{report.status.value}**",
        "",
        report.executive_summary,
        "",
        "## Findings",
        "",
    ]
    if not report.findings:
        lines.append("No findings were reported by the enabled tools.")
    for finding in report.findings:
        location = f"{finding.path}:{finding.line}" if finding.line else finding.path
        lines.extend(
            [
                f"### [{finding.severity}] {finding.rule_id}: {finding.title}",
                "",
                f"Location: `{location}`",
                "",
                finding.description,
                "",
                f"Evidence: {', '.join(finding.evidence_ids) or 'missing'}",
                "",
                f"Remediation: {finding.remediation or 'Review and remediate according to the cited rule.'}",
                "",
            ]
        )
    if report.limitations:
        lines.extend(["## Limitations", "", *[f"- {item}" for item in report.limitations], ""])
    return "\n".join(lines)


def render_sarif(report: AgentReport) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    level_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
    for finding in report.findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.description},
                "help": {"text": finding.remediation or "Review the evidence and remediate the vulnerable pattern."},
            },
        )
        region = {"startLine": finding.line} if finding.line is not None else {}
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": level_map.get(finding.severity, "warning"),
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": region,
                        }
                    }
                ],
                "properties": {"evidenceIds": finding.evidence_ids, "confidence": finding.confidence},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecMind",
                        "semanticVersion": PUBLIC_VERSION,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {"runId": report.run_id, "status": report.status.value},
            }
        ],
    }
