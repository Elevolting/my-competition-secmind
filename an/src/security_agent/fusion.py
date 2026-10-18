from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from security_agent.schemas import AgentState, Scenario

RULES: dict[str, tuple[str, ...]] = {
    "code_audit": ("代码审计", "审计", "漏洞", "sql注入", "ssrf", "xss", "python", "java", "php", "javascript", "go", "bandit", "sast"),
    "reverse": ("逆向", "pe", "elf", "exe", "dll", "二进制", "反编译", "汇编", "脱壳", "样本", "静态分析", "ida", "ghidra", "malware", "恶意代码"),
    "penetration": ("渗透", "靶机", "端口", "nmap", "扫描", "利用", "shell", "web攻击", "getshell", "目标主机"),
}
EXTENSIONS = {
    "reverse": {".exe", ".dll", ".sys", ".elf", ".so", ".bin", ".apk", ".class", ".wasm", ".dylib"},
    "code_audit": {".py", ".java", ".php", ".js", ".ts", ".go", ".rb", ".rs", ".xml", ".yml", ".yaml"},
    "penetration": {".pcap", ".pcapng", ".nessus", ".nmap", ".txt", ".url"},
}


def classify_task(
    objective: str,
    attachments: list[Any] | None = None,
    target_scope: list[str] | None = None,
) -> dict[str, Any]:
    text = (objective or "").casefold()
    if '日志' in text or re.search(r'\blogs?\b', text):
        return {"primary_type": "log_analysis", "secondary_types": [], "confidence": 0.95,
                "evidence": ["题目包含日志分析目标"], "needs_human_review": False, "scenario": Scenario.LOG_ANALYSIS}
    if any(term in text for term in ("应急", "incident", "事件响应")):
        scenario = Scenario.INCIDENT_RESPONSE
        return {"primary_type": "unsupported", "secondary_types": [], "confidence": 0.95, "evidence": ["题目关键词匹配：日志/应急"], "needs_human_review": True, "scenario": scenario}
    names = [str(getattr(item, "relative_path", getattr(item, "name", item))) for item in (attachments or [])]
    scopes = [str(item) for item in (target_scope or [])]
    scores: dict[str, float] = {key: 0.0 for key in RULES}
    evidence: dict[str, list[str]] = {key: [] for key in RULES}
    for module, terms in RULES.items():
        for term in terms:
            if term.casefold() in text:
                scores[module] += 3.0 if len(term) > 2 else 1.5
                evidence[module].append(f"题目关键词：{term}")
    for name in names:
        suffix = Path(name).suffix.casefold()
        for module, exts in EXTENSIONS.items():
            if suffix in exts:
                scores[module] += 2.5
                evidence[module].append(f"文件扩展名：{suffix}")
        lowered = name.casefold()
        if re.search(r"(^|[/\\])(bin|binary|sample|逆向|reverse|re)([/\\]|$)", lowered):
            scores["reverse"] += 1.5
            evidence["reverse"].append("目录名称暗示二进制/逆向题")
    for scope in scopes:
        parsed = urlparse(scope)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            scores["penetration"] += 6.0
            evidence["penetration"].append("授权范围包含靶场网址")
    best = max(scores, key=scores.get)
    ordered = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    if scores[best] <= 0:
        best = "code_audit"
        confidence = 0.25
    else:
        total = sum(scores.values()) or 1.0
        confidence = min(0.99, 0.55 + scores[best] / (total * 2.0))
    secondary = [name for name, value in ordered[1:] if value > 0 and value >= scores[best] * 0.45][:2]
    scenario = {
        "code_audit": Scenario.CODE_AUDIT,
        "reverse": Scenario.REVERSE_TRIAGE,
        "penetration": Scenario.PENETRATION_TEST,
    }[best]
    return {
        "primary_type": best,
        "secondary_types": secondary,
        "confidence": round(confidence, 3),
        "evidence": evidence[best],
        "needs_human_review": confidence < 0.55 or (len(secondary) > 0 and scores[secondary[0]] >= scores[best] * 0.8),
        "scenario": scenario,
    }


def routing_for_state(state: AgentState) -> dict[str, Any]:
    return classify_task(state.task.objective, state.input_artifacts, state.task.target_scope)
