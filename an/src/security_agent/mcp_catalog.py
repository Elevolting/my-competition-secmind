"""Persisted MCP configuration and legacy catalog; MCPRuntime handles protocol calls."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from security_agent.mcp_generated import GeneratedMCPStore

DEFAULT_CONFIG = Path(__file__).resolve().parents[2] / "config" / "mcp-servers.json"
# Optional local inventory; when absent the catalog falls back to its built-in safe set.
DEFAULT_TOOL_GUIDE = Path(__file__).resolve().parents[2] / "config" / "security-tools" / "agent-tool-guide.json"

_SAFE_CANDIDATES = {"local-semgrep", "local-cyberchef", "local-wiremcp"}
_RISK_BY_ID = {
    "local-semgrep": "R1",
    "local-cyberchef": "R1",
    "local-wiremcp": "R1",
    "local-http-fetch": "R2",
    "local-chrome-devtools": "R2",
    "local-web-security": "R2",
    "local-security-extended": "R3",
}
_DETAILS = {
    "local-semgrep": ("代码安全扫描", "代码路径和规则", "发现列表与证据", "代码审计且用户确认后"),
    "local-cyberchef": ("数据编码/解码与转换", "文本或字节、配方", "转换后的数据", "需要离线数据处理时"),
    "local-wiremcp": ("网络取证解析", "抓包或协议数据", "解析字段与摘要", "逆向或网络证据分析时"),
    "local-http-fetch": ("读取 HTTP 资源", "URL 与请求参数", "响应摘要", "渗透任务且用户确认后"),
    "local-chrome-devtools": ("浏览器调试", "页面或调试目标", "DOM/网络调试信息", "浏览器验证且用户确认后"),
    "local-web-security": ("Web 安全检测", "目标与检测参数", "检测结果", "授权靶场检测且用户确认后"),
    "local-security-extended": ("扩展安全分析", "任务和分析参数", "分析报告", "后续评估并审批后"),
}

# User-facing labels keep the technical MCP function name visible as a
# secondary identifier while making the registry readable in Chinese.
_TOOL_LABELS = {
    "tool_versions": "本地工具版本",
    "gitleaks_detect": "本地密钥扫描",
    "exiftool_metadata": "文件元数据读取",
    "bake_recipe": "CyberChef 配方转换",
    "batch_bake_recipe": "CyberChef 批量转换",
    "perform_magic_operation": "CyberChef Magic 识别",
    "semgrep_rule_schema": "Semgrep 规则 Schema",
    "get_supported_languages": "Semgrep 支持语言",
    "semgrep_findings": "Semgrep 发现读取",
    "semgrep_scan_with_custom_rule": "Semgrep 自定义规则扫描",
    "semgrep_scan": "Semgrep 规则集扫描",
    "get_abstract_syntax_tree": "代码 AST 分析",
    "get_summary_stats": "PCAP 统计摘要",
    "get_conversations": "PCAP 会话列表",
    "analyze_pcap": "PCAP 离线解析",
    "extended_tool_versions": "扩展工具版本",
    "trivy_scan": "Trivy 本地漏洞扫描",
    "osv_scan": "OSV 依赖漏洞扫描",
    "yara_scan": "YARA 文件扫描",
    "volatility_plugins": "Volatility 插件目录",
    "volatility_analyze": "Volatility 内存分析",
    "ghidra_headless_analyze": "Ghidra Headless 逆向分析",
    "gdb_inspect": "GDB 二进制检查",
    "mitmproxy_flow_summary": "mitmproxy 流量摘要",
    "binwalk_scan": "Binwalk 固件扫描",
    "capa_analyze": "capa 行为能力分析",
    "floss_extract": "FLOSS 字符串提取",
    "oletools_analyze": "OLE/RTF 文档分析",
    "checksec_binary": "checksec 编译保护检查",
    "ropgadget_scan": "ROP/JOP Gadget 扫描",
    "pwntools_elf_summary": "pwntools ELF 摘要",
    "pwndbg_check": "Pwndbg 环境检查",
}
_SERVER_ICONS = {
    "local-semgrep": "code",
    "local-cyberchef": "experiment",
    "local-wiremcp": "wifi",
    "local-web-security": "safety",
    "local-security-extended": "security-scan",
}
_TOOL_ICONS = {
    "tool_versions": "setting",
    "gitleaks_detect": "key",
    "exiftool_metadata": "file-search",
    "bake_recipe": "experiment",
    "batch_bake_recipe": "partition",
    "perform_magic_operation": "bulb",
    "semgrep_rule_schema": "read",
    "get_supported_languages": "global",
    "semgrep_findings": "search",
    "semgrep_scan_with_custom_rule": "code",
    "semgrep_scan": "scan",
    "get_abstract_syntax_tree": "apartment",
    "get_summary_stats": "bar-chart",
    "get_conversations": "message",
    "analyze_pcap": "fund",
    "extended_tool_versions": "setting",
    "trivy_scan": "bug",
    "osv_scan": "audit",
    "yara_scan": "filter",
    "volatility_plugins": "database",
    "volatility_analyze": "history",
    "ghidra_headless_analyze": "deployment-unit",
    "gdb_inspect": "console-sql",
    "mitmproxy_flow_summary": "bar-chart",
    "binwalk_scan": "file-search",
    "capa_analyze": "radar-chart",
    "floss_extract": "font-size",
    "oletools_analyze": "file-protect",
    "checksec_binary": "safety-certificate",
    "ropgadget_scan": "api",
    "pwntools_elf_summary": "code",
    "pwndbg_check": "tool",
}

# These tools only inspect a supplied local artifact or perform a pure data
# transformation. Network discovery, browser control, HTTP fetching, active
# packet capture and credential extraction are deliberately not displayed.
_SAFE_TOOLS: dict[str, tuple[str, str, str, str, str]] = {
    "tool_versions": ("查看本地工具版本", "无参数", "版本与诊断信息", "查看环境状态时", "R0"),
    "gitleaks_detect": ("扫描本地文件中的 Secret", "文件或工作区路径", "匹配摘要与证据", "代码审计且只读扫描时", "R1"),
    "exiftool_metadata": ("读取文件元数据", "本地文件路径", "结构化元数据", "取证或文件识别时", "R1"),
    "bake_recipe": ("执行 CyberChef 数据配方", "文本/字节与配方", "转换结果", "离线编码转换时", "R1"),
    "batch_bake_recipe": ("批量执行数据配方", "数据列表与配方", "转换结果列表", "批量离线转换时", "R1"),
    "perform_magic_operation": (
        "执行 CyberChef Magic 分析", "文本或字节", "识别出的编码和结果", "需要识别未知编码时", "R1"
    ),
    "semgrep_rule_schema": ("查看 Semgrep 规则格式", "无参数", "规则 Schema", "编写审计规则前", "R0"),
    "get_supported_languages": ("查看 Semgrep 支持的语言", "无参数", "语言列表", "选择扫描语言时", "R0"),
    "semgrep_findings": ("读取 Semgrep 发现", "扫描结果引用", "发现列表", "复核已有扫描结果时", "R1"),
    "semgrep_scan_with_custom_rule": (
        "按自定义规则扫描代码", "代码路径与规则", "发现列表与证据", "代码审计且只读扫描时", "R1"
    ),
    "semgrep_scan": ("按规则集扫描代码", "代码路径与规则集", "发现列表与证据", "代码审计且只读扫描时", "R1"),
    "get_abstract_syntax_tree": ("读取代码抽象语法树", "代码路径", "AST 摘要", "需要结构化代码证据时", "R1"),
    "get_summary_stats": ("读取抓包统计", "本地 PCAP 路径", "协议与流量统计", "离线网络取证时", "R1"),
    "get_conversations": ("读取抓包会话", "本地 PCAP 路径", "会话列表与摘要", "离线网络取证时", "R1"),
    "analyze_pcap": ("离线解析 PCAP", "本地 PCAP 与过滤条件", "解析字段与证据", "逆向或网络证据分析时", "R1"),
    "extended_tool_versions": ("查看扩展分析工具版本", "无参数", "版本与诊断信息", "查看逆向/取证环境时", "R0"),
    "trivy_scan": ("扫描本地镜像或文件系统漏洞", "本地目标路径", "漏洞与配置发现", "供应链审计且只读扫描时", "R1"),
    "osv_scan": ("查询本地依赖漏洞结果", "依赖清单或项目路径", "漏洞匹配", "依赖审计且只读扫描时", "R1"),
    "yara_scan": ("按 YARA 规则扫描文件", "文件路径与规则", "规则匹配与证据", "恶意样本初筛时", "R1"),
    "volatility_plugins": ("查看 Volatility 插件", "无参数", "插件列表", "内存取证选型时", "R0"),
    "volatility_analyze": ("离线分析内存镜像", "镜像路径与插件", "结构化取证结果", "内存取证且只读分析时", "R1"),
    "ghidra_headless_analyze": (
        "离线执行 Ghidra Headless 分析", "本地二进制路径", "函数、引用和分析日志", "逆向初筛且只读分析时", "R1"
    ),
    "gdb_inspect": (
        "批量查看二进制布局或反汇编", "二进制路径与查看模式", "结构化 GDB 输出", "Pwn/逆向静态分析时", "R1"
    ),
    "mitmproxy_flow_summary": ("离线汇总 mitmproxy 流量", "本地 flow 文件", "脱敏会话摘要", "已有授权流量取证时", "R1"),
    "binwalk_scan": ("识别固件和二进制嵌入内容", "本地文件路径", "签名、偏移与诊断", "固件或未知二进制初筛时", "R1"),
    "capa_analyze": ("识别可执行文件行为能力", "本地文件路径", "能力规则匹配", "恶意样本行为初筛时", "R1"),
    "floss_extract": ("提取和解码可执行文件字符串", "本地文件路径", "字符串分类与证据", "逆向样本字符串分析时", "R1"),
    "oletools_analyze": ("分析 Office/OLE/RTF 文件", "文件路径与分析器", "宏、对象和诊断结果", "恶意文档取证时", "R1"),
    "checksec_binary": ("检查二进制编译保护", "本地 ELF/PE 路径", "NX、PIE、Canary 等保护", "Pwn/逆向初筛时", "R1"),
    "ropgadget_scan": (
        "读取二进制 ROP/JOP Gadget", "二进制路径与类型", "Gadget 地址和指令", "漏洞研究静态分析时", "R1"
    ),
    "pwntools_elf_summary": ("读取 ELF 结构化摘要", "本地 ELF 路径", "架构、节区、符号和保护", "Pwn 初筛时", "R1"),
    "pwndbg_check": ("检查离线 Pwndbg 环境", "可选超时", "加载诊断信息", "动态调试前检查环境时", "R1"),
}

_DISPLAY_SERVER_IDS = {
    "local-web-security",
    "local-cyberchef",
    "local-semgrep",
    "local-wiremcp",
    "local-security-extended",
}
_SAFE_TOOL_SERVER_NAMES = {
    "local-web-security": {"tool_versions", "gitleaks_detect", "exiftool_metadata"},
    "local-cyberchef": {"bake_recipe", "batch_bake_recipe", "perform_magic_operation"},
    "local-semgrep": {
        "semgrep_rule_schema", "get_supported_languages", "semgrep_findings",
        "semgrep_scan_with_custom_rule", "semgrep_scan", "get_abstract_syntax_tree",
    },
    "local-wiremcp": {"get_summary_stats", "get_conversations", "analyze_pcap"},
    "local-security-extended": {
        "extended_tool_versions", "trivy_scan", "osv_scan", "yara_scan", "volatility_plugins",
        "volatility_analyze", "ghidra_headless_analyze", "gdb_inspect", "mitmproxy_flow_summary",
        "binwalk_scan", "capa_analyze", "floss_extract", "oletools_analyze", "checksec_binary",
        "ropgadget_scan", "pwntools_elf_summary", "pwndbg_check",
    },
}


class MCPCatalog:
    def __init__(
        self,
        path: Path | None = None,
        generated_root: Path | None = None,
        storage_path: Path | None = None,
    ) -> None:
        self.path = (path or DEFAULT_CONFIG).resolve()
        self.generated_root = (generated_root or self.path.parents[1] / "data" / "mcp-generated").resolve()
        # Keep managed connection settings separate from the bundled inventory.
        self.storage_path = (storage_path or self.path.parents[1] / "data" / "mcp-catalog.json").resolve()

    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"schema_version": "1.0", "runtime_enabled": False, "servers": []}
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("MCP catalog must be a JSON object")
        return payload

    def _guide_ids(self) -> set[str]:
        if not DEFAULT_TOOL_GUIDE.is_file():
            return {
                f"mcp:{server_id}:{short_name}"
                for server_id in _DISPLAY_SERVER_IDS
                for short_name in _SAFE_TOOLS
            }
        try:
            payload = json.loads(DEFAULT_TOOL_GUIDE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {
                f"mcp:{server_id}:{short_name}"
                for server_id in _DISPLAY_SERVER_IDS
                for short_name in _SAFE_TOOLS
            }
        tools = payload.get("tools", {})
        return set(tools) if isinstance(tools, dict) else set()

    def _tools_for(self, server_id: str, guide_ids: set[str]) -> list[dict[str, Any]]:
        result = []
        prefix = f"mcp:{server_id}:"
        for short_name, (purpose, inputs, outputs, timing, risk) in _SAFE_TOOLS.items():
            if short_name not in _SAFE_TOOL_SERVER_NAMES.get(server_id, set()):
                continue
            tool_id = prefix + short_name
            if tool_id not in guide_ids:
                continue
            result.append({
                "tool_id": tool_id,
                "name": short_name,
                "display_name": _TOOL_LABELS.get(short_name, short_name),
                "icon": _TOOL_ICONS.get(short_name, "tool"),
                "purpose": purpose,
                "input": inputs,
                "return": outputs,
                "invocation_timing": timing,
                "risk_level": risk,
                "available": True,
                "runtime_exposed": False,
            })
        return result

    def _default_servers(self) -> list[dict[str, Any]]:
        payload = self._load()
        guide_ids = self._guide_ids()
        result: list[dict[str, Any]] = []
        for raw in payload.get("servers", []):
            if not isinstance(raw, dict) or not raw.get("server_id"):
                continue
            server_id = str(raw["server_id"])
            parsed = urlparse(str(raw.get("url", "")))
            purpose, inputs, outputs, timing = _DETAILS.get(
                server_id, ("外部安全工具", "工具参数", "工具结果", "完成安全分析且获授权后")
            )
            tools = self._tools_for(server_id, guide_ids)
            result.append(
                {
                    "server_id": server_id,
                    "name": str(raw.get("name", server_id)),
                    "icon": _SERVER_ICONS.get(server_id, "safety"),
                    "transport": str(raw.get("transport", "unknown")),
                    "url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme and parsed.netloc else "",
                    "enabled": bool(raw.get("enabled", False)),
                    "command": str(raw.get("command") or ""),
                    "args": list(raw.get("args") or []),
                    "status": "prepared" if server_id in _SAFE_CANDIDATES else "disabled",
                    "candidate": server_id in _SAFE_CANDIDATES,
                    "risk_level": _RISK_BY_ID.get(server_id, "R2"),
                    "category": (raw.get("metadata") or {}).get("category", "security"),
                    "purpose": purpose,
                    "input": inputs,
                    "return": outputs,
                    "invocation_timing": timing,
                    "displayable": server_id in _DISPLAY_SERVER_IDS and bool(tools),
                    "safe_server": server_id in _DISPLAY_SERVER_IDS and bool(tools),
                    "tools": tools,
                    "tool_count": len(tools),
                }
            )
        return result

    def _load_managed(self) -> list[dict[str, Any]] | None:
        if not self.storage_path.is_file():
            return None
        try:
            payload = json.loads(self.storage_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return None
        if not isinstance(payload, list):
            return None
        return [self._normalize_server(item) for item in payload if isinstance(item, dict)]

    @staticmethod
    def _normalize_server(raw: dict[str, Any]) -> dict[str, Any]:
        server_id = str(raw.get("server_id") or "")
        tools = []
        for value in raw.get("tools", []):
            if not isinstance(value, dict) or not value.get("name"):
                continue
            name = str(value["name"])
            tools.append(
                {
                    "tool_id": f"mcp:{server_id}:{name}",
                    "name": name,
                    "display_name": str(value.get("display_name") or name),
                    "icon": str(value.get("icon") or "tool"),
                    "purpose": str(value.get("purpose") or "展示型 MCP 工具"),
                    "input": str(value.get("input") or "工具参数"),
                    "return": str(value.get("return") or value.get("returns") or "工具结果"),
                    "invocation_timing": str(value.get("invocation_timing") or "按需展示"),
                    "risk_level": str(value.get("risk_level") or "R1"),
                    "available": True,
                    "runtime_exposed": False,
                }
            )
        return {
            "server_id": server_id,
            "name": str(raw.get("name") or server_id),
            "icon": str(raw.get("icon") or "safety"),
            "transport": str(raw.get("transport") or "display_only"),
            "url": str(raw.get("url") or ""),
            "enabled": bool(raw.get("enabled", False)),
                    "command": str(raw.get("command") or ""),
                    "args": list(raw.get("args") or []),
            "status": "managed",
            "candidate": bool(raw.get("candidate", False)),
            "risk_level": str(raw.get("risk_level") or "R1"),
            "category": str(raw.get("category") or "security"),
            "purpose": str(raw.get("purpose") or "展示型 MCP Server"),
            "input": str(raw.get("input") or "工具参数"),
            "return": str(raw.get("return") or "工具结果"),
            "invocation_timing": str(raw.get("invocation_timing") or "按需展示"),
            "displayable": bool(raw.get("displayable", True)),
            "safe_server": bool(raw.get("safe_server", True)),
            "tools": tools,
            "tool_count": len(tools),
            "managed": True,
        }

    def servers(self) -> list[dict[str, Any]]:
        managed = self._load_managed()
        return managed if managed is not None else self._default_servers()

    def _write_servers(self, servers: list[dict[str, Any]]) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.storage_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(servers, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temporary, self.storage_path)

    def get_server(self, server_id: str) -> dict[str, Any] | None:
        return next((item for item in self.servers() if item["server_id"] == server_id), None)

    def create_server(self, payload: dict[str, Any]) -> dict[str, Any]:
        servers = self.servers()
        server_id = str(payload.get("server_id") or f"custom-server-{uuid4().hex[:8]}")
        if server_id == "secmind-local" or any(item["server_id"] == server_id for item in servers):
            raise ValueError(f"MCP server already exists: {server_id}")
        server = self._normalize_server({**payload, "server_id": server_id, "tools": []})
        self._write_servers([*servers, server])
        return server

    def update_server(self, server_id: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        servers = self.servers()
        current = next((item for item in servers if item["server_id"] == server_id), None)
        if current is None:
            return None
        updated = self._normalize_server({**current, **payload, "server_id": server_id, "tools": current["tools"]})
        self._write_servers([updated if item["server_id"] == server_id else item for item in servers])
        return updated

    def delete_server(self, server_id: str) -> bool:
        servers = self.servers()
        remaining = [item for item in servers if item["server_id"] != server_id]
        if len(remaining) == len(servers):
            return False
        self._write_servers(remaining)
        return True

    def create_tool(self, server_id: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        server = self.get_server(server_id)
        if server is None:
            return None
        name = str(payload.get("name") or f"custom_tool_{uuid4().hex[:8]}")
        if any(item["name"] == name for item in server["tools"]):
            raise ValueError(f"MCP tool already exists: {name}")
        tool = self._normalize_server({"server_id": server_id, "tools": [{**payload, "name": name}]})["tools"][0]
        server["tools"] = [*server["tools"], tool]
        self._replace_server(server)
        return tool

    def update_tool(self, server_id: str, tool_name: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        server = self.get_server(server_id)
        if server is None:
            return None
        current = next((item for item in server["tools"] if item["name"] == tool_name), None)
        if current is None:
            return None
        updated = self._normalize_server(
            {"server_id": server_id, "tools": [{**current, **payload, "name": tool_name}]}
        )["tools"][0]
        server["tools"] = [updated if item["name"] == tool_name else item for item in server["tools"]]
        self._replace_server(server)
        return updated

    def delete_tool(self, server_id: str, tool_name: str) -> bool:
        server = self.get_server(server_id)
        if server is None:
            return False
        remaining = [item for item in server["tools"] if item["name"] != tool_name]
        if len(remaining) == len(server["tools"]):
            return False
        server["tools"] = remaining
        self._replace_server(server)
        return True

    def _replace_server(self, server: dict[str, Any]) -> None:
        normalized = self._normalize_server(server)
        self._write_servers(
            [normalized if item["server_id"] == server["server_id"] else item for item in self.servers()]
        )

    def payload(self) -> dict[str, Any]:
        all_servers = self.servers()
        servers = [item for item in all_servers if item["displayable"]]
        generated_tools = GeneratedMCPStore(self.generated_root).list()
        safe_tools = sum(item["tool_count"] for item in servers)
        return {
            "schema_version": "1.0",
            "runtime_enabled": False,
            "invocation_enabled": False,
            "tool_registration": "not_registered",
            "server_count": len(servers),
            "configured_server_count": len(all_servers),
            "candidate_count": sum(1 for item in servers if item["candidate"]),
            "safe_tool_count": safe_tools,
            "excluded_servers": [item["server_id"] for item in all_servers if not item["displayable"]],
            "tool_guide_path": str(DEFAULT_TOOL_GUIDE),
            "servers": servers,
            "generated_tools": generated_tools,
        }
