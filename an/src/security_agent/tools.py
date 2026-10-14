from __future__ import annotations

import asyncio
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import httpx

from security_agent.guardrail import Guardrail, GuardrailDecision
from security_agent.mcp_generated import GeneratedMCPStore
from security_agent.penetration_integration import project_title_for_run
from security_agent.schemas import (
    Evidence,
    Finding,
    RiskLevel,
    Scenario,
    ToolContext,
    ToolManifest,
    ToolResult,
    ToolStatus,
)


class ToolError(RuntimeError):
    pass


class BaseTool(ABC):
    manifest: ToolManifest

    @abstractmethod
    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        raise NotImplementedError


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        if tool.manifest.name in self._tools:
            raise ToolError(f"Duplicate tool: {tool.manifest.name}")
        self._tools[tool.manifest.name] = tool

    def get(self, name: str) -> BaseTool:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ToolError(f"Unknown tool: {name}") from exc

    def manifests(self) -> list[ToolManifest]:
        return [tool.manifest for tool in self._tools.values()]


class ToolBroker:
    def __init__(self, registry: ToolRegistry, guardrail: Guardrail) -> None:
        self.registry = registry
        self.guardrail = guardrail

    def assess(self, name: str, args: dict[str, Any], autonomy_policy: str) -> GuardrailDecision:
        tool = self.registry.get(name)
        from security_agent.mcp_agent import MCPAgentTool

        if isinstance(tool, MCPAgentTool):
            from security_agent.mcp_approval import requires_approval, requires_context_approval
            from security_agent.guardrail import autonomy_policy_skips_approval
            if (requires_context_approval(tool.server['server_id'], tool.tool['name'])
                    or requires_approval(tool.server['server_id'], tool.tool['name'], args)
                    and not autonomy_policy_skips_approval(tool.manifest.risk_level, autonomy_policy)):
                autonomy_policy = 'graded'
            elif tool.manifest.risk_level == RiskLevel.R2:
                return self.guardrail.evaluate(
                    tool.manifest.model_copy(update={'risk_level': RiskLevel.R1}),
                    args, autonomy_policy,
                )
        return self.guardrail.evaluate(tool.manifest, args, autonomy_policy)

    async def invoke(self, name: str, args: dict[str, Any], context: ToolContext) -> ToolResult:
        return await self.registry.get(name).invoke(args, context)


REMEDIATIONS = {
    "B105": "将硬编码密钥迁移至安全的密钥管理服务，并轮换已经暴露的密钥。",
    "B301": "避免不安全的反序列化，改用经过结构校验的 JSON 等安全格式。",
    "B602": "避免使用 shell=True，应向子进程传递固定参数列表。",
    "B608": "使用参数化查询，不要通过字符串拼接构造 SQL。",
}


class BanditTool(BaseTool):
    manifest = ToolManifest(
        name="bandit_python_audit",
        version="1",
        description="Run Bandit static security analysis over Python source in the controlled workspace.",
        scenarios=[Scenario.CODE_AUDIT],
        input_schema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "properties": {"findings": {"type": "array"}}},
        risk_level=RiskLevel.R1,
        permissions=["workspace:read"],
        timeout_seconds=120,
        idempotent=True,
        requires_network=False,
    )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        started = time.monotonic()
        try:
            target = self._resolve_target(str(args.get("target", ".")), context)
        except ToolError as exc:
            return ToolResult(
                status=ToolStatus.DENIED,
                error_code="TOOL_SCOPE_VIOLATION",
                error_message=str(exc),
            )
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "bandit",
            "-r",
            str(target),
            "-f",
            "json",
            "-q",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=context.workspace,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.manifest.timeout_seconds)
        except TimeoutError:
            process.kill()
            await process.communicate()
            return ToolResult(
                status=ToolStatus.TIMEOUT,
                duration_ms=int((time.monotonic() - started) * 1000),
                error_code="TOOL_TIMEOUT",
                error_message="Bandit exceeded its execution deadline.",
            )
        except asyncio.CancelledError:
            if process.returncode is None:
                process.kill()
            await process.communicate()
            raise
        if process.returncode not in {0, 1}:
            return ToolResult(
                status=ToolStatus.ERROR,
                duration_ms=int((time.monotonic() - started) * 1000),
                error_code="BANDIT_FAILED",
                error_message=stderr.decode(errors="replace")[-2000:],
            )
        try:
            body = json.loads(stdout.decode(errors="replace") or "{}")
        except json.JSONDecodeError as exc:
            return ToolResult(
                status=ToolStatus.ERROR,
                duration_ms=int((time.monotonic() - started) * 1000),
                error_code="BANDIT_INVALID_JSON",
                error_message=str(exc),
            )
        evidence: list[Evidence] = []
        findings: list[dict[str, Any]] = []
        workspace = Path(context.workspace).resolve()
        for item in body.get("results", []):
            if item.get("test_id") == "B404":
                # Importing subprocess is context for call-site rules, not a vulnerability.
                continue
            source = Path(str(item.get("filename", ""))).resolve()
            if not source.is_file() or not source.is_relative_to(workspace):
                continue
            relative = source.relative_to(workspace).as_posix()
            item = {**item, "filename": relative}
            evidence_id = hashlib.sha256(json.dumps(item, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:24]
            ev = Evidence(
                evidence_id=evidence_id,
                source=f"bandit:{self.manifest.version}",
                summary=f"{item.get('test_id', 'UNKNOWN')} at {relative}:{item.get('line_number')}",
                artifact_ref=relative,
                sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                metadata={
                    "tool_version": self.manifest.version,
                    "test_id": item.get("test_id"),
                    "test_name": item.get("test_name"),
                },
            )
            evidence.append(ev)
            finding = Finding(
                rule_id=item.get("test_id", "UNKNOWN"),
                severity=item.get("issue_severity", "UNKNOWN"),
                confidence=item.get("issue_confidence", "UNKNOWN"),
                path=item.get("filename", "unknown"),
                line=item.get("line_number"),
                title=item.get("test_name", item.get("test_id", "Bandit finding")),
                description=item.get("issue_text", ""),
                remediation=REMEDIATIONS.get(item.get("test_id")),
                evidence_ids=[evidence_id],
                raw=item,
            )
            findings.append(finding.model_dump(mode="json"))
        return ToolResult(
            status=ToolStatus.SUCCESS,
            data={"findings": findings, "metrics": body.get("metrics", {})},
            summary=f"Bandit 扫描完成，共发现 {len(findings)} 个安全问题。",
            evidence=evidence,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    @staticmethod
    def _resolve_target(value: str, context: ToolContext) -> Path:
        workspace = Path(context.workspace).resolve()
        candidate = (workspace / value).resolve() if not Path(value).is_absolute() else Path(value).resolve()
        allowed = [Path(path).resolve() for path in context.allowed_paths]
        if not any(candidate == root or root in candidate.parents for root in allowed):
            raise ToolError("Tool target is outside the allowed workspace")
        if not candidate.exists():
            raise ToolError("Tool target does not exist")
        return candidate


STATIC_RULES: tuple[dict[str, Any], ...] = (
    {
        "rule_id": "AUDIT-JAVA-SSTI",
        "extensions": {".java"},
        "patterns": (r"@RequestParam", r"runtimeServices\.parse\s*\("),
        "severity": "CRITICAL",
        "title": "用户可控输入进入服务端模板解析器",
        "description": (
            "请求参数与运行时模板解析出现在同一源码文件中，形成服务端模板注入攻击路径。"
        ),
        "remediation": (
            "禁止编译包含请求数据的模板；不可信输入只能作为经过转义的模板上下文变量传递。"
        ),
    },
    {
        "rule_id": "AUDIT-SECRET-FLAG",
        "extensions": {".txt", ".env", ".properties", ".conf", ""},
        "patterns": (r"(?i)(?:flag|htb|ctf)\{[^\r\n}]+\}",),
        "severity": "HIGH",
        "title": "源码材料中存有敏感挑战密钥",
        "description": (
            "项目文件以明文保存了类似 flag 的敏感内容；证据中已主动隐藏匹配到的具体值。"
        ),
        "remediation": (
            "应在运行时注入密钥，并从源码压缩包和构建上下文中排除真实密钥。"
        ),
        "redact": True,
    },
    {
        "rule_id": "AUDIT-LEGACY-SPRING",
        "extensions": {".xml"},
        "patterns": (r"<artifactId>spring-boot-starter-parent</artifactId>[\s\S]{0,300}<version>1\.[0-9.]+</version>",),
        "severity": "HIGH",
        "title": "使用已停止安全维护的 Spring Boot 依赖",
        "description": "项目使用 Spring Boot 1.x 父依赖，该版本已不再获得安全更新。",
        "remediation": (
            "升级至仍受支持的 Spring Boot 版本，并在部署前执行依赖漏洞分析。"
        ),
    },
    {
        "rule_id": "AUDIT-LEGACY-VELOCITY",
        "extensions": {".xml"},
        "patterns": (r"<artifactId>velocity</artifactId>[\s\S]{0,120}<version>1\.7</version>",),
        "severity": "HIGH",
        "title": "使用过时的 Apache Velocity 依赖",
        "description": (
            "Apache Velocity 1.7 已经过时；当模板包含不可信数据时，其安全风险尤其突出。"
        ),
        "remediation": (
            "移除对不可信模板的运行时解析，并迁移至仍受支持的模板引擎版本。"
        ),
    },
    {
        "rule_id": "AUDIT-SHELL-RANDOM-NAME",
        "extensions": {".sh"},
        "patterns": (r"mv\s+/flag\.txt\s+/flag\$\(",),
        "severity": "MEDIUM",
        "title": "使用随机文件名保护密钥",
        "description": (
            "将密钥重命名为随机文件名并不构成访问控制，仍可能导致敏感内容泄露。"
        ),
        "remediation": (
            "将密钥存放在应用文件系统之外，并在访问点实施严格的身份验证和授权。"
        ),
    },
)


class WorkspaceSecurityAuditTool(BaseTool):
    manifest = ToolManifest(
        name="workspace_security_audit",
        version="1",
        description=(
            "Read and audit supported source, configuration, dependency, and container files; "
            "use Bandit for Python."
        ),
        scenarios=[Scenario.CODE_AUDIT],
        input_schema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "properties": {"findings": {"type": "array"}, "coverage": {"type": "object"}}},
        risk_level=RiskLevel.R1,
        permissions=["workspace:read"],
        timeout_seconds=120,
        idempotent=True,
        requires_network=False,
    )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        if context.analysis_backend == "local":
            return await self._invoke_local(args, context)
        try:
            target = BanditTool._resolve_target(str(args.get("target", ".")), context)
            files = [target] if target.is_file() else [p for p in target.rglob("*") if p.is_file()]
            from security_agent.secmind_adapter import invoke_secmind
            return await invoke_secmind(files, context, domain="code_audit_and_patch")
        except ToolError as exc:
            return ToolResult(status=ToolStatus.DENIED, error_code="TOOL_SCOPE_VIOLATION", error_message=str(exc))
        except (httpx.HTTPError, OSError, ValueError) as exc:
            reason = f"SecMind 分析未完成：{type(exc).__name__}"
            if context.external_execution.get("remote_run_id") or context.external_execution.get("status") == "submitting":
                return ToolResult(status=ToolStatus.ERROR, summary=reason, error_code="SECMIND_REMOTE_UNCERTAIN",
                    error_message=reason, data={"adapter": "secmind_api", **context.external_execution})
            result = await self._invoke_local(args, context)
            result.data.update(degraded=True, partial_evidence=True, remote_error=reason,
                               limitations=[reason, "仅完成本地规则扫描，未完成独立分析引擎审计"])
            result.summary = "完整分析引擎不可用，已保留本地扫描结果。"
            result.error_code = "SECMIND_SERVICE_UNAVAILABLE"
            result.error_message = reason
            result.status = ToolStatus.ERROR
            return result

    async def _invoke_local(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        started = time.monotonic()
        try:
            target = BanditTool._resolve_target(str(args.get("target", ".")), context)
        except ToolError as exc:
            return ToolResult(status=ToolStatus.DENIED, error_code="TOOL_SCOPE_VIOLATION", error_message=str(exc))

        candidates = [target] if target.is_file() else [path for path in target.rglob("*") if path.is_file()]
        supported_extensions = {extension for rule in STATIC_RULES for extension in rule["extensions"]}
        supported_extensions.update({".py", ".html", ".css", ".json", ".yml", ".yaml", ".dockerfile"})
        scanned: list[str] = []
        skipped_binary: list[str] = []
        findings: list[dict[str, Any]] = []
        evidence: list[Evidence] = []
        workspace = Path(context.workspace).resolve()

        for path in candidates:
            relative = path.resolve().relative_to(workspace).as_posix()
            suffix = path.suffix.lower()
            logical_suffix = "" if path.name.lower() == "dockerfile" else suffix
            try:
                content = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                skipped_binary.append(relative)
                continue
            if logical_suffix not in supported_extensions:
                if path.stat().st_size > 4 * 1024 * 1024 or "\x00" in content:
                    skipped_binary.append(relative)
                    continue
                logical_suffix = ".conf"
            scanned.append(relative)
            for rule in STATIC_RULES:
                if logical_suffix not in rule["extensions"]:
                    continue
                matches = [re.search(pattern, content) for pattern in rule["patterns"]]
                if not all(matches):
                    continue
                first_match = next(match for match in matches if match is not None)
                line = content.count("\n", 0, first_match.start()) + 1
                fingerprint = hashlib.sha256(
                    f"{rule['rule_id']}:{relative}:{line}".encode()
                ).hexdigest()[:24]
                ev = Evidence(
                    evidence_id=fingerprint,
                    source=f"workspace-security-audit:{self.manifest.version}",
                    summary=f"{rule['rule_id']} at {relative}:{line}",
                    artifact_ref=relative,
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                    metadata={"rule_id": rule["rule_id"], "line": line, "secret_redacted": bool(rule.get("redact"))},
                )
                evidence.append(ev)
                findings.append(
                    Finding(
                        rule_id=rule["rule_id"],
                        severity=rule["severity"],
                        confidence="HIGH",
                        path=relative,
                        line=line,
                        title=rule["title"],
                        description=rule["description"],
                        remediation=rule["remediation"],
                        evidence_ids=[fingerprint],
                        raw={"rule_id": rule["rule_id"], "secret_redacted": bool(rule.get("redact"))},
                    ).model_dump(mode="json")
                )

        python_files = [path for path in candidates if path.suffix.lower() == ".py"]
        bandit_used = bool(python_files)
        if bandit_used:
            bandit = await BanditTool().invoke({"target": str(target)}, context)
            if bandit.status != ToolStatus.SUCCESS:
                return bandit
            findings.extend(bandit.data.get("findings", []))
            evidence.extend(bandit.evidence)

        # Reuse previously approved declarative adapters for formats that the
        # built-in scanner could not classify.  No generated code is executed.
        generated_used: list[str] = []
        if context.mcp_generated_root:
            for proposal in GeneratedMCPStore(Path(context.mcp_generated_root)).proposals():
                matched = [
                    path for path in candidates
                    if "*" in proposal.file_extensions or path.suffix.casefold() in proposal.file_extensions
                ]
                if not matched:
                    continue
                generated_used.append(proposal.tool_id)
                for path in matched[:200]:
                    try:
                        raw = path.read_bytes()
                    except OSError:
                        continue
                    relative = path.resolve().relative_to(workspace).as_posix()
                    if relative not in scanned:
                        scanned.append(relative)
                    matches: list[str] = []
                    if proposal.operation == "binary_strings":
                        matches = [item.decode("ascii", errors="replace") for item in re.findall(rb"[ -~]{4,}", raw)[:20]]
                    elif proposal.operation == "json_keys":
                        try:
                            parsed = json.loads(raw.decode("utf-8"))
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            continue
                        if isinstance(parsed, dict):
                            matches = [str(key) for key in list(parsed)[:50]]
                    else:
                        text = raw.decode("utf-8", errors="replace").replace("\x00", "")
                        for pattern in proposal.patterns:
                            try:
                                matches.extend(match.group(0) for match in list(re.finditer(pattern, text))[:20])
                            except (re.error, TypeError):
                                continue
                    if not matches:
                        continue
                    digest = hashlib.sha256(raw).hexdigest()
                    evidence_id = hashlib.sha256(f"generated:{proposal.tool_id}:{relative}:{digest}".encode()).hexdigest()[:24]
                    evidence.append(Evidence(
                        evidence_id=evidence_id,
                        source=f"generated-mcp:{proposal.tool_id}",
                        summary=f"{proposal.name} 读取 {relative}，提取 {len(matches)} 项结果",
                        artifact_ref=relative,
                        sha256=digest,
                        metadata={"tool_id": proposal.tool_id, "operation": proposal.operation, "matches": matches[:20]},
                    ))
                    findings.append(Finding(
                        rule_id=f"MCP-{proposal.tool_id.upper()}",
                        severity="UNKNOWN",
                        confidence="MEDIUM",
                        path=relative,
                        title=proposal.name,
                        description=f"模型生成的受控工具提取结果：{'; '.join(matches[:5])}",
                        evidence_ids=[evidence_id],
                        raw={"tool_id": proposal.tool_id, "operation": proposal.operation},
                    ).model_dump(mode="json"))

        coverage = {
            "input_file_count": len(candidates),
            "scanned_file_count": len(scanned),
            "scanned_files": scanned,
            "skipped_file_count": len(skipped_binary),
            "skipped_files": skipped_binary,
            "python_bandit_used": bandit_used,
            "generated_tools_used": generated_used,
        }
        if not scanned and not generated_used:
            return ToolResult(
                status=ToolStatus.ERROR,
                data={"findings": [], "coverage": coverage},
                summary="安全审计未实际读取任何受支持的输入文件。",
                duration_ms=int((time.monotonic() - started) * 1000),
                error_code="NO_AUDIT_COVERAGE",
                error_message="当前配置的审计工具不支持所提供的文件。",
            )
        return ToolResult(
            status=ToolStatus.SUCCESS,
            data={"findings": findings, "coverage": coverage},
            summary=(
                f"工作区审计实际读取 {len(scanned)}/{len(candidates)} 个文件，"
                f"共发现 {len(findings)} 个安全问题。"
            ),
            evidence=evidence,
            duration_ms=int((time.monotonic() - started) * 1000),
        )


class ReverseModuleTool(BaseTool):
    manifest = ToolManifest(
        name="reverse_module", version="1", description="PE/ELF static triage via the reverse analysis service.",
        scenarios=[Scenario.REVERSE_TRIAGE], input_schema={"type":"object","properties":{"target":{"type":"string"}},"required":["target"]},
        output_schema={"type":"object"}, risk_level=RiskLevel.R1, permissions=["workspace:read"], timeout_seconds=600, idempotent=False,
    )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        started = time.monotonic()
        try:
            target = BanditTool._resolve_target(str(args.get("target", ".")), context)
        except ToolError as exc:
            return ToolResult(status=ToolStatus.DENIED, error_code="TOOL_SCOPE_VIOLATION", error_message=str(exc))
        files = [target] if target.is_file() else [p for p in target.rglob("*") if p.is_file()]

        # The reverse service owns the full reverse-analysis workflow and its
        # model/tool ledger. Upload the bounded task material to that API first
        # so this adapter does not silently reduce a reverse question to magic
        # byte detection. If the service is unavailable, retain a local static
        # triage fallback and report that degradation explicitly.
        if context.module_base_url and context.analysis_backend != "local":
            try:
                remote = await self._invoke_remote(target, files, context)
                if remote is not None:
                    return remote
            except (httpx.HTTPError, OSError, ValueError) as exc:
                if context.external_execution.get("remote_run_id") or context.external_execution.get("status") == "submitting":
                    return ToolResult(
                        status=ToolStatus.ERROR, error_code="SECMIND_REMOTE_UNCERTAIN",
                        error_message=f"远程逆向任务状态待核对：{type(exc).__name__}",
                        data={"adapter": "reverse_api", **context.external_execution},
                    )
                remote_error = f"{type(exc).__name__}"
            else:
                remote_error = "reverse service returned no result"
        else:
            remote_error = "reverse service URL is not configured"

        findings, evidence, observations = [], [], []
        for path in files[:200]:
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            magic = "PE" if raw[:2] == b"MZ" else "ELF" if raw[:4] == b"\x7fELF" else None
            if not magic:
                continue
            rel = path.resolve().relative_to(Path(context.workspace).resolve()).as_posix()
            digest = hashlib.sha256(raw).hexdigest()
            eid = hashlib.sha256(f"reverse:{rel}:{digest}".encode()).hexdigest()[:24]
            ev = Evidence(evidence_id=eid, source="reverse-module:local", summary=f"{magic} 样本 {rel}", artifact_ref=rel, sha256=digest, metadata={"format": magic, "size": len(raw)})
            evidence.append(ev)
            if context.analysis_backend == 'local':
                observations.append({'title': f'{magic} 二进制样本：{rel}',
                                     'summary': f'已读取文件头和 SHA-256：{digest}',
                                     'evidence_ids': [eid], 'type': 'observation'})
            else:
                findings.append(Finding(rule_id="REVERSE-FORMAT", severity="UNKNOWN", confidence="HIGH", path=rel, title=f"检测到 {magic} 二进制样本", description="已提取文件格式、大小和哈希，可继续由逆向服务进行导入表及行为分析。", evidence_ids=[eid], raw={"format": magic, "sha256": digest}).model_dump(mode="json"))
        if context.analysis_backend == 'local':
            return ToolResult(status=ToolStatus.SUCCESS,
                data={'observations': observations, 'adapter': 'reverse_local_round',
                      'format_count': len(observations)}, evidence=evidence,
                summary=f'完成单轮样本格式初筛，识别 {len(observations)} 个 PE/ELF 文件。',
                duration_ms=int((time.monotonic()-started)*1000))
        return ToolResult(
            status=ToolStatus.ERROR,
            data={**context.external_execution, "findings": findings, "format_count": len(findings), "adapter": "local",
                  "remote_error": remote_error, "degraded": True, "partial_evidence": True,
                  "limitations": ["仅完成本地格式初筛，最多检查 200 个文件；远程逆向分析未完成。"]},
            summary=f"逆向 API 不可用，已降级为本地样本初筛，识别 {len(findings)} 个 PE/ELF 文件。",
            error_code="REVERSE_SERVICE_UNAVAILABLE",
            error_message="远程逆向分析未完成；本地格式识别不能代替完整分析。",
            evidence=evidence,
            duration_ms=int((time.monotonic()-started)*1000),
        )

    @staticmethod
    async def _invoke_remote(target: Path, files: list[Path], context: ToolContext) -> ToolResult | None:
        from security_agent.secmind_adapter import invoke_secmind
        return await invoke_secmind(files, context, domain="forensics_static_reverse", adapter="reverse_api")


class PenetrationModuleTool(BaseTool):
    manifest = ToolManifest(
        name="penetration_module", version="1", description="Submit an authorized penetration workflow to 独立渗透服务.",
        scenarios=[Scenario.PENETRATION_TEST], input_schema={"type":"object","properties":{"target":{"type":"string"}},"required":["target"]},
        output_schema={"type":"object"}, risk_level=RiskLevel.R2, permissions=["network:authorized-target"], timeout_seconds=120,
        requires_network=True, idempotent=False,
    )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        base_url = context.module_base_url or "http://127.0.0.1:8000"
        board = context.external_execution.get("blackboard")
        project_id = board.get("project_id") if isinstance(board, dict) else None
        if (not isinstance(project_id, str) or not project_id
                or board.get("backend") != "remote"
                or board.get("status") != "entered"):
            return ToolResult(status=ToolStatus.ERROR, error_code="PENETRATION_BLACKBOARD_REQUIRED",
                              error_message="渗透任务没有可核对的预备黑板项目")
        title = project_title_for_run(context.run_id)
        activation_token = board.get("activation_token")
        if not isinstance(activation_token, str) or len(activation_token) < 32:
            return ToolResult(status=ToolStatus.ERROR, error_code="PENETRATION_ACTIVATION_CREDENTIAL_MISSING",
                              error_message="渗透预备项目缺少激活凭据")

        def request(method: str, path: str, payload: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
            data = json.dumps(payload, ensure_ascii=False).encode() if payload is not None else None
            req = urllib.request.Request(
                base_url.rstrip("/") + path, data=data,
                headers={"Content-Type": "application/json"}, method=method,
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.status, json.loads(response.read().decode(errors="replace"))

        def valid(project: Any, enabled: bool) -> bool:
            return (isinstance(project, dict) and project.get("id") == project_id
                    and project.get("title") == title and project.get("status") == "active"
                    and project.get("dispatcher_enabled") is enabled)

        try:
            if context.progress_callback:
                await context.progress_callback({'module': 'penetration', 'status': 'submitting'})
            _, detail = await asyncio.to_thread(request, "GET", f"/projects/{project_id}")
            project = detail.get("project") if isinstance(detail, dict) else None
            if not (valid(project, False) or valid(project, True)):
                raise ValueError("预备黑板项目身份或状态不匹配")
            try:
                status, receipt = await asyncio.to_thread(
                    request, "POST", f"/projects/{project_id}/dispatcher/activate",
                    {"title": title, "activation_token": activation_token},
                )
                project = receipt
            except (OSError, urllib.error.URLError, ValueError):
                # Activation may have committed even when its response was lost.
                status, detail = await asyncio.to_thread(request, "GET", f"/projects/{project_id}")
                project = detail.get("project") if isinstance(detail, dict) else None
            if not valid(project, True):
                raise ValueError("渗透服务未确认 Dispatcher 已接管预备黑板项目")
            if context.progress_callback:
                await context.progress_callback({'module': 'penetration', 'status': 'submitted', 'project_id': project_id})
            return ToolResult(
                status=ToolStatus.SUCCESS,
                data={
                    "adapter": "penetration_engine",
                    "http_status": status,
                    "project_id": project_id,
                    "project": project,
                },
                summary="独立渗透服务 已接受授权渗透工作流。",
            )
        except Exception as exc:
            return ToolResult(status=ToolStatus.ERROR, data={"adapter":"penetration_engine"}, summary="黑板服务当前不可用，渗透任务未执行。", error_code="PENETRATION_SERVICE_UNAVAILABLE", error_message=str(exc))


class LogAnalysisModuleTool(BaseTool):
    manifest = ToolManifest(name='log_analysis_module', version='1', description='Analyze uploaded logs with the SecMind engine.',
        scenarios=[Scenario.LOG_ANALYSIS], input_schema={'type': 'object', 'properties': {'target': {'type': 'string'}},
        'required': ['target'], 'additionalProperties': False}, output_schema={'type': 'object'},
        risk_level=RiskLevel.R1, permissions=['workspace:read'], timeout_seconds=600, idempotent=False)

    async def invoke(self, args, context):
        try:
            target = BanditTool._resolve_target(str(args.get('target', '.')), context)
            files = [target] if target.is_file() else [p for p in target.rglob('*') if p.is_file()]
            from security_agent.secmind_adapter import invoke_secmind
            return await invoke_secmind(files, context, domain='logs_ir_hunting', adapter='log_analysis_api')
        except ToolError as exc:
            return ToolResult(status=ToolStatus.DENIED, error_code='TOOL_SCOPE_VIOLATION', error_message=str(exc))
        except (httpx.HTTPError, OSError, ValueError) as exc:
            if context.external_execution.get('remote_run_id') or context.external_execution.get('status') == 'submitting':
                return ToolResult(status=ToolStatus.ERROR, error_code='SECMIND_REMOTE_UNCERTAIN',
                    error_message=f'远程日志任务状态待核对：{type(exc).__name__}',
                    data={'adapter': 'log_analysis_api', **context.external_execution})
            return ToolResult(status=ToolStatus.ERROR, error_code='LOG_ANALYSIS_UNAVAILABLE',
                error_message=f'日志分析引擎未完成：{type(exc).__name__}', data=dict(context.external_execution))


def default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(BanditTool())
    registry.register(WorkspaceSecurityAuditTool())
    registry.register(ReverseModuleTool())
    registry.register(PenetrationModuleTool())
    registry.register(LogAnalysisModuleTool())
    return registry
