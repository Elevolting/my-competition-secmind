"""Default built-in and external tool registry construction."""

from __future__ import annotations

from secmind.tooling.builtin_inventory import ProjectInventoryTool
from secmind.tooling.builtin_java import JavaSemanticSastTool
from secmind.tooling.builtin_python import BanditTool, PythonDataflowTool
from secmind.tooling.builtin_reverse_dynamic import SpeakeasyDynamicAnalysisTool
from secmind.tooling.builtin_reverse_pe import ReversePeAnalysisTool
from secmind.tooling.builtin_secret import SecretPatternTool
from secmind.tooling.builtin_web import WebWorkflowAuditTool
from secmind.tooling.core import BaseTool
from secmind.tooling.external_manifests import external_audit_manifests
from secmind.tooling.external_sandbox import UnavailableTool
from secmind.tooling.registry import ToolRegistry


def default_registry(
    bandit_tool: BaseTool | None = None,
    external_tools: list[BaseTool] | None = None,
) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(ProjectInventoryTool())
    registry.register(bandit_tool or BanditTool())
    registry.register(PythonDataflowTool())
    registry.register(JavaSemanticSastTool())
    registry.register(WebWorkflowAuditTool())
    registry.register(ReversePeAnalysisTool())
    registry.register(SpeakeasyDynamicAnalysisTool())
    registry.register(SecretPatternTool())
    configured = {tool.manifest.name: tool for tool in external_tools or []}
    for manifest in external_audit_manifests():
        registry.register(configured.get(manifest.name, UnavailableTool(manifest)))
    return registry


__all__ = ["default_registry"]
