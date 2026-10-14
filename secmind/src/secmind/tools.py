"""Stable public facade for SecMind's governed tool layer.

Implementation lives in :mod:`secmind.tooling` modules.  Keep this module
intentionally boring: existing imports continue to resolve here while the
registry, broker phases, and scanner adapters remain independently testable.
"""

from __future__ import annotations

# Legacy transitive imports remain available for callers that imported the
# original monolith's contracts through `secmind.tools`.
from secmind.artifact_store import ArtifactStoreError, ContentAddressedArtifactStore  # noqa: F401
from secmind.coordinator import CoordinatorStore  # noqa: F401
from secmind.execution import ExecutionConflict, ExecutionStore, parameters_hash  # noqa: F401
from secmind.guardrail import Guardrail, GuardrailAction, GuardrailDecision  # noqa: F401
from secmind.hook_bus import HookBus, HookExecutionError  # noqa: F401
from secmind.investigation.contracts import (  # noqa: F401
    ArtifactDataClass,
    ArtifactSecurityLabel,
    ArtifactView,
    DispatchPermit,
    ExecutionIdentity,
    seal_contract,
)
from secmind.investigation.store import InvestigationStore  # noqa: F401

# These language/rule constants were historically imported through this module
# and are retained as part of the compatibility surface.
from secmind.java_semantic_sast import (
    RULE_BUNDLE_DIGEST as JAVA_SEMANTIC_RULE_BUNDLE_DIGEST,
)
from secmind.java_semantic_sast import (
    TOOL_NAME as JAVA_SEMANTIC_TOOL_NAME,
)
from secmind.java_semantic_sast import (
    TOOL_VERSION as JAVA_SEMANTIC_TOOL_VERSION,
)
from secmind.java_semantic_sast import JavaSource, analyze_java_sources  # noqa: F401
from secmind.language_registry import LANGUAGE_REGISTRY_VERSION, LANGUAGE_SUFFIXES
from secmind.ledger import LedgerStore, canonical_json, redact  # noqa: F401
from secmind.metrics import TOOL_CALLS  # noqa: F401
from secmind.policy import PolicyDecisionPoint, manifest_digest  # noqa: F401
from secmind.python_dataflow import analyze_python_source  # noqa: F401
from secmind.sandbox import (  # noqa: F401
    SandboxInputFile,
    SandboxInvocation,
    SandboxResult,
    SandboxToolSpec,
    collect_sandbox_input_files,
    validate_relative_path,
)
from secmind.schemas import (  # noqa: F401
    ApprovalRequest,
    ApprovalResponse,
    ArtifactRef,
    DataSensitivity,
    DataView,
    Evidence,
    Finding,
    HookDecision,
    HookEvent,
    InputMutation,
    InvocationStatus,
    LogLayer,
    PolicyAction,
    PolicyInput,
    RiskLevel,
    Scenario,
    ToolContext,
    ToolHealth,
    ToolInputEnvelope,
    ToolManifest,
    ToolResult,
    ToolStatus,
)
from secmind.secret_scrubber import scrub_text, scrub_value  # noqa: F401
from secmind.tool_assurance import build_tool_assurance  # noqa: F401
from secmind.tooling.broker import ToolBroker
from secmind.tooling.builtin_inventory import ProjectInventoryTool
from secmind.tooling.builtin_java import JavaSemanticSastTool
from secmind.tooling.builtin_python import BanditTool, PythonDataflowTool
from secmind.tooling.builtin_reverse_dynamic import SpeakeasyDynamicAnalysisTool
from secmind.tooling.builtin_reverse_pe import ReversePeAnalysisTool
from secmind.tooling.builtin_secret import SecretPatternTool
from secmind.tooling.builtin_web import WebWorkflowAuditTool

# Contract and shared finding helpers.
from secmind.tooling.core import (
    BANDIT_CONTEXT_ONLY_RULES,
    BANDIT_CWE,
    BANDIT_RULE_BUNDLE_DIGEST,
    CWE_IMPACTS,
    CWE_TITLES,
    DEPENDENCY_FILES,
    PYTHON_DATAFLOW_RULE_BUNDLE_DIGEST,
    REMEDIATIONS,
    SECRET_ASSIGNMENT,
    SECRET_PATTERN_RULE_BUNDLE_DIGEST,
    BaseTool,
    ToolError,
    ToolInvocationIdentityError,
    ToolValidationError,
    compute_input_manifest_digest,
    normalize_bandit_findings,
    sanitized_tool_environment,
    workspace_input_manifest,
)
from secmind.tooling.external_manifests import (
    EXTERNAL_TOOL_NAMES,
    SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST,
    SEMGREP_REVIEWED_RULE_LANGUAGES,
    external_audit_manifests,
)
from secmind.tooling.external_sandbox import SandboxJsonTool, UnavailableTool
from secmind.tooling.external_semgrep import DevelopmentSemgrepTool
from secmind.tooling.factory import default_registry
from secmind.tooling.registry import ToolRegistry
from secmind.unit_of_work import ControlPlaneUnitOfWork, UnitOfWorkConflict  # noqa: F401

__all__ = [
    "BANDIT_CONTEXT_ONLY_RULES",
    "BANDIT_CWE",
    "BANDIT_RULE_BUNDLE_DIGEST",
    "BanditTool",
    "BaseTool",
    "CWE_IMPACTS",
    "CWE_TITLES",
    "DEPENDENCY_FILES",
    "DevelopmentSemgrepTool",
    "EXTERNAL_TOOL_NAMES",
    "JavaSemanticSastTool",
    "JAVA_SEMANTIC_RULE_BUNDLE_DIGEST",
    "JAVA_SEMANTIC_TOOL_NAME",
    "JAVA_SEMANTIC_TOOL_VERSION",
    "LANGUAGE_REGISTRY_VERSION",
    "LANGUAGE_SUFFIXES",
    "PYTHON_DATAFLOW_RULE_BUNDLE_DIGEST",
    "ProjectInventoryTool",
    "ReversePeAnalysisTool",
    "SpeakeasyDynamicAnalysisTool",
    "PythonDataflowTool",
    "REMEDIATIONS",
    "SECRET_ASSIGNMENT",
    "SECRET_PATTERN_RULE_BUNDLE_DIGEST",
    "SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST",
    "SEMGREP_REVIEWED_RULE_LANGUAGES",
    "SandboxJsonTool",
    "SecretPatternTool",
    "ToolBroker",
    "ToolError",
    "ToolInvocationIdentityError",
    "ToolRegistry",
    "ToolValidationError",
    "UnavailableTool",
    "WebWorkflowAuditTool",
    "compute_input_manifest_digest",
    "default_registry",
    "external_audit_manifests",
    "normalize_bandit_findings",
    "sanitized_tool_environment",
    "workspace_input_manifest",
]
