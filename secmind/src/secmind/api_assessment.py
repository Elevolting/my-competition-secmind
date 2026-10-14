from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid5

from secmind.ledger import canonical_json
from secmind.schemas import (
    Evidence,
    Finding,
    ParsedAsset,
    PolicyAction,
    PolicyDecision,
    RiskLevel,
    RunStatus,
    Scenario,
    TaskSpec,
)
from secmind.secret_scrubber import scrub_text, scrub_value

_MAX_ASSETS = 100
_MAX_OPERATIONS = 5_000
_MAX_PARAMETERS = 128
_PATH_PARAMETER = re.compile(r"\{([^{}]{1,128})\}")
_HTTP_METHODS = frozenset({"GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"})
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})
_MODIFYING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class ApiStaticAssessmentError(ValueError):
    """The supplied parser projection cannot be assessed within the static boundary."""


@dataclass(frozen=True)
class ApiEndpoint:
    endpoint_id: str
    asset_id: str
    method: str
    path: str
    parameter_names: tuple[str, ...]
    auth_schemes: tuple[str, ...]
    source_content_trust: Literal["untrusted_data"] = "untrusted_data"


@dataclass(frozen=True)
class ApiAssetGraph:
    asset_ids: tuple[str, ...]
    endpoints: tuple[ApiEndpoint, ...]
    method_counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class ApiStaticAssessmentResult:
    run_id: str
    task_spec_digest: str
    status: RunStatus
    asset_graph: ApiAssetGraph
    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]
    coverage_gaps: tuple[str, ...]
    dynamic_probe_policy: PolicyDecision
    network_requests_performed: int = 0
    dynamic_probes_enabled: bool = False
    mode: Literal["static_only"] = "static_only"


def assess_api_assets(task_spec: TaskSpec, assets: Sequence[ParsedAsset]) -> ApiStaticAssessmentResult:
    """Assess parser-produced API metadata without resolving or visiting document URLs."""

    if task_spec.primary_scenario != Scenario.API_ASSESSMENT:
        raise ApiStaticAssessmentError("TaskSpec is not an API-assessment task")
    if len(assets) > _MAX_ASSETS:
        raise ApiStaticAssessmentError(f"API assessment exceeds the {_MAX_ASSETS}-asset limit")

    allowed_asset_ids = set(task_spec.asset_ids)
    bound_assets = sorted(
        (
            asset
            for asset in assets
            if asset.parsed_asset_id in allowed_asset_ids
            and asset.asset_type in {"openapi_document", "postman_collection"}
        ),
        key=lambda item: item.parsed_asset_id,
    )
    if not bound_assets:
        raise ApiStaticAssessmentError("no OpenAPI/Postman ParsedAsset is bound to this TaskSpec")

    endpoints: list[ApiEndpoint] = []
    findings: list[Finding] = []
    evidence: list[Evidence] = []
    gaps: list[str] = []
    method_counts: dict[str, int] = {}
    for asset in bound_assets:
        evidence_item = _asset_evidence(asset)
        evidence.append(evidence_item)
        metadata = scrub_value(asset.metadata)
        safe_metadata = metadata if isinstance(metadata, Mapping) else {}
        if asset.asset_type == "openapi_document":
            operations = safe_metadata.get("operations")
            if not isinstance(operations, list):
                gaps.append(f"asset {asset.parsed_asset_id} has no bounded OpenAPI operation projection")
                continue
            for operation in operations:
                if len(endpoints) >= _MAX_OPERATIONS:
                    raise ApiStaticAssessmentError(f"API assessment exceeds the {_MAX_OPERATIONS}-operation limit")
                endpoint = _endpoint_from_operation(asset, operation)
                if endpoint is None:
                    gaps.append(f"asset {asset.parsed_asset_id} contains an invalid operation projection")
                    continue
                endpoints.append(endpoint)
                method_counts[endpoint.method] = method_counts.get(endpoint.method, 0) + 1
                findings.extend(_static_findings(endpoint, operation, evidence_item.evidence_id))
                if not _has_explicit_auth_metadata(operation):
                    gaps.append(f"endpoint {endpoint.endpoint_id} has no parser-projected authentication metadata")
            if _bounded_nonnegative_int(safe_metadata.get("server_declaration_count"), upper=100_000) > 0:
                gaps.append(
                    f"asset {asset.parsed_asset_id} server declarations were retained only as untrusted data "
                    "and not accessed"
                )
        else:
            request_count = _bounded_nonnegative_int(safe_metadata.get("request_count"), upper=_MAX_OPERATIONS)
            methods = safe_metadata.get("methods")
            if isinstance(methods, list):
                for raw_method in methods[:64]:
                    method = _safe_method(raw_method)
                    if method:
                        method_counts[method] = method_counts.get(method, 0) + 1
            gaps.append(
                f"asset {asset.parsed_asset_id} exposes {request_count} Postman request(s) without retained "
                "target URLs; no request was sent"
            )
            if _bounded_nonnegative_int(safe_metadata.get("script_block_count"), upper=100_000):
                gaps.append(
                    f"asset {asset.parsed_asset_id} contains script/event blocks treated only as untrusted data"
                )

    sorted_endpoints = tuple(sorted(endpoints, key=lambda item: (item.path, item.method, item.endpoint_id)))
    sorted_findings = tuple(sorted(findings, key=lambda item: (item.path, item.rule_id, item.finding_id)))
    if not sorted_endpoints:
        gaps.append("no endpoint-level projection was available for static authentication or parameter checks")
    status = RunStatus.COMPLETED if sorted_endpoints and not gaps else RunStatus.PARTIAL
    return ApiStaticAssessmentResult(
        run_id=task_spec.run_id,
        task_spec_digest=task_spec.content_digest,
        status=status,
        asset_graph=ApiAssetGraph(
            asset_ids=tuple(item.parsed_asset_id for item in bound_assets),
            endpoints=sorted_endpoints,
            method_counts=tuple(sorted(method_counts.items())),
        ),
        findings=sorted_findings,
        evidence=tuple(sorted(evidence, key=lambda item: item.evidence_id)),
        coverage_gaps=tuple(sorted(set(gaps))),
        dynamic_probe_policy=_dynamic_probe_policy(task_spec),
    )


def _endpoint_from_operation(asset: ParsedAsset, operation: Any) -> ApiEndpoint | None:
    if not isinstance(operation, Mapping):
        return None
    method = _safe_method(operation.get("method"))
    raw_path = operation.get("path")
    if not method or not isinstance(raw_path, str):
        return None
    path = scrub_text(raw_path)[:2_048]
    parameters = _parameter_names(operation.get("parameters"))
    auth_schemes = _auth_schemes(operation.get("security"))
    material = {
        "asset_id": asset.parsed_asset_id,
        "method": method,
        "path": path,
        "parameters": parameters,
        "auth_schemes": auth_schemes,
    }
    return ApiEndpoint(
        endpoint_id=_stable_id("api-endpoint", material),
        asset_id=asset.parsed_asset_id,
        method=method,
        path=path,
        parameter_names=parameters,
        auth_schemes=auth_schemes,
    )


def _static_findings(endpoint: ApiEndpoint, operation: Any, evidence_id: str) -> list[Finding]:
    if not isinstance(operation, Mapping):
        return []
    findings: list[Finding] = []
    if endpoint.method == "TRACE":
        findings.append(
            _finding(
                endpoint,
                evidence_id,
                rule_id="API-METHOD-TRACE",
                severity="MEDIUM",
                title="TRACE method is exposed",
                description=(
                    "The static API description declares TRACE, which can unnecessarily expand diagnostic exposure."
                ),
                remediation="Disable TRACE unless a documented, authenticated operational requirement exists.",
            )
        )
    if _auth_is_explicitly_absent(operation):
        findings.append(
            _finding(
                endpoint,
                evidence_id,
                rule_id="API-AUTH-EXPLICITLY-ABSENT",
                severity="HIGH" if endpoint.method in _MODIFYING_METHODS else "MEDIUM",
                title="Operation explicitly declares no authentication",
                description="The parser projection explicitly marks this operation as unauthenticated.",
                remediation=(
                    "Require an appropriate authentication and authorization scheme or document why public access "
                    "is safe."
                ),
            )
        )
    declared_parameters = set(endpoint.parameter_names)
    missing_path_parameters = sorted(set(_PATH_PARAMETER.findall(endpoint.path)) - declared_parameters)
    if missing_path_parameters:
        findings.append(
            _finding(
                endpoint,
                evidence_id,
                rule_id="API-PATH-PARAMETER-UNDECLARED",
                severity="MEDIUM",
                title="Path parameter lacks a declared input contract",
                description=(
                    "The path contains parameter placeholders without matching parser-projected parameter "
                    "declarations: " + ", ".join(missing_path_parameters)
                ),
                remediation="Declare each path parameter with type, format, constraints and required status.",
            )
        )
    if endpoint.method in _BODY_METHODS and operation.get("request_schema_present") is False:
        findings.append(
            _finding(
                endpoint,
                evidence_id,
                rule_id="API-REQUEST-SCHEMA-MISSING",
                severity="MEDIUM",
                title="Request body lacks an input schema",
                description=(
                    "The static projection explicitly reports no request-body schema for a body-carrying method."
                ),
                remediation="Define a bounded request schema and reject unknown or invalid fields server-side.",
            )
        )
    return findings


def _finding(
    endpoint: ApiEndpoint,
    evidence_id: str,
    *,
    rule_id: str,
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"],
    title: str,
    description: str,
    remediation: str,
) -> Finding:
    return Finding(
        finding_id=_stable_id(
            "api-finding",
            {"endpoint_id": endpoint.endpoint_id, "rule_id": rule_id, "evidence_id": evidence_id},
        ),
        rule_id=rule_id,
        severity=severity,
        confidence="HIGH",
        path=endpoint.path,
        title=title,
        description=description,
        remediation=remediation,
        evidence_ids=[evidence_id],
        raw={"source_content_trust": "untrusted_data", "network_access_performed": False},
    )


def _asset_evidence(asset: ParsedAsset) -> Evidence:
    return Evidence(
        evidence_id=_stable_id(
            "api-asset-evidence",
            {
                "parsed_asset_id": asset.parsed_asset_id,
                "content_digest": asset.content_digest,
                "parser_id": asset.parser_id,
                "parser_version": asset.parser_version,
            },
        ),
        source=f"parser:{scrub_text(asset.parser_id)[:100]}@{scrub_text(asset.parser_version)[:100]}",
        summary=(
            "Static API document projection produced by an allowlisted parser; document content remains untrusted data."
        ),
        artifact_ref=asset.artifact_id,
        sha256=asset.content_digest,
        metadata={
            "parsed_asset_id": asset.parsed_asset_id,
            "asset_type": asset.asset_type,
            "network_access_performed": False,
        },
    )


def _dynamic_probe_policy(task_spec: TaskSpec) -> PolicyDecision:
    material = {
        "run_id": task_spec.run_id,
        "task_spec_digest": task_spec.content_digest,
        "network": "disabled",
        "risk": int(RiskLevel.R2),
    }
    digest = hashlib.sha256(canonical_json(material).encode()).hexdigest()
    return PolicyDecision(
        decision_id=_stable_id("api-dynamic-probe-policy", material),
        action=PolicyAction.REQUIRE_APPROVAL,
        effective_risk=RiskLevel.R2,
        policy_ids=["API-STATIC-ONLY-1.4", "POL-R2-NETWORK"],
        reason_summary=(
            "Dynamic API requests are not implemented in this static assessment. Any future local-target probe must "
            "pass explicit scope, allowlist, Broker/PDP, R2 approval, ticket and fence checks."
        ),
        decision_input_hash=digest,
    )


def _parameter_names(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    names: set[str] = set()
    for item in value[:_MAX_PARAMETERS]:
        if isinstance(item, str):
            name = scrub_text(item).strip()[:128]
        elif isinstance(item, Mapping) and isinstance(item.get("name"), str):
            name = scrub_text(str(item["name"])).strip()[:128]
        else:
            continue
        if name:
            names.add(name)
    return tuple(sorted(names))


def _auth_schemes(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    schemes: set[str] = set()
    for item in value[:64]:
        if isinstance(item, str):
            schemes.add(scrub_text(item).strip()[:128])
        elif isinstance(item, Mapping):
            schemes.update(scrub_text(str(key)).strip()[:128] for key in item if str(key).strip())
    return tuple(sorted(item for item in schemes if item))


def _has_explicit_auth_metadata(operation: Any) -> bool:
    return isinstance(operation, Mapping) and ("security" in operation or "auth_required" in operation)


def _auth_is_explicitly_absent(operation: Mapping[Any, Any]) -> bool:
    security = operation.get("security")
    return operation.get("auth_required") is False or (isinstance(security, list) and not security)


def _safe_method(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    method = re.sub(r"[^A-Za-z]", "", value).upper()[:16]
    return method if method in _HTTP_METHODS else ""


def _bounded_nonnegative_int(value: Any, *, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return min(value, upper)


def _stable_id(namespace: str, value: object) -> str:
    return str(uuid5(NAMESPACE_URL, f"secmind:{namespace}:{canonical_json(value)}"))


__all__ = [
    "ApiAssetGraph",
    "ApiEndpoint",
    "ApiStaticAssessmentError",
    "ApiStaticAssessmentResult",
    "assess_api_assets",
]
