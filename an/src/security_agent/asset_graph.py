"""Project explicit run asset references without probing any target."""
from __future__ import annotations

import ipaddress
import math
from collections.abc import Iterable
from urllib.parse import urlsplit, urlunsplit

from security_agent.mcp_scope import target_values, validate_target_scope
from security_agent.schemas import AgentState, ToolResult, ToolStatus


def project_asset_graph(state: AgentState, mcp_receipts: Iterable[dict] = ()) -> dict:
    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}
    sources = {"scope": 0, "tool": 0, "artifact": 0, "invocation": 0}

    def in_scope(value: str) -> bool:
        try:
            validate_target_scope("local-http-fetch", {"url": value}, state.task.target_scope)
        except ValueError:
            return False
        return True

    def provenance(source: str, ref: str | None = None, confidence: float | None = None,
                   observed_at: str | None = None) -> dict:
        return {"source": source, "ref": ref, "confidence": confidence,
                "observed_at": observed_at}

    def node(key: str, kind: str, label: str, status: str, source: str,
             *, ref: str | None = None, confidence: float | None = None,
             observed_at: str | None = None) -> None:
        existing = nodes.get(key)
        if existing:
            if source not in existing["sources"]:
                existing["sources"].append(source)
            if status == "discovered" or (status == "invoked" and existing["status"] == "scoped"):
                existing["status"] = status
            if confidence is not None:
                existing["confidence"] = max(existing["confidence"] or 0.0, confidence)
            record = provenance(source, ref, confidence, observed_at)
            if record not in existing["provenance"]:
                existing["provenance"].append(record)
            return
        nodes[key] = {"id": key, "rawId": label, "type": kind, "label": label,
                      "description": label, "status": status, "sources": [source],
                      "confidence": confidence,
                      "provenance": [provenance(source, ref, confidence, observed_at)]}

    def edge(source: str, target: str, kind: str, origin: str, *, ref: str | None,
             confidence: float | None, observed_at: str | None) -> None:
        key = f"{source}->{target}"
        record = provenance(origin, ref, confidence, observed_at)
        if key in edges:
            if record not in edges[key]["provenance"]:
                edges[key]["provenance"].append(record)
            return
        edges[key] = {"id": key, "source": source, "target": target,
                      "type": kind, "label": {"includes": "包含", "serves": "服务于",
                                              "exposes": "暴露"}.get(kind, "关联"),
                      "provenance": [record]}

    def add_target(value: str, source: str, status: str, *, ref: str | None = None,
                   confidence: float | None = None, observed_at: str | None = None) -> bool:
        value = value.strip()
        if not value or len(value) > 2048:
            return False
        try:
            parts = urlsplit(value if "://" in value else "//" + value)
            port = parts.port
        except ValueError:
            return False
        if parts.scheme not in {"", "http", "https"}:
            return False
        has_host_shape = bool(parts.hostname) and (
            parts.scheme in {"http", "https"}
            or port is not None
            or parts.hostname.casefold() == "localhost"
            or "." in parts.hostname
        )
        if has_host_shape and not parts.username:
            host = parts.hostname.lower()
            try:
                ipaddress.ip_address(host)
            except ValueError:
                kind = "domain"
            else:
                kind = "ip"
            host_id = f"host:{host}"
            scheme = parts.scheme if parts.scheme in {"http", "https"} else "http"
            service = f"{scheme}://{parts.netloc.lower()}"
            service_id = f"service:{service}"
            node(host_id, kind, host, status, source, ref=ref,
                 confidence=confidence, observed_at=observed_at)
            node(service_id, "service", service, status, source, ref=ref,
                 confidence=confidence, observed_at=observed_at)
            edge(host_id, service_id, "serves", source, ref=ref,
                 confidence=confidence, observed_at=observed_at)
            if parts.path not in {"", "/"} or parts.query:
                endpoint = urlunsplit((scheme, parts.netloc.lower(), parts.path or "/", parts.query, ""))
                endpoint_id = f"endpoint:{endpoint}"
                node(endpoint_id, "endpoint", endpoint, status, source, ref=ref,
                     confidence=confidence, observed_at=observed_at)
                edge(service_id, endpoint_id, "exposes", source, ref=ref,
                     confidence=confidence, observed_at=observed_at)
            return True
        try:
            ipaddress.ip_address(value)
        except ValueError:
            # Bare scope markers such as ``uploaded-source`` and
            # ``registered-benchmark:<id>`` identify an input/benchmark, not
            # a network asset.  Only project host-like values into the graph.
            # ``localhost`` remains useful for a local-only verification
            # target; ordinary DNS names must contain a dot.
            host = value.rstrip(".").lower()
            if host != "localhost" and "." not in host:
                return False
            if not all(label and label.replace("-", "").isalnum() for label in host.split(".")):
                return False
            node(f"host:{host}", "domain", host, status, source, ref=ref,
                 confidence=confidence, observed_at=observed_at)
            return True
        node(f"host:{value}", "ip", value, status, source, ref=ref,
             confidence=confidence, observed_at=observed_at)
        return True

    for index, target in enumerate(state.task.target_scope):
        if add_target(target, "scope", "scoped", ref=f"scope:{index + 1}"):
            sources["scope"] += 1

    for artifact in state.input_artifacts:
        key = f"artifact:{artifact.artifact_id}"
        node(key, "artifact", artifact.relative_path, "input", "artifact",
             ref=artifact.artifact_id)
        nodes[key]["sha256"] = artifact.sha256
        sources["artifact"] += 1

    observations = list(state.observations)
    seen_calls = {str(item.data.get("call_id")) for item in observations if item.data.get("call_id")}
    seen_invocations: set[str] = set()
    calls: list[dict] = []
    for receipt in mcp_receipts:
        if receipt.get("run_id") != state.run_id or receipt.get("status") != "completed":
            continue
        call_id = receipt.get("call_id")
        if not isinstance(call_id, str):
            continue
        # Keep a compact, auditable call index alongside the graph.  The UI can
        # now show which blackboard worker/tool actually touched an asset,
        # without exposing full request/response blobs in the graph payload.
        try:
            receipt_targets = (
                target_values(receipt.get("arguments"), str(receipt.get("server_id") or ''))
                if isinstance(receipt.get("arguments"), dict) else []
            )
        except ValueError:
            receipt_targets = []
        blackboard = receipt.get("blackboard") if isinstance(receipt.get("blackboard"), dict) else {}
        calls.append({
            "call_id": call_id,
            "status": receipt.get("status"),
            "server_id": receipt.get("server_id"),
            "tool": receipt.get("tool"),
            "started_at": receipt.get("started_at"),
            "completed_at": receipt.get("completed_at"),
            "worker": blackboard.get("worker"),
            "intent_id": blackboard.get("intent_id"),
            "project_id": blackboard.get("project_id"),
            "target_values": receipt_targets,
        })
        arguments = receipt.get("arguments")
        if isinstance(arguments, dict) and call_id not in seen_invocations:
            try:
                targets = target_values(arguments, str(receipt.get("server_id") or ''))
            except ValueError:
                targets = []
            for target in set(targets):
                if in_scope(target) and add_target(target, "invocation", "invoked",
                                                   ref=call_id, observed_at=receipt.get("completed_at")):
                    sources["invocation"] += 1
            seen_invocations.add(call_id)
        if call_id in seen_calls:
            continue
        result = receipt.get("result")
        if not isinstance(result, dict):
            continue
        structured = result.get("structuredContent")
        if not isinstance(structured, dict) or not isinstance(structured.get("coverage"), dict):
            continue
        seen_calls.add(call_id)
        observations.append(ToolResult(status=ToolStatus.SUCCESS, data={
            "call_id": call_id, "completed_at": receipt.get("completed_at"),
            "coverage": structured["coverage"],
        }))

    for index, result in enumerate(observations):
        coverage = result.data.get("coverage")
        if result.status != ToolStatus.SUCCESS or not isinstance(coverage, dict):
            continue
        observation_ref = str(result.data.get("call_id") or f"observation:{index + 1}")
        observed_at = result.data.get("observed_at") or result.data.get("completed_at")
        if not isinstance(observed_at, str):
            observed_at = None
        raw_confidence = coverage.get("confidence", result.data.get("coverage_confidence"))
        try:
            coverage_confidence = float(raw_confidence)
        except (TypeError, ValueError):
            coverage_confidence = None
        if coverage_confidence is not None and not math.isfinite(coverage_confidence):
            coverage_confidence = None
        if coverage_confidence is not None:
            coverage_confidence = max(0.0, min(1.0, coverage_confidence))
        for key in ("assets", "targets", "hosts", "services", "endpoints"):
            values = coverage.get(key)
            if not isinstance(values, list):
                continue
            for item in values:
                value = item if isinstance(item, str) else (
                    item.get("url") or item.get("target") if isinstance(item, dict) else None
                )
                if isinstance(value, str) and in_scope(value) and add_target(
                    value, "tool", "discovered", ref=observation_ref,
                    confidence=coverage_confidence, observed_at=observed_at,
                ):
                    sources["tool"] += 1
        for key in ("target_url", "url", "host"):
            value = coverage.get(key)
            if isinstance(value, str) and in_scope(value) and add_target(
                value, "tool", "discovered", ref=observation_ref,
                confidence=coverage_confidence, observed_at=observed_at,
            ):
                sources["tool"] += 1

    return {"schema_version": "1.0", "run_id": state.run_id,
            "nodes": list(nodes.values()), "edges": list(edges.values()),
            "calls": calls,
            "sources": sources, "stats": {
                "input_file_count": len(state.input_artifacts),
                "scoped_asset_count": sum(1 for item in nodes.values() if item["status"] == "scoped"),
                "invoked_asset_count": sum(1 for item in nodes.values() if item["status"] == "invoked"),
                "discovered_asset_count": sum(1 for item in nodes.values() if item["status"] == "discovered"),
                "relationship_count": len(edges),
                "coverage_observation_count": sum(
                    1 for item in observations
                    if item.status == ToolStatus.SUCCESS and isinstance(item.data.get("coverage"), dict)
                ),
            }}
