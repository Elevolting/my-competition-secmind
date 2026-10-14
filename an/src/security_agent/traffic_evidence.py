"""Immutable, redacted HTTP exchanges attached to one platform run."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import NAMESPACE_URL, uuid4, uuid5

from sqlalchemy.orm import Session

from security_agent.ingest import InputIngestor, sha256_file
from security_agent.ledger import EventRow, canonical_json
from security_agent.report_sections import report_sections
from security_agent.schemas import Evidence
from security_agent.trace_redaction import redact_trace

MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_BODY_BYTES = 8 * 1024 * 1024
ROLES = frozenset({"baseline", "proof", "verification", "supporting"})


class EvidenceCorrupt(ValueError):
    pass


def _headers(value):
    if isinstance(value, dict):
        return [{"name": str(key), "value": str(item)} for key, item in value.items()]
    return [{"name": str(item.get("name", "")), "value": str(item.get("value", ""))}
            for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _body(value):
    if value is None:
        return None, False
    text = value if isinstance(value, str) else canonical_json(value)
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) > MAX_BODY_BYTES:
        return encoded[:MAX_BODY_BYTES].decode("utf-8", errors="ignore"), True
    return text, False


def _http_message(value):
    if not isinstance(value, str):
        return {}
    head, body = value, None
    separator = re.search(r"\r?\n\r?\n", value)
    if separator:
        head, body = value[:separator.start()], value[separator.end():]
    lines = head.splitlines()
    headers = [{"name": name.strip(), "value": item.strip()}
               for line in lines[1:] if ":" in line for name, item in [line.split(":", 1)]]
    return {"start_line": lines[0] if lines else "", "headers": headers, "body": body, "raw": value}


def _har_entry(entry):
    request, response = entry.get("request"), entry.get("response")
    if not isinstance(request, dict) or not isinstance(response, dict):
        raise ValueError("HAR 条目缺少请求或响应")
    content = response.get("content") or {}
    post = request.get("postData") or {}
    if not isinstance(content, dict) or not isinstance(post, dict):
        raise ValueError("HAR 请求或响应正文格式无效")
    def body(part):
        value, encoding = part.get("text"), part.get("encoding")
        omitted = value is None
        if encoding == "base64" and value is not None:
            try:
                decoded = base64.b64decode(value, validate=True)
            except (ValueError, TypeError, binascii.Error) as exc:
                raise ValueError("HAR 正文 base64 编码无效") from exc
            try:
                value, encoding = decoded.decode("utf-8"), "utf-8"
            except UnicodeError:
                value, encoding, omitted = None, "binary-omitted", True
        elif encoding not in {None, "utf-8", "text"}:
            raise ValueError("HAR 正文编码不受支持")
        return value, encoding, omitted

    request_body, request_encoding, request_missing = body(post)
    response_body, response_encoding, response_missing = body(content)
    return {
        "captured_at": entry.get("startedDateTime"), "method": request.get("method"),
        "url": request.get("url"), "status_code": response.get("status"),
        "request": {"headers": _headers(request.get("headers")), "body": request_body,
                    "body_encoding": request_encoding, "http_version": request.get("httpVersion")},
        "response": {"headers": _headers(response.get("headers")), "body": response_body,
                     "body_encoding": response_encoding, "http_version": response.get("httpVersion")},
        "missing": {"request_body": request_missing, "response_body": response_missing},
        "source_truncated": bool(entry.get("_truncated")),
    }


def _url_from_request(arguments, parsed):
    for value in (arguments.get("url"), arguments.get("targetUrl")):
        if isinstance(value, str) and urlsplit(value).scheme in {"http", "https"}:
            return value
    start = parsed.get("start_line", "").split()
    target = start[1] if len(start) > 1 else ""
    if urlsplit(target).scheme in {"http", "https"}:
        return target
    host = arguments.get("targetHostname") or next(
        (header["value"].strip() for header in parsed.get("headers", [])
         if header["name"].strip().lower() == "host"), None)
    if not isinstance(host, str) or not host or not target.startswith("/"):
        return None
    scheme = "https" if arguments.get("useHttps", True) else "http"
    port = arguments.get("targetPort")
    authority = host if not port or ":" in host else f"{host}:{port}"
    parts = urlsplit(target)
    return urlunsplit((scheme, authority, parts.path, parts.query, ""))


def _exchange(candidate, arguments, index):
    for _ in range(8):
        if isinstance(candidate, str):
            try:
                candidate = json.loads(candidate)
            except ValueError:
                candidate = {"response": candidate}
                break
        if not isinstance(candidate, dict):
            break
        if "structuredContent" in candidate:
            candidate = candidate["structuredContent"]
        elif isinstance(candidate.get("log"), dict):
            candidate = candidate["log"].get("entries")
        elif isinstance(candidate.get("entries"), list):
            candidate = candidate["entries"]
        elif isinstance(candidate.get("content"), list):
            texts = [item.get("text") for item in candidate["content"]
                     if isinstance(item, dict) and item.get("type") == "text"]
            if not texts:
                break
            candidate = texts[index] if index < len(texts) else texts[0]
        elif "result" in candidate and "request" not in candidate and "response" not in candidate:
            candidate = candidate["result"]
        elif isinstance(candidate.get("data"), dict) and "request" not in candidate and "response" not in candidate:
            candidate = candidate["data"]
        else:
            break
    if isinstance(candidate, list):
        if index >= len(candidate):
            raise ValueError("流量条目索引超出范围")
        candidate = candidate[index]
    if not isinstance(candidate, dict):
        raise ValueError("来源没有可识别的 HTTP 请求与响应")
    if isinstance(candidate.get("request"), dict) and "method" in candidate["request"] and \
            isinstance(candidate.get("response"), dict) and (
                "content" in candidate["response"] or "startedDateTime" in candidate or
                "httpVersion" in candidate["request"]):
        if "content" in candidate["response"] and not isinstance(candidate["response"]["content"], dict):
            raise ValueError("HAR 请求或响应正文格式无效")
        return _har_entry(candidate)
    request = candidate.get("request") or arguments.get("content") or arguments
    response = candidate.get("response") or candidate
    req = _http_message(request) if isinstance(request, str) else dict(request) if isinstance(request, dict) else {}
    resp = (_http_message(response) if isinstance(response, str) else
            dict(response) if isinstance(response, dict) else {})
    start = str(req.get("start_line") or "").split()
    status_line = str(resp.get("start_line") or "").split()
    method = req.get("method") or candidate.get("method") or arguments.get("method") or (start[0] if start else None)
    url = req.get("url") or candidate.get("url") or _url_from_request(arguments, req)
    status = resp.get("status") or resp.get("status_code") or candidate.get("status_code")
    if status is None and len(status_line) > 1 and status_line[0].startswith("HTTP/"):
        status = status_line[1]
    return {"captured_at": candidate.get("captured_at") or candidate.get("timestamp"),
            "method": method, "url": url, "status_code": status,
            "request": {"headers": _headers(req.get("headers")), "body": req.get("body"),
                        "raw": req.get("raw")},
            "response": {"headers": _headers(resp.get("headers")), "body": resp.get("body"),
                         "raw": resp.get("raw")},
            "missing": {"request_body": "body" not in req, "response_body": "body" not in resp},
            "source_truncated": bool(candidate.get("truncated") or candidate.get("output_truncated"))}


class TrafficEvidenceStore:
    def __init__(self, ledger, settings, operations):
        self.ledger, self.settings, self.operations = ledger, settings, operations
        self.ingestor = InputIngestor(settings)

    def _folder(self, run_id):
        workspace = self.ingestor._workspace_for_run(run_id)
        folder = workspace.parent / "traffic-evidence"
        if folder.exists() and (folder.is_symlink() or
                                not folder.resolve().is_relative_to(self.settings.run_root.resolve())):
            raise EvidenceCorrupt("证据目录无效")
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    def _source(self, run_id, kind, reference, index):
        if kind == "har":
            if Path(reference).name != reference or not reference.lower().endswith(".har"):
                raise ValueError("HAR 上传引用无效")
            path = self.settings.upload_root / reference
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
                raise ValueError("HAR 文件不存在或超过大小限制")
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            return _exchange(data, {}, index), reference
        if kind == "mcp":
            receipt = self.operations.get("call:" + reference)
            if not isinstance(receipt, dict) or receipt.get("run_id") != run_id:
                raise KeyError(reference)
            if receipt.get("status") not in {None, "completed"}:
                raise ValueError("MCP 调用未成功完成，无法固化流量证据")
            if receipt.get("result") is None:
                raise ValueError("MCP 回执没有 HTTP 交换内容，请选择其他回执或导入 HAR")
            exchange = _exchange(receipt.get("result"), receipt.get("arguments") or {}, index)
            exchange["captured_at"] = exchange.get("captured_at") or receipt.get("completed_at")
            return exchange, reference
        if kind == "ledger":
            with Session(self.ledger.engine) as session:
                event = session.get(EventRow, reference)
                if event is None or event.run_id != run_id or not event.event_type.startswith(("tool.", "mcp.call.")):
                    raise KeyError(reference)
                payload = json.loads(event.payload_json)
            candidate = payload.get("result") or payload.get("data")
            if candidate is None:
                raise ValueError("账本事件没有 HTTP 交换内容，请选择含结果的回执或导入 HAR")
            exchange = _exchange(candidate, payload.get("arguments") or {}, index)
            exchange["captured_at"] = exchange.get("captured_at") or event.timestamp.isoformat()
            return exchange, reference
        raise ValueError("不支持的流量来源")

    def create(self, run_id, kind, reference, index=0):
        if self.ledger.load_state(run_id) is None:
            raise KeyError(run_id)
        if not isinstance(reference, str) or not reference or not 0 <= index <= 10_000:
            raise ValueError("来源引用或条目索引无效")
        exchange, source_id = self._source(run_id, kind, reference, index)
        method, url = exchange.get("method"), exchange.get("url")
        if (not isinstance(method, str) or not method or not isinstance(url, str) or
                urlsplit(url).scheme not in {"http", "https"}):
            raise ValueError("来源缺少有效 HTTP 方法或 URL")
        try:
            status = int(exchange.get("status_code"))
        except (TypeError, ValueError) as exc:
            raise ValueError("来源缺少有效 HTTP 状态码") from exc
        if not 100 <= status <= 599:
            raise ValueError("HTTP 状态码无效")
        request = exchange["request"]
        response = exchange["response"]
        request["body"], req_truncated = _body(request.get("body"))
        response["body"], resp_truncated = _body(response.get("body"))
        if request.get("raw") is not None:
            request["raw"], raw_req_truncated = _body(request["raw"])
            req_truncated |= raw_req_truncated
        if response.get("raw") is not None:
            response["raw"], raw_resp_truncated = _body(response["raw"])
            resp_truncated |= raw_resp_truncated
        snapshot = redact_trace({
            "source": {"kind": kind, "reference": source_id, "entry_index": index},
            "captured_at": exchange.get("captured_at"),
            "method": method.upper(), "url": url, "status_code": status,
            "request": request, "response": response,
            "missing": exchange.get("missing") or {},
            "truncated": bool(exchange.get("source_truncated") or req_truncated or resp_truncated),
        })
        snapshot["request_sha256"] = hashlib.sha256(canonical_json(snapshot["request"]).encode()).hexdigest()
        snapshot["response_sha256"] = hashlib.sha256(canonical_json(snapshot["response"]).encode()).hexdigest()
        raw = (canonical_json(snapshot) + "\n").encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        evidence_id = str(uuid5(NAMESPACE_URL, f"traffic:{run_id}:{kind}:{source_id}:{index}:{digest}"))
        folder = self._folder(run_id)
        target = folder / (evidence_id + ".json")
        if target.exists():
            if target.is_symlink() or sha256_file(target) != digest:
                raise EvidenceCorrupt("已保存的流量证据校验失败")
        else:
            temporary = folder / ("." + evidence_id + "." + uuid4().hex + ".tmp")
            try:
                with temporary.open("xb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, target)
            finally:
                temporary.unlink(missing_ok=True)
            if sha256_file(target) != digest:
                raise EvidenceCorrupt("流量证据写入后校验失败")
        evidence = Evidence(evidence_id=evidence_id, source="traffic:" + kind,
            summary=f"{snapshot['method']} {snapshot['url']} -> {status}",
            artifact_ref=str(target), sha256=digest,
            metadata={"kind": "traffic", "source_kind": kind, "source_id": source_id,
                      "captured_at": snapshot["captured_at"], "method": snapshot["method"],
                      "url": snapshot["url"], "status_code": status, "truncated": snapshot["truncated"],
                      "missing": snapshot["missing"]})

        def add(state):
            existing = next((item for item in state.evidence if item.evidence_id == evidence_id), None)
            if existing and existing.sha256 != digest:
                raise EvidenceCorrupt("证据编号对应的内容已变化")
            if not existing:
                state.evidence.append(evidence)
                if state.report:
                    state.report.evidence.append(evidence)

        self.ledger.update_state(run_id, add)
        self.ledger.append(run_id, "traffic.evidence.created", {"evidence_id": evidence_id,
            "source_kind": kind, "source_id": source_id, "sha256": digest},
            actor="operator", event_id=evidence_id)
        return {"evidence_id": evidence_id, "sha256": digest, "snapshot": snapshot}

    def get(self, run_id, evidence_id):
        state = self.ledger.load_state(run_id)
        if state is None:
            raise KeyError(run_id)
        evidence = next((item for item in state.evidence if item.evidence_id == evidence_id and
                         item.metadata.get("kind") == "traffic"), None)
        if evidence is None:
            raise KeyError(evidence_id)
        target = self._folder(run_id) / (evidence_id + ".json")
        if (target.is_symlink() or not target.is_file() or not evidence.sha256 or
                sha256_file(target) != evidence.sha256):
            raise EvidenceCorrupt("流量证据文件缺失或校验失败")
        return {"evidence_id": evidence_id, "sha256": evidence.sha256,
                "snapshot": json.loads(target.read_text(encoding="utf-8")),
                "bindings": [{"finding_id": finding.finding_id, **binding}
                             for finding in state.findings for binding in finding.raw.get("traffic_bindings", [])
                             if binding.get("evidence_id") == evidence_id]}

    def bind(self, run_id, finding_id, evidence_id, role, note=""):
        if role not in ROLES or not isinstance(note, str) or len(note) > 1000:
            raise ValueError("流量证据用途或备注无效")
        self.get(run_id, evidence_id)
        safe_note = redact_trace(note.strip())
        binding = {"evidence_id": evidence_id, "role": role, "note": safe_note}
        selected = {}

        def update(state):
            finding = next((item for item in state.findings if item.finding_id == finding_id), None)
            if finding is None:
                raise KeyError(finding_id)
            bindings = finding.raw.setdefault("traffic_bindings", [])
            existing = next((item for item in bindings
                             if item.get("evidence_id") == evidence_id and item.get("role") == role), None)
            if existing is None:
                bindings.append(binding)
            selected.update(existing or binding)
            if evidence_id not in finding.evidence_ids:
                finding.evidence_ids.append(evidence_id)
            if state.report:
                state.report = state.report.model_copy(update={"findings": state.findings,
                    "evidence": state.evidence, **report_sections(state)})

        self.ledger.update_state(run_id, update)
        event_id = str(uuid5(NAMESPACE_URL, f"traffic-binding:{run_id}:{finding_id}:{evidence_id}:{role}"))
        self.ledger.append(run_id, "traffic.evidence.bound", {"finding_id": finding_id,
            "evidence_id": evidence_id, "role": role, "note": selected["note"]}, actor="operator", event_id=event_id)
        return {"finding_id": finding_id, **selected}
