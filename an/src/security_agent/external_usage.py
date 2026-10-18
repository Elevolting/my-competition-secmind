"""Import local suite receipts without loading prompts, credentials or model text.

Source databases are opened read-only. Stable receipt identities make replay on
API restart harmless. Original timestamps, not import time, drive usage charts.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import closing
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

from security_agent.model_usage import normalize_usage

SOURCES = ("platform_agent", "secmind", "security_runtime_worker")


class ExternalUsageCollector:
    def __init__(self, settings, ledger):
        self.ledger = ledger
        data = settings.runtime_model_config_path.resolve().parent
        self.paths = {
            "security_runtime_worker": data / "worker-usage.db",
            "secmind": settings.secmind_usage_database or data.parent.parent / "secmind/data/secmind.db",
        }
        self._lock = threading.Lock()
        self._cursors = dict.fromkeys(self.paths, 0)

    def sync(self) -> dict:
        status = {}
        with self._lock:
            for source, path in self.paths.items():
                if not path.is_file():
                    status[source] = {"status": "awaiting_receipts" if source == "security_runtime_worker" else "unavailable"}
                    continue
                try:
                    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)) as conn:
                        conn.row_factory = sqlite3.Row
                        while True:
                            rows = self._rows(conn, source)
                            for sequence, receipt_id, payload in rows:
                                self._import(source, receipt_id, payload)
                                self._cursors[source] = sequence
                            if len(rows) < 2000:
                                break
                    status[source] = {"status": "synced",
                                      "last_synced_at": datetime.now(UTC).isoformat()}
                except (sqlite3.Error, OSError, ValueError, TypeError, KeyError):
                    status[source] = {"status": "error", "message": "用量同步失败，已保留先前记录"}
        return status

    def _rows(self, conn, source):
        cursor = self._cursors[source]
        if source == "security_runtime_worker":
            return [(row["sequence"], row["receipt_id"], json.loads(row["payload_json"])) for row in conn.execute(
                "SELECT sequence, receipt_id, payload_json FROM usage_events WHERE sequence > ? ORDER BY sequence LIMIT 2000", (cursor,))]
        rows = conn.execute(
            "SELECT rowid AS sequence, run_id, created_at, payload_json FROM outbox_events "
            "WHERE event_type = 'model.attempt_recorded' AND rowid > ? ORDER BY rowid LIMIT 2000", (cursor,)).fetchall()
        result = []
        for row in rows:
            attempt = json.loads(row["payload_json"])
            reported = attempt.get("provider_reported_usage")
            unknown = attempt.get("unknown_usage", True)
            # Older audit events contain budget estimates. Only a provenance-bound
            # raw response receipt can establish actual historical provider usage.
            if reported is None:
                legacy = conn.execute(
                    "SELECT payload_json FROM investigation_objects WHERE object_type = 'model.raw_response_receipt.v1' "
                    "AND run_id = ? AND json_extract(payload_json, '$.provider_request_id') = ? LIMIT 1",
                    (row["run_id"], attempt["provider_request_id"])).fetchone()
                if legacy:
                    receipt = json.loads(legacy[0])
                    # A slot can contain several retries. Never attribute its
                    # cumulative usage to one attempt and double-count siblings.
                    if (receipt.get("schema_version") == "1.1" and
                            receipt.get("provider_reported_usage", {}).get("provider_requests") == 1):
                        reported = receipt.get("provider_reported_usage")
                        unknown = bool(receipt.get("unknown_usage_attempts", 0))
            usage = {}
            partial = False
            if isinstance(reported, dict):
                candidate = normalize_usage({"prompt_tokens": reported.get("input_tokens"),
                    "completion_tokens": reported.get("output_tokens"),
                    "cache_read_tokens": reported.get("cache_hit_input_tokens"),
                    "prompt_cache_miss_tokens": reported.get("cache_miss_input_tokens")})
                requests = reported.get("provider_requests")
                if type(requests) is int and requests > 0 and not unknown:
                    usage = candidate
                elif unknown and candidate.get("total_tokens", 0) > 0:
                    # SecMind retains provider-confirmed input/output even when
                    # another component is unknown and reserved conservatively.
                    usage, partial = candidate, True
            payload = {"trace_id": attempt["provider_request_id"], "remote_run_id": row["run_id"],
                "model": attempt.get("model_id", "unknown"), "usage": usage,
                "status": "completed" if attempt.get("succeeded") else "failed",
                "occurred_at": row["created_at"], "call_unit": "provider_request"}
            if partial:
                payload["usage_partial"] = True
            result.append((row["sequence"], attempt["provider_request_id"], payload))
        return result

    def _import(self, source, receipt_id, payload):
        # Whitelist metadata; never copy raw external model responses into the ledger.
        safe = {key: payload[key] for key in ("trace_id", "model", "remote_run_id", "project_id", "intent_id",
                "worker", "phase", "call_unit", "occurred_at", "usage_partial") if key in payload}
        safe.update(source=source, usage=normalize_usage(payload.get("usage")))
        safe["usage_known"] = bool(safe["usage"])
        safe["usage_provenance"] = ("provider_reported_partial" if safe.get("usage_partial") else
                                    "provider_reported" if safe["usage_known"] else "unavailable")
        state = payload["status"]
        if state not in {"started", "completed", "failed"}:
            raise ValueError("Invalid receipt state")
        # A namespaced source run keeps independent engines from colliding with
        # platform UUIDs. Task-detail association uses remote_run_id/project_id.
        origin = str(self.paths[source].resolve())
        origin_run = 'worker' if safe.get('call_unit') == 'pi_session_response_backfill' else \
            str(payload.get("remote_run_id") or payload.get("project_id") or "worker")
        run_id = str(uuid5(NAMESPACE_URL, origin + ":" + origin_run))
        # Old imports of partial SecMind attempts had empty usage. A versioned
        # event lets the existing trace be corrected without changing history.
        event_id = str(uuid5(NAMESPACE_URL, source + ":" + origin + ":" + receipt_id +
                             (":partial-provider-v1" if safe.get("usage_partial") else "")))
        original = {key: value for key, value in safe.items() if key != 'project_id'} \
            if safe.get('call_unit') == 'pi_session_response_backfill' else safe
        self.ledger.append(run_id, "external.usage." + state, original, actor=source, event_id=event_id)
        # Old Pi sessions were imported before their project could be matched.
        # A second event with the same trace links the response to its project.
        # Usage projections deduplicate that trace, so global totals stay fixed.
        if safe.get('call_unit') == 'pi_session_response_backfill' and safe.get('project_id'):
            linked_id = str(uuid5(NAMESPACE_URL, source + ":" + origin + ":" + receipt_id + ':project-link'))
            linked = {**safe, 'call_unit': 'pi_session_response_backfill_link'}
            linked_run_id = str(uuid5(NAMESPACE_URL, origin + ":" + str(safe['project_id'])))
            self.ledger.append(linked_run_id, "external.usage." + state, linked, actor=source, event_id=linked_id)
