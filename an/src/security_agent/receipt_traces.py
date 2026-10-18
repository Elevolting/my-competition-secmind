"""Recover suite-owned MCP receipts missing from the historical run ledger."""
from __future__ import annotations

from uuid import NAMESPACE_URL, uuid5

from security_agent.trace_redaction import redact_trace


class ReceiptTraceImporter:
    def __init__(self, ledger, operations):
        self.ledger, self.operations = ledger, operations

    def sync(self, run_id: str) -> None:
        if self.ledger.load_state(run_id) is None:
            raise KeyError(run_id)
        terminal_ids = {event.payload.get("call_id") for event in self.ledger.events(run_id, limit=1_000_000)
                        if event.event_type.startswith("mcp.call.") and
                        event.event_type != "mcp.call.started"}
        for _, receipt in self.operations.items("call:"):
            if (not isinstance(receipt, dict) or receipt.get("run_id") != run_id or
                    receipt.get("status") not in {"completed", "failed", "cancelled", "interrupted"}):
                continue
            call_id = receipt.get("call_id")
            if not isinstance(call_id, str) or not call_id or call_id in terminal_ids:
                continue
            event_id = str(uuid5(NAMESPACE_URL, "mcp-receipt-backfill:" + run_id + ":" + call_id))
            payload = redact_trace({**receipt, "timestamp": receipt.get("completed_at") or receipt.get("started_at")})
            self.ledger.append(run_id, "mcp.call.backfilled", payload, actor="mcp_runtime", event_id=event_id)


class TraceSources:
    def __init__(self, *importers):
        self.importers = importers

    def sync(self, run_id: str) -> None:
        for importer in self.importers:
            importer.sync(run_id)
