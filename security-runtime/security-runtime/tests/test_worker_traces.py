import json
import sqlite3

from security_runtime.dispatcher.traces import public_output, write_trace


def test_pi_public_outputs_exclude_thinking_credentials_and_duplicate_streams(tmp_path):
    events = [
        {"type": "message_update", "delta": "draft"},
        {"type": "message_end", "message": {"role": "assistant", "content": [
            {"type": "thinking", "thinking": "hidden reasoning"},
            {"type": "text", "text": "public observation"},
            {"type": "toolCall", "id": "call", "name": "http",
             "arguments": {"Authorization": "Bearer secret-token"}}]}},
        {"type": "tool_execution_end", "toolName": "http", "toolCallId": "call",
         "result": {"content": [{"type": "text", "text": "Cookie: session-secret\nstatus 200"}]}},
        {"type": "agent_end", "messages": [{"content": [{"type": "thinking", "thinking": "hidden reasoning"}]}]},
    ]
    stdout = "\n".join(json.dumps(event) for event in events)
    path = tmp_path / "journal.db"
    receipt = {"trace_id": "trace", "project_id": "project", "intent_id": "intent",
               "attempt_id": "attempt", "status": "completed"}
    write_trace(path, receipt, kind="pi", stdout=stdout)
    write_trace(path, receipt, kind="pi", stdout=stdout)
    with sqlite3.connect(path) as conn:
        rows = conn.execute("SELECT payload_json FROM worker_traces").fetchall()
    assert len(rows) == 1
    assert "public observation" in rows[0][0] and "status 200" in rows[0][0]
    assert all(secret not in rows[0][0] for secret in
               ("hidden reasoning", "secret-token", "session-secret", "draft"))
    assert len(json.loads(rows[0][0])["output"]) == 3


def test_claude_uses_only_result_envelope_and_explicit_missing(tmp_path):
    stdout = json.dumps({"type": "result", "result": "final public result", "thinking": "hidden",
                         "usage": {"input_tokens": 1}})
    assert public_output(stdout, "claudecode") == [{"type": "result", "output": "final public result"}]
    assert public_output(json.dumps({"type": "result"}), "claudecode") == []
    path = tmp_path / "journal.db"
    write_trace(path, {"trace_id": "failed", "project_id": "project", "status": "failed"}, kind="pi")
    with sqlite3.connect(path) as conn:
        payload = json.loads(conn.execute("SELECT payload_json FROM worker_traces").fetchone()[0])
    assert payload["output_available"] is False
