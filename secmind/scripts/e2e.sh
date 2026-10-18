#!/usr/bin/env bash
set -euo pipefail

evidence_dir=${SECMIND_E2E_EVIDENCE_DIR:-e2e-artifacts}
mkdir -p "$evidence_dir"

persist_json() {
  local name=$1
  local payload=$2
  printf '%s\n' "$payload" >"$evidence_dir/$name"
}

for _ in $(seq 1 60); do
  if curl --fail --silent http://127.0.0.1:8000/health >/dev/null; then
    break
  fi
  sleep 2
done
curl --fail --silent http://127.0.0.1:8000/health | grep '"status":"ok"'

run_audit() {
  local fixture=$1
  local expected_status=$2
  local upload_json upload_ref task_json run_json run_id state status

  upload_json=$(curl --fail --silent -F "file=@${fixture}" http://127.0.0.1:8000/api/v1/uploads)
  upload_ref=$(python -c 'import json,sys; print(json.load(sys.stdin)["ref"])' <<<"$upload_json")
  task_json=$(python - "$upload_ref" <<'PY'
import json
import sys

print(json.dumps({
    "objective": "audit uploaded python code",
    "attachments": [{"ref": sys.argv[1]}],
    "autonomy_policy": "graded",
}))
PY
)
  run_json=$(curl --fail --silent -H 'Content-Type: application/json' -d "$task_json" http://127.0.0.1:8000/api/v1/tasks)
  run_id=$(python -c 'import json,sys; print(json.load(sys.stdin)["run_id"])' <<<"$run_json")

  for _ in $(seq 1 90); do
    state=$(curl --fail --silent "http://127.0.0.1:8000/api/v1/runs/$run_id")
    status=$(python -c 'import json,sys; print(json.load(sys.stdin)["status"])' <<<"$state")
    if [[ "$status" == "$expected_status" ]]; then
      echo "$run_id"
      return 0
    fi
    if [[ "$status" == "completed" || "$status" == "failed" || "$status" == "partial" || "$status" == "denied" || "$status" == "recovery_required" || "$status" == "cancelled" ]]; then
      echo "unexpected terminal state for ${fixture}: ${state}" >&2
      return 1
    fi
    sleep 2
  done

  echo "run did not reach ${expected_status} before the E2E deadline: ${state}" >&2
  return 1
}

# A clean result is COMPLETE only when the verifier-approved coverage evidence
# remains visible in the report and the completion receipt closes every gate.
safe_run_id=$(run_audit examples/safe_app.py completed)
safe_state=$(curl --fail --silent "http://127.0.0.1:8000/api/v1/runs/$safe_run_id")
persist_json safe-state.json "$safe_state"
python -c 'import json,sys; body=json.load(sys.stdin); assert body["last_error"] is None; assert body["verified_claims"] >= body["total_steps"] > 0; assert body["current_step"] == body["total_steps"]' <<<"$safe_state"
safe_report=$(curl --fail --silent "http://127.0.0.1:8000/api/v1/runs/$safe_run_id/report")
persist_json safe-report.json "$safe_report"
python -c 'import json,sys; body=json.load(sys.stdin); assert body["findings"] == []; assert body["evidence"]; assert body["claim_ids"]' <<<"$safe_report"
safe_completion=$(curl --fail --silent "http://127.0.0.1:8000/api/v1/runs/$safe_run_id/completion?record_type=receipt")
persist_json safe-completion.json "$safe_completion"
python -c 'import json,sys; items=json.load(sys.stdin)["items"]; assert len(items) == 1; assert items[0]["decision"] == "complete"; assert items[0]["unsatisfied_obligation_ids"] == []' <<<"$safe_completion"
safe_ledger=$(curl --fail --silent "http://127.0.0.1:8000/api/v1/runs/$safe_run_id/ledger")
persist_json safe-ledger.json "$safe_ledger"
python -c 'import json,sys; assert json.load(sys.stdin)["chain_valid"] is True' <<<"$safe_ledger"

# The vulnerable fixture contains a concrete Flask request source flowing into
# subprocess(shell=True). Bandit and the reviewed Semgrep taint rule must both
# execute and independently bind their result to the immutable input before
# the finding can cross the public evidence boundary.
vulnerable_run_id=$(run_audit examples/vulnerable_app.py completed)
vulnerable_state=$(curl --fail --silent "http://127.0.0.1:8000/api/v1/runs/$vulnerable_run_id")
persist_json vulnerable-state.json "$vulnerable_state"
python -c 'import json,sys; body=json.load(sys.stdin); assert body["last_error"] is None; assert body["verified_claims"] >= body["total_steps"] > 0; assert body["current_step"] == body["total_steps"]' <<<"$vulnerable_state"
vulnerable_report=$(curl --fail --silent "http://127.0.0.1:8000/api/v1/runs/$vulnerable_run_id/report")
persist_json vulnerable-report.json "$vulnerable_report"
python -c 'import json,sys; body=json.load(sys.stdin); findings=body["findings"]; rules={item["rule_id"] for item in findings}; native={str(value) for item in findings for value in (item.get("raw", {}).get("test_id"), item.get("raw", {}).get("native_rule_id"), *(item.get("raw", {}).get("corroborating_native_rule_ids") or [])) if value}; native.update(str(value) for item in body["evidence"] for value in (item.get("metadata", {}).get("test_id"), item.get("metadata", {}).get("native_rule_id")) if value); assert "CWE-78" in rules, {"rules": sorted(rules)}; assert "B602" in native, {"native": sorted(native)}; assert "secmind.python.flask-shell-command-injection" in native, {"native": sorted(native)}; assert body["evidence"]; assert body["claim_ids"]' <<<"$vulnerable_report"
vulnerable_completion=$(curl --fail --silent "http://127.0.0.1:8000/api/v1/runs/$vulnerable_run_id/completion?record_type=receipt")
persist_json vulnerable-completion.json "$vulnerable_completion"
python -c 'import json,sys; items=json.load(sys.stdin)["items"]; assert len(items) == 1; assert items[0]["decision"] == "complete"; assert items[0]["unsatisfied_obligation_ids"] == []' <<<"$vulnerable_completion"
vulnerable_ledger=$(curl --fail --silent "http://127.0.0.1:8000/api/v1/runs/$vulnerable_run_id/ledger")
persist_json vulnerable-ledger.json "$vulnerable_ledger"
python -c 'import json,sys; body=json.load(sys.stdin); completed={(item["payload"].get("tool"), item["payload"].get("status")) for item in body["events"] if item["event_type"] == "tool.completed"}; assert body["chain_valid"] is True; assert ("bandit_python_audit", "success") in completed, sorted(completed); assert ("semgrep_sast", "success") in completed, sorted(completed)' <<<"$vulnerable_ledger"
