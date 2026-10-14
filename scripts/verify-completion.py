"""Offline cross-service acceptance; run with an/.venv Python. No production data or paid models."""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def isolate(root: Path):
    for key in tuple(os.environ):
        if key.startswith(("SECMIND_", "SECURITY_AGENT_")):
            os.environ.pop(key)
    for prefix in ("SECMIND_", "SECURITY_AGENT_"):
        for key, sub in [("DATABASE_URL", "default.db"), ("INPUT_ROOT", "inputs"),
                         ("UPLOAD_ROOT", "uploads"), ("RUN_ROOT", "runs"), ("ARTIFACT_ROOT", "artifacts"),
                         ("EVALUATION_ROOT", "evaluations"), ("QUESTION_BANK_ROOT", "questions"), ("MCP_GENERATED_ROOT", "mcp")]:
            path = root / prefix.lower() / sub
            os.environ[prefix + key] = "sqlite:///" + path.as_posix() if key == "DATABASE_URL" else str(path)
        os.environ[prefix + "DEMO_MODE"] = "true"
    os.environ["SECMIND_MODEL_MODE"] = "offline"
    os.environ["SECMIND_ALLOW_LIVE_MODELS"] = "false"
    os.chdir(root)


def serve_engine(root: Path, port: int):
    isolate(root)
    from secmind.api import create_app
    from secmind.config import Settings
    import uvicorn
    settings = Settings(_env_file=None, demo_mode=True, model_mode="offline", allow_live_models=False,
        unsafe_development_tools=True, qwen_api_key="", deepseek_api_key="", openai_api_key="",
        qdrant_url="http://127.0.0.1:1", hybrid_knowledge_timeout_seconds=0.05,
        alembic_config_path=ROOT / "secmind" / "alembic.ini")
    uvicorn.run(create_app(settings), host="127.0.0.1", port=port, log_level="warning")


def verify():
    import httpx
    root = Path(tempfile.mkdtemp(prefix="secmind-acceptance-"))
    isolate(root)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    python = ROOT / "secmind" / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    log_path = root / "engine.log"
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen([str(python), "-B", str(Path(__file__).resolve()),
            "--engine", "--root", str(root), "--port", str(port)], cwd=root, stdout=log, stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        try:
            with httpx.Client(timeout=2, trust_env=False) as client:
                for _ in range(150):
                    if process.poll() is not None:
                        raise RuntimeError(f"Engine exited; inspect {log_path}")
                    try:
                        if client.get(base + "/health/live").status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(0.2)
                else:
                    raise RuntimeError(f"Engine readiness timed out; inspect {log_path}")
            from fastapi.testclient import TestClient
            from security_agent.api import create_app
            from security_agent.config import Settings
            settings = Settings(_env_file=None, demo_mode=True, model_api_key="",
                reverse_base_url=base, penetration_base_url="http://127.0.0.1:1",
                penetration_poll_interval_seconds=0.2, penetration_poll_timeout_seconds=90, max_runtime_seconds=120)
            app = create_app(settings)
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("one/app.py", "import subprocess\nsubprocess.Popen('echo fixture', shell=True)\n")
                bundle.writestr("two/app.py", "print('second source file')\n")
            cases = [
                ("audit.zip", archive.getvalue(), "审计 Python 源码并生成证据报告", "code_audit"),
                ("auth.log", b"<34>1 2026-10-01T02:00:00Z host sshd 1 auth - Failed password for invalid user from 198.51.100.2\n",
                    "分析上传日志，提取事件时间线与证据", "log_analysis"),
            ]
            results = []
            with TestClient(app) as client:
                for name, data, objective, route in cases:
                    uploaded = client.post("/api/v1/uploads", files={"file": (name, data)})
                    uploaded.raise_for_status()
                    submitted = client.post("/api/v1/tasks", json={"objective": objective,
                        "attachments": [{"ref": uploaded.json()["ref"]}], "analysis_backend": "secmind",
                        "target_scope": ["uploaded-source"], "constraints": ["只读分析"]})
                    submitted.raise_for_status()
                    run_id = submitted.json()["run_id"]
                    for _ in range(650):
                        summary = client.get("/api/v1/runs/" + run_id).json()
                        if summary["status"] in {"completed", "partial", "failed", "denied", "waiting_approval"}:
                            break
                        time.sleep(0.2)
                    report_response = client.get(f"/api/v1/runs/{run_id}/report")
                    outcome = {"case": route, "status": summary["status"],
                        "remote_run_id": summary.get("external_execution", {}).get("remote_run_id"),
                        "last_error": summary.get("last_error"), "report_http": report_response.status_code}
                    if report_response.status_code == 200:
                        payload = report_response.json()
                        outcome.update(findings=len(payload["findings"]), evidence=len(payload["evidence"]),
                            limitations=payload["limitations"])
                    results.append(outcome)
                    (root / "results.json").write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
                    assert summary["module_route"] == route, summary
                    assert summary["status"] == "completed", outcome
                    assert outcome["remote_run_id"] and outcome.get("evidence", 0) > 0, outcome
                    assert client.get(f"/api/v1/runs/{run_id}/ledger").json()["chain_valid"]
                    synced = client.post(f"/api/v1/runs/{run_id}/report/refresh")
                    assert synced.status_code == 200, synced.text
                    assert synced.json()["status"] == "completed"
            print(json.dumps({"passed": len(results), "model_mode": "offline", "data_directory": str(root), "results": results}, ensure_ascii=True))
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", action="store_true")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    if args.engine:
        serve_engine(args.root, args.port)
    else:
        verify()
