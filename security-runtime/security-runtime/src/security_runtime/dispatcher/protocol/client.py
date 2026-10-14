from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import logging
import threading
import json

from pydantic import TypeAdapter
import requests
from requests.adapters import HTTPAdapter

from security_runtime.server.models import ProjectDetail, ProjectSummary, Settings
from security_runtime.server.services import planning_snapshot, planning_snapshot_hash

LOG = logging.getLogger(__name__)


class ProtocolError(RuntimeError):
    def __init__(self, message: str, status_code: int, response_text: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


@dataclass(slots=True)
class ApiResult:
    status_code: int
    data: Any | None = None
    text: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300


class SecurityRuntimeClient:
    def __init__(self, base_url: str, timeout: float = 10.0):
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._summary_adapter = TypeAdapter(list[ProjectSummary])
        self._local = threading.local()
        self._sessions: dict[int, requests.Session] = {}
        self._sessions_lock = threading.Lock()

    def close(self) -> None:
        with self._sessions_lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.close()

    def list_projects(self) -> list[ProjectSummary]:
        response = self._session().get(self._url("/projects"), timeout=self._timeout)
        response.raise_for_status()
        return self._summary_adapter.validate_python(response.json())

    def get_project(self, project_id: str) -> ProjectDetail:
        response = self._session().get(self._url(f"/projects/{project_id}"), timeout=self._timeout)
        response.raise_for_status()
        return ProjectDetail.model_validate(response.json())

    def project_events(self, project_id: str, *, after: int = 0, limit: int = 1000) -> ApiResult:
        return self._request_json(
            "GET", f"/projects/{project_id}/events?after={after}&limit={limit}", json={},
        )

    def get_settings(self) -> Settings:
        response = self._session().get(self._url("/settings"), timeout=self._timeout)
        response.raise_for_status()
        return Settings.model_validate(response.json())

    def export_project(self, project_id: str) -> str:
        response = self._session().get(
            self._url(f"/projects/{project_id}/export"),
            params={"format": "yaml"},
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.text

    def heartbeat(self, project_id: str, intent_id: str, worker: str, *, attempt_id: str | None = None, claim: bool = False) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/heartbeat",
            json={"worker": worker, "attempt_id": attempt_id, "claim": claim},
        )

    def claim_reason(self, project_id: str, worker: str, trigger: str, *, attempt_id: str | None = None) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/reason/claim",
            json={"worker": worker, "trigger": trigger, "attempt_id": attempt_id},
        )

    def reason_heartbeat(self, project_id: str, worker: str, *, attempt_id: str | None = None) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/reason/heartbeat",
            json={"worker": worker, "attempt_id": attempt_id},
        )

    def release_reason(self, project_id: str, worker: str, *, attempt_id: str | None = None) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/reason/release",
            json={"worker": worker, "attempt_id": attempt_id},
        )

    def update_project_status(self, project_id: str, status: str) -> ApiResult:
        return self._request_json(
            "PUT", f"/projects/{project_id}/status", json={"status": status},
        )

    def release(self, project_id: str, intent_id: str, worker: str, outcome: str = "waiting", *, attempt_id: str | None = None) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/release",
            json={"worker": worker, "outcome": outcome, "attempt_id": attempt_id},
        )

    def conclude(self, project_id: str, intent_id: str, worker: str, description: str | dict[str, Any], *, attempt_id: str | None = None) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/conclude",
            json={"worker": worker, **(description if isinstance(description, dict) else {"description": description}), "attempt_id": attempt_id},
        )

    def stage(self, project_id: str, intent_id: str, worker: str, phase: str, status: str, *, attempt_id: str | None = None) -> ApiResult:
        return self._request_json("POST", f"/projects/{project_id}/intents/{intent_id}/stage",
                                  json={"worker": worker, "phase": phase, "status": status, "attempt_id": attempt_id})

    def complete(self, project_id: str, from_ids: list[str], description: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/complete",
            json={"from": from_ids, "description": description, "worker": worker},
        )

    def create_intent(self, project_id: str, from_ids: list[str], description: str, creator: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents",
            json={"from": from_ids, "description": description, "creator": creator, "worker": None},
        )

    def planning_decision(self, project_id: str, decision: dict[str, Any], callback_token: str = "") -> ApiResult:
        return self._request_json(
            "POST", f"/projects/{project_id}/planning/decisions", json=decision,
            headers={"X-Security-Runtime-Token": callback_token},
        )

    def workbench_plan(
        self, workbench_url: str, project: ProjectDetail, trigger: str, decision_id: str,
        budget: dict[str, Any], tool_event_ids: list[str], callback_token: str = "",
        timeout_seconds: float = 600,
    ) -> ApiResult:
        snapshot = planning_snapshot(project)
        snapshot_hash = planning_snapshot_hash(project)
        run_id = project.project.title.removeprefix("sec-task-")
        hints = [item.model_dump(mode="json") for item in project.hints]
        module_route = next((item.content.split("：", 1)[1].strip() for item in project.hints
                             if item.content.startswith("模块：")), "unknown")
        target_scope: list[str] = []
        for hint in hints:
            content = str(hint.get("content", ""))
            if content.startswith("planner_scope_json:"):
                try:
                    decoded = json.loads(content.split(":", 1)[1])
                except (TypeError, ValueError):
                    continue
                if isinstance(decoded, list) and all(isinstance(item, str) for item in decoded):
                    target_scope = decoded
                    break
            if content.startswith("授权目标范围："):
                target_scope = [item.strip() for item in content.split("：", 1)[1].split(",") if item.strip()]
        payload = {
            "schema_version": "1.1", "run_id": run_id,
            "project_id": project.project.id, "trigger": trigger,
            "decision_id": decision_id, "snapshot_hash": snapshot_hash,
            "goal": next((item.description for item in project.facts if item.id == "goal"), ""),
            "module_route": module_route, "target_scope": target_scope,
            **snapshot, "tool_event_ids": tool_event_ids, "budget": budget,
        }
        headers = {"X-Security-Runtime-Token": callback_token} if callback_token else {}
        try:
            response = self._session().post(
                workbench_url.rstrip("/") + f"/api/v1/internal/runs/{run_id}/planning",
                json=payload, headers=headers, timeout=timeout_seconds,
            )
        except requests.RequestException as exc:
            LOG.warning("workbench planning callback failed project=%s error=%s", project.project.id, exc)
            return ApiResult(status_code=0, text=str(exc))
        data: Any | None = None
        if response.headers.get("content-type", "").startswith("application/json"):
            data = response.json()
        return ApiResult(status_code=response.status_code, data=data, text=response.text)

    def _request_json(self, method: str, path: str, json: dict[str, Any], headers: dict | None = None) -> ApiResult:
        try:
            response = self._session().request(
                method,
                self._url(path),
                json=json,
                **({"headers": headers} if headers else {}),
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            LOG.warning("request failed method=%s path=%s error=%s", method, path, exc)
            return ApiResult(status_code=0, text=str(exc))
        data: Any | None = None
        if response.headers.get("content-type", "").startswith("application/json"):
            data = response.json()
        return ApiResult(status_code=response.status_code, data=data, text=response.text)

    def _url(self, path: str) -> str:
        return f"{self._base_url}{path}"

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is not None:
            return session

        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=64, pool_maxsize=64, pool_block=False)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        self._local.session = session
        with self._sessions_lock:
            self._sessions[threading.get_ident()] = session
        return session


class AttemptBoundClient:
    def __init__(self, client: SecurityRuntimeClient, project_id: str, intent_id: str, attempt_id: str):
        self._client = client
        self._project_id = project_id
        self._intent_id = intent_id
        self._attempt_id = attempt_id

    def __getattr__(self, name: str):
        return getattr(self._client, name)

    def _check_target(self, project_id: str, intent_id: str) -> None:
        if (project_id, intent_id) != (self._project_id, self._intent_id):
            raise ValueError("Attempt-bound client used for a different intent")

    def heartbeat(self, project_id: str, intent_id: str, worker: str) -> ApiResult:
        self._check_target(project_id, intent_id)
        return self._client.heartbeat(project_id, intent_id, worker, attempt_id=self._attempt_id)

    def release(self, project_id: str, intent_id: str, worker: str, outcome: str = "waiting") -> ApiResult:
        self._check_target(project_id, intent_id)
        return self._client.release(project_id, intent_id, worker, outcome, attempt_id=self._attempt_id)

    def conclude(self, project_id: str, intent_id: str, worker: str, description: str | dict[str, Any]) -> ApiResult:
        self._check_target(project_id, intent_id)
        return self._client.conclude(project_id, intent_id, worker, description, attempt_id=self._attempt_id)

    def stage(self, project_id: str, intent_id: str, worker: str, phase: str, status: str) -> ApiResult:
        self._check_target(project_id, intent_id)
        return self._client.stage(project_id, intent_id, worker, phase, status, attempt_id=self._attempt_id)


def bind_intent_attempt(client: SecurityRuntimeClient, project_id: str, intent_id: str, attempt_id: str | None):
    return AttemptBoundClient(client, project_id, intent_id, attempt_id) if attempt_id else client


class ReasonAttemptBoundClient:
    def __init__(self, client: SecurityRuntimeClient, project_id: str, attempt_id: str):
        self._client = client
        self._project_id = project_id
        self._attempt_id = attempt_id

    def __getattr__(self, name: str):
        return getattr(self._client, name)

    def _check_project(self, project_id: str) -> None:
        if project_id != self._project_id:
            raise ValueError("Reason attempt-bound client used for a different project")

    def reason_heartbeat(self, project_id: str, worker: str) -> ApiResult:
        self._check_project(project_id)
        return self._client.reason_heartbeat(project_id, worker, attempt_id=self._attempt_id)

    def release_reason(self, project_id: str, worker: str) -> ApiResult:
        self._check_project(project_id)
        return self._client.release_reason(project_id, worker, attempt_id=self._attempt_id)

    def planning_decision(self, project_id: str, decision: dict[str, Any], callback_token: str = "") -> ApiResult:
        self._check_project(project_id)
        return self._client.planning_decision(project_id, {**decision, "reason_attempt_id": self._attempt_id}, callback_token)


def bind_reason_attempt(client: SecurityRuntimeClient, project_id: str, attempt_id: str | None):
    return ReasonAttemptBoundClient(client, project_id, attempt_id) if attempt_id else client
