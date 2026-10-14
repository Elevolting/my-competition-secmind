from __future__ import annotations

from dataclasses import dataclass, field

from security_runtime.dispatcher.config import ContainerConfig
from security_runtime.dispatcher.protocol.client import (
    ApiResult, SecurityRuntimeClient, bind_intent_attempt, bind_reason_attempt,
)
from security_runtime.dispatcher.runtime.cancellation import TaskCancellation
from security_runtime.dispatcher.runtime.containers import ContainerManager
from security_runtime.dispatcher.runtime.heartbeat import HeartbeatLease


@dataclass
class FakeProcess:
    cancelled: list[str] = field(default_factory=list)
    kill_count: int = 0

    def cancel(self, reason: str) -> None:
        self.cancelled.append(reason)

    def kill(self) -> None:
        self.kill_count += 1


class FakeContainer:
    def __init__(self) -> None:
        self.client = type("Client", (), {"api": object()})()
        self.stop_count = 0
        self.archives: list[tuple[str, bytes]] = []
        self.archive_result = True

    def stop(self, timeout: int) -> None:
        assert timeout == 1
        self.stop_count += 1

    def put_archive(self, path: str, archive: bytes) -> bool:
        self.archives.append((path, archive))
        return self.archive_result


def _manager(*, completed_action: str = "stop") -> ContainerManager:
    manager = ContainerManager.__new__(ContainerManager)
    manager._config = ContainerConfig(
        image="image",
        network_mode="host",
        completed_action=completed_action,
    )
    return manager


def test_task_cancellation_keeps_first_reason_and_cancels_late_process() -> None:
    cancellation = TaskCancellation()

    assert cancellation.cancel("project stopped")
    assert not cancellation.cancel("second reason")
    assert cancellation.reason == "project stopped"

    process = FakeProcess()
    cancellation.attach_process(process)
    assert process.cancelled == ["project stopped"]


def test_heartbeat_conflict_failure_kills_attached_process() -> None:
    process = FakeProcess()
    lease = HeartbeatLease(lambda: ApiResult(409, text="lost"), "intent", "worker", interval=60)
    lease.attach_process(process)

    lease._fail(409, "lost")

    assert lease.failure is not None
    assert lease.failure.status_code == 409
    assert process.kill_count == 1


def test_attempt_bound_client_sends_same_attempt_for_every_intent_write() -> None:
    client = SecurityRuntimeClient("http://127.0.0.1:8000")
    requests = []
    client._request_json = lambda method, path, json, **kwargs: requests.append((method, path, json)) or ApiResult(200, {})
    bound = bind_intent_attempt(client, "proj_001", "i001", "attempt-1")

    bound.heartbeat("proj_001", "i001", "worker")
    bound.stage("proj_001", "i001", "worker", "explore_execute", "running")
    bound.release("proj_001", "i001", "worker", outcome="failed")
    bound.conclude("proj_001", "i001", "worker", {"description": "result"})

    assert [path.rsplit("/", 1)[-1] for _, path, _ in requests] == [
        "heartbeat", "stage", "release", "conclude",
    ]
    assert all(payload["attempt_id"] == "attempt-1" for _, _, payload in requests)


def test_reason_attempt_bound_client_sends_same_attempt_for_every_reason_write() -> None:
    client = SecurityRuntimeClient("http://127.0.0.1:8000")
    requests = []
    client._request_json = lambda method, path, json, **kwargs: requests.append((path, json)) or ApiResult(200, {})
    bound = bind_reason_attempt(client, "proj_001", "reason-1")

    bound.reason_heartbeat("proj_001", "worker")
    bound.release_reason("proj_001", "worker")
    bound.planning_decision("proj_001", {"decision_id": "decision-1"}, callback_token="token")

    assert [path.rsplit("/", 1)[-1] for path, _ in requests] == [
        "heartbeat", "release", "decisions",
    ]
    assert [body.get("attempt_id", body.get("reason_attempt_id")) for _, body in requests] == [
        "reason-1", "reason-1", "reason-1",
    ]


def test_container_manager_build_exec_process_wraps_command_with_timeout() -> None:
    manager = _manager()
    container = FakeContainer()
    manager._require_container = lambda _name: container

    process = manager.build_exec_process("container", {"A": "B"}, ["agent", "-p", "prompt"], timeout_seconds=300)

    assert process.command == ["timeout", "-k", "5s", "300s", "agent", "-p", "prompt"]
    assert process.env == {"A": "B"}


def test_completed_container_stop_action_only_stops_running_container() -> None:
    manager = _manager()
    container = FakeContainer()
    states = iter(["running", "exited"])
    manager.inspect_state = lambda _name: next(states)
    manager._require_container = lambda _name: container

    assert manager.cleanup_completed("proj/001")
    assert manager.container_name("proj/001") == "security-runtime-dispatch-proj-001"
    assert container.stop_count == 1


def test_stopped_container_cleanup_is_noop_after_container_has_already_stopped() -> None:
    manager = _manager()
    manager.inspect_state = lambda _name: "exited"

    assert manager.cleanup_stopped("proj_001")


def test_write_text_file_uses_archive_api_and_rejects_false_result() -> None:
    manager = _manager()
    container = FakeContainer()
    manager._require_container = lambda _name: container

    manager.write_text_file("container", "/tmp/graph.yaml", "facts: []\n")
    assert container.archives[0][0] == "/tmp"

    container.archive_result = False
    try:
        manager.write_text_file("container", "/tmp/graph.yaml", "facts: []\n")
    except RuntimeError as exc:
        assert "failed to write container file" in str(exc)
    else:
        raise AssertionError("expected failed put_archive result to raise")
