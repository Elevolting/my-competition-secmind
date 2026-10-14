from __future__ import annotations

import socket
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

import scripts.secmind_test3_v083_bridge as bridge_adapter
from scripts.secmind_test3_v083_bridge import _install_contract_patches


class _FakeBridgeError(RuntimeError):
    pass


class _FakeAgentProcessError(_FakeBridgeError):
    pass


class _FakeProcess:
    next_pid = 50_000
    active: dict[int, _FakeProcess] = {}
    by_port: dict[int, _FakeProcess] = {}

    def __init__(self, port: int | None = None) -> None:
        self.pid = _FakeProcess.next_pid
        _FakeProcess.next_pid += 1
        self.returncode: int | None = None
        self.terminated = False
        self.tree_terminated = False
        self.listener: socket.socket | None = None
        if port is not None:
            self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind(("127.0.0.1", port))
            self.listener.listen(128)
            _FakeProcess.by_port[port] = self
        _FakeProcess.active[self.pid] = self

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = 0
        if self.listener is not None:
            port = int(self.listener.getsockname()[1])
            self.listener.close()
            self.listener = None
            _FakeProcess.by_port.pop(port, None)
        _FakeProcess.active.pop(self.pid, None)

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return self.returncode or 0

    def kill(self) -> None:
        self.terminated = True
        self.returncode = -9
        if self.listener is not None:
            port = int(self.listener.getsockname()[1])
            self.listener.close()
            self.listener = None
            _FakeProcess.by_port.pop(port, None)
        _FakeProcess.active.pop(self.pid, None)


def _fake_popen(*_args: Any, **_kwargs: Any) -> _FakeProcess:
    command = list(_args[0]) if _args else []
    port_index = command.index("--port") + 1 if "--port" in command else -1
    port = int(command[port_index]) if port_index > 0 else None
    return _FakeProcess(port)


class _FakeClient:
    def __init__(self, port: int, *, timeout: float = 180.0) -> None:
        self.port = port
        self.timeout = timeout


def _platform_for_startup(state: dict[str, Any]) -> ModuleType:
    platform = ModuleType("test_platform_bridge_startup")
    platform.BRIDGE_VERSION = "test"
    platform.MAX_RESPONSE_BYTES = 8 * 1024 * 1024
    platform.BridgeError = _FakeBridgeError
    platform.AgentProcessError = _FakeAgentProcessError
    platform.SecMindClient = _FakeClient
    platform.ServerProcess = lambda process, client: SimpleNamespace(process=process, client=client)
    platform.service_commands = lambda _root: [("uvicorn",)]

    def wait_for_health(server: Any) -> None:
        state["health_calls"] = state.get("health_calls", 0) + 1
        if state.get("startup_error") is not None:
            raise state["startup_error"]
        process = _FakeProcess.by_port[server.client.port]
        with socket.create_connection(("127.0.0.1", server.client.port), timeout=1.0):
            pass
        if process.listener is not None:
            process.listener.settimeout(1.0)
            connection, _address = process.listener.accept()
            connection.close()
        state.setdefault("ports", []).append(server.client.port)

    def stop_service(process: _FakeProcess) -> None:
        process.tree_terminated = True
        process.terminate()

    platform.wait_for_health = wait_for_health
    platform.stop_service = stop_service
    platform._start_service = lambda *_args, **_kwargs: None
    platform.build_task_payload = lambda request, upload: {}
    platform.convert_result = lambda request, summary, report, **kwargs: {}
    platform._object = lambda payload, label: payload
    _install_contract_patches(
        platform,
        bridge_sha256="a" * 64,
        bridge_snapshot={"bridge_sha256": "a" * 64},
        agent_snapshot={"agent_snapshot_digest": "b" * 64, "agent_git_sha": "c" * 40},
    )
    # The startup test supplies a local fake client after contract installation;
    # the production assignment remains the patched HTTP client.
    platform.SecMindClient = _FakeClient
    return platform


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def test_bridge_startup_health_cold_start_100_dynamic_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    state: dict[str, Any] = {}
    platform = _platform_for_startup(state)
    monkeypatch.setattr(bridge_adapter.subprocess, "Popen", _fake_popen)
    _FakeProcess.active.clear()
    _FakeProcess.by_port.clear()

    try:
        for _ in range(100):
            server = platform._start_service(Path("."), environment={}, port=_free_loopback_port())
            assert server.client.port in state["ports"]
            platform.stop_service(server.process)
            assert not _FakeProcess.active
    finally:
        for process in list(_FakeProcess.active.values()):
            platform.stop_service(process)
    assert state["health_calls"] == 100
    assert not _FakeProcess.active
    assert not _FakeProcess.by_port


def test_bridge_startup_exception_always_stops_process_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    state: dict[str, Any] = {"startup_error": RuntimeError("health probe exploded")}
    platform = _platform_for_startup(state)
    monkeypatch.setattr(bridge_adapter.subprocess, "Popen", _fake_popen)
    _FakeProcess.active.clear()
    _FakeProcess.by_port.clear()

    with pytest.raises(RuntimeError, match="health probe exploded"):
        platform._start_service(Path("."), environment={}, port=_free_loopback_port())

    assert state["health_calls"] == 1
    assert not _FakeProcess.active
    assert not _FakeProcess.by_port


def test_health_exhausts_three_consecutive_bad_status_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    platform = ModuleType("test_platform_bridge_bad_status_new")
    platform.BRIDGE_VERSION = "test"
    platform.MAX_RESPONSE_BYTES = 8 * 1024 * 1024
    platform.BridgeError = _FakeBridgeError
    platform.SecMindClient = _FakeClient
    platform.build_task_payload = lambda request, upload: {}
    platform.convert_result = lambda request, summary, report, **kwargs: {}
    platform._object = lambda payload, label: payload
    connection_count = 0

    class FakeResponse:
        status = 200

        def read(self, limit: int) -> bytes:
            del limit
            return b'{"status":"ok"}'

        def getheader(self, name: str) -> str:
            del name
            return "application/json"

    class FakeConnection:
        def __init__(self, host: str, port: int, *, timeout: float) -> None:
            del host, port, timeout

        def request(self, method: str, path: str, *, body: object, headers: object) -> None:
            del method, path, body, headers

        def getresponse(self) -> FakeResponse:
            nonlocal connection_count
            connection_count += 1
            raise bridge_adapter.http.client.BadStatusLine("GET /health/live HTTP/1.1")

        def close(self) -> None:
            pass

    monkeypatch.setattr(bridge_adapter.http.client, "HTTPConnection", FakeConnection)
    _install_contract_patches(
        platform,
        bridge_sha256="a" * 64,
        bridge_snapshot={"bridge_sha256": "a" * 64},
        agent_snapshot={"agent_snapshot_digest": "b" * 64, "agent_git_sha": "c" * 40},
    )

    assert platform.SecMindClient(8123, timeout=1.0).health() is False
    assert connection_count == 3


def test_post_transport_failure_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    platform = ModuleType("test_platform_bridge_post_no_retry")
    platform.BRIDGE_VERSION = "test"
    platform.MAX_RESPONSE_BYTES = 8 * 1024 * 1024
    platform.BridgeError = _FakeBridgeError
    platform.SecMindClient = _FakeClient
    platform.build_task_payload = lambda request, upload: {}
    platform.convert_result = lambda request, summary, report, **kwargs: {}
    platform._object = lambda payload, label: payload
    _install_contract_patches(
        platform,
        bridge_sha256="a" * 64,
        bridge_snapshot={"bridge_sha256": "a" * 64},
        agent_snapshot={"agent_snapshot_digest": "b" * 64, "agent_git_sha": "c" * 40},
    )
    connection_count = 0

    class FakeConnection:
        def __init__(self, host: str, port: int, *, timeout: float) -> None:
            del host, port, timeout

        def request(self, method: str, path: str, *, body: object, headers: object) -> None:
            nonlocal connection_count
            del path, body, headers
            assert method == "POST"
            connection_count += 1
            raise bridge_adapter.http.client.BadStatusLine("POST /api/v1/tasks HTTP/1.1")

        def close(self) -> None:
            pass

    monkeypatch.setattr(bridge_adapter.http.client, "HTTPConnection", FakeConnection)
    client = platform.SecMindClient(8123, timeout=1.0)
    with pytest.raises(_FakeBridgeError, match="BadStatusLine"):
        client.create_task({"objective": "offline"})
    assert connection_count == 1
