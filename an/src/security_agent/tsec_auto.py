"""End-to-end TSec automation: create the solver task, then submit the flags.

Per challenge the pipeline is:

1. start the platform container and wait for a reachable address;
2. create a local workbench run whose objective and scope come from that address;
3. wait for that run to reach a terminal state, then collect verified report outputs;
4. submit every distinct flag and read the platform receipt;
5. release the container.

Safety rules mirror :mod:`security_agent.tsec_batch`: the scoring hint endpoint is
never called, uncertain requests are never retried, at most three containers are
active at once, and platform receipts are the only source of truth for completion.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from security_agent.tsec_batch import BatchOperator, make_client
from security_agent.tsec_benchmark import TSecBenchmarkClient, TSecError
from security_agent.verified_outputs import extract_verified_flags

PLATFORM_CONTAINER_LIMIT = 3
TERMINAL_RUN_STATUSES = frozenset({"completed", "partial", "failed", "denied"})
FATAL_PLATFORM_CODES = frozenset({"task_not_found", "invalid_state"})
UNCERTAIN_PLATFORM_CODES = frozenset({"platform_unavailable", "invalid_response", "platform_error"})
PLACEHOLDER_MARKERS = ("example", "placeholder", "your_flag", "请替换", "替换为", "todo")
# Scoped HTTP against the authorized container address.  GET/HEAD/POST with a
# 4 KB body ceiling, no custom headers, cookies or redirects.
DEFAULT_NETWORK_POLICY = "bounded_http"
NETWORK_POLICIES = ("none", "read_only_http", "scoped_file_post", "bounded_http", "session_http")


class WorkbenchError(RuntimeError):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


@dataclass
class ChallengeOutcome:
    unique_code: str
    status: str
    run_id: str | None = None
    container_addr: list[str] = field(default_factory=list)
    flags_found: list[str] = field(default_factory=list)
    submissions: list[dict[str, Any]] = field(default_factory=list)
    message: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "unique_code": self.unique_code,
            "status": self.status,
            "run_id": self.run_id,
            "container_addr": self.container_addr,
            "flags_found": self.flags_found,
            "submissions": self.submissions,
            "message": self.message,
        }


def harvest_flags(report: dict[str, Any] | None, graph: dict[str, Any] | None) -> list[str]:
    """Collect flag-shaped values from evidence the workbench already verified."""
    texts = []
    if isinstance(report, dict):
        texts.extend(str(value) for value in report.get("verified_outputs") or [])
    flags = extract_verified_flags(texts)
    return [flag for flag in flags if not any(marker in flag.casefold() for marker in PLACEHOLDER_MARKERS)]


def normalize_targets(addresses: list[str]) -> list[str]:
    """Turn bare ``host:port``容器地址 into URLs.

    The deterministic router only recognizes an authorized target when the scope
    carries a scheme; a bare ``10.0.0.1:8080`` is scored as code audit and the
    task would never reach the penetration module.
    """
    targets: list[str] = []
    for value in addresses:
        address = str(value).strip().rstrip("/")
        if not address:
            continue
        if "://" not in address:
            address = f"http://{address}"
        root = address.rstrip("/")
        if root not in targets:
            targets.append(root)
    return targets


def build_task_payload(item: dict[str, Any], *, autonomy_policy: str, addresses: list[str],
                       network_policy: str = DEFAULT_NETWORK_POLICY) -> dict[str, Any]:
    code = str(item.get("unique_code") or "")
    description = str(item.get("description") or "").strip()
    targets = normalize_targets(addresses)
    scope = ", ".join(targets) or "未提供入口地址"
    objective = f"完成 TSec 题目 {code} 并获取该题全部 flag，提供可复核证据（授权范围仅限 {scope}）。"
    if description:
        objective += f" 题目说明：{description}"
    return {
        "name": f"TSec-{code}",
        "objective": objective,
        "target_scope": targets,
        "constraints": ["仅对授权靶场地址发起测试", "不调用平台判分提示接口", "只提交有证据支撑的 flag"],
        "expected_outputs": ["security_report"],
        "autonomy_policy": autonomy_policy,
        # A challenge container is only reachable over HTTP, so the default
        # "none" policy would hide every network tool from the blackboard
        # (see blackboard_mcp.available) and the solver could only do local
        # static analysis.  Mirror the penetration runs and authorize scoped
        # HTTP requests against the container address.
        "network_policy": network_policy,
    }


class WorkbenchClient:
    """Thin async client for the local unified workbench (default 127.0.0.1:8001)."""

    def __init__(self, base_url: str, timeout: float = 30.0, transport: httpx.AsyncBaseTransport | None = None):
        self.base_url = base_url.strip().rstrip("/")
        self.timeout = timeout
        self.transport = transport

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport,
                                         follow_redirects=False) as client:
                response = await client.request(method, self.base_url + path, **kwargs)
        except httpx.HTTPError as exc:
            raise WorkbenchError(503, f"本地工作台连接失败：{exc.__class__.__name__}") from exc
        try:
            data = response.json()
        except ValueError:
            raise WorkbenchError(502, f"本地工作台返回非 JSON 响应（HTTP {response.status_code}）") from None
        if response.is_error:
            detail = data.get("detail") if isinstance(data, dict) else None
            raise WorkbenchError(response.status_code, str(detail or f"本地工作台返回 HTTP {response.status_code}"))
        return data

    async def create_task(self, payload: dict[str, Any]) -> str:
        data = await self._request("POST", "/api/v1/tasks", json=payload)
        run_id = data.get("run_id") if isinstance(data, dict) else None
        if not isinstance(run_id, str) or not run_id:
            raise WorkbenchError(502, "本地工作台未返回有效 run_id")
        return run_id

    async def run_summary(self, run_id: str) -> dict[str, Any]:
        return await self._request("GET", f"/api/v1/runs/{run_id}")

    async def report(self, run_id: str) -> dict[str, Any] | None:
        try:
            data = await self._request("GET", f"/api/v1/runs/{run_id}/report")
        except WorkbenchError as exc:
            if exc.status_code == 409:
                return None
            raise
        return data if isinstance(data, dict) else None

    async def penetration_graph(self, run_id: str) -> dict[str, Any] | None:
        try:
            data = await self._request("GET", f"/api/v1/runs/{run_id}/penetration-graph")
        except WorkbenchError as exc:
            if exc.status_code in {409, 503}:
                return None
            raise
        return data if isinstance(data, dict) else None


class AutoOperator:
    """Start containers, drive local solver runs, submit harvested flags, release containers."""

    def __init__(
        self,
        platform: TSecBenchmarkClient,
        workbench: WorkbenchClient,
        *,
        max_parallel: int = PLATFORM_CONTAINER_LIMIT,
        start_timeout: float = 180.0,
        solve_timeout: float = 660.0,
        poll_interval: float = 5.0,
        autonomy_policy: str = "automatic",
        network_policy: str = DEFAULT_NETWORK_POLICY,
        auto_release_completed: bool = True,
    ):
        self.platform = platform
        self.workbench = workbench
        self.batch = BatchOperator(platform)
        self.max_parallel = max(1, min(max_parallel, PLATFORM_CONTAINER_LIMIT))
        self.start_timeout = start_timeout
        self.solve_timeout = solve_timeout
        self.poll_interval = poll_interval
        self.autonomy_policy = autonomy_policy
        if network_policy not in NETWORK_POLICIES:
            raise ValueError(f"不支持的 network_policy：{network_policy}")
        self.network_policy = network_policy
        self.auto_release_completed = auto_release_completed

    async def _wait_container(self, code: str) -> list[str]:
        deadline = time.monotonic() + self.start_timeout
        while True:
            items = await self.platform.list_challenges()
            item = next((entry for entry in items if entry.get("unique_code") == code), None)
            if item is None:
                raise TSecError(404, "challenge_not_found", f"当前任务不存在题目：{code}")
            addresses = [str(value) for value in item.get("container_addr") or [] if value]
            status = str(item.get("container_status") or "")
            if status == "available" and addresses:
                return addresses
            if status == "stopped":
                raise TSecError(503, "resource_unavailable", "容器未进入可用状态，请检查靶场资源后重试")
            if time.monotonic() >= deadline:
                raise TSecError(503, "resource_unavailable", f"等待容器就绪超时（{int(self.start_timeout)} 秒）")
            await asyncio.sleep(self.poll_interval)

    async def _wait_run(self, run_id: str) -> dict[str, Any]:
        deadline = time.monotonic() + self.solve_timeout
        summary: dict[str, Any] = {}
        while True:
            summary = await self.workbench.run_summary(run_id)
            status = str(summary.get("status") or "")
            if status in TERMINAL_RUN_STATUSES:
                return summary
            if time.monotonic() >= deadline:
                return {**summary, "status": status or "unknown", "stop_reason": summary.get("stop_reason") or
                        f"本地解题等待超时（{int(self.solve_timeout)} 秒）"}
            await asyncio.sleep(self.poll_interval)

    async def _submit_flags(self, code: str, flags: list[str]) -> tuple[list[dict[str, Any]], str | None]:
        """Submit distinct flags; return receipts and a fatal code when the whole task ended."""
        receipts: list[dict[str, Any]] = []
        for flag in flags:
            try:
                reply = await self.platform.submit(code, flag)
            except TSecError as exc:
                if exc.code == "duplicate":
                    receipts.append({"flag": flag, "status": "duplicate", "message": exc.message})
                    continue
                receipts.append({"flag": flag, "status": "error", "code": exc.code, "message": exc.message,
                                 "http_status": exc.status_code})
                if exc.code in FATAL_PLATFORM_CODES:
                    return receipts, exc.code
                if exc.code in UNCERTAIN_PLATFORM_CODES:
                    return receipts, None
                continue
            correct = reply.get("correct") is True
            receipts.append({"flag": flag, "status": "correct" if correct else "incorrect", "response": reply})
        return receipts, None

    async def _process(self, code: str) -> ChallengeOutcome:
        outcome = ChallengeOutcome(unique_code=code, status="error")
        items = await self.platform.list_challenges()
        item = next((entry for entry in items if entry.get("unique_code") == code), None)
        if item is None:
            outcome.message = "当前任务不存在该题目"
            return outcome
        try:
            addresses = await self._wait_container(code)
        except TSecError as exc:
            outcome.message = f"启动失败：{exc.code}"
            return outcome
        outcome.container_addr = addresses
        payload = build_task_payload(item, autonomy_policy=self.autonomy_policy, addresses=addresses,
                                     network_policy=self.network_policy)
        try:
            run_id = await self.workbench.create_task(payload)
        except WorkbenchError as exc:
            outcome.message = f"本地任务创建失败：{exc.message}"
            return outcome
        outcome.run_id = run_id
        summary = await self._wait_run(run_id)
        report = await self.workbench.report(run_id)
        graph = await self.workbench.penetration_graph(run_id)
        flags = harvest_flags(report, graph)
        outcome.flags_found = flags
        if not flags:
            outcome.status = "no_flag"
            outcome.message = f"本地解题未产出 flag（run 状态 {summary.get('status')}）"
            return outcome
        receipts, fatal = await self._submit_flags(code, flags)
        outcome.submissions = receipts
        if fatal:
            outcome.status = "error"
            outcome.message = f"平台鉴权或任务状态异常：{fatal}"
            return outcome
        latest = await self.platform.list_challenges()
        current = next((entry for entry in latest if entry.get("unique_code") == code), None) or {}
        accepted = int(current.get("correct_flag_count") or 0)
        total = int(current.get("flag_count") or len(flags))
        if current.get("is_completed"):
            outcome.status = "completed"
            outcome.message = f"全部 flag 已确认（{accepted}/{total}）"
        else:
            outcome.status = "incomplete"
            outcome.message = f"尚未全部通关（{accepted}/{total}），容器已保留供人工继续"
        return outcome

    async def run(self, codes: list[str], *, include_completed: bool = False) -> list[ChallengeOutcome]:
        items = await self.platform.list_challenges()
        lookup = {str(entry.get("unique_code")): entry for entry in items}
        if codes:
            selected = [code.strip() for code in dict.fromkeys(codes) if code.strip()]
            unknown = [code for code in selected if code not in lookup]
            if unknown:
                raise ValueError("当前任务不存在题目：" + ", ".join(unknown))
        else:
            selected = [code for code, entry in lookup.items() if include_completed or not entry.get("is_completed")]
        if not selected:
            raise ValueError("没有需要处理的题目")
        outcomes: list[ChallengeOutcome] = []
        pending = list(selected)
        while pending:
            snapshot = await self.platform.list_challenges()
            live = {str(entry.get("unique_code")): str(entry.get("container_status") or "stopped")
                    for entry in snapshot}
            active = sum(status != "stopped" for status in live.values())
            free = max(0, self.max_parallel - active)
            # Already-running challenges need no free slot; stopped ones consume one each.
            running = [code for code in pending if live.get(code, "stopped") != "stopped"]
            startable = [code for code in pending if live.get(code, "stopped") == "stopped"][:free]
            wave = running + startable
            if not wave:
                outcomes.extend(ChallengeOutcome(unique_code=code, status="not_attempted",
                                                 message="平台活跃容器已达上限，请先关闭已有题目")
                                for code in pending)
                break
            pending = [code for code in pending if code not in wave]
            start_results = await self.batch.start(wave)
            started = {row["unique_code"]: row for row in start_results}
            runnable = []
            for code in wave:
                row = started.get(code, {})
                if row.get("status") == "existing":
                    runnable.append(code)
                    continue
                if row.get("status") == "started":
                    runnable.append(code)
                    continue
                outcomes.append(ChallengeOutcome(unique_code=code, status="not_attempted",
                                                 message=f"未启动：{row.get('message') or row.get('status')}"))
            if runnable:
                wave_outcomes = await asyncio.gather(*(self._process(code) for code in runnable))
                outcomes.extend(wave_outcomes)
                if self.auto_release_completed:
                    # Release only challenges the platform itself reports as fully solved.
                    # Doing it each wave also frees slots for the next one.
                    released = [row.unique_code for row in wave_outcomes if row.status == "completed"]
                    if released:
                        await self.close(released)
        return outcomes

    async def close(self, codes: list[str]) -> list[dict[str, Any]]:
        return await self.batch.close(codes)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="TSec 全自动闭环：启动容器、创建本地解题任务、提取并提交 flag、释放容器")
    parser.add_argument("--env-file", type=Path, default=Path(".env"), help="读取 BENCHMARK_BASE_URL / BENCHMARK_TOKEN")
    parser.add_argument("--workbench-url", default="http://127.0.0.1:8001", help="本地统一工作台地址")
    parser.add_argument("--output", type=Path, help="保存本次 JSON 结果")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="只读查看题目、进度和容器状态")
    run = commands.add_parser("run", help="对所选题目执行全自动闭环")
    run.add_argument("codes", nargs="*", help="题目编号；省略则处理全部未通关题目")
    run.add_argument("--max-parallel", type=int, default=PLATFORM_CONTAINER_LIMIT, help="并发容器数，平台上限 3")
    run.add_argument("--start-timeout", type=float, default=180.0, help="等待容器就绪的秒数")
    run.add_argument("--solve-timeout", type=float, default=660.0, help="等待本地解题终态的秒数")
    run.add_argument("--poll-interval", type=float, default=5.0, help="轮询间隔秒数")
    run.add_argument("--autonomy-policy", choices=("automatic", "automatic_r3", "graded"),
                     default="automatic")
    run.add_argument("--network-policy", choices=NETWORK_POLICIES, default=DEFAULT_NETWORK_POLICY,
                     help="解题时授予的网络策略；默认 bounded_http（授权地址 GET/HEAD/POST，请求体 ≤4KB）；"
                          "登录态业务题可用 session_http（额外允许复用会话 Cookie 与受限请求头）")
    run.add_argument("--include-completed", action="store_true", help="同时处理已通关题目")
    run.add_argument("--keep-completed", action="store_true", help="不自动释放已通关题目的容器")
    run.add_argument("--close-all", action="store_true", help="处理结束后关闭本批次全部容器")
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    platform = make_client(args.env_file)
    workbench = WorkbenchClient(args.workbench_url)
    operator = AutoOperator(
        platform,
        workbench,
        max_parallel=getattr(args, "max_parallel", PLATFORM_CONTAINER_LIMIT),
        start_timeout=getattr(args, "start_timeout", 180.0),
        solve_timeout=getattr(args, "solve_timeout", 660.0),
        poll_interval=getattr(args, "poll_interval", 5.0),
        autonomy_policy=getattr(args, "autonomy_policy", "automatic"),
        network_policy=getattr(args, "network_policy", DEFAULT_NETWORK_POLICY),
        auto_release_completed=not getattr(args, "keep_completed", False),
    )
    if not platform.config.configured:
        print("失败：请在 an/.env 配置 BENCHMARK_BASE_URL 和 BENCHMARK_TOKEN")
        return 1

    async def execute() -> Any:
        if args.command == "list":
            return await platform.list_challenges()
        selected = [code.strip() for code in getattr(args, "codes", []) if code.strip()]
        outcomes = await operator.run(selected, include_completed=getattr(args, "include_completed", False))
        payload: Any = [outcome.as_dict() for outcome in outcomes]
        if getattr(args, "close_all", False):
            codes = [outcome.unique_code for outcome in outcomes if outcome.container_addr]
            if codes:
                payload = {"outcomes": payload, "closed": await operator.close(codes)}

        return payload

    try:
        result = asyncio.run(execute())
    except (TSecError, ValueError, WorkbenchError, OSError) as exc:
        print(f"失败：{exc}")
        return 1
    output = json.dumps(result, ensure_ascii=False, indent=2)
    print(output)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    if args.command == "list":
        return 0
    rows = result.get("outcomes") if isinstance(result, dict) else result
    bad = {"error", "not_attempted", "incomplete", "no_flag"}
    return int(any(row.get("status") in bad for row in rows))


if __name__ == "__main__":
    raise SystemExit(main())



