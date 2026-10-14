"""MCP initialize/list/call over official transports, with persisted receipts."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
from uuid import NAMESPACE_URL, uuid4, uuid5

import jsonschema
from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client

from security_agent.mcp_scope import validate_target_scope
from security_agent.operations import OperationsStore

_UNSET = object()


def exception_text(exc):
    if isinstance(exc, BaseExceptionGroup):
        return '; '.join(exception_text(child) for child in exc.exceptions)
    return str(exc) or type(exc).__name__


class MCPRuntime:
    def __init__(self, catalog, root, allowed_roots, ledger, *, kali_enabled: bool = False, kali_container: str = 'security-runtime-kali'):
        self.catalog = catalog
        self.store = OperationsStore(root / 'mcp-runtime.db')
        self.allowed_roots = allowed_roots
        self.ledger = ledger
        self.kali_enabled = kali_enabled
        self.kali_container = kali_container
        self._semaphore = asyncio.Semaphore(3)
        self._discovery_lock = asyncio.Lock()
        for key, receipt in self.store.items('call:'):
            if receipt['status'] == 'running':
                receipt.update(
                    status='interrupted',
                    error='服务重启前没有收到完成回执；不会自动重放工具调用',
                    completed_at=datetime.now(UTC).isoformat(),
                    recovered_at_startup=True,
                )
                self.store.finish_mcp_call(receipt)
            # A restart can occur after saving the recovery receipt but before
            # appending its Ledger event. The stable event ID makes replay safe.
            if receipt.get('recovered_at_startup') and receipt.get('run_id'):
                self.ledger.append(
                    receipt['run_id'], 'mcp.call.interrupted', receipt,
                    actor='mcp_runtime',
                    event_id=str(uuid5(NAMESPACE_URL, 'mcp-recovery:' + receipt['call_id'])),
                )

    def builtin(self):
        return {'server_id': 'secmind-local', 'name': 'SecMind 本机分析', 'purpose': 'Bandit 代码安全扫描、文件哈希、Python AST 与 Base64 分析',
                'transport': 'stdio', 'command': sys.executable, 'args': ['-m', 'security_agent.local_mcp'],
                'enabled': True, 'displayable': True, 'candidate': False, 'tools': [], 'builtin': True}

    def kali_builtin(self):
        return {'server_id': 'kali-tools', 'name': 'Kali 受控扫描器',
                'purpose': '通过固定参数在 security-runtime-kali 中执行受控扫描；主动检测逐次审批',
                'transport': 'stdio', 'command': sys.executable, 'args': ['-m', 'security_agent.kali_mcp'],
                'enabled': True, 'displayable': True, 'candidate': False, 'tools': [], 'builtin': True}

    def server(self, key):
        if key == 'secmind-local':
            result = self.builtin()
        elif key == 'kali-tools' and self.kali_enabled:
            result = self.kali_builtin()
        else:
            result = self.catalog.get_server(key)
        if result is None:
            raise ValueError('MCP Server 不存在')
        if not result.get('enabled'):
            raise ValueError('请先在 Server 配置中启用实际连接')
        return result

    async def wait_for_request(self, request_key: str) -> dict:
        async with asyncio.timeout(65):
            while True:
                receipt = self.store.mcp_request_receipt(request_key)
                if receipt and receipt.get('status') != 'running':
                    return receipt
                await asyncio.sleep(0.1)

    @asynccontextmanager
    async def session(self, server, *, allowed_roots=None):
        if server['server_id'] == 'local-tscanplus':
            from security_agent.bundled_integrity import tscanplus_trusted
            if not tscanplus_trusted(server):
                raise ValueError('TscanPlus 二进制签名未通过校验，已停止连接')
        async with AsyncExitStack() as stack:
            transport = server['transport']
            if transport == 'stdio':
                command = server.get('command', '')
                if not command:
                    raise ValueError('stdio 需要可执行程序及参数数组，不支持 shell 命令串')
                roots = self.allowed_roots if allowed_roots is None else allowed_roots
                # Several bundled third-party MCP binaries enable coloured
                # diagnostic output by default.  Their stdout is the JSON-RPC
                # transport, so an ANSI log line corrupts the stream before
                # the first response.  Disable terminal decorations for every
                # stdio child; diagnostics still belong on stderr.
                env = {'SECMIND_MCP_ROOTS': os.pathsep.join(str(p.resolve()) for p in roots),
                       'PYTHONIOENCODING': 'utf-8', 'NO_COLOR': '1', 'TERM': 'dumb', 'CI': '1'}
                if server.get('server_id') == 'kali-tools':
                    env['SECMIND_KALI_CONTAINER'] = self.kali_container
                args = server.get('args', [])
                if server['server_id'] == 'local-tscanplus':
                    args = ['-m', 'security_agent.tscanplus_stdio', command, *args]
                    command = sys.executable
                streams = await stack.enter_async_context(stdio_client(StdioServerParameters(
                    command=command, args=args, env=env)))
            elif transport in {'streamable_http', 'sse'}:
                url = server.get('url', '')
                parsed = urlparse(url)
                if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password:
                    raise ValueError('需要不含内嵌凭据的 HTTP(S) URL')
                factory = streamablehttp_client if transport == 'streamable_http' else sse_client
                streams = await stack.enter_async_context(factory(url))
            else:
                raise ValueError('纯目录条目不能连接，请设置 MCP 传输协议')
            read_timeout = 90 if server['server_id'] == 'kali-tools' else 45
            session = await stack.enter_async_context(ClientSession(
                streams[0], streams[1], read_timeout_seconds=timedelta(seconds=read_timeout)))
            await session.initialize()
            yield session

    async def _tools(self, session):
        result, cursor = [], None
        for _ in range(20):
            page = await session.list_tools(cursor=cursor)
            result.extend(tool.model_dump(mode='json', by_alias=True) for tool in page.tools)
            if not page.nextCursor:
                return result
            if page.nextCursor == cursor:
                raise ValueError('MCP 工具分页游标未前进')
            cursor = page.nextCursor
        raise ValueError('MCP 工具目录超过分页限制')

    async def probe(self, key):
        record = {'checked_at': datetime.now(UTC).isoformat(), 'status': 'unavailable', 'tools': []}
        try:
            server = self.server(key)
            record['connection_fingerprint'] = self.connection_fingerprint(server)
            async with self._semaphore, asyncio.timeout(35), self.session(server) as session:
                record.update(status='connected', tools=await self._tools(session))
        except Exception as exc:
            record['error'] = exception_text(exc)
        self.store.put('probe:' + key, record)
        return record

    @staticmethod
    def connection_fingerprint(server):
        connection = {key: server.get(key) for key in ('server_id', 'transport', 'command', 'args', 'url')}
        return hashlib.sha256(json.dumps(connection, sort_keys=True).encode()).hexdigest()

    @staticmethod
    def tool_fingerprint(tool):
        return hashlib.sha256(json.dumps(tool, sort_keys=True).encode()).hexdigest()

    def agent_servers(self):
        builtins = [self.builtin()]
        if self.kali_enabled:
            builtins.append(self.kali_builtin())
        return [*builtins, *[s for s in self.catalog.servers() if s.get('enabled')]]

    async def refresh_agent_tools(self):
        async with self._discovery_lock:
            pending = []
            for server in self.agent_servers():
                record = self.store.get('probe:' + server['server_id'], {})
                try:
                    fresh = datetime.now(UTC) - datetime.fromisoformat(record['checked_at']) < timedelta(seconds=60)
                except (KeyError, ValueError):
                    fresh = False
                if not fresh or record.get('connection_fingerprint') != self.connection_fingerprint(server):
                    pending.append(self.probe(server['server_id']))
            await asyncio.gather(*pending)

    def agent_tools(self):
        for server in self.agent_servers():
            if server['server_id'] == 'local-tscanplus':
                from security_agent.bundled_integrity import tscanplus_trusted
                if not tscanplus_trusted(server):
                    continue
            probe = self.store.get('probe:' + server['server_id'], {})
            if probe.get('status') == 'connected' and probe.get('connection_fingerprint') == self.connection_fingerprint(server):
                for tool in probe.get('tools', []):
                    yield server, tool

    def catalog_payload(self):
        payload = self.catalog.payload()
        builtins = [self.builtin(), *([self.kali_builtin()] if self.kali_enabled else [])]
        servers = [*builtins, *payload['servers']]
        for server in servers:
            probe = self.store.get('probe:' + server['server_id'])
            if server['server_id'] == 'local-tscanplus':
                from security_agent.bundled_integrity import tscanplus_trusted
                if not tscanplus_trusted(server):
                    probe = {'status': 'untrusted', 'tools': [],
                             'error': 'TscanPlus Authenticode 签名校验失败'}
            server['connection'] = probe or {'status': 'unchecked', 'tools': []}
        return {**payload, 'servers': servers, 'server_count': len(servers), 'runtime_enabled': True,
                'invocation_enabled': True, 'tool_registration': 'task_agent',
                'agent_tool_count': sum(1 for _ in self.agent_tools()),
                'receipts': self.store.recent('mcp', 30)}

    async def invoke(self, key, tool_name, arguments, approved=False, run_id=None,
                     expected_connection=None, expected_tool=None, blackboard=None,
                     before_call=_UNSET, request_id=None, scope_override_approval_id=None,
                     scope_override_step_id=None):
        if not approved:
            raise ValueError('实际调用需要操作人确认 approved=true')
        if not isinstance(arguments, dict):
            raise ValueError('arguments 必须是 JSON 对象')
        if key == 'local-tscanplus':
            from security_agent.bundled_integrity import tscanplus_trusted
            if not tscanplus_trusted(self.server(key)):
                raise ValueError('TscanPlus 二进制签名未通过校验，已停止调用')
        state = None
        scope_override = False
        if run_id:
            state = self.ledger.load_state(run_id)
            if state is None:
                raise ValueError('关联任务不存在')
            # An explicitly supplied ``before_call`` is an internal low-level
            # hook used by cancellation tests. Production adapters always
            # leave it at the sentinel and must provide a blackboard binding.
            if not blackboard and before_call is _UNSET:
                raise ValueError('关联任务的 MCP 调用必须由黑板意图调度')
            from security_agent.mcp_agent import PURE_TOOLS
            if tool_name not in PURE_TOOLS.get(key, set()):
                if (scope_override_approval_id and blackboard and request_id
                        and expected_connection and expected_tool):
                    call_scope = ':'.join(filter(None, (blackboard['intent_id'], blackboard.get('attempt_id'))))
                    request_key = ':'.join((run_id, blackboard['project_id'], call_scope, request_id))
                    record = self.store.mcp_approval_for_request(request_key)
                    scope_override = bool(record and record['approval_id'] == scope_override_approval_id
                        and record['status'] == 'approved' and record['server_id'] == key
                        and record['tool_name'] == tool_name and record['arguments'] == arguments
                        and record.get('version') == expected_connection + ':' + expected_tool
                        and record.get('policy_reasons'))
                if scope_override_step_id and expected_connection and expected_tool:
                    from security_agent.mcp_agent import tool_id
                    digest = hashlib.sha256(json.dumps([tool_id(key, tool_name), arguments],
                        sort_keys=True, ensure_ascii=False).encode()).hexdigest()
                    step = next((item for item in state.plan if item.step_id == scope_override_step_id), None)
                    scope_override = scope_override or bool(step and step.tool_version ==
                        expected_connection + ':' + expected_tool and any(
                            item.get('step_id') == scope_override_step_id
                            and item.get('parameters_sha256') == digest
                            and int(item.get('risk_level', -1)) >= 3
                            and item.get('decision') in {'approve', 'edit'} for item in state.approvals))
                if not scope_override:
                    validate_target_scope(key, arguments, list(state.task.target_scope))
        task_roots = None
        if blackboard:
            if state is None or not state.workspace:
                raise ValueError('黑板任务缺少已登记的工作区')
            workspace = await asyncio.to_thread(Path(state.workspace).resolve, strict=True)
            if not await asyncio.to_thread(workspace.is_dir):
                raise ValueError('黑板任务工作区不可用')
            task_roots = [workspace]
            if scope_override:
                from security_agent.mcp_boundaries import PATH_KEYS
                for field, value in arguments.items():
                    if re.sub(r'[_-]', '', str(field).casefold()) not in PATH_KEYS or not isinstance(value, str):
                        continue
                    candidate = Path(value)
                    resolved = (candidate if candidate.is_absolute() else workspace / candidate).resolve()
                    if not resolved.is_relative_to(workspace) and resolved.exists():
                        task_roots.append(resolved)
        idempotency_key = None
        if request_id is not None:
            if not isinstance(request_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{8,200}', request_id):
                raise ValueError('MCP request_id 无效')
            scope = ':'.join(filter(None, (blackboard.get('intent_id'), blackboard.get('attempt_id')))) if blackboard else ''
            idempotency_key = f"{run_id or 'anonymous'}:{scope}:{request_id}"
        receipt = {'call_id': str(uuid4()), 'server_id': key, 'tool': tool_name, 'arguments': arguments,
                   'approved': True, 'run_id': run_id, 'started_at': datetime.now(UTC).isoformat(), 'status': 'running'}
        if blackboard:
            receipt['blackboard'] = dict(blackboard)
        if idempotency_key:
            receipt['idempotency_key'] = idempotency_key
            claimed, existing = self.store.claim_mcp_request(idempotency_key, receipt['call_id'], receipt)
            if not claimed:
                if not existing or any(existing.get(field) != receipt.get(field)
                                       for field in ('server_id', 'tool', 'arguments', 'run_id', 'blackboard')):
                    raise ValueError('MCP request_id 已用于不同的工具调用')
                if existing.get('status') == 'running':
                    try:
                        return await self.wait_for_request(idempotency_key)
                    except TimeoutError as exc:
                        raise ValueError('MCP 调用仍在运行，请稍后使用相同 request_id 重试') from exc
                return existing
        else:
            # Keep non-idempotent calls recoverable while the transport is running.
            self.store.put('call:' + receipt['call_id'], receipt)
        call_started = False
        try:
            server = self.server(key)
            if expected_connection and expected_connection != self.connection_fingerprint(server):
                raise ValueError('MCP 连接配置已变更，请重新规划')
            session = self.session(server, allowed_roots=task_roots) if blackboard else self.session(server)
            async with self._semaphore, asyncio.timeout(60), session as client:
                tools = await self._tools(client)
                tool = next((tool for tool in tools if tool['name'] == tool_name), None)
                if tool is None:
                    raise ValueError('服务端没有提供此工具，请重新发现工具')
                if expected_tool and expected_tool != self.tool_fingerprint(tool):
                    raise ValueError('MCP 工具协议已变更，请重新发现并规划')
                jsonschema.validate(arguments, tool['inputSchema'])
                current = self.server(key)
                if self.connection_fingerprint(current) != self.connection_fingerprint(server):
                    raise ValueError('MCP 连接配置已变更，请重新规划')
                if before_call is not _UNSET and before_call is not None:
                    await before_call()
                call_started = True
                if run_id:
                    self.ledger.append(run_id, 'mcp.call.started', receipt, actor='mcp_runtime',
                                       event_id=str(uuid5(NAMESPACE_URL, 'mcp-start:' + receipt['call_id'])))
                result = await client.call_tool(tool_name, arguments)
                receipt.update(status='failed' if result.isError else 'completed', result=result.model_dump(mode='json', by_alias=True))
        except asyncio.CancelledError:
            receipt.update(
                status='interrupted' if call_started else 'cancelled',
                error='调用取消时工具结果未确认' if call_started else '调用在发送工具请求前取消',
            )
            raise
        except Exception as exc:
            receipt.update(status='failed', error=exception_text(exc))
        finally:
            receipt['completed_at'] = datetime.now(UTC).isoformat()
            self.store.finish_mcp_call(receipt)
            if run_id:
                self.ledger.append(run_id, 'mcp.call.' + receipt['status'], receipt, actor='mcp_runtime',
                                   event_id=str(uuid5(NAMESPACE_URL, 'mcp-finish:' + receipt['call_id'])))
        return receipt
