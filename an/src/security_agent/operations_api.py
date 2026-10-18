from __future__ import annotations

import asyncio
import hashlib
import re
from pathlib import Path
from uuid import uuid4

from fastapi import File, HTTPException, UploadFile
from fastapi.responses import JSONResponse, Response


def register_operations(app, incident, mcp, prompts):
    async def approval_is_live(record):
        state = mcp.ledger.load_state(record['run_id'])
        if state is None or state.status.value != 'running':
            return False
        try:
            _, intent = await app.state.blackboard_assignment(
                record['project_id'], record['intent_id'], record['worker'], with_intent=True,
            )
        except HTTPException:
            return False
        return record.get('attempt_id') == intent.get('attempt_id')

    app.state.mcp_approval_is_live = approval_is_live

    @app.middleware('http')
    async def protect_local_operations(request, call_next):
        is_write = request.method in {'POST', 'PUT', 'DELETE', 'PATCH'} and request.url.path.startswith('/api/v1/')
        is_tsec_hint = request.url.path == '/api/v1/tsec/challenges/hint'
        if is_write or is_tsec_hint:
            origin = request.headers.get('origin')
            settings = getattr(app.state, 'settings', None)
            api_port = getattr(settings, 'api_port', 8001)
            configured_origins = getattr(settings, 'allowed_browser_origins', '')
            allowed = {f'http://{host}:{port}' for host in ('127.0.0.1', 'localhost')
                       for port in (5173, api_port)}
            allowed.update(value.strip() for value in configured_origins.split(',') if value.strip())
            if origin and origin not in allowed:
                return JSONResponse({'detail': '不接受其他站点发起的本机操作'}, status_code=403)
        return await call_next(request)

    @app.post('/api/v1/mcp/servers/{server_id}/discover')
    async def discover(server_id: str):
        return await mcp.probe(server_id)

    @app.post('/api/v1/mcp/servers/{server_id}/invoke')
    async def invoke(server_id: str, payload: dict):
        from security_agent.mcp_agent import PURE_TOOLS

        tool_name = str(payload.get('tool', ''))
        if tool_name not in PURE_TOOLS.get(server_id, set()):
            raise HTTPException(403, '非纯 MCP 工具必须由任务黑板意图逐次审批后调用')
        if payload.get('run_id'):
            raise HTTPException(403, '关联任务调用必须由任务黑板意图调度')
        try:
            return await mcp.invoke(server_id, tool_name, payload.get('arguments', {}),
                                    payload.get('approved') is True, None,
                                    request_id=payload.get('request_id'))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get('/api/v1/mcp/receipts')
    async def receipts():
        return {'receipts': mcp.store.recent('mcp')}

    @app.get('/api/v1/mcp/approvals/{approval_id}')
    async def mcp_approval_status(approval_id: str):
        record = mcp.store.mcp_approval(approval_id)
        if record is None:
            raise HTTPException(404, 'MCP 审批请求不存在')
        if not await approval_is_live(record):
            return {'approval_id': approval_id, 'status': 'expired'}
        return {'approval_id': approval_id, 'status': record['status']}

    @app.post('/api/v1/mcp/approvals/{approval_id}')
    async def decide_mcp_approval(approval_id: str, payload: dict):
        decision = payload.get('decision')
        if decision not in {'approve', 'deny'}:
            raise HTTPException(422, '审批决定必须是 approve 或 deny')
        record = mcp.store.mcp_approval(approval_id)
        if record is None:
            raise HTTPException(404, 'MCP 审批请求不存在')
        state = mcp.ledger.load_state(record['run_id'])
        if state is None or state.status.value != 'running':
            raise HTTPException(409, '任务已结束，不能审批 MCP 调用')
        _, intent = await app.state.blackboard_assignment(record['project_id'], record['intent_id'],
                                                          record['worker'], with_intent=True)
        if record.get('attempt_id') != intent.get('attempt_id'):
            raise HTTPException(409, '审批对应的执行尝试已变更')
        if record['server_id'] == 'workbench-native':
            registry = getattr(app.state, 'workbench_tool_registry', None)
            try:
                tool = registry.get(record['tool_name'])
                matching = [tool] if record['version'] == f'workbench:{record["tool_name"]}:{tool.manifest.version}' else []
            except (AttributeError, KeyError):
                matching = []
        else:
            await mcp.refresh_agent_tools()
            matching = [tool for server, tool in mcp.agent_tools()
                        if server['server_id'] == record['server_id'] and tool['name'] == record['tool_name']
                        and mcp.connection_fingerprint(server) + ':' + mcp.tool_fingerprint(tool) == record['version']]
        if not matching:
            raise HTTPException(409, 'MCP 工具连接或协议已变更，不能批准旧请求')
        status = 'approved' if decision == 'approve' else 'denied'
        updated = mcp.store.transition_mcp_approval(approval_id, 'pending', status)
        if updated is None:
            if record['status'] != status:
                raise HTTPException(409, 'MCP 审批状态已变化')
            return {'approval_id': approval_id, 'status': status}
        mcp.ledger.append(record['run_id'], 'mcp.approval.' + status, {
            'approval_id': approval_id, 'project_id': record['project_id'],
            'intent_id': record['intent_id'], 'server_id': record['server_id'],
            'tool_name': record['tool_name'],
        }, actor='operator')
        return {'approval_id': approval_id, 'status': updated['status']}

    @app.put('/api/v1/prompts/{key}')
    async def update_prompt(key: str, payload: dict):
        try:
            return prompts.update(key, payload.get('content'), payload.get('expected_checksum'))
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get('/api/v1/prompts/{key}/history')
    async def prompt_history(key: str):
        return {'history': prompts.store.recent('prompt:' + key, 30)}

    @app.post('/api/v1/incident/samples')
    async def upload_sample(file: UploadFile = File(...)):
        name = Path(file.filename or 'sample.bin').name
        reserved_name = re.fullmatch(r'(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', name, re.IGNORECASE)
        if (not name or name in {'.', '..'} or reserved_name or name.rstrip(' .') != name
                or any(ord(char) < 32 or char in ':<>"|?*\\' for char in name)):
            raise HTTPException(422, '文件名无效')
        folder = incident.root / 'samples' / str(uuid4())
        folder.mkdir()
        path = folder / name
        size = 0
        digest = hashlib.sha256()
        try:
            with path.open('xb') as out:
                while chunk := await file.read(1024 * 1024):
                    size += len(chunk)
                    if size > 100 * 1024 * 1024:
                        raise HTTPException(413, '样本上限为 100 MiB')
                    out.write(chunk)
                    digest.update(chunk)
        except BaseException:
            path.unlink(missing_ok=True)
            folder.rmdir()
            raise
        finally:
            await file.close()
        return {'path': str(path), 'sha256': digest.hexdigest(), 'bytes': size}

    @app.get('/api/v1/incident/evidence/{evidence_id}')
    async def evidence(evidence_id: str):
        try:
            content, receipt, canonical_id = await asyncio.to_thread(incident.verified_evidence, evidence_id)
        except (KeyError, FileNotFoundError) as exc:
            raise HTTPException(404, '证据不存在') from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return Response(content, media_type='application/json', headers={
            'Content-Disposition': f'attachment; filename="host-evidence-{canonical_id}.json"',
            'X-Evidence-SHA256': receipt['sha256'],
        })
