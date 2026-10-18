"""Resumable public-API bridge to the independent SecMind analysis engine."""
from __future__ import annotations

import asyncio
import tempfile
import time
import zipfile
from pathlib import Path
from urllib.parse import quote

import httpx

from security_agent.schemas import Evidence, ToolContext, ToolResult, ToolStatus


async def invoke_secmind(files: list[Path], context: ToolContext, *, domain: str,
                         adapter: str = "secmind_api", wait_for_completion: bool = True) -> ToolResult:
    started = time.monotonic()
    remote = dict(context.external_execution)
    base = (context.module_base_url or '').rstrip('/')
    if not base:
        raise ValueError('SecMind service is not configured')
    headers = {'Authorization': 'Bearer ' + context.module_auth_token} if context.module_auth_token else {}

    async def progress(status, **extra):
        remote.update(module='secmind', adapter=adapter, status=status, **extra)
        context.external_execution.update(remote)
        if context.progress_callback:
            await context.progress_callback(dict(remote))

    def result(status, *, error=None, summary='', report=None, **data):
        report = report or {}
        return ToolResult(status=status, error_code=error, error_message=summary if error else None,
            summary=summary or str(report.get('executive_summary', '')),
            data={'adapter': adapter, 'remote_run_id': remote.get('remote_run_id'),
                  'remote_status': remote.get('status'), 'findings': report.get('findings', []),
                  'answer_payload': report.get('answer_payload'), 'limitations': report.get('limitations', []),
                  'partial_evidence': bool(report) and status != ToolStatus.SUCCESS, **data},
            evidence=[Evidence.model_validate(item) for item in report.get('evidence', [])],
            duration_ms=int((time.monotonic() - started) * 1000))

    async with httpx.AsyncClient(timeout=httpx.Timeout(20, connect=5), headers=headers,
                                 follow_redirects=False, trust_env=False) as client:
        if not remote.get('remote_run_id'):
            if remote.get('status') == 'submitting':
                return result(ToolStatus.ERROR, error='REMOTE_SUBMISSION_UNCERTAIN',
                    summary='上次提交未返回任务 ID，需核对分析引擎；未重复提交')
            if not files:
                raise ValueError('没有可分析的输入文件')
            workspace = Path(context.workspace).resolve()
            safe_files = []
            total = 0
            for path in sorted(files):
                resolved = path.resolve()
                if path.is_symlink() or not resolved.is_relative_to(workspace):
                    raise ValueError('材料超出已授权工作区')
                total += resolved.stat().st_size
                if total > 200 * 1024 * 1024 or len(safe_files) >= 10000:
                    raise ValueError('材料超过分析引擎传输上限；未截断或遗漏文件')
                safe_files.append((resolved, resolved.relative_to(workspace).as_posix()))
            # Preserve relative paths, including identically named files in
            # different directories. Never silently submit just the first 50.
            with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as archive:
                with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as bundle:
                    for path, relative in safe_files:
                        bundle.write(path, relative)
                if archive.tell() > 50 * 1024 * 1024:
                    raise ValueError('压缩后材料超过 50 MiB 上传上限')
                archive.seek(0)
                uploaded = await client.post(base + '/api/v1/uploads',
                    files={'file': ('workspace.zip', archive, 'application/zip')})
            uploaded.raise_for_status()
            reference = uploaded.json().get('ref')
            if not isinstance(reference, str) or not reference:
                raise ValueError('分析引擎未返回有效上传引用')
            await progress('submitting')
            submitted = await client.post(base + '/api/v1/tasks', json={
                'objective': context.task_objective or '分析上传材料并提供可验证证据',
                'attachments': [{'ref': reference, 'name': 'workspace.zip'}],
                'target_scope': context.target_scope, 'constraints': context.task_constraints,
                'expected_outputs': ['security_report'],
                'autonomy_policy': ('automatic' if context.autonomy_policy == 'automatic_r3'
                                    else context.autonomy_policy),
                'primary_domain': domain,
            })
            submitted.raise_for_status()
            remote_id = submitted.json().get('run_id')
            if not isinstance(remote_id, str) or not remote_id:
                raise ValueError('分析引擎未返回有效任务 ID')
            await progress('submitted', remote_run_id=remote_id)

        run_path = base + '/api/v1/runs/' + quote(remote['remote_run_id'], safe='')
        deadline = time.monotonic() + min(context.module_poll_timeout_seconds, 600)
        previous_status = None
        while time.monotonic() < deadline:
            try:
                response = await client.get(run_path)
            except (httpx.TransportError, httpx.TimeoutException):
                # A lost poll response does not change the remote task's identity.
                # Continue against the saved ID until the bounded deadline.
                await asyncio.sleep(context.module_poll_interval_seconds)
                continue
            response.raise_for_status()
            state = response.json()
            if state.get('run_id', remote['remote_run_id']) != remote['remote_run_id']:
                raise ValueError('远程状态与任务身份不匹配')
            status = str(state.get('status', 'unknown'))
            if status != previous_status:
                await progress(status)
                previous_status = status
            if status == 'waiting_approval' and state.get('pending_approval'):
                approval = state['pending_approval']
                request_id = approval.get('request_id')
                if wait_for_completion and request_id in remote.get('resolved_approval_ids', []):
                    await asyncio.sleep(context.module_poll_interval_seconds)
                    continue
                if (wait_for_completion and context.autonomy_policy == 'automatic_r3'
                        and isinstance(request_id, str) and request_id):
                    try:
                        response = await client.post(
                            run_path + '/approvals/' + quote(request_id, safe=''),
                            json={'decision': 'approve', 'resolution_id': request_id,
                                  'reason': '任务已选择免除所有审批'},
                        )
                        response.raise_for_status()
                    except (httpx.HTTPError, httpx.TimeoutException) as exc:
                        return result(ToolStatus.ERROR, error='REMOTE_APPROVAL_RESOLUTION_FAILED',
                                      summary=f'远端审批自动处理失败：{type(exc).__name__}')
                    resolved = list(dict.fromkeys([*remote.get('resolved_approval_ids', []), request_id]))
                    await progress('approval_auto_resolved', resolved_approval_ids=resolved)
                    await asyncio.sleep(context.module_poll_interval_seconds)
                    continue
                return result(ToolStatus.ERROR, error='REMOTE_APPROVAL_REQUIRED',
                    summary='分析引擎的下一步需要操作人审批', remote_approval=approval)
            if status in {'completed', 'partial', 'failed', 'denied', 'cancelled', 'recovery_required', 'waiting_clarification'}:
                try:
                    report_response = await client.get(run_path + '/report')
                except (httpx.TransportError, httpx.TimeoutException):
                    await asyncio.sleep(context.module_poll_interval_seconds)
                    continue
                if report_response.status_code in {404, 409}:
                    if wait_for_completion and status in {'completed', 'partial'}:
                        await asyncio.sleep(context.module_poll_interval_seconds)
                        continue  # Terminal state can precede the sealed report projection.
                    return result(ToolStatus.ERROR, error='REMOTE_' + status.upper(),
                        summary=f'分析引擎状态为 {status}，尚无可读取的报告')
                report_response.raise_for_status()
                report = report_response.json()
                if not isinstance(report, dict) or report.get('run_id') != remote['remote_run_id']:
                    raise ValueError('远程报告与任务身份不匹配')
                completed = status == 'completed' and report.get('status') == 'completed'
                return result(ToolStatus.SUCCESS if completed else ToolStatus.ERROR,
                    error=None if completed else 'REMOTE_' + status.upper(), report=report)
            if not wait_for_completion:
                return result(ToolStatus.ERROR, error='REMOTE_NOT_FINISHED', summary='外部任务仍在运行，报告尚未就绪')
            await asyncio.sleep(context.module_poll_interval_seconds)
        return result(ToolStatus.TIMEOUT, error='REMOTE_POLL_TIMEOUT', summary='分析引擎等待超时，已保留远程任务 ID')
