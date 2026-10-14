"""Stdio MCP bridge for a Dispatcher-assigned Worker, not a separate executor."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from urllib.parse import quote
from uuid import UUID, uuid4

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, TextContent, Tool


def create_server(base_url, project_id, intent_id, worker, receipt_root, *, transport=None):
    server = Server('secmind-blackboard-tools')
    versions = {}
    path = '/api/v1/mcp/blackboard/' + quote(project_id, safe='') + '/' + quote(intent_id, safe='')

    async def request(method, suffix, **kwargs):
        async with httpx.AsyncClient(base_url=base_url, timeout=90, trust_env=False, transport=transport) as client:
            response = await client.request(method, path + suffix, **kwargs)
            response.raise_for_status()
            return response.json()

    @server.list_tools()
    async def list_tools():
        data = await request('GET', '/tools', params={'worker': worker})
        versions.clear()
        versions.update({item['name']: item['version'] for item in data['tools']})
        return [Tool(name=item['name'], description=item['description'], inputSchema=item['inputSchema'])
                for item in data['tools']]

    @server.call_tool()
    async def call_tool(name, arguments):
        if name not in versions:
            await list_tools()
        if name not in versions:
            raise ValueError('Tool is unavailable')
        payload = {
            'worker': worker, 'tool': name, 'arguments': arguments, 'version': versions[name],
            'request_id': str(uuid4()),
        }
        receipt = await request('POST', '/invoke', json=payload)
        while receipt.get('approval_required'):
            await asyncio.sleep(2)
            async with httpx.AsyncClient(base_url=base_url, timeout=20, trust_env=False,
                                         transport=transport) as client:
                response = await client.get('/api/v1/mcp/approvals/' + receipt['approval_id'])
                response.raise_for_status()
                status = response.json()['status']
            if status == 'approved':
                receipt = await request('POST', '/invoke', json=payload)
            elif status != 'pending':
                raise ValueError('MCP 调用审批' + ('已拒绝' if status == 'denied' else '已失效'))
        folder = Path(receipt_root) / '.mcp-results'
        folder.mkdir(parents=True, exist_ok=True)
        # The filename is assigned by our own runtime, never by tool output.
        artifact = folder / (str(UUID(receipt['call_id'])) + '.json')
        raw = json.dumps(receipt, ensure_ascii=False, indent=2)
        artifact.write_text(raw, encoding='utf-8')
        result = receipt.get('result', {})
        output = json.dumps(result, ensure_ascii=False) if result else receipt.get('error', '')
        return CallToolResult(isError=receipt['status'] != 'completed', content=[TextContent(type='text', text=(
            f"Receipt: {artifact}\nStatus: {receipt['status']}\n"
            f"Blackboard: {project_id}/{intent_id}\n{output[:32000]}"
        ))])

    return server


async def main():
    server = create_server(
        os.environ['SECMIND_WORKBENCH_URL'], os.environ['SECMIND_PROJECT_ID'],
        os.environ['SECMIND_INTENT_ID'], os.environ['SECMIND_WORKER_NAME'], Path.cwd(),
    )
    async with stdio_server() as (reader, writer):
        await server.run(reader, writer, server.create_initialization_options())


if __name__ == '__main__':
    asyncio.run(main())
