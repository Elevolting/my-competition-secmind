"""Refresh paths for the four project-owned MCP connections after relocation."""
from pathlib import Path
from security_agent.mcp_catalog import MCPCatalog

root = Path(__file__).resolve().parents[1]
tools = root / '_runtime/tools'
catalog = MCPCatalog(storage_path=root / 'an/data/mcp-catalog.json')
definitions = [
    ('local-yakit', 'Yakit / Yak MCP', 'yak/yak.exe', ['mcp', '--transport', 'stdio']),
    ('local-tscanplus', 'TscanPlus MCP', 'tscanplus/app/TscanPlus_Win_Amd64.exe', ['mcp', 'stdio']),
    ('local-reqable', 'Reqable MCP', 'reqable/app/mcp-server.exe', ['--port', '9001']),
    ('local-burp', 'Burp Suite MCP', None, []),
]
for key, name, executable, args in definitions:
    current = catalog.get_server(key)
    # Keep a user's enabled/disabled choice and any explicit arguments, while
    # always repairing paths and the project-owned Burp endpoint after a move.
    settings = dict(current or {}, server_id=key, name=name,
                    enabled=(current.get('enabled', True) if current else True),
                    transport='stdio' if executable else 'sse',
                    command=str(tools / executable) if executable else '',
                    args=(current.get('args', args) if current and executable else args),
                    url='' if executable else 'http://127.0.0.1:9876')
    if current:
        catalog.update_server(key, settings)
    else:
        settings['purpose'] = name + ' 官方工具连接'
        catalog.create_server(settings)
    print(f'Configured {key}')
