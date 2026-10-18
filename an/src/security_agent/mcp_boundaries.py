"""Conservative checks for connected tools with unstructured destinations."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from security_agent.mcp_scope import yakit_http_target


YAKIT_FIXED_HTTP_KEYS = frozenset({
    'request', 'isHttps', 'fuzzTagMode', 'noFollowRedirect',
    'perRequestTimeoutSeconds', 'repeatTimes', 'concurrent', 'noSystemProxy',
    'disableUseConnPool', 'noFixContentLength', 'responseCharset', 'isGmTls', 'randomJA3',
})

UNSCOPED_NETWORK_TOOLS = {
    'local-yakit': {'http_fuzzer', 'execute_web_fuzzer_tab', 'start_mitm_v2',
                    'start_facades', 'require_dnslog_domain', 'require_random_port_token'},
}
PATH_KEYS = frozenset({'path', 'filepath', 'filename', 'file', 'targetsfile',
                       'inputfile', 'outputfile', 'directory', 'folder'})
TOOL_PATH_KEYS = {
    ('local-tscanplus', 'dir_scan'): frozenset({'dict'}),
    ('local-tscanplus', 'jwt_crack'): frozenset({'dict'}),
    ('local-tscanplus', 'pwd_crack'): frozenset({'pairf'}),
    ('local-tscanplus', 'subdomain_scan'): frozenset({'subdict'}),
    ('local-tscanplus', 'tscan_scan'): frozenset({'crackpairf', 'dirdict', 'subdict'}),
}


class AmbiguousMCPPathError(ValueError):
    pass


def validate_workbench_arguments(server_id: str, tool_name: str,
                                 arguments: dict[str, Any], workspace: Path) -> None:
    if tool_name in UNSCOPED_NETWORK_TOOLS.get(server_id, set()):
        if server_id == 'local-yakit' and tool_name == 'http_fuzzer':
            # A closed fuzztag engine and disabled redirects make a fixed raw
            # packet as scopeable as a structured HTTP request. Connection
            # overrides, batch targets and unknown options still need review.
            if (arguments.get('fuzzTagMode') != 'close'
                    or arguments.get('noFollowRedirect') is not True
                    or arguments.keys() - YAKIT_FIXED_HTTP_KEYS):
                raise ValueError('此 MCP 工具的原始请求或动态目标无法可靠限定在授权范围内')
            yakit_http_target(arguments)
        else:
            raise ValueError('此 MCP 工具的原始请求或动态目标无法可靠限定在授权范围内')
    if server_id == 'local-yakit' and tool_name == 'port_scan':
        targets = arguments.get('targets', [])
        if (arguments.get('enableCClassScan') or arguments.get('enableBrute')
                or arguments.get('targetsFile') or not isinstance(targets, list)
                or any(not isinstance(target, str) or '/' in target for target in targets)):
            raise ValueError('端口扫描仅允许明确列出的单个主机，不允许网段扩展或文件目标')

    root = workspace.resolve(strict=True)
    path_keys = PATH_KEYS | TOOL_PATH_KEYS.get((server_id, tool_name), frozenset())

    def inspect_path(value: Any) -> None:
        if isinstance(value, str) and value.strip():
            candidate = Path(value)
            if not candidate.is_absolute():
                raise AmbiguousMCPPathError('MCP 文件参数必须使用任务工作区内的绝对路径')
            resolved = candidate.resolve()
            if not resolved.is_relative_to(root):
                raise ValueError('MCP 文件参数超出任务工作区')
        elif isinstance(value, list):
            for item in value:
                inspect_path(item)

    def inspect(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                compact = re.sub(r'[_-]', '', str(key).casefold())
                if compact in path_keys:
                    inspect_path(item)
                inspect(item)
        elif isinstance(value, list):
            for item in value:
                inspect(item)

    inspect(arguments)
