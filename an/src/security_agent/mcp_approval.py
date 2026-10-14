"""Review rules for MCP calls made from a blackboard intent."""
from __future__ import annotations

import re

from security_agent.mcp_agent import PURE_TOOLS
from security_agent.mcp_scope import _http1_target

REVIEWED_READ_ONLY = {
    'secmind-local': {'hash_file', 'inspect_python', 'audit_python'},
    'kali-tools': {'kali_tool_version', 'nmap_scan', 'naabu_scan',
                   'whatweb_fingerprint', 'katana_crawl'},
}

# These calls expose server-wide state without a target that can be checked
# against the task scope. Risk-tier autonomy does not authorize that access.
GLOBAL_STATE_TOOLS = {
    'local-yakit': {'query_ports', 'get_mitm_filter'},
    'local-tscanplus': {'query_results', 'route_candidates'},
    'local-reqable': {'capture_breakpoint_get_config', 'capture_rewrite_get_config'},
}


def requires_context_approval(server_id: str, tool_name: str) -> bool:
    return tool_name in GLOBAL_STATE_TOOLS.get(server_id, set())

_R3_NAME = re.compile(r'(?:^|_)(?:delete|remove|wipe|drop|destroy|format|ransomware|'
                      r'reverse_shell|credential_theft|persistence|disable_security)(?:_|$)')


def destructive_tool(server_id: str, tool_name: str, server_risk: str | None = None) -> bool:
    # The bundled extended-analysis server is labelled R3 as an inventory;
    # its read-only analyzers do not inherit that label as destructive actions.
    return bool(_R3_NAME.search(tool_name.casefold())) or (server_risk == 'R3' and server_id != 'local-security-extended')


def offline_safe(server_id: str, tool_name: str) -> bool:
    return (tool_name in PURE_TOOLS.get(server_id, set())
            or server_id == 'secmind-local'
            or server_id == 'kali-tools' and tool_name == 'kali_tool_version')


def _burp_read_only_http1(arguments: dict) -> bool:
    if set(arguments) != {'content', 'targetHostname', 'targetPort', 'usesHttps'}:
        return False
    content = arguments.get('content')
    if not isinstance(content, str) or '\r\n\r\n' not in content:
        return False
    head, body = content.split('\r\n\r\n', 1)
    if body or '\n' in head.replace('\r\n', ''):
        return False
    lines = head.split('\r\n')
    if not re.fullmatch(r'(GET|HEAD) /[^\s]* HTTP/1\.[01]', lines[0]):
        return False
    names = []
    for line in lines[1:]:
        if ':' not in line or line.startswith((' ', '\t')):
            return False
        name, value = line.split(':', 1)
        name = name.casefold()
        if name not in {'host', 'connection'}:
            return False
        if name == 'connection' and value.strip().casefold() not in {'close', 'keep-alive'}:
            return False
        names.append(name)
    if names.count('host') != 1 or names.count('connection') > 1:
        return False
    try:
        _http1_target({key.casefold(): value for key, value in arguments.items()})
    except ValueError:
        return False
    return True


def _tscanplus_read_only_http(arguments: dict) -> bool:
    allowed = {'url', 'method', 'body', 'headers', 'cookie', 'follow_redirect',
               'path_as_is', 'timeout', 'max_bytes', 'max_lines'}
    return (set(arguments) <= allowed
            and isinstance(arguments.get('url'), str)
            and str(arguments.get('method', 'GET')).upper() in {'GET', 'HEAD'}
            and arguments.get('body') in (None, '')
            and arguments.get('headers') in (None, '')
            and arguments.get('cookie') in (None, '')
            and arguments.get('follow_redirect', False) is False)


def requires_approval(server_id: str, tool_name: str, arguments: dict) -> bool:
    if tool_name in PURE_TOOLS.get(server_id, set()):
        return False
    if tool_name in REVIEWED_READ_ONLY.get(server_id, set()):
        return False
    if server_id == 'local-burp' and tool_name == 'send_http1_request':
        return not _burp_read_only_http1(arguments)
    if server_id == 'local-tscanplus' and tool_name == 'http_request':
        return not _tscanplus_read_only_http(arguments)
    return True
