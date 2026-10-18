"""Authorization checks for MCP tools that act on network targets."""
from __future__ import annotations

import posixpath
import re
from ipaddress import ip_address
from typing import Any
from urllib.parse import unquote, urlparse

# These bundled tools accept a remote/browser target. Other bundled tools are
# local artifact analyzers; their MCP endpoint being HTTP does not make their
# input a network target.
NETWORK_SERVERS = frozenset({'local-http-fetch', 'local-chrome-devtools'})
# Findings recorders only write into the workbench's own result list.  Their
# ``url``/``request``/``response`` fields describe where a finding was observed;
# the tool itself sends nothing.  Scope-gating them rejects a finding precisely
# because it documents the pivot the run just performed, so evidence already in
# hand could never be written down.
LOCAL_RECORD_TOOLS = frozenset({
    ('local-tscanplus', 'record_finding'),
})
ABSOLUTE_URL = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
HOST_HEADER = re.compile(r'(?im)^Host:\s*([^\s]+)')
TARGET_KEYS = frozenset({
    'target', 'targets', 'target_url', 'url', 'urls', 'uri', 'uris', 'domains',
    'endpoint', 'host', 'hostname', 'domain', 'base_url', 'proxy',
    'proxy_url', 'callback', 'callback_url', 'webhook', 'webhook_url',
    'remote', 'remote_url', 'address', 'server', 'server_url',
    'actualaddr', 'batchtarget', 'dnslogaddr', 'downstreamproxy',
    'sni', 'overwritesni', 'dnservers', 'etchosts',
    'ip', 'ipaddress', 'targethost', 'targetip', 'targetaddress',
    'remotehost', 'remoteip', 'remoteaddress',
    'destinationhost', 'destinationip', 'destinationurl',
    'desthost', 'destip', 'desturl',
    'connecthost', 'connectip', 'connecturl', 'bucket_url',
})
COMPACT_TARGET_KEYS = frozenset(re.sub(r'[_-]', '', key) for key in TARGET_KEYS)


def _target_key(key: Any) -> str:
    return re.sub(r'[_-]', '', str(key).casefold())


def requires_target_scope(server_id: str, arguments: dict[str, Any],
                          tool_name: str | None = None) -> bool:
    if tool_name is not None and (server_id, tool_name) in LOCAL_RECORD_TOOLS:
        return False
    if server_id in NETWORK_SERVERS:
        return True
    return _has_target_key(arguments) or bool(_embedded_targets(arguments))


def _embedded_targets(value: Any) -> list[str]:
    if isinstance(value, str):
        return [*ABSOLUTE_URL.findall(value), *HOST_HEADER.findall(value)]
    if isinstance(value, dict):
        return [target for child in value.values() for target in _embedded_targets(child)]
    if isinstance(value, (list, tuple, set)):
        return [target for child in value for target in _embedded_targets(child)]
    return []


def _has_target_key(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_target_key(key) in COMPACT_TARGET_KEYS | {'targethostname'} or _has_target_key(item)
                   for key, item in value.items())
    if isinstance(value, (list, tuple, set)):
        return any(_has_target_key(item) for item in value)
    return False


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, dict):
        return [item for child in value.values() for item in _strings(child)]
    if isinstance(value, (list, tuple, set)):
        return [item for child in value for item in _strings(child)]
    return []


def _values(arguments: Any, server_id: str) -> list[str]:
    if isinstance(arguments, dict):
        result: list[str] = []
        has_http1_target = 'targetHostname' in arguments
        if has_http1_target:
            result.append(_http1_target({
                'targethostname': arguments['targetHostname'],
                'targetport': arguments.get('targetPort'),
                'useshttps': arguments.get('usesHttps'),
                'content': arguments.get('content'),
            }))
        for key, value in arguments.items():
            compact = _target_key(key)
            if has_http1_target and key in {'targetHostname', 'targetPort', 'usesHttps', 'content'}:
                continue
            if server_id == 'local-tscanplus' and compact in {'domains', 'targets', 'urls'} and isinstance(value, str):
                result.extend(part.strip() for part in value.split(',') if part.strip())
            elif compact in COMPACT_TARGET_KEYS | {'targethostname'}:
                result.extend(_strings(value))
            elif isinstance(value, (dict, list, tuple, set)):
                result.extend(_values(value, server_id))
        return result
    if isinstance(arguments, (list, tuple, set)):
        return [item for value in arguments for item in _values(value, server_id)]
    return [arguments.strip()] if isinstance(arguments, str) and arguments.strip() else []


def target_values(arguments: dict[str, Any], server_id: str = '') -> list[str]:
    """Return network destinations using the same parsing as the scope gate."""
    if server_id == 'local-yakit' and 'request' in arguments:
        try:
            target = yakit_http_target(arguments)
        except ValueError:
            # Malformed/dynamic packets remain subject to boundary review.
            pass
        else:
            rest = {key: value for key, value in arguments.items() if key != 'request'}
            return list(dict.fromkeys([
                target, *_values(rest, server_id), *_embedded_targets(rest),
                *ABSOLUTE_URL.findall(arguments['request']),
            ]))
    embedded_source = {
        key: value for key, value in arguments.items()
        if not ('targetHostname' in arguments and key == 'content')
        and not (server_id == 'local-tscanplus' and _target_key(key) in {'domains', 'targets', 'urls'}
                 and isinstance(value, str))
    }
    return list(dict.fromkeys([*_values(arguments, server_id), *_embedded_targets(embedded_source)]))


def yakit_http_target(arguments: dict[str, Any]) -> str:
    """Resolve a fixed Yakit packet's Host, scheme, port and request path."""
    request = arguments.get('request')
    https = arguments.get('isHttps')
    if not isinstance(request, str) or not isinstance(https, bool):
        raise ValueError('Yakit HTTP 请求必须明确提供 request 和 isHttps')
    header = re.split(r'\r?\n\r?\n', request, maxsplit=1)[0]
    lines = header.splitlines()
    if not lines or not re.fullmatch(r'[A-Z]+ (/[^\s]*) HTTP/1\.[01]', lines[0]):
        raise ValueError('Yakit HTTP 请求行必须使用绝对路径')
    hosts = []
    for line in lines[1:]:
        if not re.fullmatch(r'[A-Za-z0-9!#$%&\'*+.^_`|~-]+:[^\r\n]*', line):
            raise ValueError('Yakit HTTP 请求头格式不明确')
        name, value = line.split(':', 1)
        if name.casefold() == 'host':
            hosts.append(value.strip())
    if len(hosts) != 1:
        raise ValueError('Yakit HTTP 请求必须提供唯一 Host 头')
    host = urlparse('//' + hosts[0])
    try:
        port = host.port if host.port is not None else (443 if https else 80)
    except ValueError as exc:
        raise ValueError('Yakit HTTP Host 头无效') from exc
    if (not host.hostname or host.username or host.password or host.path or host.query
            or host.fragment or any(char.isspace() for char in hosts[0])):
        raise ValueError('Yakit HTTP Host 头无效')
    return _http1_target({'targethostname': host.hostname, 'targetport': port,
                          'useshttps': https, 'content': header})


def _http1_target(arguments: dict[str, Any]) -> str:
    host = arguments.get('targethostname')
    port = arguments.get('targetport')
    https = arguments.get('useshttps')
    content = arguments.get('content')
    if (not isinstance(host, str) or not host or any(char in host for char in '/\\@?#')
            or type(port) is not int or not 1 <= port <= 65535
            or not isinstance(https, bool) or not isinstance(content, str)):
        raise ValueError('HTTP/1 请求目标参数无效')
    authority = f'[{host}]' if ':' in host else host
    parsed_host = urlparse('//' + authority)
    if parsed_host.hostname is None or parsed_host.hostname.casefold() != host.casefold().strip('[]'):
        raise ValueError('HTTP/1 目标主机无效')
    first = content.splitlines()[0] if content.splitlines() else ''
    match = re.fullmatch(r'[A-Z]+ (/[^\s]*) HTTP/1\.[01]', first)
    if not match:
        raise ValueError('HTTP/1 请求行必须使用绝对路径')
    headers = content.splitlines()[1:]
    host_headers = [line.split(':', 1)[1].strip() for line in headers if line.lower().startswith('host:')]
    if len(host_headers) != 1:
        raise ValueError('HTTP/1 请求必须提供唯一 Host 头')
    header = urlparse('//' + host_headers[0])
    try:
        header_port = header.port or (443 if https else 80)
    except ValueError as exc:
        raise ValueError('HTTP/1 Host 头无效') from exc
    if header.hostname != parsed_host.hostname or header_port != port:
        raise ValueError('HTTP/1 Host 头与连接目标不一致')
    scheme = 'https' if https else 'http'
    return f'{scheme}://{authority}:{port}{match.group(1)}'


def _endpoint(value: str):
    if any(ord(char) < 32 for char in value) or '\\' in value:
        return None
    parsed = urlparse(value if '://' in value else '//' + value)
    if not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.casefold()
    if port is None and scheme in {'http', 'https'}:
        port = 443 if scheme == 'https' else 80
    path = parsed.path or '/'
    if '\\' in path or '%25' in path.casefold():
        return None
    path = unquote(path)
    if '\\' in path or any(ord(char) < 32 for char in path):
        return None
    path = posixpath.normpath(path)
    return scheme, parsed.hostname.casefold().rstrip('.'), port, path, parsed.query


def _matches(value: str, scope: str) -> bool:
    target = _endpoint(value)
    allowed = _endpoint(scope)
    if target is None or allowed is None:
        return False
    target_scheme, target_host, target_port, target_path, target_query = target
    allowed_scheme, allowed_host, allowed_port, allowed_path, allowed_query = allowed
    if allowed_scheme and target_scheme and allowed_scheme != target_scheme:
        return False
    if allowed_port is not None and target_port != allowed_port:
        return False
    if allowed_query and target_query != allowed_query:
        return False
    try:
        target_ip, allowed_ip = ip_address(target_host), ip_address(allowed_host)
        host_match = target_ip == allowed_ip
    except ValueError:
        # Subdomains are separate authorization targets unless the operator
        # explicitly lists them in target_scope.
        host_match = target_host == allowed_host
    if not host_match:
        return False
    prefix = allowed_path.rstrip('/') or '/'
    return prefix == '/' or target_path == prefix or target_path.startswith(prefix + '/')


def validate_target_scope(server_id: str, arguments: dict[str, Any], target_scope: list[str],
                          tool_name: str | None = None) -> None:
    """Raise when a network target is absent or outside the task allowlist."""
    if not requires_target_scope(server_id, arguments, tool_name):
        return
    values = target_values(arguments, server_id)
    scopes = [item for item in target_scope if isinstance(item, str) and item.strip()]
    if not values:
        raise ValueError('网络 MCP 工具必须提供任务授权范围内的 target/url')
    if not scopes or not all(any(_matches(value, scope) for scope in scopes) for value in values):
        raise ValueError('MCP 网络目标不在任务授权范围内')
