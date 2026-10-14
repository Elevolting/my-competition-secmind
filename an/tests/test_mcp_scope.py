import pytest

from security_agent.mcp_boundaries import validate_workbench_arguments
from security_agent.mcp_scope import target_values, validate_target_scope


def test_network_mcp_requires_an_authorized_target():
    with pytest.raises(ValueError, match='授权范围内'):
        validate_target_scope('local-http-fetch', {'url': 'https://outside.test/'}, [])
    with pytest.raises(ValueError, match='不在任务授权范围内'):
        validate_target_scope('local-http-fetch', {'url': 'https://outside.test/'}, ['https://target.test'])


def test_network_mcp_accepts_scoped_host_and_rejects_sibling_host():
    validate_target_scope('local-http-fetch', {'url': 'https://target.test/path/a'}, ['https://target.test'])
    with pytest.raises(ValueError):
        validate_target_scope('local-http-fetch', {'url': 'https://target.test:444/'}, ['https://target.test'])
    with pytest.raises(ValueError):
        validate_target_scope('local-http-fetch', {'url': 'https://evil.target.test/'}, ['https://target.test'])


def test_query_bearing_scope_requires_the_same_query():
    scope = ['https://target.test/app?tenant=one']
    validate_target_scope('local-http-fetch', {'url': 'https://target.test/app?tenant=one'}, scope)
    with pytest.raises(ValueError, match='不在任务授权范围内'):
        validate_target_scope('local-http-fetch', {'url': 'https://target.test/app?tenant=two'}, scope)
    with pytest.raises(ValueError, match='不在任务授权范围内'):
        validate_target_scope('local-http-fetch', {'url': 'https://target.test/app'}, scope)
    validate_target_scope('local-http-fetch',
                          {'url': 'https://target.test/app?tenant=two'}, ['https://target.test/app'])


def test_http_method_is_not_parsed_as_another_network_target():
    validate_target_scope('local-tscanplus',
                          {'url': 'https://target.test/app/page', 'method': 'GET', 'follow_redirect': False},
                          ['https://target.test/app/'])


def test_local_tools_with_local_paths_do_not_need_network_scope():
    validate_target_scope('secmind-local', {'path': 'sample.py'}, [])
    validate_target_scope('local-web-security', {'path': 'sample.py'}, [])


def test_nested_network_targets_cannot_bypass_scope():
    validate_target_scope('third-party', {'request': {'url': 'https://target.test/app'}},
                          ['https://target.test/app'])
    with pytest.raises(ValueError, match='不在任务授权范围内'):
        validate_target_scope('third-party', {'request': {'url': 'https://outside.test/'}},
                              ['https://target.test/'])
    with pytest.raises(ValueError, match='不在任务授权范围内'):
        validate_target_scope('third-party', {'options': {'targets': [
            {'url': 'https://target.test/'}, {'url': 'https://outside.test/'}]}},
            ['https://target.test/'])


def test_yakit_aliases_cannot_redirect_network_calls():
    for arguments in ({'actualAddr': 'outside.test:443'},
                      {'batchTarget': ['https://outside.test/']},
                      {'dnsLogAddr': 'outside.test:443'}):
        with pytest.raises(ValueError):
            validate_target_scope('local-yakit', arguments, ['https://target.test/'])


def test_tscanplus_domains_and_bucket_url_are_scoped():
    validate_target_scope('local-tscanplus', {'domains': 'target.test'}, ['target.test'])
    with pytest.raises(ValueError, match='不在任务授权范围内'):
        validate_target_scope('local-tscanplus',
                              {'domains': 'target.test, outside.test'}, ['target.test'])
    with pytest.raises(ValueError, match='不在任务授权范围内'):
        validate_target_scope('local-tscanplus',
                              {'bucket_url': 'https://outside.test/bucket'},
                              ['https://target.test/'])
    for key in ('domains', 'targets', 'urls'):
        values = 'target.test, outside.test' if key == 'domains' else (
            'https://target.test/, https://outside.test/')
        assert len(target_values({key: values}, 'local-tscanplus')) == 2
        with pytest.raises(ValueError, match='不在任务授权范围内'):
            validate_target_scope('local-tscanplus', {key: values},
                                  ['target.test' if key == 'domains' else 'https://target.test/'])


@pytest.mark.parametrize('arguments', [
    {'targetHost': 'outside.test:443'},
    {'target_host': 'outside.test:443'},
    {'target-ip': '192.0.2.20'},
    {'remoteHost': 'outside.test:443'},
    {'destinationUrl': 'https://outside.test/'},
    {'options': {'connect_host': 'outside.test:443'}},
    {'ipAddress': '192.0.2.20'},
    {'targetAddress': 'outside.test:443'},
    {'destHost': 'outside.test:443'},
])
def test_network_target_aliases_cannot_bypass_scope(arguments):
    with pytest.raises(ValueError, match='不在任务授权范围内'):
        validate_target_scope('third-party', arguments, ['https://target.test/'])


def test_embedded_absolute_urls_and_host_headers_are_scoped():
    with pytest.raises(ValueError):
        validate_target_scope('third-party', {'request': 'GET / HTTP/1.1\r\nHost: outside.test\r\n'},
                              ['https://target.test/'])
    with pytest.raises(ValueError):
        validate_target_scope('third-party', {'payload': {'raw': 'visit https://outside.test/private'}},
                              ['https://target.test/'])


def yakit_request(path='/allowed/page', host='target.test', https=True, **options):
    return {'request': f'GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n',
            'isHttps': https, 'fuzzTagMode': 'close', 'noFollowRedirect': True, **options}


@pytest.mark.parametrize('https,host,scope', [
    (True, 'target.test', 'https://target.test/allowed'),
    (False, 'target.test', 'http://target.test/allowed'),
    (True, 'target.test:8443', 'https://target.test:8443/allowed'),
    (True, '[2001:db8::1]:8443', 'https://[2001:db8::1]:8443/allowed'),
])
def test_fixed_yakit_packet_preserves_scheme_port_and_path(tmp_path, https, host, scope):
    arguments = yakit_request(host=host, https=https)
    validate_workbench_arguments('local-yakit', 'http_fuzzer', arguments, tmp_path)
    validate_target_scope('local-yakit', arguments, [scope])
    expected = scope + '/page' if ':8443' in scope else (
        scope.replace('/allowed', ':443/allowed' if https else ':80/allowed') + '/page')
    assert target_values(arguments, 'local-yakit') == [expected]


@pytest.mark.parametrize('options', [
    {'fuzzTagMode': 'standard'}, {'noFollowRedirect': False},
    {'actualAddr': 'outside.test:443'}, {'batchTarget': ['https://outside.test']},
    {'batchTargetFile': True}, {'proxy': 'http://outside.test:8080'},
    {'sni': 'outside.test'}, {'overwriteSNI': True},
    {'dnsServers': ['192.0.2.1']}, {'etcHosts': [{'key': 'target.test', 'value': '192.0.2.1'}]},
    {'newDestinationOption': 'outside.test'},
])
def test_yakit_dynamic_or_overridden_connection_still_needs_review(tmp_path, options):
    with pytest.raises(ValueError, match='动态目标'):
        validate_workbench_arguments('local-yakit', 'http_fuzzer', yakit_request(**options), tmp_path)


@pytest.mark.parametrize('arguments', [
    yakit_request(host='outside.test'), yakit_request(path='/admin'),
    yakit_request(path='/allowed/%2e%2e/admin'), yakit_request(https=False),
    yakit_request(host='target.test:444'),
])
def test_yakit_fixed_packet_cannot_escape_scope(arguments):
    with pytest.raises(ValueError, match='不在任务授权范围内'):
        validate_target_scope('local-yakit', arguments, ['https://target.test/allowed'])


@pytest.mark.parametrize('packet', [
    'GET /allowed HTTP/1.1\r\n\r\n',
    'GET /allowed HTTP/1.1\r\nHost: target.test\r\nHost: outside.test\r\n\r\n',
    'GET https://outside.test/ HTTP/1.1\r\nHost: target.test\r\n\r\n',
    'GET /allowed HTTP/1.1\r\nHost: user@target.test\r\n\r\n',
    'GET /allowed HTTP/1.1\r\nHost: target.test\r\n folded: value\r\n\r\n',
])
def test_ambiguous_yakit_packet_still_needs_review(tmp_path, packet):
    with pytest.raises(ValueError):
        validate_workbench_arguments('local-yakit', 'http_fuzzer',
                                     {**yakit_request(), 'request': packet}, tmp_path)


def test_workspace_and_unstructured_network_arguments_are_rejected(tmp_path):
    with pytest.raises(ValueError, match='文件目标'):
        validate_workbench_arguments('local-yakit', 'port_scan',
                                     {'targets': ['target.test'], 'ports': '80', 'targetsFile': '../other.txt'},
                                     tmp_path)
    with pytest.raises(ValueError, match='工作区'):
        validate_workbench_arguments('local-reqable', 'collection_create',
                                     {'filePath': str(tmp_path.parent / 'other.txt')}, tmp_path)
    with pytest.raises(ValueError, match='动态目标'):
        validate_workbench_arguments('local-yakit', 'http_fuzzer',
                                     {'request': 'GET / HTTP/1.1\r\nHost: outside.test\r\n'}, tmp_path)
    with pytest.raises(ValueError, match='网段扩展'):
        validate_workbench_arguments('local-yakit', 'port_scan',
                                     {'targets': ['192.0.2.0/24'], 'ports': '80'}, tmp_path)


@pytest.mark.parametrize('tool_name,key', [
    ('dir_scan', 'dict'), ('jwt_crack', 'dict'), ('pwd_crack', 'pairf'),
    ('subdomain_scan', 'sub_dict'), ('tscan_scan', 'crack_pairf'),
    ('tscan_scan', 'dir_dict'), ('tscan_scan', 'sub_dict'),
])
def test_tscanplus_dictionary_files_stay_in_workspace(tmp_path, tool_name, key):
    validate_workbench_arguments('local-tscanplus', tool_name,
                                 {key: str(tmp_path / 'words.txt')}, tmp_path)
    with pytest.raises(ValueError, match='绝对路径'):
        validate_workbench_arguments('local-tscanplus', tool_name, {key: 'words.txt'}, tmp_path)
    with pytest.raises(ValueError, match='工作区'):
        validate_workbench_arguments('local-tscanplus', tool_name,
                                     {key: str(tmp_path.parent / 'outside.txt')}, tmp_path)


def test_nested_path_arrays_stay_in_workspace(tmp_path):
    with pytest.raises(ValueError, match='工作区'):
        validate_workbench_arguments('third-party', 'scan',
                                     {'options': {'path': [str(tmp_path / 'inside.txt'),
                                                            str(tmp_path.parent / 'outside.txt')]}}, tmp_path)


def test_http1_request_uses_connection_target_and_request_path():
    request = {'targetHostname': 'target.test', 'targetPort': 443, 'usesHttps': True,
               'content': 'GET /app/login HTTP/1.1\r\nHost: target.test\r\n\r\n'}
    validate_target_scope('local-burp', request, ['https://target.test/app'])
    with pytest.raises(ValueError, match='不在任务授权范围内'):
        validate_target_scope('local-burp', {**request, 'targetHostname': 'outside.test',
            'content': 'GET /app/login HTTP/1.1\r\nHost: outside.test\r\n\r\n'}, ['https://target.test/app'])
    with pytest.raises(ValueError, match='不在任务授权范围内'):
        validate_target_scope('local-burp', {**request, 'content': 'GET /admin HTTP/1.1\r\nHost: target.test\r\n\r\n'},
                              ['https://target.test/app'])
    with pytest.raises(ValueError, match='Host 头与连接目标不一致'):
        validate_target_scope('local-burp', {**request, 'content': 'GET /app HTTP/1.1\r\nHost: outside.test\r\n\r\n'},
                              ['https://target.test/app'])


def test_http1_alias_cannot_override_connection_target():
    request = {'targetHostname': 'outside.test', 'targetPort': 443, 'usesHttps': True,
               'content': 'GET /app HTTP/1.1\r\nHost: outside.test\r\n\r\n',
               'target_host_name': 'target.test'}
    with pytest.raises(ValueError, match='不在任务授权范围内'):
        validate_target_scope('local-burp', request, ['https://target.test/app'])


def test_encoded_parent_path_cannot_escape_scope():
    with pytest.raises(ValueError, match='不在任务授权范围内'):
        validate_target_scope('local-http-fetch', {'url': 'https://target.test/app/%2e%2e/admin'},
                              ['https://target.test/app'])


@pytest.mark.parametrize('url', [
    'https://target.test/app/%5c../admin',
    'https://target.test/app/%00/admin',
    'https://target.test/app/ok\r\nHost: outside.test',
])
def test_encoded_separators_and_control_characters_cannot_pass_scope(url):
    with pytest.raises(ValueError, match='不在任务授权范围内'):
        validate_target_scope('local-http-fetch', {'url': url}, ['https://target.test/app'])
