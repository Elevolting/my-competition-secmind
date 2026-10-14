from types import SimpleNamespace

from security_agent.guardrail import Guardrail, GuardrailAction
from security_agent.mcp_agent import MCPAgentTool
from security_agent.mcp_approval import requires_approval
from security_agent.tools import ToolBroker


def burp_request(method='GET', *, headers='', body='', path='/allowed/page'):
    return {
        'targetHostname': 'target.test', 'targetPort': 443, 'usesHttps': True,
        'content': (f'{method} {path} HTTP/1.1\r\nHost: target.test\r\n'
                    f'Connection: close\r\n{headers}\r\n{body}'),
    }


def test_burp_scoped_read_only_http1_does_not_require_approval():
    for method in ('GET', 'HEAD'):
        assert not requires_approval('local-burp', 'send_http1_request', burp_request(method))


def test_burp_mutating_or_ambiguous_http1_requires_approval():
    for request in (
        burp_request('POST'),
        burp_request(body='payload'),
        burp_request(headers='Cookie: session=secret\r\n'),
        burp_request(headers='Transfer-Encoding: chunked\r\n'),
        burp_request(headers='Host: target.test\r\n'),
        burp_request(headers='Connection: upgrade\r\n'),
        {**burp_request(), 'targetHostname': 'other.test'},
        {**burp_request(), 'extra': 'unreviewed'},
    ):
        assert requires_approval('local-burp', 'send_http1_request', request)


def test_unknown_and_write_tools_still_require_approval():
    assert requires_approval('local-burp', 'send_http2_request', {})
    assert requires_approval('local-tscanplus', 'record_finding', {})
    assert requires_approval('local-yakit', 'execute_web_fuzzer_tab', {})


def test_global_result_queries_require_approval_even_when_read_only():
    for server_id, tool_name in (
        ('local-yakit', 'query_ports'),
        ('local-yakit', 'get_mitm_filter'),
        ('local-tscanplus', 'query_results'),
        ('local-tscanplus', 'route_candidates'),
        ('local-reqable', 'capture_breakpoint_get_config'),
        ('local-reqable', 'capture_rewrite_get_config'),
    ):
        assert requires_approval(server_id, tool_name, {})
    assert requires_approval('local-reqable', 'capture_breakpoint_set_enabled', {})


def test_tscanplus_get_requires_approval_when_request_is_not_plain_read_only():
    plain = {'url': 'https://target.test/allowed', 'method': 'GET', 'follow_redirect': False}
    assert not requires_approval('local-tscanplus', 'http_request', plain)
    for changed in ({'method': 'POST'}, {'body': 'payload'}, {'headers': 'X-Action: run'},
                    {'cookie': 'session=secret'}, {'follow_redirect': True},
                    {'unreviewed_option': 'value'}, {'headers': {'X-Action': 'run'}}):
        assert requires_approval('local-tscanplus', 'http_request', {**plain, **changed})


def test_broker_grades_reviewed_get_by_arguments():
    runtime = SimpleNamespace(connection_fingerprint=lambda _server: 'server-version',
                              tool_fingerprint=lambda _tool: 'tool-version')
    server = {'server_id': 'local-burp', 'name': 'Burp'}
    tool = MCPAgentTool(runtime, server, {'name': 'send_http1_request',
                                         'description': 'HTTP request', 'inputSchema': {'type': 'object'}})
    broker = ToolBroker(SimpleNamespace(get=lambda _name: tool), Guardrail())
    assert broker.assess(tool.manifest.name, burp_request(), 'graded').action == GuardrailAction.ALLOW
    assert (broker.assess(tool.manifest.name, burp_request('POST'), 'automatic').action
            == GuardrailAction.ALLOW)
    assert (broker.assess(tool.manifest.name, burp_request('POST'), 'graded').action
            == GuardrailAction.REQUIRE_APPROVAL)
