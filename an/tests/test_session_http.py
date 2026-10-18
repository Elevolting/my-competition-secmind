import pytest

from security_agent import bounded_http, session_http


def test_session_http_policy_identity_is_stable():
    assert session_http.POLICY == "session_http"
    assert "Cookie" in session_http.CONSTRAINT
    assert session_http.POLICY != bounded_http.POLICY


@pytest.mark.parametrize("arguments", [
    {"method": "GET", "url": "https://target.test/"},
    {"method": "GET", "url": "https://target.test/api/admin/", "cookie": "PHPSESSID=abc123"},
    {"method": "GET", "url": "https://target.test/api/admin/",
     "headers": "Cookie: PHPSESSID=abc123"},
    {"method": "GET", "url": "https://target.test/api/admin/",
     "headers": "Cookie: session=abc; theme=dark"},
    {"method": "GET", "url": "https://target.test/api/admin/",
     "headers": "Host: target.test:443"},
    {"method": "GET", "url": "https://target.test/api/admin/",
     "headers": "Authorization: Bearer x; X-Requested-With: XMLHttpRequest"},
    {"method": "POST", "url": "https://target.test/login.php",
     "cookie": "PHPSESSID=abc", "body": "username=admin&password=admin123",
     "headers": "Content-Type: application/x-www-form-urlencoded"},
    {"method": "HEAD", "url": "https://target.test/", "cookie": "a=b"},
    {"method": "get", "url": "https://target.test/", "body": "x", "cookie": "a=b"},
])
def test_session_http_accepts_session_carrying_requests(arguments):
    session_http.validate_request(arguments)


@pytest.mark.parametrize("arguments", [
    {"method": "PUT", "url": "https://target.test/"},
    {"method": "DELETE", "url": "https://target.test/"},
    {"method": "GET", "url": "https://target.test/", "follow_redirect": True},
    {"method": "GET", "url": "https://target.test/", "headers": "X-Forwarded-For: 127.0.0.1"},
    {"method": "GET", "url": "https://target.test/", "headers": "Transfer-Encoding: chunked"},
    {"method": "GET", "url": "https://target.test/", "headers": "not-a-header"},
    {"method": "POST", "url": "https://target.test/", "body": "x" * (session_http.MAX_BODY_BYTES + 1)},
    {"method": "HEAD", "url": "https://target.test/", "body": "x"},
    {"method": "GET", "url": "https://target.test/", "body": {"json": "object"}},
    {"method": "GET", "url": "https://target.test/", "cookie": 12345},
    {"method": "GET", "url": "https://target.test/", "cookie": "a=b\r\nHost: outside.test"},
    {"method": "GET", "url": "https://target.test/", "cookie": "\r\n"},
    {"method": "GET", "url": "https://target.test/", "headers": "Host: target.test\x00"},
    {"method": "GET", "url": "https://target.test/", "headers": "Host: outside.test"},
    {"method": "GET", "url": "https://target.test/", "headers": "Host: target.test:444"},
    {"method": "GET", "url": "https://target.test/", "headers": "Host: target.test:0"},
    {"method": "GET", "url": "https://target.test/", "headers": "Host: target.test\nHost: outside.test"},
    {"method": "GET", "url": "https://target.test/", "headers": "Cookie: a=b; Host: outside.test"},
])
def test_session_http_rejects_out_of_policy_requests(arguments):
    with pytest.raises(ValueError):
        session_http.validate_request(arguments)


def test_session_http_does_not_reintroduce_a_call_cap():
    """The bridge bounds work by runtime; a session must not be cut off by a
    hidden per-intent call ceiling (that stranded a-05 one request short)."""
    assert session_http.MAX_CALLS_PER_RUN is None
    assert session_http.MAX_CALLS_PER_INTENT is None

def test_session_http_still_rejects_cookies_under_bounded_http():
    """The wider session capability must not leak into the bounded policy."""
    with pytest.raises(ValueError):
        bounded_http.validate_request({"method": "GET", "url": "https://target.test/",
                                       "cookie": "PHPSESSID=abc"})
