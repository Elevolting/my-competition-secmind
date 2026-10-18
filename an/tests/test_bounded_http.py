import pytest

from security_agent import bounded_http


def test_bounded_http_policy_identity_is_stable():
    assert bounded_http.POLICY == "bounded_http"
    assert "4 KB" in bounded_http.CONSTRAINT


@pytest.mark.parametrize("arguments", [
    {"method": "GET", "url": "https://target.test/"},
    {"method": "HEAD", "url": "https://target.test/"},
    {"method": "POST", "url": "https://target.test/?path=PHp://input",
     "body": "<?php system('cat /var/www/html/flag.php'); ?>"},
    {"method": "POST", "url": "https://target.test/", "body": "x" * bounded_http.MAX_BODY_BYTES},
    {"method": "get", "url": "https://target.test/", "body": "file=index.php"},
    # GET with a body is deliberately allowed: file-inclusion targets read
    # php://input for GET as well as POST.
    {"url": "https://target.test/", "body": "x"},
    {"method": "GET", "url": "https://target.test/", "follow_redirect": False, "body": "payload"},
])
def test_bounded_http_accepts_bounded_body_requests(arguments):
    bounded_http.validate_request(arguments)


@pytest.mark.parametrize("arguments", [
    {"method": "PUT", "url": "https://target.test/"},
    {"method": "DELETE", "url": "https://target.test/"},
    {"method": "POST", "url": "https://target.test/", "body": "x" * (bounded_http.MAX_BODY_BYTES + 1)},
    {"method": "HEAD", "url": "https://target.test/", "body": "x"},
    {"method": "GET", "url": "https://target.test/", "follow_redirect": True},
    {"method": "GET", "url": "https://target.test/", "headers": "Host: outside.test"},
    {"method": "GET", "url": "https://target.test/", "cookie": "session=x"},
    {"method": "POST", "url": "https://target.test/", "body": {"json": "object"}},
])
def test_bounded_http_rejects_out_of_policy_requests(arguments):
    with pytest.raises(ValueError):
        bounded_http.validate_request(arguments)
