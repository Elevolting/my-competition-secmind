import pytest

from security_agent.scoped_file_post import Grant, validate_post


GRANT = Grant("original", "https://target.test/", "one-time-request-001")


@pytest.mark.parametrize("body", [
    "file=%2Fetc%2Fpasswd",
    "file=..%2F..%2Fflag.php",
    "file=php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3Dindex.php",
])
def test_scoped_post_accepts_one_local_read_target(body):
    validate_post({"url": GRANT.target_url, "body": body}, GRANT)


@pytest.mark.parametrize("arguments", [
    {"url": "https://other.test/", "body": "file=index.php"},
    {"url": "https://target.test/?file=x", "body": "file=index.php"},
    {"url": "https://target.test/", "body": "file=index.php&other=x"},
    {"url": "https://target.test/", "body": "file=index.php&file=flag"},
    {"url": "https://target.test/", "body": "file="},
    {"url": "https://target.test/", "body": "file=http%3A%2F%2Fevil.test%2Fx"},
    {"url": "https://target.test/", "body": "file=php%3A%2F%2Finput"},
    {"url": "https://target.test/", "body": "file=php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3Dhttp%3A%2F%2Fevil.test"},
    {"url": "https://target.test/", "body": "file=" + "a" * 2050},
    {"url": "https://target.test/", "body": "file=%GG"},
])
def test_scoped_post_rejects_out_of_grant_or_nonlocal_target(arguments):
    with pytest.raises(ValueError):
        validate_post(arguments, GRANT)
