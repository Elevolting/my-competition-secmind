import pytest

from security_agent.verified_outputs import (extract_verified_flags, include_verified_outputs,
                                             is_runtime_metadata_source,
                                             without_runtime_metadata)


@pytest.mark.parametrize("value", [
    "flag{de31e03b-fa61-4bbd-98d5-54a45d698cda}",
    "flag{1}",
    "FLAG{a_b-c.d}",
    "ctfshow{abc123}",
    "flag{x}",
])
def test_extracts_real_flag_shapes(value):
    assert extract_verified_flags([value]) == [value]


@pytest.mark.parametrize("value", [
    # The extraction pattern quoted back inside its own report is not a flag.
    "grep 'flag{[^}]*}' -r /challenge",
    "flag{[^}",
    "flag{.*}",
    "regex flag{a|b} here",
    "flag{your_flag_here}",
    "flag{placeholder}",
    "flag{...}",
])
def test_rejects_pattern_and_placeholder_literals(value):
    assert extract_verified_flags([value]) == []


def test_deduplicates_preserving_first_seen_order():
    values = ["flag{b}", "flag{a}", "flag{b}"]
    assert extract_verified_flags(values) == ["flag{b}", "flag{a}"]


def test_report_citing_its_own_grep_yields_one_flag():
    report_text = (
        "FLAG: flag{de31e03b-fa61-4bbd-98d5-54a45d698cda}",
        "verified by: grep 'flag{[^}]*}' -r /challenge",
    )
    assert extract_verified_flags(report_text) == ["flag{de31e03b-fa61-4bbd-98d5-54a45d698cda}"]


def test_include_verified_outputs_appends_only_missing_values():
    assert include_verified_outputs("summary", []) == "summary"
    assert include_verified_outputs("has flag{a}", ["flag{a}"]) == "has flag{a}"
    assert include_verified_outputs("summary", ["flag{a}"]) == "summary 已验证目标输出：flag{a}。"


@pytest.mark.parametrize("context", [
    # A NUL-separated environment dump is the platform's per-instance state.
    "HOSTNAME=abc\x00HOME=/root\x00PATH=/usr/bin\x00FLAG=ctfshow{per-instance}\x00",
    "PATH=/usr/local/bin\x00LANG=C.UTF-8\x00FLAG=ctfshow{per-instance}",
    # Receipts are JSON-serialized before the check, so the separators arrive
    # escaped rather than as raw bytes.
    "HOSTNAME=abc\\u0000HOME=/root\\u0000PATH=/usr/bin\\u0000FLAG=ctfshow{per-instance}\\u0000",
])
def test_environment_dumps_are_runtime_metadata(context):
    assert is_runtime_metadata_source(context)


@pytest.mark.parametrize("context", [
    # A configuration file that merely uses ``KEY=VALUE`` lines is a normal
    # challenge artifact and must keep working as a flag source.
    "DB_HOST=localhost\nDB_USER=root\nFLAG=CTF{from_env_file}\n",
    "flag{de31e03b-fa61-4bbd-98d5-54a45d698cda}",
    "Server: nginx/1.20.1\nSet-Cookie: session=abc",
])
def test_configuration_files_are_not_runtime_metadata(context):
    assert not is_runtime_metadata_source(context)


def test_output_found_only_in_an_environment_dump_is_dropped():
    value = "ctfshow{per-instance}"
    assert without_runtime_metadata([
        (value, "HOSTNAME=abc\x00HOME=/root\x00PATH=/usr/bin\x00FLAG=" + value),
    ]) == []


def test_output_the_application_itself_returned_is_kept():
    value = "CTF{flask_session_is_secure}"
    assert without_runtime_metadata([
        (value, "HOSTNAME=abc\x00HOME=/root\x00PATH=/usr/bin\x00FLAG=ctfshow{per-instance}"),
        (value, "{'body': '" + value + "'}"),
    ]) == [value]
