import pytest

from security_agent.verified_outputs import extract_verified_flags, include_verified_outputs


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
