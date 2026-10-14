from __future__ import annotations

from secmind.web_static_audit import (
    _hidden_stage_values,
    _mask_comments,
    _mask_strings,
    _matching_brace,
    _password_key_role,
    _stage_branches,
    analyze_web_source,
)


def test_analyzer_rejects_empty_and_oversized_sources_without_parsing() -> None:
    assert analyze_web_source("") == ()
    assert analyze_web_source("x" * (2 * 1024 * 1024 + 1)) == ()


def test_matching_brace_ignores_comments_strings_and_escaped_quotes() -> None:
    source = r"""{
$double = "quoted \" } brace";
$single = 'quoted \' } brace';
// a line-comment brace must not close the branch: }
# nor may a hash-comment brace: }
/* block comments can contain both { and } */
if ($ok) { call(); }
} trailing
"""

    closing = _matching_brace(source, 0)

    assert closing == source.index("\n} trailing") + 1


def test_matching_brace_fails_closed_for_unterminated_input() -> None:
    assert _matching_brace("{ if ($ok) { call(); }", 0) is None


def test_comment_mask_preserves_offsets_strings_and_newlines() -> None:
    source = r"""$double = "not // a comment; escaped \" quote";
$single = 'not # a comment; escaped \' quote';
// remove this line and its }
# remove this hash comment too
/* remove this block { but preserve
its newline } */
$after = 1;
"""

    masked = _mask_comments(source)

    assert len(masked) == len(source)
    assert masked.count("\n") == source.count("\n")
    assert "not // a comment" in masked
    assert "not # a comment" in masked
    assert "remove this" not in masked
    assert "$after = 1;" in masked


def test_string_mask_preserves_offsets_and_newlines_across_escapes() -> None:
    source = """$double = "alpha \\" beta";
$single = 'gamma \\' delta';
$after = 1;
"""

    masked = _mask_strings(source)

    assert len(masked) == len(source)
    assert masked.count("\n") == source.count("\n")
    assert "alpha" not in masked
    assert "gamma" not in masked
    assert "$after = 1;" in masked


def test_stage_parser_rejects_orphan_semicolon_and_unclosed_branches() -> None:
    source = """<?php
$_POST['stage'] === 'orphan';
if ($_POST['stage'] === 'semicolon'); { return; }
if ($_POST['stage'] === 'unclosed') { return;
"""
    code_view = _mask_strings(_mask_comments(source))

    assert _stage_branches(source, code_view) == ()


def test_stage_parser_enforces_the_branch_resource_limit() -> None:
    source = "\n".join(f"if ($_POST['stage'] === 's{index}') {{ return; }}" for index in range(80))
    code_view = _mask_strings(_mask_comments(source))

    branches = _stage_branches(source, code_view)

    assert len(branches) == 64
    assert branches[0].value == "s0"
    assert branches[-1].value == "s63"


def test_hidden_stage_parser_ignores_wrong_type_name_and_invalid_value() -> None:
    body = """
<input type="text" name="stage" value="commit">
<input type="hidden" name="other" value="commit">
<input type="hidden" name="stage" value="not valid!">
<input type="hidden" name="stage" value="commit">
"""

    values = _hidden_stage_values(body, key="stage")

    assert len(values) == 1
    assert values[0][1] == "commit"


def test_password_key_classifier_rejects_unrelated_inputs() -> None:
    assert _password_key_role("username") is None
