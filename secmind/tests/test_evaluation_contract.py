from __future__ import annotations

import json
from pathlib import Path

CASES_PATH = Path("evaluation/cases.json")
TAXONOMY_PATH = Path("evaluation/cases.taxonomy.json")

EXPECTED_CANONICAL_RULES = {
    "shell_true": {"CWE-78"},
    "hardcoded_password": {"CWE-798"},
    "pickle_loads": {"CWE-502"},
    "unsafe_eval": {"CWE-95"},
    "assert_guard": {"CWE-703"},
    "yaml_load": {"CWE-502"},
    "requests_no_verify": {"CWE-295", "CWE-400"},
    "tempfile_mktemp": {"CWE-377"},
    "weak_random": {"CWE-330"},
    "weak_md5": {"CWE-327"},
    "unsafe_exec": {"CWE-95"},
    "chmod_world": {"CWE-732"},
    "bind_all": {"CWE-605"},
    "hardcoded_tmp": {"CWE-377"},
    "weak_sha1": {"CWE-327"},
    "ftp_import": {"CWE-319"},
    "xml_etree": {"CWE-611"},
    "marshal_loads": {"CWE-502"},
    "secret_api_key": {"CWE-798"},
    "secret_client_secret": {"CWE-798"},
}


def test_evaluation_suite_has_forty_balanced_rule_labeled_cases() -> None:
    cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    assert len(cases) == 40
    assert sum(not case["expected_rule_ids"] for case in cases) == 20
    assert sum(bool(case["expected_rule_ids"]) for case in cases) == 20
    assert len({case["name"] for case in cases}) == 40
    assert all("max_findings" in case for case in cases)
    assert all("source" in case and "project_path" not in case for case in cases)

    positive_rules = {case["name"]: set(case["expected_rule_ids"]) for case in cases if case["expected_rule_ids"]}
    assert positive_rules == EXPECTED_CANONICAL_RULES


def test_evaluation_rule_labels_follow_versioned_public_finding_taxonomy() -> None:
    cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    taxonomy = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))

    assert taxonomy["schema_version"] == "1.1"
    assert taxonomy["taxonomy_version"] == "secmind-public-finding-rule-id-v2"
    assert taxonomy["dataset_file"] == CASES_PATH.name

    all_rule_ids = {rule_id for case in cases for rule_id in case["expected_rule_ids"]}
    retained_native = set(taxonomy["retained_unmapped_native_rule_ids"])
    mapped_native = set(taxonomy["native_to_canonical"])
    context_only_native = set(taxonomy["excluded_context_only_native_rule_ids"])

    assert {rule_id for rule_id in all_rule_ids if rule_id.startswith("B")} == retained_native
    assert all_rule_ids.isdisjoint(mapped_native)
    assert all_rule_ids.isdisjoint(context_only_native)
    assert all(
        rule_id.startswith("CWE-") or rule_id.startswith("SECMIND-") or rule_id in retained_native
        for rule_id in all_rule_ids
    )
