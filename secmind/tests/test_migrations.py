from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text


@pytest.fixture(autouse=True)
def _migration_tests_use_explicit_database_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep explicit temporary SQLite URLs isolated from process-level DSNs."""

    monkeypatch.delenv("SECMIND_DATABASE_URL", raising=False)


def test_business_migration_is_repeatable(tmp_path) -> None:
    url = f"sqlite:///{(tmp_path / 'migration.db').as_posix()}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    command.upgrade(config, "head")
    tables = set(inspect(create_engine(url)).get_table_names())
    assert {
        "runs",
        "ledger_events",
        "tool_invocations",
        "approvals",
        "run_jobs",
        "step_runs",
        "model_invocations",
        "model_gateway_failures",
        "outbox_events",
        "artifact_objects",
        "knowledge_documents",
        "task_specs",
        "task_spec_revisions",
        "parser_runs",
        "clarification_requests",
    } <= tables
    run_job_columns = {column["name"] for column in inspect(create_engine(url)).get_columns("run_jobs")}
    assert "wake_requested" in run_job_columns
    model_columns = {column["name"] for column in inspect(create_engine(url)).get_columns("model_invocations")}
    assert {
        "cache_hit_input_tokens",
        "cache_miss_input_tokens",
        "task_kind",
        "model_lane",
        "router_version",
        "prompt_version",
        "prompt_artifact_id",
        "prompt_selection_digest",
        "request_digest",
        "attempt_ordinal",
        "stage",
        "error_type",
        "status_code",
        "duration_ms",
        "retryable",
        "deadline_ms",
        "remaining_budget_ms",
        "route",
        "route_profile",
        "logical_call_id",
        "parent_logical_call_id",
        "prompt_optimizer_attempt_id",
        "prompt_lineage_reason",
        "lineage_stage",
    } <= model_columns
    prompt_attempt_columns = {
        column["name"] for column in inspect(create_engine(url)).get_columns("prompt_optimization_attempts")
    }
    assert {
        "request_digest",
        "selection_digest",
        "logical_call_id",
        "parent_logical_call_id",
        "lineage_reason",
    } <= prompt_attempt_columns
    prompt_artifact_columns = {column["name"] for column in inspect(create_engine(url)).get_columns("prompt_artifacts")}
    assert {"selection_digest", "optimizer_attempt_id", "lineage_reason"} <= prompt_artifact_columns
    assert next(column for column in inspect(create_engine(url)).get_columns("prompt_artifacts")
                if column["name"] == "template_version")["type"].length == 180
    assert next(column for column in inspect(create_engine(url)).get_columns("prompt_templates")
                if column["name"] == "version")["type"].length == 180


def test_model_route_audit_migration_preserves_existing_invocations(tmp_path) -> None:
    url = f"sqlite:///{(tmp_path / 'model-audit-upgrade.db').as_posix()}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "0015_fusion_evidence_ids")
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO model_invocations (
                    model_invocation_id, run_id, provider_request_id, model_id, status,
                    input_tokens, output_tokens, cache_hit_input_tokens,
                    cache_miss_input_tokens, cost_microunits, request_hash,
                    created_at, updated_at
                ) VALUES (
                    'legacy-model-1', 'legacy-run', 'legacy-request', 'qwen-plus', 'completed',
                    1, 1, 0, 1, 1, :request_hash, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                )
                """
            ),
            {"request_hash": "a" * 64},
        )

    command.upgrade(config, "head")
    with engine.connect() as connection:
        row = connection.execute(
            text(
                """
                SELECT request_hash, task_kind, model_lane, router_version, prompt_version,
                       attempt_ordinal, stage, retryable, route_profile
                FROM model_invocations
                WHERE model_invocation_id = 'legacy-model-1'
                """
            )
        ).one()
    assert tuple(row) == (
        "a" * 64,
        "legacy_unknown",
        "legacy_unknown",
        "legacy_unknown",
        "legacy_unknown",
        0,
        "provider",
        0,
        "legacy_unknown",
    )


def test_migration_heads_fit_postgresql_alembic_version_column() -> None:
    heads = ScriptDirectory.from_config(Config("alembic.ini")).get_heads()
    assert heads and all(len(head) <= 32 for head in heads)


def test_v05_taskspec_migration_downgrades_and_reapplies(tmp_path) -> None:
    url = f"sqlite:///{(tmp_path / 'migration-cycle.db').as_posix()}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    command.downgrade(config, "0004_v04_cognitive_kernel")
    downgraded = set(inspect(create_engine(url)).get_table_names())
    assert {
        "task_specs",
        "task_spec_revisions",
        "parser_runs",
        "clarification_requests",
    }.isdisjoint(downgraded)
    downgraded_columns = {column["name"] for column in inspect(create_engine(url)).get_columns("run_jobs")}
    assert "wake_requested" not in downgraded_columns

    command.upgrade(config, "head")
    upgraded = set(inspect(create_engine(url)).get_table_names())
    assert {
        "task_specs",
        "task_spec_revisions",
        "parser_runs",
        "clarification_requests",
    } <= upgraded
