"""Add v0.5 governed scenario, log, retention, and reconciliation projections."""

import sqlalchemy as sa
from alembic import op

revision = "0006_v05_governed_scenarios"
down_revision = "0005_v05_taskspec_alpha"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scenario_routes",
        sa.Column("route_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("scenario", sa.String(length=50), nullable=False),
        sa.Column("strategy", sa.String(length=30), nullable=True),
        sa.Column("route_digest", sa.String(length=64), nullable=False),
        sa.Column("route_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scenario_routes_run_id", "scenario_routes", ["run_id"])

    op.create_table(
        "plan_revisions",
        sa.Column("revision_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("trigger", sa.String(length=50), nullable=False),
        sa.Column("parent_plan_digest", sa.String(length=64), nullable=False),
        sa.Column("plan_digest", sa.String(length=64), nullable=False),
        sa.Column("revision_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "revision"),
    )
    op.create_index("ix_plan_revisions_run_id", "plan_revisions", ["run_id"])

    op.create_table(
        "input_envelopes",
        sa.Column("invocation_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("step_id", sa.String(length=100), nullable=False),
        sa.Column("raw_digest", sa.String(length=64), nullable=False),
        sa.Column("observable_digest", sa.String(length=64), nullable=False),
        sa.Column("execution_digest", sa.String(length=64), nullable=False),
        sa.Column("envelope_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_input_envelopes_run_id", "input_envelopes", ["run_id"])

    op.create_table(
        "input_mutations",
        sa.Column("mutation_id", sa.String(length=36), primary_key=True),
        sa.Column("invocation_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("stage", sa.String(length=30), nullable=False),
        sa.Column("field_path", sa.String(length=500), nullable=False),
        sa.Column("parent_digest", sa.String(length=64), nullable=False),
        sa.Column("new_digest", sa.String(length=64), nullable=False),
        sa.Column("mutation_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_input_mutations_invocation_id", "input_mutations", ["invocation_id"])
    op.create_index("ix_input_mutations_run_id", "input_mutations", ["run_id"])

    op.create_table(
        "retention_profiles",
        sa.Column("profile_id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=100), nullable=False, unique=True),
        sa.Column("profile_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "retention_holds",
        sa.Column("hold_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("actor", sa.String(length=100), nullable=False),
        sa.Column("reason", sa.String(length=1000), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_retention_holds_run_id", "retention_holds", ["run_id"])

    op.create_table(
        "log_streams",
        sa.Column("stream_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("source", sa.String(length=500), nullable=False),
        sa.Column("format", sa.String(length=100), nullable=False),
        sa.Column("timezone", sa.String(length=100), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("total_size", sa.BigInteger(), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=True),
        sa.Column("view", sa.String(length=30), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_log_streams_run_id", "log_streams", ["run_id"])

    op.create_table(
        "log_segments",
        sa.Column("segment_id", sa.String(length=36), primary_key=True),
        sa.Column("stream_id", sa.String(length=36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("offset", sa.BigInteger(), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("artifact_id", sa.String(length=64), nullable=False),
        sa.Column("record_start", sa.BigInteger(), nullable=True),
        sa.Column("record_end", sa.BigInteger(), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("diagnostics_json", sa.Text(), nullable=False),
        sa.UniqueConstraint("stream_id", "sequence"),
    )
    op.create_index("ix_log_segments_stream_id", "log_segments", ["stream_id"])
    op.create_index("ix_log_segments_artifact_id", "log_segments", ["artifact_id"])

    op.create_table(
        "normalized_security_events",
        sa.Column("event_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("stream_id", sa.String(length=36), nullable=False),
        sa.Column("segment_id", sa.String(length=36), nullable=False),
        sa.Column("source_offset", sa.BigInteger(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("event_digest", sa.String(length=64), nullable=False),
        sa.Column("event_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "event_digest"),
    )
    op.create_index("ix_normalized_events_run_time", "normalized_security_events", ["run_id", "occurred_at"])
    op.create_index("ix_normalized_events_stream", "normalized_security_events", ["stream_id"])

    op.create_table(
        "data_access_events",
        sa.Column("access_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("actor", sa.String(length=100), nullable=False),
        sa.Column("view", sa.String(length=30), nullable=False),
        sa.Column("resource_type", sa.String(length=50), nullable=False),
        sa.Column("resource_id", sa.String(length=100), nullable=False),
        sa.Column("purpose", sa.String(length=500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_data_access_events_run_id", "data_access_events", ["run_id"])

    op.create_table(
        "approval_batches",
        sa.Column("batch_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("ready_wave", sa.String(length=100), nullable=False),
        sa.Column("risk_level", sa.Integer(), nullable=False),
        sa.Column("parameter_summary_digest", sa.String(length=64), nullable=False),
        sa.Column("actor", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("batch_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_approval_batches_run_id", "approval_batches", ["run_id"])

    op.create_table(
        "operator_sessions",
        sa.Column("session_id", sa.String(length=36), primary_key=True),
        sa.Column("actor", sa.String(length=100), nullable=False),
        sa.Column("role", sa.String(length=30), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_operator_sessions_actor", "operator_sessions", ["actor"])

    op.create_table(
        "resume_assessments",
        sa.Column("assessment_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("action", sa.String(length=50), nullable=False),
        sa.Column("reason_code", sa.String(length=100), nullable=False),
        sa.Column("state_version", sa.Integer(), nullable=False),
        sa.Column("fence", sa.Integer(), nullable=False),
        sa.Column("checkpoint_state_version", sa.Integer(), nullable=True),
        sa.Column("checkpoint_id", sa.String(length=100), nullable=True),
        sa.Column("control_digest", sa.String(length=64), nullable=False),
        sa.Column("runner_resources_collected", sa.Boolean(), nullable=False),
        sa.Column("assessment_json", sa.Text(), nullable=False),
        sa.Column("consumption_id", sa.String(length=36), nullable=True, unique=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_by", sa.String(length=100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_resume_assessments_run_id", "resume_assessments", ["run_id"])


def downgrade() -> None:
    tables = (
        ("resume_assessments", ("ix_resume_assessments_run_id",)),
        ("operator_sessions", ("ix_operator_sessions_actor",)),
        ("approval_batches", ("ix_approval_batches_run_id",)),
        ("data_access_events", ("ix_data_access_events_run_id",)),
        ("normalized_security_events", ("ix_normalized_events_stream", "ix_normalized_events_run_time")),
        ("log_segments", ("ix_log_segments_artifact_id", "ix_log_segments_stream_id")),
        ("log_streams", ("ix_log_streams_run_id",)),
        ("retention_holds", ("ix_retention_holds_run_id",)),
        ("input_mutations", ("ix_input_mutations_run_id", "ix_input_mutations_invocation_id")),
        ("input_envelopes", ("ix_input_envelopes_run_id",)),
        ("plan_revisions", ("ix_plan_revisions_run_id",)),
        ("scenario_routes", ("ix_scenario_routes_run_id",)),
    )
    for table, indexes in tables:
        for index in indexes:
            op.drop_index(index, table_name=table)
        op.drop_table(table)
    op.drop_table("retention_profiles")
