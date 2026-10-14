"""Add the v0.3 leased coordinator and transactional outbox control plane."""

import sqlalchemy as sa
from alembic import op

revision = "0002_v03_control_plane"
down_revision = "0001_business_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("runs") as batch:
        batch.add_column(sa.Column("state_version", sa.Integer(), nullable=False, server_default="1"))

    with op.batch_alter_table("tool_invocations") as batch:
        batch.add_column(sa.Column("owner_id", sa.String(length=100), nullable=True))
        batch.add_column(sa.Column("fence", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))

    with op.batch_alter_table("approvals") as batch:
        batch.add_column(sa.Column("resolution_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("fence", sa.Integer(), nullable=False, server_default="0"))
        batch.create_unique_constraint("uq_approvals_resolution_id", ["resolution_id"])

    op.create_table(
        "run_jobs",
        sa.Column("run_id", sa.String(length=36), primary_key=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("owner_id", sa.String(length=100), nullable=True),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_run_jobs_status", "run_jobs", ["status"])
    op.create_index("ix_run_jobs_owner_id", "run_jobs", ["owner_id"])
    op.create_index("ix_run_jobs_lease_until", "run_jobs", ["lease_until"])
    op.create_index("ix_run_jobs_next_attempt_at", "run_jobs", ["next_attempt_at"])

    op.create_table(
        "step_runs",
        sa.Column("step_run_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("step_id", sa.String(length=100), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("transition_id", sa.String(length=200), nullable=False),
        sa.Column("fence", sa.Integer(), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "step_id", "attempt"),
    )
    op.create_index("ix_step_runs_run_id", "step_runs", ["run_id"])
    op.create_index("ix_step_runs_status", "step_runs", ["status"])

    op.create_table(
        "model_invocations",
        sa.Column("model_invocation_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("step_id", sa.String(length=100), nullable=True),
        sa.Column("provider_request_id", sa.String(length=200), nullable=True),
        sa.Column("model_id", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("output_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cost_microunits", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("response_hash", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_model_invocations_run_id", "model_invocations", ["run_id"])
    op.create_index("ix_model_invocations_status", "model_invocations", ["status"])

    op.create_table(
        "outbox_events",
        sa.Column("outbox_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("transition_id", sa.String(length=200), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("actor", sa.String(length=100), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("projected_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("run_id", "transition_id"),
    )
    op.create_index("ix_outbox_events_run_id", "outbox_events", ["run_id"])
    op.create_index("ix_outbox_events_event_type", "outbox_events", ["event_type"])
    op.create_index("ix_outbox_events_status", "outbox_events", ["status"])

    op.create_table(
        "artifact_objects",
        sa.Column("artifact_id", sa.String(length=64), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("invocation_id", sa.String(length=36), nullable=True),
        sa.Column("storage_ref", sa.String(length=300), nullable=False, unique=True),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("media_type", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_artifact_objects_run_id", "artifact_objects", ["run_id"])


def downgrade() -> None:
    op.drop_index("ix_artifact_objects_run_id", table_name="artifact_objects")
    op.drop_table("artifact_objects")
    op.drop_index("ix_outbox_events_status", table_name="outbox_events")
    op.drop_index("ix_outbox_events_event_type", table_name="outbox_events")
    op.drop_index("ix_outbox_events_run_id", table_name="outbox_events")
    op.drop_table("outbox_events")
    op.drop_index("ix_model_invocations_status", table_name="model_invocations")
    op.drop_index("ix_model_invocations_run_id", table_name="model_invocations")
    op.drop_table("model_invocations")
    op.drop_index("ix_step_runs_status", table_name="step_runs")
    op.drop_index("ix_step_runs_run_id", table_name="step_runs")
    op.drop_table("step_runs")
    op.drop_index("ix_run_jobs_next_attempt_at", table_name="run_jobs")
    op.drop_index("ix_run_jobs_lease_until", table_name="run_jobs")
    op.drop_index("ix_run_jobs_owner_id", table_name="run_jobs")
    op.drop_index("ix_run_jobs_status", table_name="run_jobs")
    op.drop_table("run_jobs")

    with op.batch_alter_table("approvals") as batch:
        batch.drop_constraint("uq_approvals_resolution_id", type_="unique")
        batch.drop_column("fence")
        batch.drop_column("consumed_at")
        batch.drop_column("resolution_id")
    with op.batch_alter_table("tool_invocations") as batch:
        batch.drop_column("heartbeat_at")
        batch.drop_column("fence")
        batch.drop_column("owner_id")
    with op.batch_alter_table("runs") as batch:
        batch.drop_column("state_version")
