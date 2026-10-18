"""Add v0.5 alpha TaskSpec, parser and clarification control tables."""

import sqlalchemy as sa
from alembic import op

revision = "0005_v05_taskspec_alpha"
down_revision = "0004_v04_cognitive_kernel"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("run_jobs") as batch:
        batch.add_column(sa.Column("wake_requested", sa.Boolean(), nullable=False, server_default=sa.false()))

    op.create_table(
        "task_specs",
        sa.Column("task_spec_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False, unique=True),
        sa.Column("current_revision", sa.Integer(), nullable=False),
        sa.Column("content_digest", sa.String(length=64), nullable=False),
        sa.Column("spec_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_task_specs_run_id", "task_specs", ["run_id"])

    op.create_table(
        "task_spec_revisions",
        sa.Column("revision_id", sa.String(length=36), primary_key=True),
        sa.Column("task_spec_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("content_digest", sa.String(length=64), nullable=False),
        sa.Column("parent_revision_digest", sa.String(length=64), nullable=True),
        sa.Column("reason", sa.String(length=200), nullable=False),
        sa.Column("spec_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "revision"),
    )
    op.create_index("ix_task_spec_revisions_task_spec_id", "task_spec_revisions", ["task_spec_id"])
    op.create_index("ix_task_spec_revisions_run_id", "task_spec_revisions", ["run_id"])

    op.create_table(
        "parser_runs",
        sa.Column("parser_run_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("artifact_id", sa.String(length=36), nullable=False),
        sa.Column("parser_id", sa.String(length=100), nullable=False),
        sa.Column("parser_version", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("input_digest", sa.String(length=64), nullable=False),
        sa.Column("output_digest", sa.String(length=64), nullable=True),
        sa.Column("run_json", sa.Text(), nullable=False),
        sa.Column("parsed_asset_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_parser_runs_run_id", "parser_runs", ["run_id"])
    op.create_index("ix_parser_runs_artifact_id", "parser_runs", ["artifact_id"])

    op.create_table(
        "clarification_requests",
        sa.Column("request_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("task_spec_id", sa.String(length=36), nullable=False),
        sa.Column("task_spec_revision", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("request_json", sa.Text(), nullable=False),
        sa.Column("response_json", sa.Text(), nullable=True),
        sa.Column("response_digest", sa.String(length=64), nullable=True),
        sa.Column("resolution_id", sa.String(length=36), nullable=True),
        sa.Column("requested_fence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("consumed_fence", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_clarification_requests_run_id", "clarification_requests", ["run_id"])
    op.create_index("ix_clarification_requests_status", "clarification_requests", ["status"])


def downgrade() -> None:
    op.drop_index("ix_clarification_requests_status", table_name="clarification_requests")
    op.drop_index("ix_clarification_requests_run_id", table_name="clarification_requests")
    op.drop_table("clarification_requests")
    op.drop_index("ix_parser_runs_artifact_id", table_name="parser_runs")
    op.drop_index("ix_parser_runs_run_id", table_name="parser_runs")
    op.drop_table("parser_runs")
    op.drop_index("ix_task_spec_revisions_run_id", table_name="task_spec_revisions")
    op.drop_index("ix_task_spec_revisions_task_spec_id", table_name="task_spec_revisions")
    op.drop_table("task_spec_revisions")
    op.drop_index("ix_task_specs_run_id", table_name="task_specs")
    op.drop_table("task_specs")
    with op.batch_alter_table("run_jobs") as batch:
        batch.drop_column("wake_requested")
