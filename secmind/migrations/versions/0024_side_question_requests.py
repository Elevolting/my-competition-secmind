"""Persist independent side-question identity and budget settlement."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0024_side_question_requests"
down_revision = "0023_model_request_snapshots"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "side_question_requests",
        sa.Column("question_id", sa.String(36), primary_key=True),
        sa.Column("request_key", sa.String(200), nullable=False, unique=True),
        sa.Column("parent_key", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(200), nullable=False),
        sa.Column("source", sa.String(30), nullable=False),
        sa.Column("snapshot_id", sa.String(36), nullable=False),
        sa.Column("snapshot_version", sa.Integer(), nullable=False),
        sa.Column("configuration_identity", sa.String(64), nullable=False),
        sa.Column("question_sha256", sa.String(64), nullable=False),
        sa.Column("question_text", sa.Text(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("reserved_input_tokens", sa.Integer(), nullable=False),
        sa.Column("reserved_output_tokens", sa.Integer(), nullable=False),
        sa.Column("settled_input_tokens", sa.Integer(), nullable=False),
        sa.Column("settled_output_tokens", sa.Integer(), nullable=False),
        sa.Column("provider_requests", sa.Integer(), nullable=False),
        sa.Column("answer_text", sa.Text(), nullable=True),
        sa.Column("error_type", sa.String(100), nullable=True),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
    )
    op.create_index("ix_side_question_requests_parent_key", "side_question_requests", ["parent_key"])
    op.create_index("ix_side_question_requests_run_id", "side_question_requests", ["run_id"])
    op.create_index("ix_side_question_requests_snapshot_id", "side_question_requests", ["snapshot_id"])
    op.create_index("ix_side_question_requests_status", "side_question_requests", ["status"])


def downgrade() -> None:
    op.drop_table("side_question_requests")
