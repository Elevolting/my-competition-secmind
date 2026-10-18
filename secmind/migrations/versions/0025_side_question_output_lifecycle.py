"""Persist streamed side-question output and restart fencing."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0025_side_question_output"
down_revision = "0024_side_question_requests"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "side_question_requests", sa.Column("output_sequence", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column(
        "side_question_requests", sa.Column("clear_version", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column(
        "side_question_requests",
        sa.Column("observed_input_tokens", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "side_question_requests",
        sa.Column("observed_output_tokens", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "side_question_requests",
        sa.Column("observed_provider_requests", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_table(
        "side_question_output_events",
        sa.Column("question_id", sa.String(36), nullable=False),
        sa.Column("event_sequence", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(20), nullable=False),
        sa.Column("clear_version", sa.Integer(), nullable=False),
        sa.Column("delta_text", sa.Text(), nullable=True),
        sa.Column("cumulative_text", sa.Text(), nullable=True),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.PrimaryKeyConstraint("question_id", "event_sequence"),
    )
    op.create_index(
        "ix_side_question_output_events_question_id",
        "side_question_output_events",
        ["question_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_side_question_output_events_question_id", table_name="side_question_output_events")
    op.drop_table("side_question_output_events")
    op.drop_column("side_question_requests", "observed_provider_requests")
    op.drop_column("side_question_requests", "observed_output_tokens")
    op.drop_column("side_question_requests", "observed_input_tokens")
    op.drop_column("side_question_requests", "clear_version")
    op.drop_column("side_question_requests", "output_sequence")
