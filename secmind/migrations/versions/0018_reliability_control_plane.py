"""Add retry/dead-letter metadata and monotonic projection heads."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0018_reliability_control"
down_revision = "0017_model_gateway_diag"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("outbox_events") as batch:
        batch.add_column(sa.Column("payload_digest", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("failure_class", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("dead_lettered_at", sa.DateTime(timezone=True), nullable=True))
        batch.create_index("ix_outbox_events_payload_digest", ["payload_digest"])
        batch.create_index("ix_outbox_events_next_attempt_at", ["next_attempt_at"])

    with op.batch_alter_table("run_notebooks") as batch:
        batch.add_column(sa.Column("source_fence", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("source_transition_id", sa.String(length=200), nullable=True))

    op.create_table(
        "projection_heads",
        sa.Column("run_id", sa.String(length=36), primary_key=True),
        sa.Column("source_state_version", sa.Integer(), nullable=False),
        sa.Column("source_fence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source_transition_id", sa.String(length=200), nullable=False),
        sa.Column("projection_digest", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("projection_heads")
    with op.batch_alter_table("run_notebooks") as batch:
        batch.drop_column("source_transition_id")
        batch.drop_column("source_fence")
    with op.batch_alter_table("outbox_events") as batch:
        batch.drop_index("ix_outbox_events_next_attempt_at")
        batch.drop_index("ix_outbox_events_payload_digest")
        batch.drop_column("dead_lettered_at")
        batch.drop_column("failure_class")
        batch.drop_column("next_attempt_at")
        batch.drop_column("payload_digest")
