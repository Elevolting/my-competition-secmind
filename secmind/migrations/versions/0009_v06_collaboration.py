"""Add v0.6 typed collaboration delivery receipts."""

import sqlalchemy as sa
from alembic import op

revision = "0009_v06_collaboration"
down_revision = "0008_v06_planning_contracts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "investigation_messages",
        sa.Column("message_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("recipient_role", sa.String(length=100), nullable=False),
        sa.Column("kind", sa.String(length=60), nullable=False),
        sa.Column("dedupe_key", sa.String(length=200), nullable=False),
        sa.Column("payload_digest", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "dedupe_key"),
    )
    op.create_index("ix_investigation_messages_run_id", "investigation_messages", ["run_id"])
    op.create_index("ix_investigation_messages_recipient_role", "investigation_messages", ["recipient_role"])
    op.create_index("ix_investigation_messages_expires_at", "investigation_messages", ["expires_at"])
    op.create_table(
        "message_receipts",
        sa.Column("message_id", sa.String(length=36), primary_key=True),
        sa.Column("delivery_attempt", sa.Integer(), nullable=False),
        sa.Column("reservation_owner", sa.String(length=100), nullable=False),
        sa.Column("delivery_fence", sa.Integer(), nullable=False),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("receipt_version", sa.Integer(), nullable=False),
        sa.Column("transport_status", sa.String(length=20), nullable=False),
        sa.Column("processing_status", sa.String(length=30), nullable=False),
        sa.Column("processed_transition_id", sa.String(length=200), nullable=True),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("message_receipts")
    op.drop_index("ix_investigation_messages_expires_at", table_name="investigation_messages")
    op.drop_index("ix_investigation_messages_recipient_role", table_name="investigation_messages")
    op.drop_index("ix_investigation_messages_run_id", table_name="investigation_messages")
    op.drop_table("investigation_messages")
