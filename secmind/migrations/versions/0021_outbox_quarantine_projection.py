"""Persist operator skip receipts and projection source receipt CAS metadata."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0021_outbox_quarantine_proj"
down_revision = "0020_prompt_lineage_completion"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Some installations carried the 0020 revision marker forward while
    # retaining an older physical outbox schema.  Keep this linear migration
    # self-healing: normal 0018 databases simply skip the already-present
    # reliability columns, while those installations receive the same durable
    # CAS/quarantine shape without manual SQL edits.
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    outbox_columns = {column["name"] for column in inspector.get_columns("outbox_events")}
    outbox_indexes = {index["name"] for index in inspector.get_indexes("outbox_events")}
    with op.batch_alter_table("outbox_events") as batch:
        if "payload_digest" not in outbox_columns:
            batch.add_column(sa.Column("payload_digest", sa.String(length=64), nullable=True))
        if "next_attempt_at" not in outbox_columns:
            batch.add_column(sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True))
        if "failure_class" not in outbox_columns:
            batch.add_column(sa.Column("failure_class", sa.String(length=64), nullable=True))
        if "dead_lettered_at" not in outbox_columns:
            batch.add_column(sa.Column("dead_lettered_at", sa.DateTime(timezone=True), nullable=True))
        if "quarantine_reason" not in outbox_columns:
            batch.add_column(sa.Column("quarantine_reason", sa.Text(), nullable=True))
        if "quarantined_by" not in outbox_columns:
            batch.add_column(sa.Column("quarantined_by", sa.String(length=100), nullable=True))
        if "quarantined_at" not in outbox_columns:
            batch.add_column(sa.Column("quarantined_at", sa.DateTime(timezone=True), nullable=True))
        if "skip_receipt_id" not in outbox_columns:
            batch.add_column(sa.Column("skip_receipt_id", sa.String(length=36), nullable=True))
        if "skip_receipt_digest" not in outbox_columns:
            batch.add_column(sa.Column("skip_receipt_digest", sa.String(length=64), nullable=True))
        if "ix_outbox_events_payload_digest" not in outbox_indexes:
            batch.create_index("ix_outbox_events_payload_digest", ["payload_digest"])
        if "ix_outbox_events_next_attempt_at" not in outbox_indexes:
            batch.create_index("ix_outbox_events_next_attempt_at", ["next_attempt_at"])
        if "ix_outbox_events_skip_receipt_id" not in outbox_indexes:
            batch.create_index("ix_outbox_events_skip_receipt_id", ["skip_receipt_id"])

    notebook_columns = {column["name"] for column in inspector.get_columns("run_notebooks")}
    with op.batch_alter_table("run_notebooks") as batch:
        if "source_fence" not in notebook_columns:
            batch.add_column(sa.Column("source_fence", sa.Integer(), nullable=False, server_default="0"))
        if "source_transition_id" not in notebook_columns:
            batch.add_column(sa.Column("source_transition_id", sa.String(length=200), nullable=True))

    table_names = set(inspector.get_table_names())
    if "projection_heads" not in table_names:
        op.create_table(
            "projection_heads",
            sa.Column("run_id", sa.String(length=36), primary_key=True),
            sa.Column("source_state_version", sa.Integer(), nullable=False),
            sa.Column("source_fence", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("source_transition_id", sa.String(length=200), nullable=False),
            sa.Column("projection_digest", sa.String(length=64), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("outbox_receipt_id", sa.String(length=36), nullable=True),
        )
        op.create_index("ix_projection_heads_outbox_receipt_id", "projection_heads", ["outbox_receipt_id"])
    else:
        projection_columns = {column["name"] for column in inspector.get_columns("projection_heads")}
        projection_indexes = {index["name"] for index in inspector.get_indexes("projection_heads")}
        with op.batch_alter_table("projection_heads") as batch:
            if "outbox_receipt_id" not in projection_columns:
                batch.add_column(sa.Column("outbox_receipt_id", sa.String(length=36), nullable=True))
            if "ix_projection_heads_outbox_receipt_id" not in projection_indexes:
                batch.create_index("ix_projection_heads_outbox_receipt_id", ["outbox_receipt_id"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "projection_heads" in set(inspector.get_table_names()):
        projection_columns = {column["name"] for column in inspector.get_columns("projection_heads")}
        projection_indexes = {index["name"] for index in inspector.get_indexes("projection_heads")}
        if "outbox_receipt_id" in projection_columns or "ix_projection_heads_outbox_receipt_id" in projection_indexes:
            with op.batch_alter_table("projection_heads") as batch:
                if "ix_projection_heads_outbox_receipt_id" in projection_indexes:
                    batch.drop_index("ix_projection_heads_outbox_receipt_id")
                if "outbox_receipt_id" in projection_columns:
                    batch.drop_column("outbox_receipt_id")

    outbox_columns = {column["name"] for column in inspector.get_columns("outbox_events")}
    outbox_indexes = {index["name"] for index in inspector.get_indexes("outbox_events")}
    with op.batch_alter_table("outbox_events") as batch:
        if "ix_outbox_events_skip_receipt_id" in outbox_indexes:
            batch.drop_index("ix_outbox_events_skip_receipt_id")
        if "skip_receipt_digest" in outbox_columns:
            batch.drop_column("skip_receipt_digest")
        if "skip_receipt_id" in outbox_columns:
            batch.drop_column("skip_receipt_id")
        if "quarantined_at" in outbox_columns:
            batch.drop_column("quarantined_at")
        if "quarantined_by" in outbox_columns:
            batch.drop_column("quarantined_by")
        if "quarantine_reason" in outbox_columns:
            batch.drop_column("quarantine_reason")
