"""Add durable archive freeze boundaries for runs."""

import sqlalchemy as sa
from alembic import op


revision = "0026_archive_freezes"
down_revision = "0025_side_question_output"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "run_archive_freezes",
        sa.Column("run_id", sa.String(length=36), primary_key=True),
        sa.Column("freeze_id", sa.String(length=200), nullable=False, unique=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("state_version", sa.Integer(), nullable=False),
        sa.Column("latest_event_sequence", sa.Integer(), nullable=False),
        sa.Column("ledger_head_hash", sa.String(length=64), nullable=False),
        sa.Column("artifact_snapshot_digest", sa.String(length=64), nullable=True),
        sa.Column("frozen_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_run_archive_freezes_freeze_id", "run_archive_freezes", ["freeze_id"], unique=True)
    op.create_index("ix_run_archive_freezes_status", "run_archive_freezes", ["status"])


def downgrade() -> None:
    op.drop_index("ix_run_archive_freezes_status", table_name="run_archive_freezes")
    op.drop_index("ix_run_archive_freezes_freeze_id", table_name="run_archive_freezes")
    op.drop_table("run_archive_freezes")
