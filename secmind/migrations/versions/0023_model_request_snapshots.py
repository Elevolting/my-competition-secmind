"""Persist immutable snapshots of actual primary model requests."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0023_model_request_snapshots"
down_revision = "0022_widen_prompt_versions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "model_request_snapshots",
        sa.Column("version", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("snapshot_id", sa.String(36), nullable=False, unique=True),
        sa.Column("parent_key", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(200), nullable=False),
        sa.Column("source", sa.String(30), nullable=False),
        sa.Column("step_id", sa.String(200), nullable=True),
        sa.Column("worker_id", sa.String(200), nullable=True),
        sa.Column("captured_at", sa.String(40), nullable=False),
        sa.Column("model_id", sa.String(200), nullable=False),
        sa.Column("configuration_identity", sa.String(64), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("redacted", sa.Boolean(), nullable=False),
        sa.Column("request_json", sa.Text(), nullable=False),
        sa.Column("provenance_json", sa.Text(), nullable=False),
        sqlite_autoincrement=True,
    )
    op.create_index("ix_model_request_snapshots_parent_key", "model_request_snapshots", ["parent_key"])
    op.create_index("ix_model_request_snapshots_run_id", "model_request_snapshots", ["run_id"])


def downgrade() -> None:
    op.drop_table("model_request_snapshots")
