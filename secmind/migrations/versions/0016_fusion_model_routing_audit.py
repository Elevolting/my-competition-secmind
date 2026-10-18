"""Persist deterministic model-route audit metadata for every provider attempt."""

import sqlalchemy as sa
from alembic import op

revision = "0016_fusion_model_audit"
down_revision = "0015_fusion_evidence_ids"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "model_invocations",
        sa.Column("task_kind", sa.String(length=50), nullable=False, server_default="legacy_unknown"),
    )
    op.add_column(
        "model_invocations",
        sa.Column("model_lane", sa.String(length=30), nullable=False, server_default="legacy_unknown"),
    )
    op.add_column(
        "model_invocations",
        sa.Column("router_version", sa.String(length=100), nullable=False, server_default="legacy_unknown"),
    )
    op.add_column(
        "model_invocations",
        sa.Column("prompt_version", sa.String(length=256), nullable=False, server_default="legacy_unknown"),
    )


def downgrade() -> None:
    op.drop_column("model_invocations", "prompt_version")
    op.drop_column("model_invocations", "router_version")
    op.drop_column("model_invocations", "model_lane")
    op.drop_column("model_invocations", "task_kind")
