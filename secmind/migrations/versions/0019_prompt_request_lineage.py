"""Persist immutable prompt artifact and selection lineage per provider request."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0019_prompt_lineage"
down_revision = "0018_reliability_control"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("model_invocations") as batch:
        batch.add_column(sa.Column("prompt_artifact_id", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("prompt_selection_digest", sa.String(length=64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("model_invocations") as batch:
        batch.drop_column("prompt_selection_digest")
        batch.drop_column("prompt_artifact_id")
