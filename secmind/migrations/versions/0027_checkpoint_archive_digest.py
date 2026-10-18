"""Persist checkpoint snapshot digests at archive freeze boundaries."""

import sqlalchemy as sa
from alembic import op

revision = "0027_checkpoint_archive_digest"
down_revision = "0026_archive_freezes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "run_archive_freezes",
        sa.Column("checkpoint_snapshot_digest", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("run_archive_freezes", "checkpoint_snapshot_digest")
