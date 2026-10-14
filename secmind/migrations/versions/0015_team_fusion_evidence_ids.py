"""Widen immutable evidence identifiers used by cognitive-kernel links."""

import sqlalchemy as sa
from alembic import op

revision = "0015_fusion_evidence_ids"
down_revision = "0014_v08_cache_telemetry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # batch_alter_table emits a normal ALTER on PostgreSQL and safely rebuilds
    # the table on SQLite, including the existing unique constraint.
    with op.batch_alter_table("evidence_links") as batch:
        batch.alter_column(
            "evidence_id",
            existing_type=sa.String(length=36),
            type_=sa.String(length=100),
            existing_nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("evidence_links") as batch:
        batch.alter_column(
            "evidence_id",
            existing_type=sa.String(length=100),
            type_=sa.String(length=36),
            existing_nullable=False,
        )
