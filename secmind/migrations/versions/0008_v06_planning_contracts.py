"""Add v0.6 append-only planning and investigation contracts."""

import sqlalchemy as sa
from alembic import op

revision = "0008_v06_planning_contracts"
down_revision = "0007_v06_trust_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "investigation_objects",
        sa.Column("object_id", sa.String(length=100), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("object_type", sa.String(length=80), nullable=False),
        sa.Column("logical_key", sa.String(length=200), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("content_digest", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "object_type", "logical_key", "version"),
    )
    op.create_index("ix_investigation_objects_run_id", "investigation_objects", ["run_id"])
    op.create_index("ix_investigation_objects_object_type", "investigation_objects", ["object_type"])


def downgrade() -> None:
    op.drop_index("ix_investigation_objects_object_type", table_name="investigation_objects")
    op.drop_index("ix_investigation_objects_run_id", table_name="investigation_objects")
    op.drop_table("investigation_objects")
