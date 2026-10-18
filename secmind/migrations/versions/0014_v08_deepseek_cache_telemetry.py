"""Persist provider cache-hit telemetry for v0.8 cost accounting."""

import sqlalchemy as sa
from alembic import op

revision = "0014_v08_cache_telemetry"
down_revision = "0013_v07_prompt_intelligence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "model_invocations",
        sa.Column("cache_hit_input_tokens", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "model_invocations",
        sa.Column("cache_miss_input_tokens", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("model_invocations", "cache_miss_input_tokens")
    op.drop_column("model_invocations", "cache_hit_input_tokens")
