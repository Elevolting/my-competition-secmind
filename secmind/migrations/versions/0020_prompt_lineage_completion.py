"""Complete provider-attempt to prompt lineage persistence."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0020_prompt_lineage_completion"
down_revision = "0019_prompt_lineage"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Nullable identity links preserve rows written by pre-lineage releases;
    # every new provider attempt is normalized by CoordinatorStore before it
    # reaches these columns. Typed defaults keep legacy rows explicit rather
    # than silently treating them as an unclassified prompt.
    with op.batch_alter_table("model_invocations") as batch:
        batch.add_column(sa.Column("logical_call_id", sa.String(length=128), nullable=True))
        batch.add_column(sa.Column("parent_logical_call_id", sa.String(length=128), nullable=True))
        batch.add_column(sa.Column("prompt_optimizer_attempt_id", sa.String(length=160), nullable=True))
        batch.add_column(
            sa.Column(
                "prompt_lineage_reason",
                sa.String(length=80),
                nullable=False,
                server_default="legacy_unbound_prompt",
            )
        )
        batch.add_column(sa.Column("lineage_stage", sa.String(length=32), nullable=False, server_default="legacy"))
        batch.create_index("ix_model_invocations_logical_call_id", ["logical_call_id"])
        batch.create_index("ix_model_invocations_parent_logical_call_id", ["parent_logical_call_id"])
        batch.create_index("ix_model_invocations_prompt_optimizer_attempt_id", ["prompt_optimizer_attempt_id"])

    with op.batch_alter_table("prompt_optimization_attempts") as batch:
        batch.add_column(sa.Column("request_digest", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("selection_digest", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("logical_call_id", sa.String(length=128), nullable=True))
        batch.add_column(sa.Column("parent_logical_call_id", sa.String(length=128), nullable=True))
        batch.add_column(
            sa.Column("lineage_reason", sa.String(length=80), nullable=False, server_default="optimizer_attempt")
        )
        batch.create_index("ix_prompt_optimization_attempts_request_digest", ["request_digest"])
        batch.create_index("ix_prompt_optimization_attempts_selection_digest", ["selection_digest"])
        batch.create_index("ix_prompt_optimization_attempts_logical_call_id", ["logical_call_id"])
        batch.create_index("ix_prompt_optimization_attempts_parent_logical_call_id", ["parent_logical_call_id"])

    with op.batch_alter_table("prompt_artifacts") as batch:
        batch.add_column(sa.Column("selection_digest", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("optimizer_attempt_id", sa.String(length=160), nullable=True))
        batch.add_column(sa.Column("lineage_reason", sa.String(length=80), nullable=False, server_default="fixed_mode"))
        batch.create_index("ix_prompt_artifacts_selection_digest", ["selection_digest"])
        batch.create_index("ix_prompt_artifacts_optimizer_attempt_id", ["optimizer_attempt_id"])


def downgrade() -> None:
    with op.batch_alter_table("prompt_artifacts") as batch:
        batch.drop_index("ix_prompt_artifacts_optimizer_attempt_id")
        batch.drop_index("ix_prompt_artifacts_selection_digest")
        batch.drop_column("lineage_reason")
        batch.drop_column("optimizer_attempt_id")
        batch.drop_column("selection_digest")

    with op.batch_alter_table("prompt_optimization_attempts") as batch:
        batch.drop_index("ix_prompt_optimization_attempts_parent_logical_call_id")
        batch.drop_index("ix_prompt_optimization_attempts_logical_call_id")
        batch.drop_index("ix_prompt_optimization_attempts_selection_digest")
        batch.drop_index("ix_prompt_optimization_attempts_request_digest")
        batch.drop_column("lineage_reason")
        batch.drop_column("parent_logical_call_id")
        batch.drop_column("logical_call_id")
        batch.drop_column("selection_digest")
        batch.drop_column("request_digest")

    with op.batch_alter_table("model_invocations") as batch:
        batch.drop_index("ix_model_invocations_prompt_optimizer_attempt_id")
        batch.drop_index("ix_model_invocations_parent_logical_call_id")
        batch.drop_index("ix_model_invocations_logical_call_id")
        batch.drop_column("lineage_stage")
        batch.drop_column("prompt_lineage_reason")
        batch.drop_column("prompt_optimizer_attempt_id")
        batch.drop_column("parent_logical_call_id")
        batch.drop_column("logical_call_id")
