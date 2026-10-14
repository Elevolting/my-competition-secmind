"""Add the v0.7 adaptive prompt intelligence persistence boundary."""

import sqlalchemy as sa
from alembic import op

revision = "0013_v07_prompt_intelligence"
down_revision = "0012_v07_direct_anchor"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "prompt_templates",
        sa.Column("template_id", sa.String(length=128), primary_key=True),
        sa.Column("version", sa.String(length=40), primary_key=True),
        sa.Column("role", sa.String(length=30), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_prompt_templates_role", "prompt_templates", ["role"])
    op.create_index("ix_prompt_templates_status", "prompt_templates", ["status"])

    op.create_table(
        "prompt_optimization_attempts",
        sa.Column("attempt_id", sa.String(length=160), primary_key=True),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("context_id", sa.String(length=160), nullable=False),
        sa.Column("context_digest", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("model_id", sa.String(length=128), nullable=False),
        sa.Column("response_hash", sa.String(length=64), nullable=True),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_prompt_optimization_attempts_run_id", "prompt_optimization_attempts", ["run_id"])
    op.create_index("ix_prompt_optimization_attempts_context_id", "prompt_optimization_attempts", ["context_id"])
    op.create_index("ix_prompt_optimization_attempts_status", "prompt_optimization_attempts", ["status"])

    op.create_table(
        "prompt_artifacts",
        sa.Column("run_id", sa.String(length=64), primary_key=True),
        sa.Column("artifact_id", sa.String(length=64), primary_key=True),
        sa.Column("context_id", sa.String(length=160), nullable=False),
        sa.Column("role", sa.String(length=30), nullable=False),
        sa.Column("mode", sa.String(length=30), nullable=False),
        sa.Column("template_id", sa.String(length=128), nullable=False),
        sa.Column("template_version", sa.String(length=40), nullable=False),
        sa.Column("rendered_prompt_digest", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "context_id", "artifact_id"),
    )
    op.create_index("ix_prompt_artifacts_context_id", "prompt_artifacts", ["context_id"])
    op.create_index("ix_prompt_artifacts_role", "prompt_artifacts", ["role"])
    op.create_index("ix_prompt_artifacts_mode", "prompt_artifacts", ["mode"])
    op.create_index("ix_prompt_artifacts_template_id", "prompt_artifacts", ["template_id"])

    op.create_table(
        "prompt_outcomes",
        sa.Column("outcome_id", sa.String(length=64), primary_key=True),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("artifact_id", sa.String(length=64), nullable=False),
        sa.Column("model_receipt_id", sa.String(length=160), nullable=False),
        sa.Column("schema_valid", sa.Boolean(), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=False),
        sa.Column("output_tokens", sa.Integer(), nullable=False),
        sa.Column("cost_units", sa.Float(), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_prompt_outcomes_run_id", "prompt_outcomes", ["run_id"])
    op.create_index("ix_prompt_outcomes_artifact_id", "prompt_outcomes", ["artifact_id"])
    op.create_index("ix_prompt_outcomes_model_receipt_id", "prompt_outcomes", ["model_receipt_id"])


def downgrade() -> None:
    op.drop_index("ix_prompt_outcomes_model_receipt_id", table_name="prompt_outcomes")
    op.drop_index("ix_prompt_outcomes_artifact_id", table_name="prompt_outcomes")
    op.drop_index("ix_prompt_outcomes_run_id", table_name="prompt_outcomes")
    op.drop_table("prompt_outcomes")

    op.drop_index("ix_prompt_artifacts_template_id", table_name="prompt_artifacts")
    op.drop_index("ix_prompt_artifacts_mode", table_name="prompt_artifacts")
    op.drop_index("ix_prompt_artifacts_role", table_name="prompt_artifacts")
    op.drop_index("ix_prompt_artifacts_context_id", table_name="prompt_artifacts")
    op.drop_table("prompt_artifacts")

    op.drop_index("ix_prompt_optimization_attempts_status", table_name="prompt_optimization_attempts")
    op.drop_index("ix_prompt_optimization_attempts_context_id", table_name="prompt_optimization_attempts")
    op.drop_index("ix_prompt_optimization_attempts_run_id", table_name="prompt_optimization_attempts")
    op.drop_table("prompt_optimization_attempts")

    op.drop_index("ix_prompt_templates_status", table_name="prompt_templates")
    op.drop_index("ix_prompt_templates_role", table_name="prompt_templates")
    op.drop_table("prompt_templates")
