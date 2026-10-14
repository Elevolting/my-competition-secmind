"""Persist typed model-gateway attempt and failure diagnostics."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0017_model_gateway_diag"
down_revision = "0016_fusion_model_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("model_invocations", sa.Column("request_digest", sa.String(length=64), nullable=True))
    op.add_column(
        "model_invocations",
        sa.Column("attempt_ordinal", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "model_invocations",
        sa.Column("stage", sa.String(length=64), nullable=False, server_default="provider"),
    )
    op.add_column("model_invocations", sa.Column("error_type", sa.String(length=80), nullable=True))
    op.add_column("model_invocations", sa.Column("status_code", sa.Integer(), nullable=True))
    op.add_column(
        "model_invocations",
        sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "model_invocations",
        sa.Column("retryable", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "model_invocations",
        sa.Column("deadline_ms", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "model_invocations",
        sa.Column("remaining_budget_ms", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "model_invocations",
        sa.Column("route", sa.String(length=120), nullable=False, server_default="legacy_unknown"),
    )
    op.add_column(
        "model_invocations",
        sa.Column("route_profile", sa.String(length=64), nullable=False, server_default="legacy_unknown"),
    )

    op.create_table(
        "model_gateway_failures",
        sa.Column("failure_id", sa.String(length=64), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("logical_call_id", sa.String(length=128), nullable=True),
        sa.Column("error_type", sa.String(length=80), nullable=False),
        sa.Column("stage", sa.String(length=64), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("retryable", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("request_digest", sa.String(length=64), nullable=True),
        sa.Column("route", sa.String(length=120), nullable=False),
        sa.Column("route_profile", sa.String(length=64), nullable=False),
        sa.Column("model_id", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("prompt_version", sa.String(length=256), nullable=False, server_default=""),
        sa.Column("deadline_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("remaining_budget_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("fallback_status", sa.String(length=32), nullable=False),
        sa.Column("attempts_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_model_gateway_failures_run_id", "model_gateway_failures", ["run_id"])
    op.create_index(
        "ix_model_gateway_failures_logical_call_id",
        "model_gateway_failures",
        ["logical_call_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_model_gateway_failures_logical_call_id", table_name="model_gateway_failures")
    op.drop_index("ix_model_gateway_failures_run_id", table_name="model_gateway_failures")
    op.drop_table("model_gateway_failures")
    for column in (
        "route_profile",
        "route",
        "remaining_budget_ms",
        "deadline_ms",
        "retryable",
        "duration_ms",
        "status_code",
        "error_type",
        "stage",
        "attempt_ordinal",
        "request_digest",
    ):
        op.drop_column("model_invocations", column)
