"""Add v0.6 hierarchical usage and actual execution identity."""

import sqlalchemy as sa
from alembic import op

revision = "0011_v06_usage_execution"
down_revision = "0010_v06_evidence_completion"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "usage_reservations",
        sa.Column("reservation_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("parent_reservation_id", sa.String(length=36), nullable=True),
        sa.Column("transition_id", sa.String(length=200), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("content_digest", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_usage_reservations_run_id", "usage_reservations", ["run_id"])
    op.create_index("ix_usage_reservations_parent_reservation_id", "usage_reservations", ["parent_reservation_id"])
    op.create_index("ix_usage_reservations_status", "usage_reservations", ["status"])
    op.create_table(
        "usage_settlements",
        sa.Column("settlement_id", sa.String(length=36), primary_key=True),
        sa.Column("reservation_id", sa.String(length=36), nullable=False, unique=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("receipt_digest", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("settled_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_usage_settlements_reservation_id", "usage_settlements", ["reservation_id"])
    op.create_index("ix_usage_settlements_run_id", "usage_settlements", ["run_id"])
    op.create_table(
        "dispatch_permits",
        sa.Column("permit_id", sa.String(length=36), primary_key=True),
        sa.Column("invocation_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("step_run_id", sa.String(length=36), nullable=False),
        sa.Column("run_fence", sa.Integer(), nullable=False),
        sa.Column("step_fence", sa.Integer(), nullable=False),
        sa.Column("input_digest", sa.String(length=64), nullable=False),
        sa.Column("nonce", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("invocation_id", "nonce"),
    )
    for column in ("invocation_id", "run_id", "step_run_id", "status", "expires_at"):
        op.create_index(f"ix_dispatch_permits_{column}", "dispatch_permits", [column])
    op.create_table(
        "execution_identities",
        sa.Column("identity_digest", sa.String(length=64), primary_key=True),
        sa.Column("invocation_id", sa.String(length=36), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("step_run_id", sa.String(length=36), nullable=False),
        sa.Column("run_fence", sa.Integer(), nullable=False),
        sa.Column("step_fence", sa.Integer(), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("settled_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("invocation_id", "attempt"),
    )
    op.create_index("ix_execution_identities_invocation_id", "execution_identities", ["invocation_id"])
    op.create_index("ix_execution_identities_run_id", "execution_identities", ["run_id"])


def downgrade() -> None:
    op.drop_index("ix_execution_identities_run_id", table_name="execution_identities")
    op.drop_index("ix_execution_identities_invocation_id", table_name="execution_identities")
    op.drop_table("execution_identities")
    for column in ("expires_at", "status", "step_run_id", "run_id", "invocation_id"):
        op.drop_index(f"ix_dispatch_permits_{column}", table_name="dispatch_permits")
    op.drop_table("dispatch_permits")
    op.drop_index("ix_usage_settlements_run_id", table_name="usage_settlements")
    op.drop_index("ix_usage_settlements_reservation_id", table_name="usage_settlements")
    op.drop_table("usage_settlements")
    op.drop_index("ix_usage_reservations_status", table_name="usage_reservations")
    op.drop_index("ix_usage_reservations_parent_reservation_id", table_name="usage_reservations")
    op.drop_index("ix_usage_reservations_run_id", table_name="usage_reservations")
    op.drop_table("usage_reservations")
