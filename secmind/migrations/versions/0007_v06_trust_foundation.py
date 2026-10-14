"""Add v0.6 recovery authority and transition truth."""

import sqlalchemy as sa
from alembic import op

revision = "0007_v06_trust_foundation"
down_revision = "0006_v05_governed_scenarios"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for name, type_, default in (
        ("run_fence", sa.Integer(), "0"),
        ("plan_revision", sa.Integer(), "0"),
        ("generation", sa.Integer(), "0"),
        ("version", sa.Integer(), "1"),
    ):
        op.add_column("step_runs", sa.Column(name, type_, nullable=False, server_default=default))
    op.add_column("step_runs", sa.Column("reservation_id", sa.String(length=36), nullable=True))
    op.add_column("step_runs", sa.Column("dispatch_permit_id", sa.String(length=36), nullable=True))
    op.add_column("outbox_events", sa.Column("transition_ordinal", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("outbox_events", sa.Column("subsequence", sa.Integer(), nullable=False, server_default="0"))
    op.create_index("ix_outbox_events_transition_ordinal", "outbox_events", ["transition_ordinal"])

    op.create_table(
        "recovery_commands",
        sa.Column("command_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("action", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("issued_fence", sa.Integer(), nullable=False),
        sa.Column("command_digest", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("owner_id", sa.String(length=100), nullable=True),
        sa.Column("result_receipt_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "command_digest"),
    )
    op.create_index("ix_recovery_commands_run_id", "recovery_commands", ["run_id"])
    op.create_index("ix_recovery_commands_status", "recovery_commands", ["status"])

    op.create_table(
        "transition_receipts",
        sa.Column("transition_id", sa.String(length=200), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("graph_node_id", sa.String(length=100), nullable=False),
        sa.Column("pre_state_version", sa.Integer(), nullable=False),
        sa.Column("pre_state_digest", sa.String(length=64), nullable=False),
        sa.Column("post_state_version", sa.Integer(), nullable=False),
        sa.Column("post_state_digest", sa.String(length=64), nullable=False),
        sa.Column("post_state_json", sa.Text(), nullable=False),
        sa.Column("run_fence", sa.Integer(), nullable=False),
        sa.Column("transition_ordinal", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("event_payload_digest", sa.String(length=64), nullable=False),
        sa.Column("receipt_digest", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("committed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "transition_ordinal"),
    )
    op.create_index("ix_transition_receipts_run_id", "transition_receipts", ["run_id"])

    op.create_table(
        "node_result_receipts",
        sa.Column("node_result_id", sa.String(length=36), primary_key=True),
        sa.Column("transition_id", sa.String(length=200), nullable=False),
        sa.Column("producer_type", sa.String(length=80), nullable=False),
        sa.Column("deterministic_key", sa.String(length=200), nullable=False),
        sa.Column("result_ref", sa.String(length=300), nullable=False),
        sa.Column("result_digest", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("transition_id", "deterministic_key"),
    )
    op.create_index("ix_node_result_receipts_transition_id", "node_result_receipts", ["transition_id"])


def downgrade() -> None:
    op.drop_index("ix_node_result_receipts_transition_id", table_name="node_result_receipts")
    op.drop_table("node_result_receipts")
    op.drop_index("ix_transition_receipts_run_id", table_name="transition_receipts")
    op.drop_table("transition_receipts")
    op.drop_index("ix_recovery_commands_status", table_name="recovery_commands")
    op.drop_index("ix_recovery_commands_run_id", table_name="recovery_commands")
    op.drop_table("recovery_commands")
    op.drop_index("ix_outbox_events_transition_ordinal", table_name="outbox_events")
    op.drop_column("outbox_events", "subsequence")
    op.drop_column("outbox_events", "transition_ordinal")
    for name in ("dispatch_permit_id", "reservation_id", "version", "generation", "plan_revision", "run_fence"):
        op.drop_column("step_runs", name)
