"""Add v0.6 artifact labels, secure projections, and completion receipts."""

import sqlalchemy as sa
from alembic import op

revision = "0010_v06_evidence_completion"
down_revision = "0009_v06_collaboration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "artifact_security_labels",
        sa.Column("label_id", sa.String(length=36), primary_key=True),
        sa.Column("artifact_id", sa.String(length=64), nullable=False),
        sa.Column("owner_run_id", sa.String(length=36), nullable=False),
        sa.Column("owner_step_id", sa.String(length=100), nullable=True),
        sa.Column("owner_invocation_id", sa.String(length=36), nullable=True),
        sa.Column("view", sa.String(length=30), nullable=False),
        sa.Column("data_class", sa.String(length=30), nullable=False),
        sa.Column("allowed_purposes_json", sa.Text(), nullable=False),
        sa.Column("retention_policy_id", sa.String(length=100), nullable=False),
        sa.Column("classification_version", sa.Integer(), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("artifact_id", "owner_run_id", "classification_version"),
    )
    op.create_index("ix_artifact_security_labels_artifact_id", "artifact_security_labels", ["artifact_id"])
    op.create_index("ix_artifact_security_labels_owner_run_id", "artifact_security_labels", ["owner_run_id"])
    op.create_index("ix_artifact_security_labels_view", "artifact_security_labels", ["view"])
    op.create_table(
        "secure_state_projections",
        sa.Column("projection_id", sa.String(length=36), primary_key=True),
        sa.Column("source_ref", sa.String(length=300), nullable=False, unique=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("source_digest", sa.String(length=64), nullable=False),
        sa.Column("observable_digest", sa.String(length=64), nullable=False),
        sa.Column("scrub_receipt_digest", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_secure_state_projections_run_id", "secure_state_projections", ["run_id"])
    op.create_table(
        "completion_snapshots",
        sa.Column("snapshot_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("run_state_version", sa.Integer(), nullable=False),
        sa.Column("run_fence", sa.Integer(), nullable=False),
        sa.Column("quiet_epoch", sa.Integer(), nullable=False),
        sa.Column("snapshot_digest", sa.String(length=64), nullable=False),
        sa.Column("is_quiet", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "run_state_version", "quiet_epoch"),
    )
    op.create_index("ix_completion_snapshots_run_id", "completion_snapshots", ["run_id"])
    op.create_table(
        "completion_receipts",
        sa.Column("receipt_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("decision", sa.String(length=40), nullable=False),
        sa.Column("receipt_digest", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "snapshot_id"),
    )
    op.create_index("ix_completion_receipts_run_id", "completion_receipts", ["run_id"])
    op.create_index("ix_completion_receipts_snapshot_id", "completion_receipts", ["snapshot_id"])


def downgrade() -> None:
    op.drop_index("ix_completion_receipts_snapshot_id", table_name="completion_receipts")
    op.drop_index("ix_completion_receipts_run_id", table_name="completion_receipts")
    op.drop_table("completion_receipts")
    op.drop_index("ix_completion_snapshots_run_id", table_name="completion_snapshots")
    op.drop_table("completion_snapshots")
    op.drop_index("ix_secure_state_projections_run_id", table_name="secure_state_projections")
    op.drop_table("secure_state_projections")
    op.drop_index("ix_artifact_security_labels_view", table_name="artifact_security_labels")
    op.drop_index("ix_artifact_security_labels_owner_run_id", table_name="artifact_security_labels")
    op.drop_index("ix_artifact_security_labels_artifact_id", table_name="artifact_security_labels")
    op.drop_table("artifact_security_labels")
