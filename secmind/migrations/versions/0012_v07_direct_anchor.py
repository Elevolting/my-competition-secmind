"""Add the v0.7 Direct-anchor persistence tables.

The existing control-plane schema deliberately uses ``run_id`` as an indexed
application-level reference instead of a database foreign key.  These tables
follow that strategy so the audit store can remain colocated with, or be
projected independently from, the run ledger.
"""

import sqlalchemy as sa
from alembic import op

revision = "0012_v07_direct_anchor"
down_revision = "0011_v06_usage_execution"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_units",
        sa.Column("run_id", sa.String(length=36), primary_key=True),
        sa.Column("unit_id", sa.String(length=80), primary_key=True),
        sa.Column("language", sa.String(length=30), nullable=False),
        sa.Column("primary_path", sa.String(length=1024), nullable=False),
        sa.Column("source_sha256", sa.String(length=64), nullable=False),
        sa.Column("input_manifest_digest", sa.String(length=64), nullable=False),
        sa.Column("profile_digest", sa.String(length=64), nullable=False),
        sa.Column("scope_digest", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("state_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("run_fence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("payload_digest", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "unit_id", "payload_digest"),
    )
    op.create_index("ix_audit_units_run_id", "audit_units", ["run_id"])
    op.create_index("ix_audit_units_status", "audit_units", ["status"])
    op.create_index("ix_audit_units_run_status", "audit_units", ["run_id", "status"])

    op.create_table(
        "provider_receipts",
        sa.Column("receipt_id", sa.String(length=256), primary_key=True),
        sa.Column("run_id", sa.String(length=36), primary_key=True),
        sa.Column("logical_call_id", sa.String(length=128), nullable=False),
        sa.Column("provider_request_id", sa.String(length=128), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("model_id", sa.String(length=128), nullable=False),
        sa.Column("prompt_version", sa.String(length=128), nullable=False),
        sa.Column("request_digest", sa.String(length=64), nullable=False),
        sa.Column("response_sha256", sa.String(length=64), nullable=False),
        sa.Column("receipt_digest", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "provider_request_id"),
        sa.UniqueConstraint("run_id", "logical_call_id", "attempt"),
    )
    op.create_index("ix_provider_receipts_run_id", "provider_receipts", ["run_id"])
    op.create_index(
        "ix_provider_receipts_logical_call",
        "provider_receipts",
        ["run_id", "logical_call_id"],
    )

    op.create_table(
        "baseline_verdicts",
        sa.Column("record_id", sa.String(length=80), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("unit_id", sa.String(length=80), nullable=False),
        sa.Column("provider_receipt_id", sa.String(length=256), nullable=True),
        sa.Column("verdict", sa.String(length=30), nullable=False),
        sa.Column("verdict_digest", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "unit_id"),
    )
    op.create_index("ix_baseline_verdicts_run_id", "baseline_verdicts", ["run_id"])
    op.create_index(
        "ix_baseline_verdicts_provider_receipt_id",
        "baseline_verdicts",
        ["provider_receipt_id"],
    )

    op.create_table(
        "unit_decisions",
        sa.Column("decision_id", sa.String(length=80), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("unit_id", sa.String(length=80), nullable=False),
        sa.Column("lane", sa.String(length=20), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("release_id", sa.String(length=80), nullable=True),
        sa.Column("action", sa.String(length=30), nullable=False),
        sa.Column("decision_digest", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "unit_id", "lane", "revision"),
    )
    op.create_index("ix_unit_decisions_run_id", "unit_decisions", ["run_id"])
    op.create_index("ix_unit_decisions_run_lane", "unit_decisions", ["run_id", "lane"])
    op.create_index("ix_unit_decisions_release_id", "unit_decisions", ["release_id"])

    op.create_table(
        "patch_releases",
        sa.Column("release_id", sa.String(length=80), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("patch_type", sa.String(length=100), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("profile_digest", sa.String(length=64), nullable=False),
        sa.Column("policy_digest", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("state_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("payload_digest", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("revocation_reason", sa.String(length=500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("patch_type", "version"),
    )
    op.create_index("ix_patch_releases_run_id", "patch_releases", ["run_id"])
    op.create_index("ix_patch_releases_status", "patch_releases", ["status"])
    op.create_index(
        "ix_patch_releases_type_status",
        "patch_releases",
        ["patch_type", "status"],
    )


def downgrade() -> None:
    op.drop_index("ix_patch_releases_type_status", table_name="patch_releases")
    op.drop_index("ix_patch_releases_status", table_name="patch_releases")
    op.drop_index("ix_patch_releases_run_id", table_name="patch_releases")
    op.drop_table("patch_releases")

    op.drop_index("ix_unit_decisions_release_id", table_name="unit_decisions")
    op.drop_index("ix_unit_decisions_run_lane", table_name="unit_decisions")
    op.drop_index("ix_unit_decisions_run_id", table_name="unit_decisions")
    op.drop_table("unit_decisions")

    op.drop_index(
        "ix_baseline_verdicts_provider_receipt_id",
        table_name="baseline_verdicts",
    )
    op.drop_index("ix_baseline_verdicts_run_id", table_name="baseline_verdicts")
    op.drop_table("baseline_verdicts")

    op.drop_index("ix_provider_receipts_logical_call", table_name="provider_receipts")
    op.drop_index("ix_provider_receipts_run_id", table_name="provider_receipts")
    op.drop_table("provider_receipts")

    op.drop_index("ix_audit_units_run_status", table_name="audit_units")
    op.drop_index("ix_audit_units_status", table_name="audit_units")
    op.drop_index("ix_audit_units_run_id", table_name="audit_units")
    op.drop_table("audit_units")
