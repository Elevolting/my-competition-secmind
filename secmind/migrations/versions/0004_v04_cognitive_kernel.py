"""Add the v0.4 trusted cognitive kernel metadata plane."""

import sqlalchemy as sa
from alembic import op

revision = "0004_v04_cognitive_kernel"
down_revision = "0003_v03_knowledge"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("tool_invocations") as batch:
        batch.add_column(sa.Column("grant_id", sa.String(length=36), nullable=True))
        batch.create_index("ix_tool_invocations_grant_id", ["grant_id"])

    with op.batch_alter_table("outbox_events") as batch:
        batch.add_column(sa.Column("owner_id", sa.String(length=100), nullable=True))
        batch.add_column(sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("last_error", sa.Text(), nullable=True))
        batch.create_index("ix_outbox_events_lease_until", ["lease_until"])

    with op.batch_alter_table("step_runs") as batch:
        batch.add_column(sa.Column("owner_id", sa.String(length=100), nullable=True))
        batch.add_column(sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("context_pack_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("outcome_contract_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("dependency_outputs_json", sa.Text(), nullable=True))
        batch.create_index("ix_step_runs_lease_until", ["lease_until"])
        batch.create_index("ix_step_runs_owner_id", ["owner_id"])

    op.create_table(
        "artifact_owners",
        sa.Column("run_id", sa.String(length=36), primary_key=True),
        sa.Column("artifact_id", sa.String(length=64), primary_key=True),
        sa.Column("invocation_id", sa.String(length=36), nullable=True),
        sa.Column("producer_step_id", sa.String(length=100), nullable=False),
        sa.Column("output_name", sa.String(length=100), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("media_type", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_artifact_owners_artifact_id", "artifact_owners", ["artifact_id"])

    op.create_table(
        "repository_indexes",
        sa.Column("index_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False, unique=True),
        sa.Column("artifact_id", sa.String(length=64), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("summary_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_repository_indexes_run_id", "repository_indexes", ["run_id"])

    op.create_table(
        "context_items",
        sa.Column("context_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=40), nullable=False),
        sa.Column("source", sa.String(length=500), nullable=False),
        sa.Column("authority_level", sa.Integer(), nullable=False),
        sa.Column("taint", sa.String(length=20), nullable=False),
        sa.Column("sensitivity", sa.String(length=40), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("token_estimate", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("artifact_id", sa.String(length=64), nullable=True),
        sa.Column("metadata_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "content_hash", "kind"),
    )
    op.create_index("ix_context_items_run_id", "context_items", ["run_id"])
    op.create_index("ix_context_items_kind", "context_items", ["kind"])

    op.create_table(
        "context_packs",
        sa.Column("pack_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("step_id", sa.String(length=100), nullable=True),
        sa.Column("agent_profile", sa.String(length=100), nullable=False),
        sa.Column("pack_digest", sa.String(length=64), nullable=False),
        sa.Column("manifest_json", sa.Text(), nullable=False),
        sa.Column("token_budget", sa.Integer(), nullable=False),
        sa.Column("token_used", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "pack_digest"),
    )
    op.create_index("ix_context_packs_run_id", "context_packs", ["run_id"])
    op.create_index("ix_context_packs_step_id", "context_packs", ["step_id"])

    op.create_table(
        "skill_packages",
        sa.Column("skill_id", sa.String(length=100), primary_key=True),
        sa.Column("active_version", sa.String(length=100), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "skill_versions",
        sa.Column("skill_id", sa.String(length=100), primary_key=True),
        sa.Column("version", sa.String(length=100), primary_key=True),
        sa.Column("package_digest", sa.String(length=64), nullable=False, unique=True),
        sa.Column("signer", sa.String(length=200), nullable=False),
        sa.Column("manifest_json", sa.Text(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "outcome_contracts",
        sa.Column("contract_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("step_id", sa.String(length=100), nullable=False),
        sa.Column("contract_digest", sa.String(length=64), nullable=False),
        sa.Column("contract_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "step_id"),
    )
    op.create_index("ix_outcome_contracts_run_id", "outcome_contracts", ["run_id"])

    op.create_table(
        "claims",
        sa.Column("claim_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("step_id", sa.String(length=100), nullable=True),
        sa.Column("claim_type", sa.String(length=100), nullable=False),
        sa.Column("subject_ref", sa.String(length=500), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("producer", sa.String(length=100), nullable=False),
        sa.Column("claim_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_claims_run_id", "claims", ["run_id"])
    op.create_index("ix_claims_status", "claims", ["status"])

    op.create_table(
        "evidence_links",
        sa.Column("link_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("claim_id", sa.String(length=36), nullable=False),
        sa.Column("evidence_id", sa.String(length=36), nullable=False),
        sa.Column("relation", sa.String(length=30), nullable=False),
        sa.Column("weight", sa.Float(), nullable=False),
        sa.Column("verifier_status", sa.String(length=30), nullable=False),
        sa.Column("grader_id", sa.String(length=100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("claim_id", "evidence_id", "relation"),
    )
    op.create_index("ix_evidence_links_run_id", "evidence_links", ["run_id"])
    op.create_index("ix_evidence_links_claim_id", "evidence_links", ["claim_id"])

    op.create_table(
        "run_notebooks",
        sa.Column("run_id", sa.String(length=36), primary_key=True),
        sa.Column("notebook_digest", sa.String(length=64), nullable=False),
        sa.Column("notebook_json", sa.Text(), nullable=False),
        sa.Column("state_version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "policy_decisions",
        sa.Column("decision_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("step_id", sa.String(length=100), nullable=False),
        sa.Column("action", sa.String(length=30), nullable=False),
        sa.Column("effective_risk", sa.Integer(), nullable=False),
        sa.Column("decision_input_hash", sa.String(length=64), nullable=False),
        sa.Column("decision_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "decision_input_hash"),
    )
    op.create_index("ix_policy_decisions_run_id", "policy_decisions", ["run_id"])

    op.create_table(
        "capability_grants",
        sa.Column("grant_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("actor", sa.String(length=100), nullable=False),
        sa.Column("grant_digest", sa.String(length=64), nullable=False, unique=True),
        sa.Column("grant_json", sa.Text(), nullable=False),
        sa.Column("max_uses", sa.Integer(), nullable=False),
        sa.Column("uses", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_capability_grants_run_id", "capability_grants", ["run_id"])
    op.create_index("ix_capability_grants_expires_at", "capability_grants", ["expires_at"])

    op.create_table(
        "hook_executions",
        sa.Column("execution_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("step_id", sa.String(length=100), nullable=True),
        sa.Column("hook_id", sa.String(length=100), nullable=False),
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("input_hash", sa.String(length=64), nullable=False),
        sa.Column("output_hash", sa.String(length=64), nullable=True),
        sa.Column("result_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("hook_id", "event_id"),
    )
    op.create_index("ix_hook_executions_run_id", "hook_executions", ["run_id"])

    op.create_table(
        "replay_bundles",
        sa.Column("replay_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("parent_run_id", sa.String(length=36), nullable=True),
        sa.Column("artifact_id", sa.String(length=64), nullable=False),
        sa.Column("manifest_digest", sa.String(length=64), nullable=False),
        sa.Column("ledger_head_hash", sa.String(length=64), nullable=False),
        sa.Column("ledger_head_signature", sa.Text(), nullable=True),
        sa.Column("mode", sa.String(length=40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "manifest_digest"),
    )
    op.create_index("ix_replay_bundles_run_id", "replay_bundles", ["run_id"])


def downgrade() -> None:
    op.drop_index("ix_replay_bundles_run_id", table_name="replay_bundles")
    op.drop_table("replay_bundles")
    op.drop_index("ix_hook_executions_run_id", table_name="hook_executions")
    op.drop_table("hook_executions")
    op.drop_index("ix_capability_grants_expires_at", table_name="capability_grants")
    op.drop_index("ix_capability_grants_run_id", table_name="capability_grants")
    op.drop_table("capability_grants")
    op.drop_index("ix_policy_decisions_run_id", table_name="policy_decisions")
    op.drop_table("policy_decisions")
    op.drop_table("run_notebooks")
    op.drop_index("ix_evidence_links_claim_id", table_name="evidence_links")
    op.drop_index("ix_evidence_links_run_id", table_name="evidence_links")
    op.drop_table("evidence_links")
    op.drop_index("ix_claims_status", table_name="claims")
    op.drop_index("ix_claims_run_id", table_name="claims")
    op.drop_table("claims")
    op.drop_index("ix_outcome_contracts_run_id", table_name="outcome_contracts")
    op.drop_table("outcome_contracts")
    op.drop_table("skill_versions")
    op.drop_table("skill_packages")
    op.drop_index("ix_context_packs_step_id", table_name="context_packs")
    op.drop_index("ix_context_packs_run_id", table_name="context_packs")
    op.drop_table("context_packs")
    op.drop_index("ix_context_items_kind", table_name="context_items")
    op.drop_index("ix_context_items_run_id", table_name="context_items")
    op.drop_table("context_items")
    op.drop_index("ix_repository_indexes_run_id", table_name="repository_indexes")
    op.drop_table("repository_indexes")
    op.drop_index("ix_artifact_owners_artifact_id", table_name="artifact_owners")
    op.drop_table("artifact_owners")

    with op.batch_alter_table("step_runs") as batch:
        batch.drop_index("ix_step_runs_owner_id")
        batch.drop_index("ix_step_runs_lease_until")
        batch.drop_column("dependency_outputs_json")
        batch.drop_column("outcome_contract_id")
        batch.drop_column("context_pack_id")
        batch.drop_column("heartbeat_at")
        batch.drop_column("lease_until")
        batch.drop_column("owner_id")

    with op.batch_alter_table("tool_invocations") as batch:
        batch.drop_index("ix_tool_invocations_grant_id")
        batch.drop_column("grant_id")

    with op.batch_alter_table("outbox_events") as batch:
        batch.drop_index("ix_outbox_events_lease_until")
        batch.drop_column("last_error")
        batch.drop_column("attempts")
        batch.drop_column("lease_until")
        batch.drop_column("owner_id")
