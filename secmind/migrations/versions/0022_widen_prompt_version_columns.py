"""Allow full prompt version identifiers in the prompt catalog and artifact store."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0022_widen_prompt_versions"
down_revision = "0021_outbox_quarantine_proj"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("prompt_templates") as batch:
        batch.alter_column("version", existing_type=sa.String(length=40), type_=sa.String(length=180))
    with op.batch_alter_table("prompt_artifacts") as batch:
        batch.alter_column("template_version", existing_type=sa.String(length=40), type_=sa.String(length=180))


def downgrade() -> None:
    bind = op.get_bind()
    for table, column in (("prompt_templates", "version"), ("prompt_artifacts", "template_version")):
        count = bind.execute(sa.text(f"SELECT COUNT(*) FROM {table} WHERE length({column}) > 40")).scalar_one()
        if count:
            raise RuntimeError(f"Cannot narrow {table}.{column}: {count} values exceed 40 characters")
    with op.batch_alter_table("prompt_artifacts") as batch:
        batch.alter_column("template_version", existing_type=sa.String(length=180), type_=sa.String(length=40))
    with op.batch_alter_table("prompt_templates") as batch:
        batch.alter_column("version", existing_type=sa.String(length=180), type_=sa.String(length=40))
