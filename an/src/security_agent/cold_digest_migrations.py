"""Explicit schema migrations for the durable cold-digest projection.

The blackboard ledger owns the database engine, but the cold-digest tables have
their own schema lifecycle.  Keeping this migration boundary separate prevents
``Base.metadata.create_all`` from being treated as a production upgrade
mechanism while still allowing an existing prototype database to be opened.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import Table, insert, select, update

CURRENT_COLD_DIGEST_SCHEMA = 2


class ColdDigestMigrationError(RuntimeError):
    """The persisted cold-digest schema cannot be used safely."""


def ensure_cold_digest_schema(engine: Any) -> int:
    """Create or upgrade the cold-digest tables and return the schema version.

    Version one is the original durable prototype schema.  Version two adds a
    durable round identity table used to make planner wakeups idempotent.  A
    database created by the prototype has no schema marker; its existing cold
    tables are treated as version one and then upgraded normally.
    """

    # Import lazily so the model module can use this helper during store
    # construction without introducing a module import cycle.
    from security_agent.cold_digest import (
        ColdDigestCoverRow,
        ColdDigestNodeRow,
        ColdDigestRoundRow,
        ColdDigestRow,
        ColdDigestRunRow,
        ColdDigestSchemaRow,
    )

    schema_table = cast(Table, ColdDigestSchemaRow.__table__)
    v1_tables = (
        ColdDigestRunRow.__table__,
        ColdDigestNodeRow.__table__,
        ColdDigestRow.__table__,
        ColdDigestCoverRow.__table__,
    )

    with engine.begin() as connection:
        schema_table.create(connection, checkfirst=True)
        version = connection.execute(
            select(ColdDigestSchemaRow.version).where(ColdDigestSchemaRow.schema_id == 1)
        ).scalar_one_or_none()

        if version is None:
            # Existing installations from the prototype already have these
            # tables, while fresh installations need them created here.
            for table in v1_tables:
                cast(Table, table).create(connection, checkfirst=True)
            connection.execute(
                insert(ColdDigestSchemaRow).values(
                    schema_id=1,
                    version=1,
                    updated_at=datetime.now(UTC),
                )
            )
            version = 1

        if version > CURRENT_COLD_DIGEST_SCHEMA:
            raise ColdDigestMigrationError(
                f"cold-digest schema {version} is newer than supported {CURRENT_COLD_DIGEST_SCHEMA}"
            )

        if version < 2:
            cast(Table, ColdDigestRoundRow.__table__).create(connection, checkfirst=True)
            connection.execute(
                update(ColdDigestSchemaRow)
                .where(ColdDigestSchemaRow.schema_id == 1)
                .values(version=2, updated_at=datetime.now(UTC))
            )
            version = 2

    return int(version)
