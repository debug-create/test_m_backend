"""Database engine and session factory."""

import secrets

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from config import DATABASE_URL


class Base(DeclarativeBase):
    pass


_engine_options = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    _engine_options["connect_args"] = {"check_same_thread": False}
engine = create_engine(DATABASE_URL, **_engine_options)


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    # Import models so metadata is populated
    import models.db_models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _apply_additive_migrations()


def _apply_additive_migrations() -> None:
    """Add columns introduced during the prototype without destroying demo data."""
    additions = {
        "entities": {
            "pseudonymous_id": "VARCHAR(64)",
            "regime_state": "VARCHAR(16) NOT NULL DEFAULT 'nominal'",
            "regime_feature": "VARCHAR(64) DEFAULT 'overall_deviation'",
            "regime_baseline": "FLOAT",
            "regime_last_evaluated_at": "DATETIME",
        },
        "cases": {
            "data_quality": "VARCHAR(16) NOT NULL DEFAULT 'sufficient'",
            "residual_unresolved_count": "INTEGER NOT NULL DEFAULT 0",
            "fusion_components": "JSON NOT NULL DEFAULT '{}'",
            "event_risk_breakdown": "JSON NOT NULL DEFAULT '[]'",
            "retroactive_justification_review": "BOOLEAN NOT NULL DEFAULT 0",
            "current_assessment_id": "INTEGER",
        },
        "events": {
            "latitude": "FLOAT",
            "longitude": "FLOAT",
        },
        "context_ledger": {
            "approval_state": "VARCHAR(16) NOT NULL DEFAULT 'approved'",
            "supersedes_id": "INTEGER",
            "proposed_by": "VARCHAR(128)",
            "proposed_at": "DATETIME",
            "reviewed_by": "VARCHAR(128)",
            "reviewed_at": "DATETIME",
            "review_note": "TEXT",
            "effective_from": "DATETIME",
            "effective_until": "DATETIME",
            "late_context": "BOOLEAN NOT NULL DEFAULT 0",
        },
    }
    with engine.begin() as connection:
        inspector = inspect(connection)
        tables = set(inspector.get_table_names())
        for table, columns in additions.items():
            if table not in tables:
                continue
            existing = {c["name"] for c in inspector.get_columns(table)}
            for name, ddl in columns.items():
                if name not in existing:
                    connection.execute(text(f'ALTER TABLE "{table}" ADD COLUMN "{name}" {ddl}'))

        # Existing entities receive opaque stable references without exposing names.
        if "entities" in tables:
            rows = connection.execute(
                text("SELECT id FROM entities WHERE pseudonymous_id IS NULL")
            ).fetchall()
            for row in rows:
                connection.execute(
                    text("UPDATE entities SET pseudonymous_id=:ref WHERE id=:id"),
                    {"ref": f"ent_{secrets.token_hex(8)}", "id": row.id},
                )
        if "context_ledger" in tables:
            connection.execute(text(
                "UPDATE context_ledger SET effective_from=valid_from "
                "WHERE effective_from IS NULL"
            ))
            connection.execute(text(
                "UPDATE context_ledger SET effective_until=valid_until "
                "WHERE effective_until IS NULL"
            ))
