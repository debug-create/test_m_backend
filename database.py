"""Database engine and session factory."""

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from config import DATABASE_URL


class Base(DeclarativeBase):
    pass


engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)


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
            "regime_state": "VARCHAR(16) NOT NULL DEFAULT 'nominal'",
            "regime_feature": "VARCHAR(64) DEFAULT 'overall_deviation'",
            "regime_baseline": "FLOAT",
            "regime_last_evaluated_at": "DATETIME",
        },
        "cases": {
            "data_quality": "VARCHAR(16) NOT NULL DEFAULT 'sufficient'",
            "residual_unresolved_count": "INTEGER NOT NULL DEFAULT 0",
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
