"""SQLAlchemy engine/session setup.

SQLite is the only supported backend (local, single-user). The database file
lives in ``data/reportforge.db`` (see core.config). Foreign keys are enabled
per-connection because SQLite defaults to off.
"""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from . import config


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


engine = create_engine(
    f"sqlite:///{config.DB_PATH}",
    connect_args={"check_same_thread": False},
)


@event.listens_for(engine, "connect")
def _enable_sqlite_fk(dbapi_conn, _record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_session():
    """FastAPI dependency: one session per request, closed afterwards."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables (idempotent)."""
    # import models so they register on Base.metadata
    from ..models import finding, report  # noqa: F401

    Base.metadata.create_all(bind=engine)