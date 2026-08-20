"""Database Engine singleton for KarsaSec Sprint F3.

Reads DATABASE_URL from environment. Falls back to local dev Postgres.
Provides session factory for use by all repository implementations.
"""

from __future__ import annotations

from contextlib import contextmanager
import os
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from karsasec.persistence.models import Base


_DEFAULT_URL = "postgresql://localhost:5432/karsasec"


def _get_database_url() -> str:
    return os.environ.get("DATABASE_URL", _DEFAULT_URL)


# ---------------------------------------------------------------------------
# Engine & session factory
# ---------------------------------------------------------------------------

def build_engine(url: str | None = None):
    """Create and return a configured SQLAlchemy engine."""
    db_url = url or _get_database_url()
    if "sqlite" in db_url:
        return create_engine(
            db_url,
            connect_args={"check_same_thread": False, "timeout": 30},
            echo=False,
            future=True,
        )
    return create_engine(
        db_url,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
        echo=False,
        future=True,
    )


def create_all_tables(engine=None) -> None:
    """Create all tables defined in models if they do not exist."""
    eng = engine or build_engine()
    Base.metadata.create_all(bind=eng)


def drop_all_tables(engine=None) -> None:
    """Drop all tables. Used in test teardown only."""
    eng = engine or build_engine()
    Base.metadata.drop_all(bind=eng)


class DatabaseSessionFactory:
    """Thread-safe session factory wrapper. One instance per application process."""

    def __init__(self, url: str | None = None) -> None:
        self._engine = build_engine(url)
        self._session_factory = sessionmaker(
            bind=self._engine,
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
        )

    @property
    def engine(self):
        return self._engine

    def get_session(self) -> Session:
        """Return a new DB session. Caller is responsible for commit/close."""
        return self._session_factory()

    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """Context manager that commits on success and rolls back on error."""
        session = self.get_session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


# ---------------------------------------------------------------------------
# Module-level singleton (lazy init)
# ---------------------------------------------------------------------------

_factory: DatabaseSessionFactory | None = None


def get_session_factory() -> DatabaseSessionFactory:
    """Return the module-level singleton DatabaseSessionFactory."""
    global _factory
    if _factory is None:
        _factory = DatabaseSessionFactory()
    return _factory


def reset_session_factory(url: str | None = None) -> None:
    """Reset the singleton — used in tests to inject test DB URL."""
    global _factory
    _factory = DatabaseSessionFactory(url)
