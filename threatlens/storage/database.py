from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker

from threatlens.storage.models import Base


def build_engine(database_url: str) -> Engine:
    connect_args: dict[str, object] = {}
    if database_url.startswith("sqlite"):
        connect_args = {"check_same_thread": False, "timeout": 30}
    return create_engine(
        database_url,
        future=True,
        connect_args=connect_args,
        pool_pre_ping=True,
    )


class Database:
    def __init__(self, database_url: str) -> None:
        self._engine = build_engine(database_url)
        self._session_factory = sessionmaker(
            bind=self._engine, expire_on_commit=False, class_=Session
        )

    def create_all(self) -> None:
        Base.metadata.create_all(self._engine)

    def drop_all(self) -> None:
        Base.metadata.drop_all(self._engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @property
    def engine(self) -> Engine:
        return self._engine

    def dispose(self) -> None:
        self._engine.dispose()

    def backup(self, destination: Path) -> Path:
        """Create a consistent SQLite backup for the operational backup job."""
        url = make_url(str(self._engine.url))
        if url.get_backend_name() != "sqlite" or url.database in {None, ":memory:"}:
            raise RuntimeError("the built-in backup command supports file-based SQLite only")
        source = Path(url.database)
        destination.parent.mkdir(parents=True, exist_ok=True)
        self.dispose()
        with sqlite3.connect(source) as source_db, sqlite3.connect(destination) as target_db:
            source_db.backup(target_db)
        return destination
