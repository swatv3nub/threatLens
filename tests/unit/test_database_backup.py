from __future__ import annotations

from threatlens.storage.database import Database


def test_sqlite_database_backup(settings, tmp_path) -> None:
    database = Database(settings.database_url)
    database.create_all()
    destination = tmp_path / "backup.db"

    database.backup(destination)

    assert destination.exists()
