import sqlite3

import pytest

from scripts.backup_sqlite import backup


def test_backup_round_trip_and_refuses_overwrite(tmp_path):
    source, target = tmp_path / "source.db", tmp_path / "backup.db"
    with sqlite3.connect(source) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE evidence (id TEXT)")
        connection.execute("INSERT INTO evidence VALUES ('important')")
        connection.commit()
        result = backup(source, target)
    assert result["integrity"] == "ok"
    assert len(result["sha256"]) == 64
    with sqlite3.connect(target) as restored:
        assert restored.execute("SELECT * FROM evidence").fetchall() == [("important",)]
    with pytest.raises(FileExistsError):
        backup(source, target)
    with pytest.raises(ValueError):
        backup(source, source)
