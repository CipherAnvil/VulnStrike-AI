import os
import sqlite3
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.storage import database

ROOT = Path(__file__).resolve().parents[2]
DEVELOPMENT_DATABASE = ROOT / "vulnstrike.db"


def snapshot(path: Path) -> bytes | None:
    return path.read_bytes() if path.exists() else None


def test_engine_uses_isolated_temp_database(test_database_path):
    engine_path = Path(database.engine.url.database).resolve()
    temp_root = Path(tempfile.gettempdir()).resolve()

    assert os.environ["DATABASE_URL"] == database.DATABASE_URL
    assert engine_path == test_database_path.resolve()
    assert engine_path != DEVELOPMENT_DATABASE.resolve()
    assert engine_path.is_relative_to(temp_root)


def test_background_task_writes_only_to_test_database(test_database_path):
    before = snapshot(DEVELOPMENT_DATABASE)

    with TestClient(app) as client:
        response = client.post(
            "/api/scans",
            json={
                "target_url": "http://localhost:8088",
                "authorized_confirmation": True,
                "profile": "quick",
                "enabled_modules": ["cve_intel"],
            },
        )

    assert response.status_code == 200
    scan_id = response.json()["id"]
    assert snapshot(DEVELOPMENT_DATABASE) == before

    connection = sqlite3.connect(test_database_path)
    try:
        row = connection.execute(
            "SELECT status FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
    finally:
        connection.close()

    assert row is not None
    assert row[0] == "completed"
