import contextlib
import os
import shutil
import sys
import tempfile
from pathlib import Path
import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

TEST_DIR = Path(tempfile.mkdtemp(prefix="vulnstrike-pytest-"))
TEST_DATABASE_PATH = TEST_DIR / "vulnstrike-test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DATABASE_PATH.as_posix()}"


@pytest.fixture(scope="session")
def test_database_path():
    return TEST_DATABASE_PATH


def pytest_sessionfinish(session, exitstatus):
    with contextlib.suppress(Exception):
        from app.storage.database import engine

        engine.dispose()
    shutil.rmtree(TEST_DIR, ignore_errors=True)
