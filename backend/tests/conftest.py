"""Pytest configuration for isolated test execution.

Ensures all tests run in an isolated test database (test_runner.db)
so that the production database (sentinel.db) is never polluted with test artifacts.
"""
import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.db import base

TEST_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "test_runner.db"))
TEST_DB_URL = f"sqlite:///{TEST_DB_PATH}"


@pytest.fixture(scope="session", autouse=True)
def isolated_test_database():
    """Setup isolated test database for entire test session, then cleanly drop it."""
    orig_db_url = settings.DATABASE_URL
    orig_engine = base.engine
    orig_session_local = base.SessionLocal

    # 1. Point to isolated test database
    settings.DATABASE_URL = TEST_DB_URL
    test_engine = create_engine(
        TEST_DB_URL,
        connect_args={"check_same_thread": False},
    )
    base.engine = test_engine
    base.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    base.init_db()

    yield

    # 2. Teardown: Restore original and delete test database
    test_engine.dispose()
    base.engine = orig_engine
    base.SessionLocal = orig_session_local
    settings.DATABASE_URL = orig_db_url

    for ext in ("", "-wal", "-shm"):
        fpath = f"{TEST_DB_PATH}{ext}"
        if os.path.exists(fpath):
            try:
                os.remove(fpath)
            except Exception:
                pass
