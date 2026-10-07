from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    pass


# Ensure directory exists for SQLite
import os
db_path = settings.DATABASE_URL.replace("sqlite:///", "")
os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {},
    echo=settings.DEBUG,
)


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enforce foreign key constraints and production WAL mode on SQLite."""
    if "sqlite" in settings.DATABASE_URL:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=10000")
        cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Session:
    """Dependency for FastAPI route injection."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables and perform lightweight migrations. Safe to call multiple times."""
    Base.metadata.create_all(bind=engine)
    if "sqlite" in settings.DATABASE_URL:
        try:
            with engine.connect() as conn:
                cursor = conn.connection.cursor()
                cursor.execute("PRAGMA table_info(scans)")
                cols = [row[1] for row in cursor.fetchall()]
                if "spec_version" not in cols:
                    cursor.execute("ALTER TABLE scans ADD COLUMN spec_version VARCHAR")
                if "serial_number" not in cols:
                    cursor.execute("ALTER TABLE scans ADD COLUMN serial_number VARCHAR")
                if "provenance" not in cols:
                    cursor.execute("ALTER TABLE scans ADD COLUMN provenance JSON")
                conn.connection.commit()
                cursor.close()
        except Exception:
            pass

