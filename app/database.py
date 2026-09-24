from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase
import os

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
os.makedirs(DATA_DIR, exist_ok=True)
SQLALCHEMY_DATABASE_URL = f"sqlite:///{os.path.join(DATA_DIR, 'akm.db')}"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})


@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
    ensure_columns()


# Columns added after v1: create_all won't add them to existing DBs.
_MIGRATIONS = [
    ("investigations", "schedule_enabled", "INTEGER NOT NULL DEFAULT 0"),
    ("investigations", "schedule_cron", "VARCHAR(100)"),
    ("investigations", "schedule_max_items", "INTEGER NOT NULL DEFAULT 25"),
    ("investigations", "schedule_max_rounds", "INTEGER NOT NULL DEFAULT 2"),
    ("investigations", "last_scheduled_at", "DATETIME"),
    ("investigations", "next_run_at", "DATETIME"),
    ("artifacts", "run_id", "INTEGER"),
    ("relationships", "run_id", "INTEGER"),
    ("relationships", "created_at", "DATETIME"),
    ("agent_runs", "trigger", "VARCHAR(20) NOT NULL DEFAULT 'manual'"),
    ("explanations", "trace", "TEXT"),
    ("explanations", "mode", "VARCHAR(20) DEFAULT 'explain'"),
    ("explanations", "depth", "VARCHAR(20) DEFAULT 'balanced'"),
    ("explanations", "audience", "VARCHAR(20) DEFAULT 'intermediate'"),
    ("explanations", "max_pages", "INTEGER DEFAULT 6"),
    ("explanations", "hops", "INTEGER DEFAULT 0"),
    ("explanations", "meta", "TEXT"),
    ("explanations", "parent_id", "INTEGER"),
    ("explanations", "thread_id", "INTEGER"),
    ("explanations", "quiz", "TEXT"),
    ("explanations", "bookmarked", "INTEGER NOT NULL DEFAULT 0"),
]


def ensure_columns():
    with engine.begin() as conn:
        for table, column, ddl in _MIGRATIONS:
            cols = [r[1] for r in
                    conn.execute(text(f"PRAGMA table_info({table})")).fetchall()]
            if column not in cols:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
