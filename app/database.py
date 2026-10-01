from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase
import os

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
os.makedirs(DATA_DIR, exist_ok=True)
# Overridable so tests (and throwaway audits) can point at a scratch database
# instead of the real one.
SQLALCHEMY_DATABASE_URL = os.environ.get(
    "AKM_DATABASE_URL", f"sqlite:///{os.path.join(DATA_DIR, 'akm.db')}")

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
    # Imported here, not at module scope: the ledger models build on Base, and
    # database is their foundation, so a top-level import would be circular.
    from . import ledger_models  # noqa: F401
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
    ("explanations", "watched", "INTEGER NOT NULL DEFAULT 0"),
    ("investigations", "preferred_domains", "VARCHAR(500)"),
    ("investigations", "auto_save_explanations", "INTEGER NOT NULL DEFAULT 1"),
    ("investigations", "hidden", "INTEGER NOT NULL DEFAULT 0"),
    ("artifacts", "drift", "INTEGER NOT NULL DEFAULT 0"),
    ("security_assessments", "inherent_pct", "FLOAT"),
    ("security_assessments", "residual_pct", "FLOAT"),
    ("security_assessments", "model_json", "TEXT"),
    ("security_assessments", "supersedes_id", "INTEGER"),
    ("security_assessments", "hypothesis_json", "TEXT"),
    ("security_assessments", "controls_json", "TEXT"),
    ("security_assessments", "scoring_json", "TEXT"),
    ("security_assessments", "workflow_text", "TEXT"),
    ("security_assessments", "doc_urls_json", "TEXT"),
    ("security_assessments", "focus_json", "TEXT"),
    ("security_assessments", "require_approval", "INTEGER"),
    ("security_assessments", "perspectives_json", "TEXT"),
    # Which threat pack scored this row. Nullable on purpose: existing
    # assessments predate versioned packs, and stamping them with today's
    # fingerprint would be a false claim about how they were produced.
    ("security_assessments", "threat_pack_version", "VARCHAR(20)"),
    ("security_assessments", "threat_pack_fingerprint", "VARCHAR(20)"),
    # Ledger sessions: additive columns on the existing run table, so an
    # already-audited run keeps its chain and simply gains a session link.
    ("ledger_runs", "kind", "VARCHAR(20) NOT NULL DEFAULT 'task'"),
    ("ledger_runs", "session_id", "VARCHAR(64)"),
    ("ledger_runs", "client_key", "VARCHAR(64)"),
    ("ledger_runs", "last_seen_at", "DATETIME"),
    # Trace id per event. Additive and unhashed (see LedgerEvent.trace), so an
    # existing run keeps verifying byte-for-byte and simply gains the column.
    # ledger_audit_drops needs no entry: it is a new table, so create_all makes
    # it whole.
    ("ledger_events", "trace", "VARCHAR(48)"),
]


def ensure_columns():
    with engine.begin() as conn:
        for table, column, ddl in _MIGRATIONS:
            cols = [r[1] for r in
                    conn.execute(text(f"PRAGMA table_info({table})")).fetchall()]
            if not cols:
                continue  # table not created yet (model not imported); create_all will make it
            if column not in cols:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
