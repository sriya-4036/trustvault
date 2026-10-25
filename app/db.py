from sqlalchemy import create_engine, event, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .models import Base, Category

DEFAULT_CATEGORIES = ("Contracts", "HR", "Finance", "Legal", "Engineering", "Audit", "Other")

_AUDIT_TRIGGERS = (
    """CREATE TRIGGER IF NOT EXISTS audit_events_no_update BEFORE UPDATE ON audit_events
       BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END""",
    """CREATE TRIGGER IF NOT EXISTS audit_events_no_delete BEFORE DELETE ON audit_events
       BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END""",
)


def make_engine(url: str) -> Engine:
    is_sqlite = url.startswith("sqlite")
    engine = create_engine(
        url, connect_args={"check_same_thread": False, "timeout": 30} if is_sqlite else {}
    )
    if is_sqlite:

        @event.listens_for(engine, "connect")
        def _pragmas(dbapi_conn, _record):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.close()

    return engine


def init_db(engine: Engine) -> None:
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        if engine.dialect.name == "sqlite":
            for ddl in _AUDIT_TRIGGERS:
                conn.execute(text(ddl))
    with Session(engine) as db:
        if db.execute(select(Category).limit(1)).first() is None:
            db.add_all(Category(name=n) for n in DEFAULT_CATEGORIES)
            db.commit()
