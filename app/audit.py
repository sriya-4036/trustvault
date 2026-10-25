import hashlib
import json
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditEvent, Document, User

GENESIS_HASH = "0" * 64

# Fields covered by each event's hash. Changing any of them breaks the chain.
HASHED_FIELDS = (
    "ts", "actor_id", "actor_username", "actor_role", "action", "outcome",
    "document_id", "document_name", "target_user_id", "target_username",
    "details", "ip", "user_agent", "prev_hash",
)

PERMISSION_ACTIONS = ("permission_granted", "permission_changed", "permission_revoked", "ownership_transferred")
DOCUMENT_ACTIONS = ("upload", "view", "download", "metadata_updated", "new_version", "delete", "upload_rejected")

# Serialises "read chain head -> insert -> commit" so the chain never forks.
# Single-process deployment assumption; see README.
_CHAIN_LOCK = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def compute_hash(ev: AuditEvent) -> str:
    payload = json.dumps({f: getattr(ev, f) for f in HASHED_FIELDS}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _client(request: Request | None) -> tuple[str, str]:
    if request is None:
        return "", "cli"
    ip = request.client.host if request.client else ""
    return ip[:64], (request.headers.get("user-agent") or "")[:256]


class _Batch:
    def __init__(self, db: Session, request: Request | None):
        self.db = db
        self.request = request
        self._prev: str | None = None

    def add(
        self,
        action: str,
        *,
        actor: User | None = None,
        actor_username: str | None = None,
        outcome: str = "success",
        document: Document | None = None,
        document_id: str | None = None,
        document_name: str | None = None,
        target: User | None = None,
        details: dict | None = None,
    ) -> AuditEvent:
        if self._prev is None:
            self._prev = self.db.execute(
                select(AuditEvent.hash).order_by(AuditEvent.id.desc()).limit(1)
            ).scalar() or GENESIS_HASH
        ip, ua = _client(self.request)
        ev = AuditEvent(
            ts=_now_iso(),
            actor_id=actor.id if actor else None,
            actor_username=(actor.username if actor else (actor_username or ""))[:64],
            actor_role=actor.role if actor else "",
            action=action,
            outcome=outcome,
            document_id=document.id if document else document_id,
            document_name=((document.name if document else document_name) or "")[:200],
            target_user_id=target.id if target else None,
            target_username=target.username if target else "",
            details=json.dumps(details or {}, sort_keys=True, default=str),
            ip=ip,
            user_agent=ua,
            prev_hash=self._prev,
        )
        ev.hash = compute_hash(ev)
        self._prev = ev.hash
        self.db.add(ev)
        return ev


@contextmanager
def batch(db: Session, request: Request | None):
    """Record several events atomically with whatever else is pending in `db`.

    The commit happens here: an action and its audit record land together or not at all.
    """
    with _CHAIN_LOCK:
        b = _Batch(db, request)
        yield b
        db.commit()


def record(db: Session, request: Request | None, action: str, **kwargs) -> AuditEvent:
    with batch(db, request) as b:
        return b.add(action, **kwargs)


@dataclass
class ChainReport:
    ok: bool
    count: int
    head_hash: str
    first_bad_id: int | None = None
    reason: str = ""


def verify_chain(db: Session) -> ChainReport:
    prev = GENESIS_HASH
    count = 0
    for ev in db.execute(select(AuditEvent).order_by(AuditEvent.id)).scalars():
        count += 1
        if ev.prev_hash != prev:
            return ChainReport(False, count, prev, ev.id, "Link to previous event is broken (event removed or reordered).")
        if compute_hash(ev) != ev.hash:
            return ChainReport(False, count, prev, ev.id, "Event contents do not match its hash (event modified).")
        prev = ev.hash
    return ChainReport(True, count, prev)


def parse_details(ev: AuditEvent) -> dict:
    try:
        return json.loads(ev.details or "{}")
    except ValueError:
        return {}
