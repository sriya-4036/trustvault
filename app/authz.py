"""The single place that decides who may do what to a document.

Every document route goes through `load_document`. Anyone without the required
permission gets the same 404 as for a document that does not exist, so
probing IDs reveals nothing, and the attempt is written to the audit log.
"""
import re
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from . import audit
from .deps import Ctx
from .models import PERM_EDIT, PERM_MANAGE, PERM_READ, Document, Grant, User, utcnow

_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_OWNER_PERMS = frozenset({PERM_READ, PERM_EDIT, PERM_MANAGE})
_GRANT_PERMS = {PERM_READ: frozenset({PERM_READ}), PERM_EDIT: frozenset({PERM_READ, PERM_EDIT})}


def active_grant_clause(now: datetime):
    return or_(Grant.expires_at.is_(None), Grant.expires_at > now)


def permissions_for(db: Session, user: User, doc: Document | None) -> frozenset[str]:
    if doc is None or doc.deleted_at is not None or not user.is_active:
        return frozenset()
    if doc.owner_id == user.id:
        return _OWNER_PERMS
    grant = db.execute(
        select(Grant).where(
            and_(Grant.document_id == doc.id, Grant.user_id == user.id, active_grant_clause(utcnow()))
        )
    ).scalar_one_or_none()
    if grant is None:
        return frozenset()
    return _GRANT_PERMS.get(grant.permission, frozenset())


def load_document(c: Ctx, doc_id: str, need: str) -> tuple[Document, frozenset[str]]:
    doc = c.db.get(Document, doc_id) if _ID_RE.match(doc_id or "") else None
    perms = permissions_for(c.db, c.user, doc)
    if need not in perms:
        audit.record(
            c.db, c.request, "access_denied",
            actor=c.user, outcome="denied",
            document_id=doc.id if doc else None,
            document_name=doc.name if doc else None,
            details={
                "required": need,
                "path": c.request.url.path,
                "method": c.request.method,
                **({} if doc else {"requested_id": (doc_id or "")[:64]}),
            },
        )
        raise HTTPException(status_code=404, detail="Document not found.")
    return doc, perms
