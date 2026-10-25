from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session, aliased, selectinload

from .authz import active_grant_clause
from .models import Document, Grant, User, utcnow

SCOPES = ("all", "mine", "shared")
DATE_FIELDS = ("uploaded", "modified")
MAX_RESULTS = 200


def like_pattern(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def parse_date(raw: str) -> date | None:
    try:
        return date.fromisoformat(raw.strip()) if raw and raw.strip() else None
    except ValueError:
        return None


@dataclass
class SearchFilters:
    q: str = ""
    owner: str = ""
    category_id: int | None = None
    date_from: date | None = None
    date_to: date | None = None
    date_field: str = "uploaded"
    scope: str = "all"
    errors: list[str] = field(default_factory=list)

    @classmethod
    def from_params(cls, q="", owner="", category="", date_from="", date_to="", date_field="uploaded", scope="all"):
        f = cls(q=(q or "").strip()[:200], owner=(owner or "").strip()[:64])
        if category and str(category).isdigit():
            f.category_id = int(category)
        f.date_from = parse_date(date_from)
        f.date_to = parse_date(date_to)
        if date_from and f.date_from is None:
            f.errors.append("'From' date is not a valid date (use YYYY-MM-DD).")
        if date_to and f.date_to is None:
            f.errors.append("'To' date is not a valid date (use YYYY-MM-DD).")
        f.date_field = date_field if date_field in DATE_FIELDS else "uploaded"
        f.scope = scope if scope in SCOPES else "all"
        return f


def search_documents(db: Session, user: User | None, f: SearchFilters, *, admin_all: bool = False, include_deleted: bool = False):
    """Documents matching `f`. Unless `admin_all`, restricted to what `user` may read."""
    owner = aliased(User)
    stmt = select(Document).join(owner, Document.owner_id == owner.id)

    if not admin_all:
        g = aliased(Grant)
        stmt = stmt.outerjoin(
            g,
            and_(
                g.document_id == Document.id,
                g.user_id == user.id,
                or_(g.expires_at.is_(None), g.expires_at > utcnow()),
            ),
        )
        owned = Document.owner_id == user.id
        shared = and_(Document.owner_id != user.id, g.id.is_not(None))
        access = {"mine": owned, "shared": shared}.get(f.scope, or_(owned, shared))
        stmt = stmt.where(access, Document.deleted_at.is_(None))
    elif not include_deleted:
        stmt = stmt.where(Document.deleted_at.is_(None))

    if f.q:
        stmt = stmt.where(Document.name.ilike(like_pattern(f.q), escape="\\"))
    if f.owner:
        pat = like_pattern(f.owner)
        stmt = stmt.where(or_(owner.username.ilike(pat, escape="\\"), owner.full_name.ilike(pat, escape="\\")))
    if f.category_id:
        stmt = stmt.where(Document.category_id == f.category_id)
    col = Document.created_at if f.date_field == "uploaded" else Document.updated_at
    if f.date_from:
        stmt = stmt.where(col >= datetime.combine(f.date_from, datetime.min.time()))
    if f.date_to:
        stmt = stmt.where(col < datetime.combine(f.date_to + timedelta(days=1), datetime.min.time()))

    stmt = stmt.options(
        selectinload(Document.owner), selectinload(Document.category), selectinload(Document.versions)
    ).order_by(Document.updated_at.desc()).limit(MAX_RESULTS)
    return list(db.execute(stmt).scalars().unique())


def grants_by_document(db: Session, user: User, doc_ids: list[str]) -> dict[str, Grant]:
    if not doc_ids:
        return {}
    rows = db.execute(
        select(Grant).where(Grant.user_id == user.id, Grant.document_id.in_(doc_ids), active_grant_clause(utcnow()))
    ).scalars()
    return {g.document_id: g for g in rows}
