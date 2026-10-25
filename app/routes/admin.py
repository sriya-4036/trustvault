import csv
import io
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import selectinload

from .. import audit
from ..authz import active_grant_clause
from ..deps import Ctx, check_csrf, require_admin
from ..models import (
    ROLE_ADMIN, ROLE_OWNER, ROLES, AuditEvent, Category, Document, Grant, User, UserSession, utcnow,
)
from ..search import SearchFilters, like_pattern, parse_date, search_documents
from ..security import USERNAME_RE, hash_password, password_problems
from ..web import render

router = APIRouter(prefix="/admin")
PAGE_SIZE = 50

ACTION_GROUPS = {
    "permissions": audit.PERMISSION_ACTIONS,
    "documents": audit.DOCUMENT_ACTIONS,
    "auth": ("login", "login_failed", "logout", "account_locked", "password_changed", "password_change_failed"),
    "users": ("user_created", "role_changed", "user_deactivated", "user_activated", "password_reset", "user_unlocked"),
}


def _audit_stmt(action="", actor="", document="", outcome="", date_from="", date_to="", target=""):
    stmt = select(AuditEvent)
    if action in ACTION_GROUPS:
        stmt = stmt.where(AuditEvent.action.in_(ACTION_GROUPS[action]))
    elif action:
        stmt = stmt.where(AuditEvent.action == action)
    if actor:
        stmt = stmt.where(AuditEvent.actor_username.ilike(like_pattern(actor.strip().lower()), escape="\\"))
    if target:
        stmt = stmt.where(AuditEvent.target_username.ilike(like_pattern(target.strip().lower()), escape="\\"))
    if document:
        d = document.strip()
        stmt = stmt.where(or_(AuditEvent.document_id == d,
                              AuditEvent.document_name.ilike(like_pattern(d), escape="\\")))
    if outcome:
        stmt = stmt.where(AuditEvent.outcome == outcome)
    if (d := parse_date(date_from)):
        stmt = stmt.where(AuditEvent.ts >= d.isoformat())
    if (d := parse_date(date_to)):
        stmt = stmt.where(AuditEvent.ts < (d + timedelta(days=1)).isoformat())
    return stmt


def _distinct_actions(c: Ctx) -> list[str]:
    return list(c.db.execute(select(AuditEvent.action).distinct().order_by(AuditEvent.action)).scalars())


def _user_or_404(c: Ctx, user_id: int) -> User:
    user = c.db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")
    return user


@router.get("")
def dashboard(c: Ctx = Depends(require_admin)):
    db = c.db
    since = (utcnow() - timedelta(hours=24)).isoformat()
    stats = {
        "users": dict(db.execute(select(User.role, func.count()).where(User.is_active.is_(True)).group_by(User.role)).all()),
        "documents": db.scalar(select(func.count()).select_from(Document).where(Document.deleted_at.is_(None))),
        "grants": db.scalar(select(func.count()).select_from(Grant).where(active_grant_clause(utcnow()))),
        "events_24h": db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.ts >= since)),
        "denied_24h": db.scalar(select(func.count()).select_from(AuditEvent).where(
            AuditEvent.ts >= since, AuditEvent.outcome == "denied")),
        "downloads_24h": db.scalar(select(func.count()).select_from(AuditEvent).where(
            AuditEvent.ts >= since, AuditEvent.action == "download")),
    }
    recent = lambda stmt: list(db.execute(stmt.order_by(AuditEvent.id.desc()).limit(10)).scalars())
    return render(c.request, "admin/dashboard.html", {
        "stats": stats,
        "recent_activity": recent(select(AuditEvent).where(AuditEvent.action.in_(audit.DOCUMENT_ACTIONS))),
        "recent_permissions": recent(select(AuditEvent).where(AuditEvent.action.in_(audit.PERMISSION_ACTIONS))),
        "recent_denied": recent(select(AuditEvent).where(AuditEvent.outcome.in_(("denied", "failure")))),
    })


@router.get("/audit")
def audit_log(
    c: Ctx = Depends(require_admin), action: str = "", actor: str = "", target: str = "", document: str = "",
    outcome: str = "", date_from: str = "", date_to: str = "", page: int = 1,
):
    page = max(page, 1)
    stmt = _audit_stmt(action, actor, document, outcome, date_from, date_to, target)
    total = c.db.scalar(select(func.count()).select_from(stmt.subquery()))
    events = list(c.db.execute(
        stmt.order_by(AuditEvent.id.desc()).offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE)
    ).scalars())
    params = {"action": action, "actor": actor, "target": target, "document": document, "outcome": outcome,
              "date_from": date_from, "date_to": date_to}
    return render(c.request, "admin/audit.html", {
        "events": events, "total": total, "page": page, "pages": max(1, -(-total // PAGE_SIZE)),
        "params": params, "actions": _distinct_actions(c), "groups": list(ACTION_GROUPS),
        "parse": audit.parse_details,
    })


def _csv_safe(value) -> str:
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@router.get("/audit.csv")
def audit_csv(
    c: Ctx = Depends(require_admin), action: str = "", actor: str = "", target: str = "", document: str = "",
    outcome: str = "", date_from: str = "", date_to: str = "",
):
    stmt = _audit_stmt(action, actor, document, outcome, date_from, date_to, target).order_by(AuditEvent.id)
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ["id", "ts", "actor_username", "actor_role", "action", "outcome", "document_id", "document_name",
            "target_username", "details", "ip", "user_agent", "prev_hash", "hash"]
    w.writerow(cols)
    n = 0
    for ev in c.db.execute(stmt).scalars():
        w.writerow([_csv_safe(getattr(ev, col)) for col in cols])
        n += 1
    audit.record(c.db, c.request, "audit_exported", actor=c.user, details={
        "rows": n, "filters": {"action": action, "actor": actor, "target": target, "document": document,
                               "outcome": outcome, "date_from": date_from, "date_to": date_to},
    })
    return Response(buf.getvalue(), media_type="text/csv", headers={
        "Content-Disposition": f'attachment; filename="trustvault-audit-{utcnow():%Y%m%d-%H%M%S}.csv"',
    })


@router.get("/audit/verify")
def audit_verify(c: Ctx = Depends(require_admin)):
    report = audit.verify_chain(c.db)
    audit.record(c.db, c.request, "audit_verified", actor=c.user, outcome="success" if report.ok else "failure",
                 details={"ok": report.ok, "events": report.count, "first_bad_id": report.first_bad_id})
    return render(c.request, "admin/verify.html", {"report": report})


@router.get("/permissions")
def permissions(
    c: Ctx = Depends(require_admin), actor: str = "", target: str = "", document: str = "",
    date_from: str = "", date_to: str = "",
):
    events = list(c.db.execute(
        _audit_stmt("permissions", actor, document, "", date_from, date_to, target)
        .order_by(AuditEvent.id.desc()).limit(200)
    ).scalars())
    grants = list(c.db.execute(
        select(Grant).join(Document).where(Document.deleted_at.is_(None))
        .options(selectinload(Grant.document), selectinload(Grant.user), selectinload(Grant.granted_by))
        .order_by(Grant.granted_at.desc())
    ).scalars())
    return render(c.request, "admin/permissions.html", {
        "events": events, "grants": grants, "now": utcnow(), "parse": audit.parse_details,
        "params": {"actor": actor, "target": target, "document": document, "date_from": date_from, "date_to": date_to},
    })


@router.get("/documents")
def documents(
    c: Ctx = Depends(require_admin), q: str = "", owner: str = "", category: str = "", date_from: str = "",
    date_to: str = "", date_field: str = "uploaded", deleted: str = "",
):
    f = SearchFilters.from_params(q, owner, category, date_from, date_to, date_field)
    docs = search_documents(c.db, None, f, admin_all=True, include_deleted=deleted == "1")
    return render(c.request, "admin/documents.html", {
        "docs": docs, "f": f, "deleted": deleted == "1",
        "categories": list(c.db.execute(select(Category).order_by(Category.name)).scalars()),
    })


@router.get("/documents/{doc_id}")
def document_detail(doc_id: str, c: Ctx = Depends(require_admin)):
    doc = c.db.get(Document, doc_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="Document not found.")
    history = list(c.db.execute(
        select(AuditEvent).where(AuditEvent.document_id == doc.id).order_by(AuditEvent.id.desc())
    ).scalars())
    owners = list(c.db.execute(
        select(User).where(User.role == ROLE_OWNER, User.is_active.is_(True), User.id != doc.owner_id)
        .order_by(User.username)
    ).scalars())
    return render(c.request, "admin/document.html", {
        "doc": doc, "history": history, "owners": owners, "now": utcnow(), "parse": audit.parse_details,
    })


@router.post("/documents/{doc_id}/transfer")
def transfer(doc_id: str, c: Ctx = Depends(require_admin), csrf_token: str = Form(""), username: str = Form("")):
    check_csrf(c, csrf_token)
    doc = c.db.get(Document, doc_id)
    if doc is None or doc.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Document not found.")
    new_owner = c.db.execute(select(User).where(
        User.username == username.strip().lower(), User.role == ROLE_OWNER, User.is_active.is_(True)
    )).scalar_one_or_none()
    if new_owner is None or new_owner.id == doc.owner_id:
        return RedirectResponse(f"/admin/documents/{doc.id}?msg=transfer_error", status_code=303)
    old_owner = doc.owner
    c.db.execute(delete(Grant).where(Grant.document_id == doc.id, Grant.user_id == new_owner.id))
    doc.owner_id = new_owner.id
    doc.updated_at = utcnow()
    audit.record(c.db, c.request, "ownership_transferred", actor=c.user, document=doc, target=new_owner,
                 details={"from": old_owner.username, "to": new_owner.username})
    return RedirectResponse(f"/admin/documents/{doc.id}?msg=transferred", status_code=303)


@router.get("/users")
def users(c: Ctx = Depends(require_admin)):
    rows = list(c.db.execute(select(User).order_by(User.username)).scalars())
    owned = dict(c.db.execute(
        select(Document.owner_id, func.count()).where(Document.deleted_at.is_(None)).group_by(Document.owner_id)
    ).all())
    return render(c.request, "admin/users.html", {
        "users": rows, "owned": owned, "roles": ROLES, "now": utcnow(), "errors": [], "form": {},
    })


@router.post("/users")
def create_user(
    c: Ctx = Depends(require_admin), csrf_token: str = Form(""), username: str = Form(""),
    full_name: str = Form(""), role: str = Form(""), password: str = Form(""),
):
    check_csrf(c, csrf_token)
    username = username.strip().lower()
    full_name = " ".join(full_name.split())[:128]
    errors = []
    if not USERNAME_RE.match(username):
        errors.append("Username must be 3-32 characters: lowercase letters, digits, '.', '_' or '-'.")
    elif c.db.execute(select(User).where(User.username == username)).first():
        errors.append("That username is taken.")
    if not full_name:
        errors.append("Full name is required.")
    if role not in ROLES:
        errors.append("Choose a role.")
    errors += password_problems(password, username, c.settings.min_password_length)
    if errors:
        rows = list(c.db.execute(select(User).order_by(User.username)).scalars())
        return render(c.request, "admin/users.html", {
            "users": rows, "owned": {}, "roles": ROLES, "now": utcnow(), "errors": errors,
            "form": {"username": username, "full_name": full_name, "role": role},
        }, 400)
    user = User(username=username, full_name=full_name, role=role, must_change_password=True,
                password_hash=hash_password(password, c.settings.bcrypt_rounds))
    c.db.add(user)
    c.db.flush()
    audit.record(c.db, c.request, "user_created", actor=c.user, target=user, details={"role": role})
    return RedirectResponse("/admin/users?msg=user_created", status_code=303)


def _end_sessions(c: Ctx, user: User) -> None:
    c.db.execute(delete(UserSession).where(UserSession.user_id == user.id))


@router.post("/users/{user_id}/role")
def change_role(user_id: int, c: Ctx = Depends(require_admin), csrf_token: str = Form(""), role: str = Form("")):
    check_csrf(c, csrf_token)
    user = _user_or_404(c, user_id)
    if user.id == c.user.id:
        return RedirectResponse("/admin/users?msg=user_error_self", status_code=303)
    if role not in ROLES:
        raise HTTPException(status_code=400)
    if role == user.role:
        return RedirectResponse("/admin/users", status_code=303)
    owns = c.db.scalar(select(func.count()).select_from(Document).where(
        Document.owner_id == user.id, Document.deleted_at.is_(None)))
    if role != ROLE_OWNER and owns:
        return RedirectResponse("/admin/users?msg=user_error_owns_docs", status_code=303)
    old = user.role
    user.role = role
    _end_sessions(c, user)
    audit.record(c.db, c.request, "role_changed", actor=c.user, target=user, details={"from": old, "to": role})
    return RedirectResponse("/admin/users?msg=user_updated", status_code=303)


@router.post("/users/{user_id}/deactivate")
def deactivate(user_id: int, c: Ctx = Depends(require_admin), csrf_token: str = Form("")):
    check_csrf(c, csrf_token)
    user = _user_or_404(c, user_id)
    if user.id == c.user.id:
        return RedirectResponse("/admin/users?msg=user_error_self", status_code=303)
    grants = list(c.db.execute(
        select(Grant).where(Grant.user_id == user.id).options(selectinload(Grant.document))
    ).scalars())
    user.is_active = False
    user.deactivated_at = utcnow()
    _end_sessions(c, user)
    with audit.batch(c.db, c.request) as log:
        for g in grants:
            log.add("permission_revoked", actor=c.user, document=g.document, target=user,
                    details={"permission": g.permission, "reason": "user_deactivated"})
            c.db.delete(g)
        log.add("user_deactivated", actor=c.user, target=user, details={"grants_revoked": len(grants)})
    return RedirectResponse("/admin/users?msg=user_updated", status_code=303)


@router.post("/users/{user_id}/activate")
def activate(user_id: int, c: Ctx = Depends(require_admin), csrf_token: str = Form("")):
    check_csrf(c, csrf_token)
    user = _user_or_404(c, user_id)
    user.is_active = True
    user.deactivated_at = None
    audit.record(c.db, c.request, "user_activated", actor=c.user, target=user)
    return RedirectResponse("/admin/users?msg=user_updated", status_code=303)


@router.post("/users/{user_id}/reset-password")
def reset_password(user_id: int, c: Ctx = Depends(require_admin), csrf_token: str = Form(""), password: str = Form("")):
    check_csrf(c, csrf_token)
    user = _user_or_404(c, user_id)
    if user.id == c.user.id:
        return RedirectResponse("/admin/users?msg=user_error_self", status_code=303)
    problems = password_problems(password, user.username, c.settings.min_password_length)
    if problems:
        return render(c.request, "error.html", {"status": 400, "detail": " ".join(problems)}, 400)
    user.password_hash = hash_password(password, c.settings.bcrypt_rounds)
    user.must_change_password = True
    user.failed_logins = 0
    user.locked_until = None
    _end_sessions(c, user)
    audit.record(c.db, c.request, "password_reset", actor=c.user, target=user)
    return RedirectResponse("/admin/users?msg=user_updated", status_code=303)


@router.post("/users/{user_id}/unlock")
def unlock(user_id: int, c: Ctx = Depends(require_admin), csrf_token: str = Form("")):
    check_csrf(c, csrf_token)
    user = _user_or_404(c, user_id)
    user.failed_logins = 0
    user.locked_until = None
    audit.record(c.db, c.request, "user_unlocked", actor=c.user, target=user)
    return RedirectResponse("/admin/users?msg=user_updated", status_code=303)


@router.get("/categories")
def categories(c: Ctx = Depends(require_admin)):
    rows = c.db.execute(
        select(Category, func.count(Document.id)).outerjoin(
            Document, (Document.category_id == Category.id) & Document.deleted_at.is_(None)
        ).group_by(Category.id).order_by(Category.name)
    ).all()
    return render(c.request, "admin/categories.html", {"rows": rows})


@router.post("/categories")
def create_category(c: Ctx = Depends(require_admin), csrf_token: str = Form(""), name: str = Form("")):
    check_csrf(c, csrf_token)
    name = " ".join(name.split())
    if not name or len(name) > 64 or c.db.execute(select(Category).where(func.lower(Category.name) == name.lower())).first():
        return RedirectResponse("/admin/categories?msg=category_error", status_code=303)
    c.db.add(Category(name=name))
    audit.record(c.db, c.request, "category_created", actor=c.user, details={"name": name})
    return RedirectResponse("/admin/categories?msg=category_created", status_code=303)
