import hashlib
from datetime import datetime, timedelta
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select

from .. import audit
from ..authz import load_document
from ..deps import Ctx, check_csrf, require_uploader, require_user
from ..models import (
    GRANTABLE_PERMS,
    PERM_EDIT,
    PERM_MANAGE,
    PERM_READ,
    AuditEvent,
    Category,
    Document,
    DocumentVersion,
    Grant,
    User,
    utcnow,
)
from ..search import SearchFilters, grants_by_document, parse_date, search_documents
from ..validation import UploadRejected, ValidatedFile, validate_upload
from ..web import render

router = APIRouter()

MAX_NAME = 200
MAX_DESCRIPTION = 2000


def _categories(c: Ctx) -> list[Category]:
    return list(c.db.execute(select(Category).order_by(Category.name)).scalars())


def _clean_metadata(c: Ctx, name: str, description: str, category_id: str, fallback_name: str = ""):
    errors = []
    name = " ".join((name or "").split()) or fallback_name
    if not name:
        errors.append("Name is required.")
    elif len(name) > MAX_NAME:
        errors.append(f"Name must be at most {MAX_NAME} characters.")
    description = (description or "").strip()
    if len(description) > MAX_DESCRIPTION:
        errors.append(f"Description must be at most {MAX_DESCRIPTION} characters.")
    category = c.db.get(Category, int(category_id)) if (category_id or "").isdigit() else None
    if category is None:
        errors.append("Choose a valid category.")
    return name, description, category, errors


def _validate_file(c: Ctx, file: UploadFile | None) -> tuple[ValidatedFile | None, str | None]:
    if file is None or not file.filename:
        return None, "Choose a file to upload."
    try:
        return validate_upload(file.filename, file.file, c.settings.max_upload_bytes), None
    except UploadRejected as e:
        return None, str(e)


def _content_disposition(filename: str) -> str:
    ascii_name = "".join(ch if 32 <= ord(ch) < 127 and ch not in '"\\' else "_" for ch in filename)
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(filename)}"


@router.get("/")
def home():
    return RedirectResponse("/documents", status_code=303)


@router.get("/documents")
def list_documents(
    c: Ctx = Depends(require_user),
    q: str = "", owner: str = "", category: str = "", date_from: str = "", date_to: str = "",
    date_field: str = "uploaded", scope: str = "all",
):
    f = SearchFilters.from_params(q, owner, category, date_from, date_to, date_field, scope)
    docs = search_documents(c.db, c.user, f)
    grants = grants_by_document(c.db, c.user, [d.id for d in docs])
    return render(c.request, "documents.html", {
        "docs": docs, "grants": grants, "f": f, "categories": _categories(c),
    })


@router.get("/documents/new")
def new_document(c: Ctx = Depends(require_uploader)):
    return render(c.request, "upload.html", {"categories": _categories(c), "errors": [], "form": {}})


@router.post("/documents")
def upload_document(
    c: Ctx = Depends(require_uploader),
    csrf_token: str = Form(""),
    name: str = Form(""),
    description: str = Form(""),
    category_id: str = Form(""),
    file: UploadFile | None = File(None),
):
    check_csrf(c, csrf_token)
    vf, file_error = _validate_file(c, file)
    fallback = vf.filename.rsplit(".", 1)[0] if vf else ""
    name, description, category, errors = _clean_metadata(c, name, description, category_id, fallback)
    if file_error:
        errors.insert(0, file_error)
    if errors:
        if file_error:
            audit.record(c.db, c.request, "upload_rejected", actor=c.user, outcome="failure",
                         details={"filename": (file.filename or "")[:200] if file else "", "reason": file_error})
        form = {"name": name, "description": description, "category_id": category_id}
        return render(c.request, "upload.html", {"categories": _categories(c), "errors": errors, "form": form}, 400)

    key = c.request.app.state.blobs.put(vf.data)
    try:
        now = utcnow()
        doc = Document(name=name, description=description, category_id=category.id, owner_id=c.user.id,
                       created_at=now, updated_at=now)
        c.db.add(doc)
        c.db.flush()
        c.db.add(DocumentVersion(
            document_id=doc.id, version_no=1, original_filename=vf.filename, content_type=vf.content_type,
            size_bytes=vf.size, sha256=vf.sha256, storage_key=key, uploaded_by_id=c.user.id, uploaded_at=now,
        ))
        audit.record(c.db, c.request, "upload", actor=c.user, document=doc, details={
            "version": 1, "filename": vf.filename, "size": vf.size, "sha256": vf.sha256, "category": category.name,
        })
    except Exception:
        c.request.app.state.blobs.delete(key)
        raise
    return RedirectResponse(f"/documents/{doc.id}?msg=uploaded", status_code=303)


@router.get("/documents/{doc_id}")
def document_detail(doc_id: str, c: Ctx = Depends(require_user)):
    doc, perms = load_document(c, doc_id, PERM_READ)
    audit.record(c.db, c.request, "view", actor=c.user, document=doc)
    ctx = {"doc": doc, "perms": perms, "now": utcnow(), "categories": _categories(c)}
    if PERM_MANAGE in perms:
        ctx["grants"] = sorted(doc.grants, key=lambda g: g.user.username)
        ctx["history"] = list(c.db.execute(
            select(AuditEvent).where(AuditEvent.document_id == doc.id).order_by(AuditEvent.id.desc()).limit(100)
        ).scalars())
        ctx["candidates"] = list(c.db.execute(
            select(User).where(User.is_active.is_(True), User.id != c.user.id).order_by(User.username)
        ).scalars())
    return render(c.request, "document.html", ctx)


@router.get("/documents/{doc_id}/download")
def download(doc_id: str, c: Ctx = Depends(require_user), version: str = ""):
    doc, _ = load_document(c, doc_id, PERM_READ)
    if version:
        v = next((v for v in doc.versions if str(v.version_no) == version), None)
    else:
        v = doc.current_version
    if v is None or v.storage_key is None:
        raise HTTPException(status_code=404, detail="Document not found.")

    data = c.request.app.state.blobs.get(v.storage_key)
    if hashlib.sha256(data).hexdigest() != v.sha256:
        audit.record(c.db, c.request, "integrity_failure", actor=c.user, outcome="failure", document=doc,
                     details={"version": v.version_no})
        raise HTTPException(status_code=500)
    audit.record(c.db, c.request, "download", actor=c.user, document=doc, details={
        "version": v.version_no, "filename": v.original_filename, "sha256": v.sha256,
    })
    return Response(data, media_type=v.content_type, headers={
        "Content-Disposition": _content_disposition(v.original_filename),
        "Content-Security-Policy": "sandbox; default-src 'none'",
        "Cache-Control": "no-store",
    })


@router.get("/documents/{doc_id}/edit")
def edit_form(doc_id: str, c: Ctx = Depends(require_user)):
    doc, perms = load_document(c, doc_id, PERM_EDIT)
    form = {"name": doc.name, "description": doc.description, "category_id": str(doc.category_id)}
    return render(c.request, "edit.html", {"doc": doc, "perms": perms, "form": form, "errors": [],
                                           "categories": _categories(c)})


@router.post("/documents/{doc_id}/edit")
def edit_document(
    doc_id: str,
    c: Ctx = Depends(require_user),
    csrf_token: str = Form(""),
    name: str = Form(""),
    description: str = Form(""),
    category_id: str = Form(""),
):
    check_csrf(c, csrf_token)
    doc, perms = load_document(c, doc_id, PERM_EDIT)
    name, description, category, errors = _clean_metadata(c, name, description, category_id)
    if errors:
        form = {"name": name, "description": description, "category_id": category_id}
        return render(c.request, "edit.html", {"doc": doc, "perms": perms, "form": form, "errors": errors,
                                               "categories": _categories(c)}, 400)
    changes = {}
    if name != doc.name:
        changes["name"] = [doc.name, name]
    if description != doc.description:
        changes["description"] = [doc.description, description]
    if category.id != doc.category_id:
        changes["category"] = [doc.category.name, category.name]
    if changes:
        doc.name, doc.description, doc.category_id = name, description, category.id
        doc.updated_at = utcnow()
        audit.record(c.db, c.request, "metadata_updated", actor=c.user, document=doc, details={"changes": changes})
    return RedirectResponse(f"/documents/{doc.id}?msg=updated", status_code=303)


@router.post("/documents/{doc_id}/versions")
def upload_version(
    doc_id: str,
    c: Ctx = Depends(require_user),
    csrf_token: str = Form(""),
    file: UploadFile | None = File(None),
):
    check_csrf(c, csrf_token)
    doc, perms = load_document(c, doc_id, PERM_EDIT)
    vf, error = _validate_file(c, file)
    if error:
        audit.record(c.db, c.request, "upload_rejected", actor=c.user, outcome="failure", document=doc,
                     details={"filename": (file.filename or "")[:200] if file else "", "reason": error})
        form = {"name": doc.name, "description": doc.description, "category_id": str(doc.category_id)}
        return render(c.request, "edit.html", {"doc": doc, "perms": perms, "form": form, "errors": [error],
                                               "categories": _categories(c)}, 400)
    key = c.request.app.state.blobs.put(vf.data)
    try:
        now = utcnow()
        version_no = (doc.current_version.version_no if doc.current_version else 0) + 1
        c.db.add(DocumentVersion(
            document_id=doc.id, version_no=version_no, original_filename=vf.filename,
            content_type=vf.content_type, size_bytes=vf.size, sha256=vf.sha256, storage_key=key,
            uploaded_by_id=c.user.id, uploaded_at=now,
        ))
        doc.updated_at = now
        audit.record(c.db, c.request, "new_version", actor=c.user, document=doc, details={
            "version": version_no, "filename": vf.filename, "size": vf.size, "sha256": vf.sha256,
        })
    except Exception:
        c.request.app.state.blobs.delete(key)
        raise
    return RedirectResponse(f"/documents/{doc.id}?msg=version_added", status_code=303)


@router.post("/documents/{doc_id}/delete")
def delete_document(doc_id: str, c: Ctx = Depends(require_user), csrf_token: str = Form(""), confirm: str = Form("")):
    check_csrf(c, csrf_token)
    doc, _ = load_document(c, doc_id, PERM_MANAGE)
    if confirm != "yes":
        return RedirectResponse(f"/documents/{doc.id}?msg=delete_unconfirmed", status_code=303)
    keys = [v.storage_key for v in doc.versions if v.storage_key]
    revoked = [{"user": g.user.username, "permission": g.permission} for g in doc.grants]
    for g in list(doc.grants):
        c.db.delete(g)
    for v in doc.versions:
        v.storage_key = None
    doc.deleted_at = utcnow()
    audit.record(c.db, c.request, "delete", actor=c.user, document=doc, details={
        "versions_destroyed": len(keys), "grants_removed": revoked,
    })
    for key in keys:
        c.request.app.state.blobs.delete(key)
    return RedirectResponse("/documents?msg=deleted", status_code=303)


@router.post("/documents/{doc_id}/grants")
def grant_access(
    doc_id: str,
    c: Ctx = Depends(require_user),
    csrf_token: str = Form(""),
    username: str = Form(""),
    permission: str = Form(""),
    expires_on: str = Form(""),
):
    check_csrf(c, csrf_token)
    doc, _ = load_document(c, doc_id, PERM_MANAGE)
    back = f"/documents/{doc.id}"
    if permission not in GRANTABLE_PERMS:
        return RedirectResponse(f"{back}?msg=grant_bad_permission", status_code=303)
    target = c.db.execute(
        select(User).where(User.username == username.strip().lower()[:64], User.is_active.is_(True))
    ).scalar_one_or_none()
    if target is None:
        return RedirectResponse(f"{back}?msg=grant_user_not_found", status_code=303)
    if target.id == doc.owner_id:
        return RedirectResponse(f"{back}?msg=grant_self", status_code=303)
    expires_at = None
    if expires_on.strip():
        d = parse_date(expires_on)
        if d is None or d < utcnow().date():
            return RedirectResponse(f"{back}?msg=grant_bad_date", status_code=303)
        expires_at = datetime.combine(d + timedelta(days=1), datetime.min.time())

    existing = c.db.execute(
        select(Grant).where(Grant.document_id == doc.id, Grant.user_id == target.id)
    ).scalar_one_or_none()
    if existing:
        old = {"permission": existing.permission, "expires_at": existing.expires_at}
        existing.permission, existing.expires_at = permission, expires_at
        existing.granted_by_id, existing.granted_at = c.user.id, utcnow()
        audit.record(c.db, c.request, "permission_changed", actor=c.user, document=doc, target=target, details={
            "from": old, "to": {"permission": permission, "expires_at": expires_at},
        })
        msg = "grant_updated"
    else:
        c.db.add(Grant(document_id=doc.id, user_id=target.id, permission=permission,
                       granted_by_id=c.user.id, expires_at=expires_at))
        audit.record(c.db, c.request, "permission_granted", actor=c.user, document=doc, target=target, details={
            "permission": permission, "expires_at": expires_at,
        })
        msg = "granted"
    return RedirectResponse(f"{back}?msg={msg}", status_code=303)


@router.post("/documents/{doc_id}/grants/{grant_id}/revoke")
def revoke_access(doc_id: str, grant_id: str, c: Ctx = Depends(require_user), csrf_token: str = Form("")):
    check_csrf(c, csrf_token)
    doc, _ = load_document(c, doc_id, PERM_MANAGE)
    grant = c.db.get(Grant, grant_id)
    if grant is None or grant.document_id != doc.id:
        raise HTTPException(status_code=404, detail="Document not found.")
    target = grant.user
    details = {"permission": grant.permission, "expires_at": grant.expires_at}
    c.db.delete(grant)
    audit.record(c.db, c.request, "permission_revoked", actor=c.user, document=doc, target=target, details=details)
    return RedirectResponse(f"/documents/{doc.id}?msg=revoked", status_code=303)
