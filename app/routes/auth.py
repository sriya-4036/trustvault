from datetime import timedelta

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .. import audit
from ..deps import (
    LOGIN_CSRF_COOKIE,
    SESSION_COOKIE,
    Ctx,
    check_csrf,
    get_db,
    load_session,
    require_user,
)
from ..models import User, UserSession, utcnow
from ..security import (
    burn_password_check,
    hash_password,
    new_token,
    password_problems,
    token_hash,
    tokens_equal,
    verify_password,
)
from ..web import render

router = APIRouter()
GENERIC_LOGIN_ERROR = "Incorrect username or password, or the account is locked or disabled."


def _login_page(request: Request, error: str = "", username: str = "", status_code: int = 200):
    token = new_token()
    with Session(request.app.state.engine) as db:
        no_users = db.execute(select(User.id).limit(1)).first() is None
    ctx = {"login_csrf": token, "error": error, "username": username, "no_users": no_users}
    resp = render(request, "login.html", ctx, status_code)
    resp.set_cookie(
        LOGIN_CSRF_COOKIE, token, httponly=True, samesite="strict",
        secure=request.app.state.settings.cookie_secure, max_age=3600, path="/login",
    )
    return resp


@router.get("/login")
def login_form(request: Request, db: Session = Depends(get_db)):
    if load_session(request, db):
        return RedirectResponse("/documents", status_code=303)
    return _login_page(request)


@router.post("/login")
def login(
    request: Request,
    db: Session = Depends(get_db),
    username: str = Form(""),
    password: str = Form(""),
    csrf_token: str = Form(""),
):
    settings = request.app.state.settings
    if not tokens_equal(csrf_token, request.cookies.get(LOGIN_CSRF_COOKIE)):
        return _login_page(request, "Your sign-in form expired. Please try again.", status_code=400)

    uname = username.strip().lower()[:64]
    user = db.execute(select(User).where(User.username == uname)).scalar_one_or_none()
    now = utcnow()

    if user is None:
        burn_password_check(password)
        audit.record(db, request, "login_failed", actor_username=uname, outcome="failure", details={"reason": "unknown_user"})
        return _login_page(request, GENERIC_LOGIN_ERROR, uname, 401)

    if not user.is_active or (user.locked_until and user.locked_until > now):
        burn_password_check(password)
        reason = "inactive" if not user.is_active else "locked"
        audit.record(db, request, "login_failed", actor=user, outcome="failure", details={"reason": reason})
        return _login_page(request, GENERIC_LOGIN_ERROR, uname, 401)

    if not verify_password(password, user.password_hash):
        user.failed_logins += 1
        details = {"reason": "bad_password", "failed_attempts": user.failed_logins}
        with audit.batch(db, request) as log:
            log.add("login_failed", actor=user, outcome="failure", details=details)
            if user.failed_logins >= settings.max_failed_logins:
                user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
                user.failed_logins = 0
                log.add("account_locked", actor=user, outcome="failure", details={"minutes": settings.lockout_minutes})
        return _login_page(request, GENERIC_LOGIN_ERROR, uname, 401)

    user.failed_logins = 0
    user.locked_until = None
    token = new_token()
    sess = UserSession(
        id=token_hash(token),
        user_id=user.id,
        csrf_token=new_token(),
        expires_at=now + timedelta(hours=settings.session_absolute_hours),
        ip=(request.client.host if request.client else "")[:64],
        user_agent=(request.headers.get("user-agent") or "")[:256],
    )
    db.add(sess)
    audit.record(db, request, "login", actor=user)

    resp = RedirectResponse("/documents", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE, token, httponly=True, samesite="lax", secure=settings.cookie_secure,
        max_age=settings.session_absolute_hours * 3600, path="/",
    )
    resp.delete_cookie(LOGIN_CSRF_COOKIE, path="/login")
    return resp


@router.post("/logout")
def logout(c: Ctx = Depends(require_user), csrf_token: str = Form("")):
    check_csrf(c, csrf_token)
    c.db.delete(c.session)
    audit.record(c.db, c.request, "logout", actor=c.user)
    resp = RedirectResponse("/login?msg=signed_out", status_code=303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@router.get("/account/password")
def password_form(c: Ctx = Depends(require_user)):
    return render(c.request, "password.html", {"errors": []})


@router.post("/account/password")
def change_password(
    c: Ctx = Depends(require_user),
    csrf_token: str = Form(""),
    current_password: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
):
    check_csrf(c, csrf_token)
    errors = []
    if not verify_password(current_password, c.user.password_hash):
        errors.append("Current password is incorrect.")
    errors += password_problems(new_password, c.user.username, c.settings.min_password_length)
    if new_password != confirm_password:
        errors.append("New passwords do not match.")
    if new_password and new_password == current_password:
        errors.append("New password must differ from the current one.")
    if errors:
        audit.record(c.db, c.request, "password_change_failed", actor=c.user, outcome="failure")
        return render(c.request, "password.html", {"errors": errors}, status_code=400)

    c.user.password_hash = hash_password(new_password, c.settings.bcrypt_rounds)
    c.user.must_change_password = False
    c.db.execute(delete(UserSession).where(UserSession.user_id == c.user.id, UserSession.id != c.session.id))
    audit.record(c.db, c.request, "password_changed", actor=c.user)
    return RedirectResponse("/documents?msg=password_changed", status_code=303)
