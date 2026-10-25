from dataclasses import dataclass
from datetime import timedelta

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from . import audit
from .config import Settings
from .models import ROLE_ADMIN, ROLE_OWNER, User, UserSession, utcnow
from .security import token_hash, tokens_equal

SESSION_COOKIE = "tv_session"
LOGIN_CSRF_COOKIE = "tv_login_csrf"
PASSWORD_CHANGE_PATHS = {"/account/password", "/logout"}


class LoginRequired(Exception):
    pass


class PasswordChangeRequired(Exception):
    pass


@dataclass
class Ctx:
    request: Request
    db: Session
    user: User
    session: UserSession

    @property
    def settings(self) -> Settings:
        return self.request.app.state.settings


def get_db(request: Request):
    db = request.app.state.SessionLocal()
    try:
        yield db
    finally:
        db.close()


def load_session(request: Request, db: Session) -> UserSession | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token or len(token) > 128:
        return None
    sess = db.get(UserSession, token_hash(token))
    if sess is None:
        return None
    settings: Settings = request.app.state.settings
    now = utcnow()
    idle_limit = sess.last_seen + timedelta(minutes=settings.session_idle_minutes)
    if now >= sess.expires_at or now >= idle_limit or not sess.user.is_active:
        db.delete(sess)
        db.commit()
        return None
    if (now - sess.last_seen).total_seconds() > 30:
        sess.last_seen = now
        db.commit()
    return sess


def require_user(request: Request, db: Session = Depends(get_db)) -> Ctx:
    sess = load_session(request, db)
    if sess is None:
        raise LoginRequired()
    request.state.user = sess.user
    request.state.session = sess
    if sess.user.must_change_password and request.url.path not in PASSWORD_CHANGE_PATHS:
        raise PasswordChangeRequired()
    return Ctx(request=request, db=db, user=sess.user, session=sess)


def _deny_role(c: Ctx, needed: str) -> None:
    audit.record(
        c.db, c.request, "access_denied", actor=c.user, outcome="denied",
        details={"path": c.request.url.path, "required_role": needed},
    )
    raise HTTPException(status_code=403, detail="You do not have permission to do that.")


def require_admin(c: Ctx = Depends(require_user)) -> Ctx:
    if c.user.role != ROLE_ADMIN:
        _deny_role(c, ROLE_ADMIN)
    return c


def require_uploader(c: Ctx = Depends(require_user)) -> Ctx:
    if c.user.role != ROLE_OWNER:
        _deny_role(c, ROLE_OWNER)
    return c


def check_csrf(c: Ctx, submitted: str | None) -> None:
    if not tokens_equal(submitted, c.session.csrf_token):
        audit.record(
            c.db, c.request, "csrf_rejected", actor=c.user, outcome="denied",
            details={"path": c.request.url.path},
        )
        raise HTTPException(status_code=403, detail="Your form expired. Reload the page and try again.")
