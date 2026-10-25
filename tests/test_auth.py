from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.deps import SESSION_COOKIE
from app.models import Document, User, UserSession, utcnow

from .conftest import PASSWORD, UserClient


def test_wrong_password_and_unknown_user_look_identical(app):
    c = UserClient(app, "alice")
    r1 = c.login("wrong-password-123")
    other = TestClient(app, follow_redirects=False)
    page = other.get("/login")
    import re
    tok = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    r2 = other.post("/login", data={"username": "ghost", "password": "whatever", "csrf_token": tok})
    assert r1.status_code == r2.status_code == 401
    assert "Incorrect username or password" in r1.text and "Incorrect username or password" in r2.text


def test_lockout_after_repeated_failures(app):
    c = UserClient(app, "bob")
    for _ in range(app.state.settings.max_failed_logins):
        assert c.login("nope-nope-nope").status_code == 401
    assert c.login(PASSWORD).status_code == 401
    with app.state.SessionLocal() as s:
        u = s.execute(select(User).where(User.username == "bob")).scalar_one()
        assert u.locked_until and u.locked_until > utcnow()


def test_login_requires_login_csrf(app):
    anon = TestClient(app, follow_redirects=False)
    r = anon.post("/login", data={"username": "alice", "password": PASSWORD, "csrf_token": "forged"})
    assert r.status_code == 400
    assert SESSION_COOKIE not in r.cookies


def test_session_token_is_stored_hashed(app):
    c = UserClient(app, "alice")
    raw = c.http.cookies.get(SESSION_COOKIE)
    with app.state.SessionLocal() as s:
        ids = list(s.execute(select(UserSession.id)).scalars())
    assert raw not in ids and len(ids) == 1


def test_logout_invalidates_session_server_side(app):
    c = UserClient(app, "alice")
    raw = c.http.cookies.get(SESSION_COOKIE)
    assert c.post("/logout").status_code == 303
    replay = TestClient(app, follow_redirects=False)
    replay.cookies.set(SESSION_COOKIE, raw)
    assert replay.get("/documents").headers["location"] == "/login"


def test_idle_session_expires(app):
    c = UserClient(app, "alice")
    with app.state.SessionLocal() as s:
        for sess in s.execute(select(UserSession)).scalars():
            sess.last_seen = utcnow() - timedelta(minutes=app.state.settings.session_idle_minutes + 1)
        s.commit()
    assert c.get("/documents").headers["location"] == "/login"


def test_csrf_required_on_state_changes(app, login, category_id):
    alice = login("alice")
    doc_id = alice.upload("Doc", category_id)
    r = alice.post(f"/documents/{doc_id}/grants", {"username": "carol", "permission": "read"}, csrf=False)
    assert r.status_code == 403
    bob = login("bob")
    r = alice.post(f"/documents/{doc_id}/delete", {"confirm": "yes", "csrf_token": bob.csrf})
    assert r.status_code == 403
    assert login("carol").get(f"/documents/{doc_id}").status_code == 404
    with app.state.SessionLocal() as s:
        assert s.get(Document, doc_id).deleted_at is None


def test_admin_created_user_must_change_password(app, login):
    admin = login("admin")
    r = admin.post("/admin/users", {"username": "erin", "full_name": "Erin", "role": "viewer", "password": "temporary-pass-123"})
    assert r.status_code == 303
    erin = UserClient.__new__(UserClient)
    erin.app, erin.username = app, "erin"
    erin.http = TestClient(app, follow_redirects=False)
    assert erin.login("temporary-pass-123").status_code == 303
    r = erin.http.get("/documents")
    assert r.status_code == 303 and r.headers["location"].startswith("/account/password")


def test_weak_passwords_rejected(login):
    r = login("admin").post("/admin/users", {"username": "frank", "full_name": "F", "role": "viewer", "password": "short"})
    assert r.status_code == 400 and "at least 12" in r.text


def test_password_change_signs_out_other_sessions(app):
    a1, a2 = UserClient(app, "alice"), UserClient(app, "alice")
    r = a1.post("/account/password", {"current_password": PASSWORD, "new_password": "a-brand-new-passphrase",
                                       "confirm_password": "a-brand-new-passphrase"})
    assert r.status_code == 303
    assert a1.get("/documents").status_code == 200
    assert a2.get("/documents").headers["location"] == "/login"


def test_security_headers_present(app, login):
    r = login("alice").get("/documents")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"
    cookie = TestClient(app, follow_redirects=False)
    import re
    page = cookie.get("/login")
    tok = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    resp = cookie.post("/login", data={"username": "alice", "password": PASSWORD, "csrf_token": tok})
    set_cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in set_cookie and "samesite=lax" in set_cookie


def test_output_is_escaped(login, category_id):
    alice = login("alice")
    doc_id = alice.upload("<script>alert(1)</script>", category_id)
    page = alice.get(f"/documents/{doc_id}").text
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
