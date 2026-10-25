"""One user must never reach another user's documents.

Every document endpoint is exercised by every user who was *not* granted
access, and we assert both the response (an indistinguishable 404) and that
nothing changed underneath.
"""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.models import Document, DocumentVersion, Grant, User, utcnow

from .conftest import SECRET

OUTSIDERS = ["bob", "carol", "admin"]  # dave holds a read grant; see test_reader_*


def _attempts(doc_id, grant_id, category_id):
    """(method, path, form data, files) for every operation on a document."""
    f = lambda: {"file": ("v2.txt", b"overwritten", "text/plain")}
    return [
        ("GET", f"/documents/{doc_id}", None, None),
        ("GET", f"/documents/{doc_id}/download", None, None),
        ("GET", f"/documents/{doc_id}/download?version=1", None, None),
        ("GET", f"/documents/{doc_id}/edit", None, None),
        ("POST", f"/documents/{doc_id}/edit", {"name": "pwned", "description": "", "category_id": str(category_id)}, None),
        ("POST", f"/documents/{doc_id}/versions", {}, f),
        ("POST", f"/documents/{doc_id}/delete", {"confirm": "yes"}, None),
        ("POST", f"/documents/{doc_id}/grants", {"username": "INTRUDER", "permission": "edit"}, None),
        ("POST", f"/documents/{doc_id}/grants/{grant_id}/revoke", {}, None),
    ]


@pytest.fixture
def private_doc(login, category_id, db):
    alice = login("alice")
    doc_id = alice.upload("Salary letter", category_id)
    # A grant to dave (read) so we can test that others cannot revoke it.
    assert alice.grant(doc_id, "dave").status_code == 303
    grant_id = db.execute(select(Grant.id).where(Grant.document_id == doc_id)).scalar_one()
    return doc_id, grant_id


def _snapshot(app, doc_id):
    with app.state.SessionLocal() as s:
        doc = s.get(Document, doc_id)
        return {
            "name": doc.name,
            "deleted": doc.deleted_at,
            "owner": doc.owner_id,
            "versions": s.scalar(select(func.count()).select_from(DocumentVersion).where(DocumentVersion.document_id == doc_id)),
            "grants": sorted((g.user_id, g.permission) for g in s.execute(select(Grant).where(Grant.document_id == doc_id)).scalars()),
            "blobs": [app.state.blobs.exists(v.storage_key) for v in doc.versions],
        }


@pytest.mark.parametrize("outsider", OUTSIDERS)
def test_outsiders_cannot_read_change_or_delete(app, login, private_doc, category_id, outsider):
    doc_id, grant_id = private_doc
    before = _snapshot(app, doc_id)
    client = login(outsider)
    for method, path, data, files in _attempts(doc_id, grant_id, category_id):
        if method == "GET":
            r = client.get(path)
        else:
            r = client.post(path, data, files=files() if files else None)
        assert r.status_code == 404, f"{outsider} {method} {path} -> {r.status_code}"
        assert SECRET not in r.content
        assert b"Salary letter" not in r.content
    assert _snapshot(app, doc_id) == before


def test_not_found_is_indistinguishable_from_forbidden(login, private_doc):
    bob = login("bob")
    real = bob.get(f"/documents/{private_doc[0]}")
    fake = bob.get("/documents/" + "0" * 32)
    garbage = bob.get("/documents/../../etc/passwd")
    assert real.status_code == fake.status_code == 404
    assert real.text == fake.text
    assert garbage.status_code == 404


def test_reader_cannot_reach_owner_only_or_edit_operations(app, login, private_doc, category_id):
    doc_id, grant_id = private_doc
    dave = login("dave")  # holds a read grant
    assert dave.get(f"/documents/{doc_id}").status_code == 200
    r = dave.get(f"/documents/{doc_id}/download")
    assert r.status_code == 200 and r.content == SECRET
    before = _snapshot(app, doc_id)
    for method, path, data, files in _attempts(doc_id, grant_id, category_id)[3:]:
        r = dave.get(path) if method == "GET" else dave.post(path, data, files=files() if files else None)
        assert r.status_code == 404, f"reader {method} {path} -> {r.status_code}"
    assert _snapshot(app, doc_id) == before


def test_reader_does_not_see_access_list_or_history(login, private_doc):
    page = login("dave").get(f"/documents/{private_doc[0]}").text
    assert "Who has access" not in page and "Access history" not in page


def test_editor_can_edit_but_not_delete_or_share(app, login, private_doc, category_id):
    doc_id, grant_id = private_doc
    alice = login("alice")
    assert alice.grant(doc_id, "carol", "edit").status_code == 303
    carol = login("carol")
    r = carol.post(f"/documents/{doc_id}/edit", {"name": "Renamed by editor", "description": "x", "category_id": str(category_id)})
    assert r.status_code == 303
    r = carol.post(f"/documents/{doc_id}/versions", {}, files={"file": ("v2.txt", b"version two", "text/plain")})
    assert r.status_code == 303
    assert carol.get(f"/documents/{doc_id}/download").content == b"version two"
    assert carol.get(f"/documents/{doc_id}/download?version=1").content == SECRET
    before = _snapshot(app, doc_id)
    assert carol.post(f"/documents/{doc_id}/delete", {"confirm": "yes"}).status_code == 404
    assert carol.grant(doc_id, "bob", "read").status_code == 404
    assert carol.post(f"/documents/{doc_id}/grants/{grant_id}/revoke").status_code == 404
    assert _snapshot(app, doc_id) == before


def test_revocation_is_immediate(login, private_doc):
    doc_id, grant_id = private_doc
    dave = login("dave")
    assert dave.get(f"/documents/{doc_id}/download").status_code == 200
    assert login("alice").post(f"/documents/{doc_id}/grants/{grant_id}/revoke").status_code == 303
    assert dave.get(f"/documents/{doc_id}/download").status_code == 404
    assert dave.get(f"/documents/{doc_id}").status_code == 404
    assert doc_id not in dave.get("/documents").text


def test_expired_grant_gives_no_access(app, login, private_doc):
    doc_id, grant_id = private_doc
    dave = login("dave")
    assert dave.get(f"/documents/{doc_id}").status_code == 200
    with app.state.SessionLocal() as s:
        s.get(Grant, grant_id).expires_at = utcnow() - timedelta(seconds=1)
        s.commit()
    assert dave.get(f"/documents/{doc_id}/download").status_code == 404
    assert doc_id not in dave.get("/documents").text


def test_grant_with_future_expiry_works_and_past_is_rejected(login, private_doc):
    doc_id, _ = private_doc
    alice = login("alice")
    future = (utcnow() + timedelta(days=3)).date().isoformat()
    past = (utcnow() - timedelta(days=3)).date().isoformat()
    assert "grant_bad_date" in alice.grant(doc_id, "carol", "read", past).headers["location"]
    assert login("carol").get(f"/documents/{doc_id}").status_code == 404
    assert alice.grant(doc_id, "carol", "read", future).headers["location"].endswith("msg=granted")
    assert login("carol").get(f"/documents/{doc_id}").status_code == 200


def test_cannot_revoke_a_grant_on_another_document_via_own_document(app, login, category_id, db):
    alice, bob = login("alice"), login("bob")
    alices_doc = alice.upload("Alice doc", category_id)
    bobs_doc = bob.upload("Bob doc", category_id)
    bob.grant(bobs_doc, "carol")
    bobs_grant = db.execute(select(Grant.id).where(Grant.document_id == bobs_doc)).scalar_one()
    r = alice.post(f"/documents/{alices_doc}/grants/{bobs_grant}/revoke")
    assert r.status_code == 404
    assert login("carol").get(f"/documents/{bobs_doc}").status_code == 200


def test_search_only_returns_accessible_documents(login, category_id):
    alice, bob = login("alice"), login("bob")
    a = alice.upload("Quarterly report Alice", category_id)
    b = bob.upload("Quarterly report Bob", category_id)
    for who, visible, hidden in (("alice", a, b), ("bob", b, a)):
        for query in ("?q=Quarterly", "?owner=alice", "?owner=bob", "?scope=all", f"?category={category_id}"):
            page = login(who).get("/documents" + query).text
            assert hidden not in page, f"{who} saw a hidden doc via {query}"
        assert visible in login(who).get("/documents?q=quarterly").text
    for who in ("carol", "dave", "admin"):
        page = login(who).get("/documents?q=Quarterly").text
        assert a not in page and b not in page
    # Wildcards in the query are literal, not a way to match everything.
    assert a not in alice.get("/documents?q=%25").text


def test_shared_with_me_and_owned_scopes(login, category_id):
    alice = login("alice")
    a = alice.upload("For carol", category_id)
    alice.grant(a, "carol")
    carol = login("carol")
    assert a in carol.get("/documents?scope=shared").text
    assert a not in carol.get("/documents?scope=mine").text


def test_viewer_cannot_upload(app, login, category_id):
    carol = login("carol")
    assert carol.get("/documents/new").status_code == 403
    r = carol.post("/documents", {"name": "x", "category_id": str(category_id)},
                   files={"file": ("x.txt", b"hello", "text/plain")})
    assert r.status_code == 403
    with app.state.SessionLocal() as s:
        assert s.scalar(select(func.count()).select_from(Document)) == 0


def test_admin_sees_metadata_but_cannot_download(login, private_doc):
    doc_id, _ = private_doc
    admin = login("admin")
    assert admin.get(f"/admin/documents/{doc_id}").status_code == 200
    assert admin.get(f"/documents/{doc_id}/download").status_code == 404
    assert SECRET not in admin.get(f"/admin/documents/{doc_id}").content


@pytest.mark.parametrize("who", ["alice", "bob", "carol", "dave"])
def test_non_admins_cannot_use_admin_pages(app, login, private_doc, who):
    doc_id, _ = private_doc
    client = login(who)
    for path in ("/admin", "/admin/audit", "/admin/audit.csv", "/admin/permissions", "/admin/documents",
                 f"/admin/documents/{doc_id}", "/admin/users", "/admin/audit/verify", "/admin/categories"):
        assert client.get(path).status_code == 403, path
    target = app.state.SessionLocal().execute(select(User.id).where(User.username == "dave")).scalar_one()
    assert client.post(f"/admin/users/{target}/role", {"role": "admin"}).status_code == 403
    assert client.post(f"/admin/documents/{doc_id}/transfer", {"username": who}).status_code == 403
    assert client.post("/admin/users", {"username": "evil", "full_name": "E", "role": "admin",
                                         "password": "x" * 20}).status_code == 403
    with app.state.SessionLocal() as s:
        assert s.execute(select(User.role).where(User.id == target)).scalar_one() == "viewer"
        assert s.execute(select(User).where(User.username == "evil")).first() is None


def test_unauthenticated_requests_are_sent_to_login(app, private_doc):
    doc_id, grant_id = private_doc
    anon = TestClient(app, follow_redirects=False)
    for path in ("/documents", f"/documents/{doc_id}", f"/documents/{doc_id}/download", "/admin", "/admin/audit.csv"):
        r = anon.get(path)
        assert r.status_code == 303 and r.headers["location"] == "/login", path
        assert SECRET not in r.content
    r = anon.post(f"/documents/{doc_id}/delete", data={"confirm": "yes"})
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_deactivated_user_loses_session_and_grants(app, login, private_doc, db):
    doc_id, _ = private_doc
    dave = login("dave")
    assert dave.get(f"/documents/{doc_id}").status_code == 200
    dave_id = db.execute(select(User.id).where(User.username == "dave")).scalar_one()
    assert login("admin").post(f"/admin/users/{dave_id}/deactivate").status_code == 303
    r = dave.get(f"/documents/{doc_id}/download")
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert dave.login("correct-horse-battery-staple").status_code == 401
    with app.state.SessionLocal() as s:
        assert s.execute(select(Grant).where(Grant.user_id == dave_id)).first() is None
    # Reactivation does not silently restore old access.
    login("admin").post(f"/admin/users/{dave_id}/activate")
    from .conftest import UserClient
    assert UserClient(app, "dave").get(f"/documents/{doc_id}").status_code == 404


def test_deleted_document_is_gone_for_everyone_and_content_destroyed(app, login, private_doc):
    doc_id, _ = private_doc
    with app.state.SessionLocal() as s:
        key = s.get(Document, doc_id).versions[0].storage_key
    assert app.state.blobs.exists(key)
    assert login("alice").post(f"/documents/{doc_id}/delete", {"confirm": "yes"}).status_code == 303
    assert not app.state.blobs.exists(key)
    for who in ("alice", "dave"):
        assert login(who).get(f"/documents/{doc_id}").status_code == 404
        assert login(who).get(f"/documents/{doc_id}/download").status_code == 404


def test_delete_requires_confirmation(app, login, private_doc):
    doc_id, _ = private_doc
    r = login("alice").post(f"/documents/{doc_id}/delete", {})
    assert "delete_unconfirmed" in r.headers["location"]
    assert login("alice").get(f"/documents/{doc_id}").status_code == 200


def test_ownership_transfer_moves_control(login, private_doc, db):
    doc_id, grant_id = private_doc
    assert login("admin").post(f"/admin/documents/{doc_id}/transfer", {"username": "bob"}).status_code == 303
    assert login("alice").get(f"/documents/{doc_id}").status_code == 404
    bob = login("bob")
    assert bob.get(f"/documents/{doc_id}/download").content == SECRET
    assert bob.post(f"/documents/{doc_id}/grants/{grant_id}/revoke").status_code == 303


def test_transfer_only_to_active_owner_role(login, private_doc):
    doc_id, _ = private_doc
    r = login("admin").post(f"/admin/documents/{doc_id}/transfer", {"username": "carol"})
    assert "transfer_error" in r.headers["location"]
    assert login("carol").get(f"/documents/{doc_id}").status_code == 404


def test_owner_with_documents_cannot_be_demoted(login, private_doc, db):
    alice_id = db.execute(select(User.id).where(User.username == "alice")).scalar_one()
    r = login("admin").post(f"/admin/users/{alice_id}/role", {"role": "viewer"})
    assert "user_error_owns_docs" in r.headers["location"]


def test_cannot_grant_to_unknown_or_inactive_user(login, private_doc):
    doc_id, _ = private_doc
    assert "grant_user_not_found" in login("alice").grant(doc_id, "nobody").headers["location"]
    assert "grant_bad_permission" in login("alice").grant(doc_id, "carol", "admin").headers["location"]
