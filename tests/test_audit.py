import csv
import io
import json
import sqlite3

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app import audit
from app.models import AuditEvent

from .conftest import SECRET


def events(app, **where):
    with app.state.SessionLocal() as s:
        stmt = select(AuditEvent).order_by(AuditEvent.id)
        for k, v in where.items():
            stmt = stmt.where(getattr(AuditEvent, k) == v)
        return list(s.execute(stmt).scalars())


def test_full_document_lifecycle_is_recorded(app, login, category_id, db):
    alice, carol = login("alice"), login("carol")
    doc_id = alice.upload("Contract", category_id)
    alice.grant(doc_id, "carol", "edit")
    carol.get(f"/documents/{doc_id}")
    carol.get(f"/documents/{doc_id}/download")
    carol.post(f"/documents/{doc_id}/edit", {"name": "Contract v2", "description": "", "category_id": str(category_id)})
    carol.post(f"/documents/{doc_id}/versions", {}, files={"file": ("c.txt", b"new text", "text/plain")})
    alice.grant(doc_id, "carol", "read")
    grant_id = db.execute(text("select id from grants where document_id=:d"), {"d": doc_id}).scalar()
    alice.post(f"/documents/{doc_id}/grants/{grant_id}/revoke")
    alice.post(f"/documents/{doc_id}/delete", {"confirm": "yes"})

    trail = [(e.actor_username, e.action, e.target_username) for e in events(app, document_id=doc_id)]
    assert trail == [
        ("alice", "upload", ""),
        ("alice", "permission_granted", "carol"),
        ("carol", "view", ""),
        ("carol", "download", ""),
        ("carol", "metadata_updated", ""),
        ("carol", "new_version", ""),
        ("alice", "permission_changed", "carol"),
        ("alice", "permission_revoked", "carol"),
        ("alice", "delete", ""),
    ]
    by_action = {e.action: json.loads(e.details) for e in events(app, document_id=doc_id)}
    assert by_action["download"]["version"] == 1 and len(by_action["download"]["sha256"]) == 64
    assert by_action["metadata_updated"]["changes"]["name"] == ["Contract", "Contract v2"]
    assert by_action["permission_changed"]["from"]["permission"] == "edit"
    assert by_action["permission_changed"]["to"]["permission"] == "read"
    assert all(e.ip for e in events(app, document_id=doc_id))


def test_denied_attempts_are_recorded_with_actor(app, login, category_id):
    doc_id = login("alice").upload("Private", category_id)
    login("bob").get(f"/documents/{doc_id}/download")
    login("bob").get("/documents/" + "f" * 32)
    denied = events(app, action="access_denied", actor_username="bob")
    assert len(denied) == 2
    assert denied[0].document_id == doc_id and denied[0].outcome == "denied"
    assert json.loads(denied[1].details)["requested_id"] == "f" * 32


def test_auth_events_recorded(app, login):
    alice = login("alice")
    alice.login("bad-password-xyz")
    alice.post("/logout")
    actions = [e.action for e in events(app, actor_username="alice")]
    assert actions[:1] == ["login"] and "login_failed" in actions and "logout" in actions


def test_rejected_upload_is_recorded_and_creates_nothing(app, login, category_id):
    alice = login("alice")
    r = alice.post("/documents", {"name": "evil", "category_id": str(category_id)},
                   files={"file": ("evil.exe", b"MZ\x90\x00", "application/octet-stream")})
    assert r.status_code == 400
    assert events(app, action="upload_rejected")[0].actor_username == "alice"
    assert not events(app, action="upload")


def test_chain_verifies(app, login, category_id):
    login("alice").upload("A", category_id)
    with app.state.SessionLocal() as s:
        report = audit.verify_chain(s)
    assert report.ok and report.count >= 2


def test_audit_rows_cannot_be_updated_or_deleted(app, login, category_id):
    login("alice").upload("A", category_id)
    with app.state.SessionLocal() as s:
        with pytest.raises(DBAPIError, match="append-only"):
            s.execute(text("UPDATE audit_events SET actor_username='nobody'"))
        s.rollback()
        with pytest.raises(DBAPIError, match="append-only"):
            s.execute(text("DELETE FROM audit_events"))
        s.rollback()


def _raw(app):
    return sqlite3.connect(app.state.settings.database_url.removeprefix("sqlite:///"))


@pytest.mark.parametrize("tamper", ["modify", "remove"])
def test_tampering_is_detected(app, login, category_id, tamper):
    doc_id = login("alice").upload("A", category_id)
    login("carol").get(f"/documents/{doc_id}")  # denied, recorded
    login("alice").get(f"/documents/{doc_id}/download")
    target = events(app, action="access_denied")[0].id
    con = _raw(app)
    con.execute("DROP TRIGGER audit_events_no_update")
    con.execute("DROP TRIGGER audit_events_no_delete")
    if tamper == "modify":
        con.execute("UPDATE audit_events SET actor_username='someone_else' WHERE id=?", (target,))
    else:
        con.execute("DELETE FROM audit_events WHERE id=?", (target,))
    con.commit()
    con.close()
    with app.state.SessionLocal() as s:
        report = audit.verify_chain(s)
    assert not report.ok
    assert report.first_bad_id == (target if tamper == "modify" else target + 1)
    page = login("admin").get("/admin/audit/verify")
    assert "TAMPERING DETECTED" in page.text


def test_admin_activity_and_permission_views(app, login, category_id):
    alice = login("alice")
    doc_id = alice.upload("Board minutes", category_id)
    alice.grant(doc_id, "dave")
    login("bob").get(f"/documents/{doc_id}")
    admin = login("admin")
    dash = admin.get("/admin").text
    assert "Board minutes" in dash and "permission_granted" in dash and "access_denied" in dash
    perms = admin.get("/admin/permissions?target=dave").text
    assert "permission_granted" in perms and "dave" in perms
    filtered = admin.get("/admin/audit?actor=bob&outcome=denied").text
    assert "access_denied" in filtered and "upload" not in filtered.split("<tbody>")[1]
    detail = admin.get(f"/admin/documents/{doc_id}").text
    assert "permission_granted" in detail and "access_denied" in detail


def test_csv_export_neutralises_formulas(app, login, category_id):
    login("alice").upload("=HYPERLINK(\"http://evil\")", category_id)
    r = login("admin").get("/admin/audit.csv?action=upload")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert rows and rows[0]["document_name"].startswith("'=")
    assert events(app, action="audit_exported")


def test_file_contents_never_written_to_audit(app, login, category_id):
    doc_id = login("alice").upload("Salary", category_id)
    login("alice").get(f"/documents/{doc_id}/download")
    with app.state.SessionLocal() as s:
        dump = " ".join(e.details for e in s.execute(select(AuditEvent)).scalars())
    assert SECRET.decode() not in dump
