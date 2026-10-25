import io
import re
import struct
import zipfile
import zlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.config import Settings
from app.main import create_app
from app.models import Category, User
from app.security import hash_password

PASSWORD = "correct-horse-battery-staple"
USERS = [("admin", "admin"), ("alice", "owner"), ("bob", "owner"), ("carol", "viewer"), ("dave", "viewer")]
SECRET = b"TOP-SECRET-SALARY-DATA-12345"


@pytest.fixture
def settings(tmp_path):
    return Settings(
        data_dir=tmp_path / "data",
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        master_key=b"k" * 32,
        bcrypt_rounds=4,
        max_upload_bytes=256 * 1024,
    )


@pytest.fixture
def app(settings):
    app = create_app(settings)
    with app.state.SessionLocal() as db:
        for username, role in USERS:
            db.add(User(username=username, full_name=username.title(), role=role,
                        password_hash=hash_password(PASSWORD, 4)))
        db.commit()
    return app


@pytest.fixture
def db(app):
    s = app.state.SessionLocal()
    yield s
    s.close()


@pytest.fixture
def category_id(app):
    with app.state.SessionLocal() as s:
        return s.execute(select(Category.id).order_by(Category.id)).scalars().first()


class UserClient:
    """A browser-like session for one user: own cookie jar, own CSRF token."""

    def __init__(self, app, username: str, password: str = PASSWORD):
        self.app = app
        self.username = username
        self.http = TestClient(app, follow_redirects=False)
        self.csrf = ""
        r = self.login(password)
        assert r.status_code == 303, f"login failed for {username}: {r.status_code}"
        page = self.http.get("/account/password")
        self.csrf = re.search(r'name="csrf-token" content="([^"]+)"', page.text).group(1)

    def login(self, password: str):
        """Sign in from a fresh browser; on success this client adopts the new session."""
        fresh = TestClient(self.app, follow_redirects=False)
        page = fresh.get("/login")
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        r = fresh.post("/login", data={"username": self.username, "password": password, "csrf_token": token})
        if r.status_code == 303:
            self.http.cookies.set("tv_session", fresh.cookies.get("tv_session"))
        return r

    def get(self, url, **kw):
        return self.http.get(url, **kw)

    def post(self, url, data=None, files=None, csrf=True):
        data = dict(data or {})
        if csrf:
            data.setdefault("csrf_token", self.csrf)
        return self.http.post(url, data=data, files=files)

    def upload(self, name, category_id, content=SECRET, filename="letter.txt"):
        r = self.post("/documents", {"name": name, "category_id": str(category_id)},
                      files={"file": (filename, content, "application/octet-stream")})
        assert r.status_code == 303, r.text
        return r.headers["location"].split("/documents/")[1].split("?")[0]

    def grant(self, doc_id, username, permission="read", expires_on=""):
        return self.post(f"/documents/{doc_id}/grants",
                         {"username": username, "permission": permission, "expires_on": expires_on})


@pytest.fixture
def login(app):
    clients = {}

    def _login(username):
        if username not in clients:
            clients[username] = UserClient(app, username)
        return clients[username]

    return _login


def make_png() -> bytes:
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + chunk(b"IEND", b"")


def make_pdf(extra: bytes = b"") -> bytes:
    return b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog " + extra + b" >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"


def make_docx(with_macro: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        z.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships/>')
        z.writestr("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="x"/>')
        if with_macro:
            z.writestr("word/vbaProject.bin", b"\x00" * 64)
    return buf.getvalue()
