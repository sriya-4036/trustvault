import io
import os

import pytest

from app.validation import UploadRejected, sanitize_filename, validate_upload

from .conftest import make_docx, make_pdf, make_png

LIMIT = 1024 * 1024


def v(name, data, limit=LIMIT):
    return validate_upload(name, io.BytesIO(data), limit)


@pytest.mark.parametrize("name,data,ctype", [
    ("notes.txt", b"hello world\n", "text/plain"),
    ("data.csv", b"a,b\n1,2\n", "text/csv"),
    ("report.pdf", make_pdf(), "application/pdf"),
    ("pic.png", make_png(), "image/png"),
    ("letter.docx", make_docx(), "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
])
def test_accepts_valid_files(name, data, ctype):
    f = v(name, data)
    assert f.content_type == ctype and f.size == len(data) and len(f.sha256) == 64


@pytest.mark.parametrize("name", ["virus.exe", "page.html", "image.svg", "script.js", "noext", "macro.docm", "a.php"])
def test_rejects_disallowed_extensions(name):
    with pytest.raises(UploadRejected, match="not allowed"):
        v(name, b"whatever")


@pytest.mark.parametrize("name,data", [
    ("fake.pdf", make_png()),
    ("fake.png", make_pdf()),
    ("page.txt", b"<!DOCTYPE html><html><script>alert(1)</script></html>"),
    ("fake.docx", make_pdf()),
    ("fake.jpg", b"GIF89a" + b"\x00" * 50),
])
def test_rejects_content_that_does_not_match_extension(name, data):
    with pytest.raises(UploadRejected, match="does not match"):
        v(name, data)


def test_rejects_empty_and_oversized():
    with pytest.raises(UploadRejected, match="empty"):
        v("a.txt", b"")
    with pytest.raises(UploadRejected, match="larger than"):
        v("a.txt", b"x" * (LIMIT + 1))


def test_rejects_pdf_with_javascript():
    with pytest.raises(UploadRejected, match="scripts"):
        v("x.pdf", make_pdf(b"/OpenAction << /S /JavaScript /JS (app.alert(1)) >>"))


def test_rejects_docx_with_macros():
    with pytest.raises(UploadRejected, match="macros"):
        v("x.docx", make_docx(with_macro=True))


def test_rejects_invalid_text():
    with pytest.raises(UploadRejected):
        v("x.txt", "café".encode("latin-1") + b" text " * 10)


def test_filename_sanitised():
    assert sanitize_filename("../../etc/passwd.txt") == "passwd.txt"
    assert sanitize_filename("C:\\Users\\x\\report.pdf") == "report.pdf"
    assert sanitize_filename("evil\r\nheader.txt") == "evilheader.txt"
    assert sanitize_filename('a"b<c>.txt') == "a_b_c_.txt"
    with pytest.raises(UploadRejected):
        sanitize_filename("...")
    with pytest.raises(UploadRejected):
        sanitize_filename("a" * 200 + ".txt")


def test_upload_endpoint_rejects_and_stores_encrypted(app, login, category_id, settings):
    alice = login("alice")
    r = alice.post("/documents", {"name": "x", "category_id": str(category_id)},
                   files={"file": ("x.pdf", b"not a pdf at all", "application/pdf")})
    assert r.status_code == 400 and "does not match" in r.text
    r = alice.post("/documents", {"name": "x", "category_id": str(category_id)},
                   files={"file": ("big.txt", b"x" * (settings.max_upload_bytes + 1), "text/plain")})
    assert r.status_code == 400 and "larger than" in r.text
    secret = b"PLAINTEXT-MARKER-0123456789"
    alice.upload("Encrypted", category_id, content=secret)
    blobs = [os.path.join(d, f) for d, _, fs in os.walk(settings.data_dir / "blobs") for f in fs]
    assert blobs and all(secret not in open(p, "rb").read() for p in blobs)


def test_download_headers_force_attachment(login, category_id):
    alice = login("alice")
    doc_id = alice.upload("H", category_id, content=b"hello", filename='we"ird name.txt')
    r = alice.get(f"/documents/{doc_id}/download")
    assert r.headers["content-disposition"].startswith("attachment;")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in r.headers["content-security-policy"]


def test_metadata_validation(login, category_id):
    alice = login("alice")
    r = alice.post("/documents", {"name": "x" * 300, "category_id": str(category_id)},
                   files={"file": ("a.txt", b"hi", "text/plain")})
    assert r.status_code == 400 and "at most 200" in r.text
    r = alice.post("/documents", {"name": "ok", "category_id": "9999"},
                   files={"file": ("a.txt", b"hi", "text/plain")})
    assert r.status_code == 400 and "valid category" in r.text
