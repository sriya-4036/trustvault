import hashlib
import io
import re
import unicodedata
import zipfile
from dataclasses import dataclass
from typing import BinaryIO

import magic

MAX_FILENAME_LENGTH = 150
MAX_ZIP_UNCOMPRESSED = 200 * 1024 * 1024
MAX_ZIP_RATIO = 100
MAX_ZIP_ENTRIES = 5000

_OOXML = {
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "word/document.xml"),
    "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xl/workbook.xml"),
    "pptx": ("application/vnd.openxmlformats-officedocument.presentationml.presentation", "ppt/presentation.xml"),
}

# extension -> (canonical content type stored and served, MIME types libmagic may report)
ALLOWED_TYPES: dict[str, tuple[str, set[str]]] = {
    "pdf": ("application/pdf", {"application/pdf"}),
    "txt": ("text/plain", {"text/plain"}),
    "csv": ("text/csv", {"text/csv", "text/plain", "application/csv"}),
    "png": ("image/png", {"image/png"}),
    "jpg": ("image/jpeg", {"image/jpeg"}),
    "jpeg": ("image/jpeg", {"image/jpeg"}),
    **{ext: (ct, {ct, "application/zip"}) for ext, (ct, _) in _OOXML.items()},
}

_PDF_ACTIVE = re.compile(rb"/(JavaScript|JS|Launch|EmbeddedFile)(?![A-Za-z0-9])")


class UploadRejected(ValueError):
    pass


@dataclass
class ValidatedFile:
    filename: str
    extension: str
    content_type: str
    data: bytes
    size: int
    sha256: str


def sanitize_filename(raw: str | None) -> str:
    name = unicodedata.normalize("NFKC", raw or "")
    name = name.replace("\\", "/").split("/")[-1]
    name = re.sub(r"[\x00-\x1f\x7f]", "", name)
    name = re.sub(r'[<>:"|?*;]', "_", name).strip().strip(".").strip()
    if not name:
        raise UploadRejected("The file has no usable name.")
    if len(name) > MAX_FILENAME_LENGTH:
        raise UploadRejected(f"File name is longer than {MAX_FILENAME_LENGTH} characters.")
    return name


def extension_of(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def read_limited(stream: BinaryIO, max_bytes: int) -> bytes:
    data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise UploadRejected(f"File is larger than the {max_bytes // (1024 * 1024)} MB limit.")
    return data


def _check_text(data: bytes) -> None:
    if b"\x00" in data:
        raise UploadRejected("Text files must not contain binary data.")
    try:
        data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise UploadRejected("Text files must be UTF-8 encoded.") from None


def _check_pdf(data: bytes) -> None:
    if not data.startswith(b"%PDF-"):
        raise UploadRejected("File does not look like a PDF.")
    if _PDF_ACTIVE.search(data):
        raise UploadRejected("PDFs with embedded scripts, launch actions or attachments are not accepted.")


def _check_ooxml(data: bytes, ext: str) -> None:
    required_part = _OOXML[ext][1]
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                raise UploadRejected("Office document has too many parts.")
            total = sum(i.file_size for i in infos)
            if total > MAX_ZIP_UNCOMPRESSED or total > MAX_ZIP_RATIO * max(len(data), 1):
                raise UploadRejected("Office document expands to an unreasonable size.")
            names = {i.filename for i in infos}
    except zipfile.BadZipFile:
        raise UploadRejected("Office document is corrupt.") from None
    if "[Content_Types].xml" not in names or required_part not in names:
        raise UploadRejected(f"File is not a valid .{ext} document.")
    if any(n.lower().endswith("vbaproject.bin") for n in names):
        raise UploadRejected("Documents containing macros are not accepted.")


def validate_upload(raw_filename: str | None, stream: BinaryIO, max_bytes: int) -> ValidatedFile:
    filename = sanitize_filename(raw_filename)
    ext = extension_of(filename)
    if ext not in ALLOWED_TYPES:
        allowed = ", ".join(sorted(ALLOWED_TYPES))
        raise UploadRejected(f"File type '.{ext}' is not allowed. Allowed: {allowed}.")
    data = read_limited(stream, max_bytes)
    if not data:
        raise UploadRejected("The file is empty.")

    canonical, accepted = ALLOWED_TYPES[ext]
    sniffed = magic.from_buffer(data[:65536], mime=True)
    if sniffed not in accepted:
        raise UploadRejected(f"File content ({sniffed}) does not match its .{ext} extension.")

    if ext in ("txt", "csv"):
        _check_text(data)
    elif ext == "pdf":
        _check_pdf(data)
    elif ext in _OOXML:
        _check_ooxml(data, ext)

    return ValidatedFile(
        filename=filename,
        extension=ext,
        content_type=canonical,
        data=data,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )
