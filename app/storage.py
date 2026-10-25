import os
import re
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_KEY_RE = re.compile(r"^[0-9a-f]{32}$")


def load_or_create_master_key(data_dir: Path, configured: bytes | None) -> bytes:
    if configured is not None:
        if len(configured) != 32:
            raise ValueError("TRUSTVAULT_MASTER_KEY must decode to 32 bytes")
        return configured
    key_file = data_dir / "master.key"
    if key_file.exists():
        return key_file.read_bytes()
    key = AESGCM.generate_key(bit_length=256)
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


class BlobStore:
    """Stores file contents encrypted with AES-256-GCM under random, non-guessable keys.

    The storage key is bound into the ciphertext as associated data, so a blob
    copied over another blob's path fails authentication instead of decrypting.
    """

    def __init__(self, root: Path, master_key: bytes):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._aead = AESGCM(master_key)

    def _path(self, key: str) -> Path:
        if not _KEY_RE.match(key):
            raise ValueError("invalid storage key")
        return self.root / key[:2] / key

    def put(self, data: bytes) -> str:
        key = secrets.token_hex(16)
        nonce = os.urandom(12)
        blob = nonce + self._aead.encrypt(nonce, data, key.encode())
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(blob)
        os.replace(tmp, path)
        return key

    def get(self, key: str) -> bytes:
        blob = self._path(key).read_bytes()
        return self._aead.decrypt(blob[:12], blob[12:], key.encode())

    def delete(self, key: str) -> None:
        try:
            self._path(key).unlink()
        except FileNotFoundError:
            pass

    def exists(self, key: str) -> bool:
        return self._path(key).exists()
