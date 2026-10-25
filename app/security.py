import base64
import hashlib
import hmac
import re
import secrets

import bcrypt

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
MAX_PASSWORD_LENGTH = 128


def _prehash(password: str) -> bytes:
    # bcrypt truncates at 72 bytes; pre-hashing keeps long passphrases intact.
    return base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest())


def hash_password(password: str, rounds: int = 12) -> str:
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt(rounds)).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_prehash(password), password_hash.encode())
    except ValueError:
        return False


_DUMMY_HASH: str | None = None


def burn_password_check(password: str) -> None:
    """Spend the same time as a real check so unknown usernames are not distinguishable."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("dummy-password-for-timing", 12)
    verify_password(password, _DUMMY_HASH)


def password_problems(password: str, username: str, min_length: int) -> list[str]:
    problems = []
    if len(password) < min_length:
        problems.append(f"Password must be at least {min_length} characters.")
    if len(password) > MAX_PASSWORD_LENGTH:
        problems.append(f"Password must be at most {MAX_PASSWORD_LENGTH} characters.")
    if username and username.lower() in password.lower():
        problems.append("Password must not contain the username.")
    return problems


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def tokens_equal(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode(), b.encode())
