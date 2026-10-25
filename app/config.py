import base64
import os
from dataclasses import dataclass
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    data_dir: Path
    database_url: str
    master_key: bytes | None = None
    max_upload_bytes: int = 10 * 1024 * 1024
    session_idle_minutes: int = 30
    session_absolute_hours: int = 12
    cookie_secure: bool = False
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    min_password_length: int = 12
    bcrypt_rounds: int = 12

    @classmethod
    def from_env(cls) -> "Settings":
        data_dir = Path(os.environ.get("TRUSTVAULT_DATA_DIR", "./data")).resolve()
        key = os.environ.get("TRUSTVAULT_MASTER_KEY")
        return cls(
            data_dir=data_dir,
            database_url=os.environ.get("TRUSTVAULT_DATABASE_URL", f"sqlite:///{data_dir / 'trustvault.db'}"),
            master_key=base64.urlsafe_b64decode(key) if key else None,
            max_upload_bytes=int(os.environ.get("TRUSTVAULT_MAX_UPLOAD_BYTES", 10 * 1024 * 1024)),
            session_idle_minutes=int(os.environ.get("TRUSTVAULT_SESSION_IDLE_MINUTES", 30)),
            session_absolute_hours=int(os.environ.get("TRUSTVAULT_SESSION_ABSOLUTE_HOURS", 12)),
            cookie_secure=_bool("TRUSTVAULT_COOKIE_SECURE", False),
            max_failed_logins=int(os.environ.get("TRUSTVAULT_MAX_FAILED_LOGINS", 5)),
            lockout_minutes=int(os.environ.get("TRUSTVAULT_LOCKOUT_MINUTES", 15)),
            bcrypt_rounds=int(os.environ.get("TRUSTVAULT_BCRYPT_ROUNDS", 12)),
        )
