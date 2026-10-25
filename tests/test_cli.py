import base64
import os

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import cli
from app.config import Settings
from app.db import make_engine
from app.models import User


def _users(data_dir):
    engine = make_engine(f"sqlite:///{data_dir / 'trustvault.db'}")
    with Session(engine) as db:
        return {u.username: u.role for u in db.execute(select(User)).scalars()}


def _env(monkeypatch, tmp_path, **extra):
    for k in ("TRUSTVAULT_SEED_DEMO", "TRUSTVAULT_ADMIN_PASSWORD", "TRUSTVAULT_ADMIN_USERNAME", "TRUSTVAULT_DATABASE_URL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("TRUSTVAULT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("TRUSTVAULT_BCRYPT_ROUNDS", "4")
    for k, v in extra.items():
        monkeypatch.setenv(k, v)


def test_bootstrap_noop_without_env(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    assert cli.main(["bootstrap"]) == 0
    assert not (tmp_path / "trustvault.db").exists()


def test_bootstrap_creates_first_admin_once(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path, TRUSTVAULT_ADMIN_PASSWORD="a-long-admin-passphrase-1", TRUSTVAULT_ADMIN_USERNAME="root")
    assert cli.main(["bootstrap"]) == 0
    assert _users(tmp_path) == {"root": "admin"}
    monkeypatch.setenv("TRUSTVAULT_ADMIN_USERNAME", "second")
    assert cli.main(["bootstrap"]) == 0
    assert _users(tmp_path) == {"root": "admin"}


def test_bootstrap_seed_demo_is_idempotent(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path, TRUSTVAULT_SEED_DEMO="true")
    assert cli.main(["bootstrap"]) == 0
    assert cli.main(["bootstrap"]) == 0
    assert set(_users(tmp_path)) == {u for u, _, _ in cli.DEMO_USERS}


def test_render_style_master_key_accepted(monkeypatch, tmp_path):
    # Render's generateValue gives standard (not url-safe) base64 of 32 random bytes.
    raw = bytes([0xFB, 0xFF] * 16)
    std = base64.b64encode(raw).decode()
    assert "+" in std or "/" in std
    _env(monkeypatch, tmp_path, TRUSTVAULT_MASTER_KEY=std)
    assert Settings.from_env().master_key == raw
    assert os.environ["TRUSTVAULT_MASTER_KEY"] == std
