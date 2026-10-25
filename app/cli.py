"""Command line helpers: `python -m app.cli create-user ...`, `seed-demo` and `bootstrap`."""
import argparse
import getpass
import io
import os
import sys

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .config import Settings
from .db import init_db, make_engine
from .models import ROLES, Category, Document, DocumentVersion, Grant, User
from .security import USERNAME_RE, hash_password, password_problems
from .storage import BlobStore, load_or_create_master_key
from .validation import validate_upload

DEMO_PASSWORD = "TrustVault-demo-2026!"
DEMO_USERS = [
    ("admin", "Avery Admin", "admin"),
    ("alice", "Alice Owner (HR)", "owner"),
    ("bob", "Bob Owner (Sales)", "owner"),
    ("carol", "Carol Viewer", "viewer"),
    ("dave", "Dave Viewer", "viewer"),
]


def _setup():
    settings = Settings.from_env()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    engine = make_engine(settings.database_url)
    init_db(engine)
    return settings, engine


def create_user(args) -> int:
    settings, engine = _setup()
    username = args.username.strip().lower()
    if not USERNAME_RE.match(username) or args.role not in ROLES:
        print("Invalid username or role.", file=sys.stderr)
        return 2
    password = args.password or getpass.getpass("Password: ")
    problems = password_problems(password, username, settings.min_password_length)
    if problems:
        print(" ".join(problems), file=sys.stderr)
        return 2
    with Session(engine) as db:
        if db.execute(select(User).where(User.username == username)).first():
            print("User exists.", file=sys.stderr)
            return 1
        user = User(username=username, full_name=args.full_name or username, role=args.role,
                    password_hash=hash_password(password, settings.bcrypt_rounds))
        db.add(user)
        db.flush()
        audit.record(db, None, "user_created", actor_username="cli", target=user, details={"role": args.role})
    print(f"Created {args.role} '{username}'.")
    return 0


def seed_demo(_args) -> int:
    settings, engine = _setup()
    blobs = BlobStore(settings.data_dir / "blobs", load_or_create_master_key(settings.data_dir, settings.master_key))
    with Session(engine) as db:
        if db.execute(select(User).limit(1)).first():
            print("Database already has users; not seeding.")
            return 0
        users = {}
        for username, name, role in DEMO_USERS:
            users[username] = User(username=username, full_name=name, role=role,
                                   password_hash=hash_password(DEMO_PASSWORD, settings.bcrypt_rounds))
            db.add(users[username])
        db.flush()
        cats = {c.name: c for c in db.execute(select(Category)).scalars()}
        samples = [
            ("alice", "Salary letter - Carol", "HR", "salary-carol.txt", b"Dear Carol, your salary from 1 Jan is ...\n", [("carol", "read")]),
            ("alice", "Salary letter - Dave", "HR", "salary-dave.txt", b"Dear Dave, your salary from 1 Jan is ...\n", [("dave", "read")]),
            ("bob", "Acme master services agreement", "Contracts", "acme-msa.csv", b"clause,text\n1,Scope\n2,Fees\n", [("carol", "edit")]),
            ("bob", "Globex pricing (confidential)", "Finance", "globex-pricing.csv", b"sku,price\nA,100\nB,250\n", []),
        ]
        with audit.batch(db, None) as log:
            for owner, name, cat, filename, data, shares in samples:
                vf = validate_upload(filename, io.BytesIO(data), settings.max_upload_bytes)
                doc = Document(name=name, category_id=cats[cat].id, owner_id=users[owner].id)
                db.add(doc)
                db.flush()
                db.add(DocumentVersion(document_id=doc.id, version_no=1, original_filename=vf.filename,
                                       content_type=vf.content_type, size_bytes=vf.size, sha256=vf.sha256,
                                       storage_key=blobs.put(vf.data), uploaded_by_id=users[owner].id))
                log.add("upload", actor=users[owner], document=doc, details={"version": 1, "filename": vf.filename, "seed": True})
                for who, perm in shares:
                    db.add(Grant(document_id=doc.id, user_id=users[who].id, permission=perm, granted_by_id=users[owner].id))
                    log.add("permission_granted", actor=users[owner], document=doc, target=users[who],
                            details={"permission": perm, "seed": True})
    print("Seeded demo users (password: %s): %s" % (DEMO_PASSWORD, ", ".join(u for u, _, _ in DEMO_USERS)))
    return 0


def bootstrap(_args) -> int:
    """Container start-up hook for hosts without shell access (e.g. Render).

    TRUSTVAULT_SEED_DEMO=true seeds the demo data into an empty database.
    TRUSTVAULT_ADMIN_PASSWORD (+ optional TRUSTVAULT_ADMIN_USERNAME) creates the first admin.
    Both do nothing once users exist.
    """
    if os.environ.get("TRUSTVAULT_SEED_DEMO", "").strip().lower() in {"1", "true", "yes", "on"}:
        return seed_demo(_args)
    password = os.environ.get("TRUSTVAULT_ADMIN_PASSWORD")
    if not password:
        print("bootstrap: TRUSTVAULT_SEED_DEMO / TRUSTVAULT_ADMIN_PASSWORD not set; no users created.")
        return 0
    settings, engine = _setup()
    with Session(engine) as db:
        if db.execute(select(User).limit(1)).first():
            return 0
    username = os.environ.get("TRUSTVAULT_ADMIN_USERNAME", "admin")
    ns = argparse.Namespace(username=username, role="admin", full_name="Administrator", password=password)
    return create_user(ns)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    cu = sub.add_parser("create-user", help="Create a user (e.g. the first admin)")
    cu.add_argument("username")
    cu.add_argument("--role", choices=ROLES, default="admin")
    cu.add_argument("--full-name", default="")
    cu.add_argument("--password", help="Prompted if omitted")
    cu.set_defaults(func=create_user)
    sd = sub.add_parser("seed-demo", help="Create demo users and documents in an empty database")
    sd.set_defaults(func=seed_demo)
    bs = sub.add_parser("bootstrap", help="Seed demo data or create the first admin from environment variables")
    bs.set_defaults(func=bootstrap)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
