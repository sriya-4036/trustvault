# TrustVault

Secure document sharing with a real audit trail. The wrong person cannot reach a document, and you can prove exactly who did.

Stack: Python 3.10+, FastAPI, SQLAlchemy 2, SQLite, server-rendered Jinja2 (no JavaScript), pytest.

## Run it

Step-by-step setup for Windows, macOS and Linux, deploying to Render for a public link, and troubleshooting: see **[RUNBOOK.md](RUNBOOK.md)**.

```bash
sudo apt-get install -y libmagic1            # used to sniff uploaded content
pip install -r requirements-dev.txt

# Option A: demo data (admin, alice, bob, carol, dave; password TrustVault-demo-2026!)
python -m app.cli seed-demo
# Option B: just a first administrator
python -m app.cli create-user admin --role admin --full-name "First Admin"

uvicorn app.main:create_app --factory --port 8000
pytest -q                                     # 75 tests
```

Docker: `docker build -t trustvault . && docker run -p 8000:8000 -v tv:/data -e TRUSTVAULT_MASTER_KEY=... trustvault`
(create the first user with `docker run --rm -v tv:/data trustvault python -m app.cli create-user admin --role admin`).

| Variable | Default | Meaning |
|---|---|---|
| `TRUSTVAULT_DATA_DIR` | `./data` | SQLite DB, encrypted blobs, generated dev key |
| `TRUSTVAULT_MASTER_KEY` | generated into `data/master.key` | urlsafe-base64 32-byte AES key. Set it in production and keep it out of the data volume |
| `TRUSTVAULT_COOKIE_SECURE` | `false` | Set `true` behind HTTPS (also enables HSTS) |
| `TRUSTVAULT_MAX_UPLOAD_BYTES` | 10 MB | Upload size limit |
| `TRUSTVAULT_SESSION_IDLE_MINUTES` / `_ABSOLUTE_HOURS` | 30 / 12 | Session lifetime |
| `TRUSTVAULT_MAX_FAILED_LOGINS` / `_LOCKOUT_MINUTES` | 5 / 15 | Account lockout |

## Roles

Access to a document comes from ownership or a named grant on that document. Nothing else: no folders, no inherited access, no public links, no admin override.

| Capability | Admin | Owner | Viewer |
|---|:-:|:-:|:-:|
| Sign in, change own password | yes | yes | yes |
| Upload new documents | no | yes | no |
| Read/download a document | only if granted | own + granted | only if granted |
| Edit details / upload new version | only if granted *edit* | own + granted *edit* | only if granted *edit* |
| Grant / change / revoke access, delete | no | own documents only | no |
| See who has access and the access history of a document | all documents (metadata only) | own documents | no |
| Create users, change roles, deactivate, reset passwords, unlock | yes | no | no |
| Transfer ownership (e.g. when someone leaves) | yes | no | no |
| Audit log, permission changes, CSV export, chain verification | yes | no | no |

Grant levels on a single document:

* **read**: view details, download any version.
* **edit**: read, plus rename/re-categorise/describe and upload new versions. Editors cannot delete, share, or see the access list.
* **owner** (not grantable): everything, including sharing, revoking and deleting.

Grants can carry an expiry date; expired grants stop working immediately and are shown struck through.

Design decisions:

* **Admins cannot read content.** They run the system and audit it, but opening a salary letter needs the owner to share it, which is itself audited. This separates duties: whoever manages accounts cannot quietly read the files.
* **No folder permissions.** Organising uses categories and search, which never grant access. That way, giving someone one file never gives them forty.
* **Leaving the company.** Deactivating a user ends their sessions and revokes every grant they hold, one audit event per grant. Reactivating does not bring old access back. Admins transfer the leaver's documents to another owner. An owner who still owns documents cannot be demoted.
* **Deleting** destroys the encrypted content of every version and removes all grants. The document's metadata and its whole audit trail stay, so the record of who read it survives the file.

## Security model

| Threat | Control | Where |
|---|---|---|
| Reading, changing or deleting someone else's document (IDOR) | Every document route calls `authz.load_document(ctx, id, need)`, the only place permissions are decided. It returns the **same 404** whether the document doesn't exist or you aren't allowed to see it, and records an `access_denied` event | `app/authz.py` |
| Revoking a grant on a different document | Grant must belong to the document in the URL | `routes/documents.py: revoke_access` |
| Search leaking titles | Search query joins only owned documents or active grants for the caller; `%`/`_` are escaped | `app/search.py` |
| Stale access (leavers, old links) | No share links. Every request re-checks session, `is_active`, and grant expiry | `deps.py`, `authz.py` |
| Session theft or fixation | 256-bit random token; only its SHA-256 is stored; new session at login; HttpOnly, SameSite=Lax, optional Secure; idle and absolute expiry; server-side logout; password change and admin reset end other sessions | `deps.py`, `routes/auth.py` |
| CSRF | Per-session token on every POST (constant-time compare); double-submit token on the login form | `deps.check_csrf` |
| Password guessing | bcrypt (SHA-256 pre-hash, so long passphrases aren't truncated); lockout after 5 failures; identical error and timing for unknown users; minimum 12 characters; admin-set passwords must be changed at first sign-in | `security.py` |
| Malicious uploads | Extension allowlist; libmagic content sniffing must match the extension; UTF-8/no-NUL text; PDFs with JavaScript/Launch/EmbeddedFile rejected; OOXML structure checked, macros (`vbaProject.bin`) and zip bombs rejected; size limit enforced on the request and while reading; file names normalised and stripped of paths/control characters | `app/validation.py` |
| Stored XSS / content sniffing | Jinja autoescape; CSP `script-src 'none'`; downloads are `Content-Disposition: attachment` with `nosniff` and a sandbox CSP | `main.py`, `routes/documents.py` |
| Disk or backup theft | Blobs encrypted with AES-256-GCM under random 128-bit names; the storage key is bound as associated data; SHA-256 checked on every download | `app/storage.py` |
| Tampering with the audit trail | See below | `app/audit.py` |

### Audit trail

Recorded: sign-in (success, failure, lockout), sign-out, password changes; upload, view, download, metadata change (old and new values), new version, delete, rejected upload; grant, permission change (from/to), revoke, ownership transfer; user created, role changed, deactivated/reactivated, password reset, unlocked; every denied access attempt and CSRF rejection; audit export and verification. Each event stores time (UTC, microseconds), actor and role, document id and name, target user, details (JSON), IP and user agent. File contents are never written to the log.

Why it holds up as evidence:

1. **Atomic with the action.** `audit.record()` is the commit point, so an action and its audit event are saved together or not at all. A download is logged before any bytes are sent.
2. **Append-only.** SQLite triggers reject `UPDATE` and `DELETE` on `audit_events`.
3. **Hash-chained.** Each event stores `sha256(contents + previous hash)`. **Admin → Verify audit chain** recomputes the whole chain and names the first event that was changed, removed or reordered. To also catch events cut off the end, record the chain head shown there somewhere outside TrustVault.
4. **Denormalised.** Actor and document names are copied into the event, so the trail stays readable after users or documents change or are deleted.

Admin views: an overview with counters and recent activity, permission changes and denied attempts; a filterable, paginated audit log (by action or group, actor, target user, document, outcome, date) with CSV export (cells starting with `=+-@` are prefixed to block spreadsheet formula injection); permission-change history plus every current grant; every document's metadata, access list and full history.

## Tests

`pytest -q` runs 75 tests. The key file is `tests/test_access_control.py`:

* every user without access (another owner, a viewer, the admin) tries **every** document operation (view, download current and old versions, edit form, edit, new version, delete, grant, revoke). Each must return 404, must not leak the content or the title, and must leave the document, its versions, grants and encrypted blobs unchanged;
* readers cannot edit, share or delete; editors cannot share or delete;
* revocation, expiry, deactivation, deletion and ownership transfer take effect on the very next request;
* a grant id from another document can't be revoked through your own document;
* search under every filter returns only documents you can access;
* viewers cannot upload; non-admins get 403 on every admin page and action; anonymous users are sent to login.

To check that these tests really catch problems, I broke the owner check in `authz.py` on purpose: 15 of the access-control tests failed.

Other files: `test_audit.py` (full lifecycle trail, denied attempts, append-only triggers, detecting modified and removed events, admin views, CSV injection), `test_auth.py` (lockout, CSRF, session hashing, expiry, logout, forced password change, headers, XSS escaping), `test_upload_validation.py`.

## Limitations and next steps

* The audit chain is serialised with an in-process lock, so run **one worker** (as the Dockerfile does). Running several workers would need a database lock such as a Postgres advisory lock.
* SQLite fits one node. Moving to Postgres only needs `TRUSTVAULT_DATABASE_URL`, plus re-creating the append-only triggers in Postgres syntax.
* Not built yet: SSO/MFA, malware scanning (ClamAV hook), key rotation, legal hold and retention policies, periodic export of the chain head to WORM storage.
