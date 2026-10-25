# TrustVault Runbook

How to set up, run, test and reset TrustVault on your own computer.

---

## 1. What you need

| Tool | Version | Check with |
|---|---|---|
| Python | 3.10, 3.11 or 3.12 | `python3 --version` (Windows: `py --version`) |
| Git | any | `git --version` |
| libmagic | system library used to check what a file really is | see step 3 |

Docker is optional (see section 8).

---

## 2. Get the code

```bash
git clone https://github.com/sriya-4036/trustvault.git
cd trustvault
```

---

## 3. Install libmagic (one time)

TrustVault checks the *contents* of every upload, not just its extension. That check uses libmagic.

| OS | Command |
|---|---|
| Ubuntu / Debian | `sudo apt-get install -y libmagic1` |
| Fedora | `sudo dnf install -y file-libs` |
| macOS (Homebrew) | `brew install libmagic` |
| Windows | Nothing to do. `pip` installs `python-magic-bin`, which already includes it |

---

## 4. Create a virtual environment and install dependencies

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements-dev.txt
```

**Windows (PowerShell)**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

> If PowerShell blocks the activate script, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, then try again.

Once the venv is active your prompt starts with `(.venv)`. Every command below assumes that.

---

## 5. Create users

Pick **one** of these.

### Option A: demo data (recommended the first time)

```bash
python -m app.cli seed-demo
```

This creates five users, all with the password **`TrustVault-demo-2026!`**:

| Username | Role | What you'll see |
|---|---|---|
| `admin` | admin | Admin overview, audit log, permission changes, users. Cannot open documents |
| `alice` | owner | Owns two HR salary letters, shared with carol (read) and dave (read) |
| `bob` | owner | Owns two sales documents, one shared with carol (edit) |
| `carol` | viewer | Sees only the two documents shared with her |
| `dave` | viewer | Sees only his salary letter |

### Option B: start empty with your own admin

```bash
python -m app.cli create-user admin --role admin --full-name "First Admin"
# asks for a password (at least 12 characters)
```

Sign in as that admin, open **Users**, and create owners and viewers from there.

---

## 6. Start the app

```bash
uvicorn app.main:create_app --factory --port 8000
```

Open **http://localhost:8000** and sign in.

* Add `--reload` while editing code so the server restarts on every change.
* Stop the server with `Ctrl+C`.
* To use a different port, change `--port 8000`.
* To reach it from a phone on the same Wi-Fi, add `--host 0.0.0.0` and open `http://<your-computer-ip>:8000` on the phone.

### A 2-minute tour

1. Sign in as **alice**. Open *Salary letter - Carol*: you see versions, who has access, and the access history.
2. Under *Grant access to a named person*, give **bob** `read`, then revoke it again.
3. Sign out and sign in as **carol**. She sees only her two documents. Paste the URL of one of alice's other documents: you get **"not found"**.
4. Sign in as **admin**. **Admin → Overview** shows everything you just did, including carol's denied attempt. **Verify audit chain** confirms that no audit entry has been changed.

---

## 7. Run the tests

```bash
pytest -q
```

Expected: `75 passed`. The most important file is `tests/test_access_control.py`: users who don't have access try every action on someone else's documents and must be refused. Tests use their own temporary database and never touch `./data`.

Handy variations:

```bash
pytest tests/test_access_control.py -v     # just the cross-user access tests
pytest -k revoke -v                         # tests whose name contains "revoke"
```

---

## 8. Run with Docker (optional)

```bash
docker build -t trustvault .
docker volume create tv-data

# create the first admin (or use seed-demo instead)
docker run --rm -it -v tv-data:/data trustvault python -m app.cli create-user admin --role admin
# docker run --rm -v tv-data:/data trustvault python -m app.cli seed-demo

docker run -p 8000:8000 -v tv-data:/data trustvault
```

Then open http://localhost:8000.

---

## 9. Where things are stored

Everything lives in `./data` (or `$TRUSTVAULT_DATA_DIR`):

| Path | What it is |
|---|---|
| `data/trustvault.db` | SQLite database: users, documents, grants, audit log |
| `data/blobs/` | Uploaded files, **encrypted** (AES-256-GCM) under random names |
| `data/master.key` | Encryption key, generated on first run. **Lose it and the files can't be read** |

### Start over from scratch

Stop the server, then:

```bash
rm -rf data            # Windows PowerShell: Remove-Item -Recurse -Force data
python -m app.cli seed-demo
```

---

## 10. Settings (environment variables)

All optional. Set them before starting the server, e.g. `export TRUSTVAULT_MAX_UPLOAD_BYTES=20971520` (PowerShell: `$env:TRUSTVAULT_MAX_UPLOAD_BYTES=20971520`).

| Variable | Default | Meaning |
|---|---|---|
| `TRUSTVAULT_DATA_DIR` | `./data` | Folder for database, blobs and generated key |
| `TRUSTVAULT_DATABASE_URL` | SQLite file in the data folder | SQLAlchemy URL |
| `TRUSTVAULT_MASTER_KEY` | read from or created in `data/master.key` | Base64 32-byte key. Set this in production and keep it **outside** the data folder |
| `TRUSTVAULT_COOKIE_SECURE` | `false` | `true` when served over HTTPS |
| `TRUSTVAULT_MAX_UPLOAD_BYTES` | `10485760` (10 MB) | Upload size limit |
| `TRUSTVAULT_SESSION_IDLE_MINUTES` | `30` | Sign out after this much inactivity |
| `TRUSTVAULT_SESSION_ABSOLUTE_HOURS` | `12` | Sign out after this long regardless |
| `TRUSTVAULT_MAX_FAILED_LOGINS` | `5` | Failed sign-ins before lockout |
| `TRUSTVAULT_LOCKOUT_MINUTES` | `15` | Lockout duration |

Generate a production key:

```bash
python -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

---

## 11. Troubleshooting

| Problem | Fix |
|---|---|
| `ImportError: failed to find libmagic` | Install libmagic (step 3). On macOS with Apple Silicon, also try `export DYLD_LIBRARY_PATH=/opt/homebrew/lib` |
| `python3: command not found` (Windows) | Use `py` instead of `python3` |
| `Address already in use` | Something else is on port 8000. Use `--port 8001` |
| Can't sign in after several wrong passwords (account locked) | Wait 15 minutes, or sign in as admin and click **Unlock** on the Users page |
| `Database already has users; not seeding.` | Demo data already exists. Reset with section 9 if you want fresh data |
| Downloads fail after deleting `data/master.key` | The key and the encrypted files belong together. Delete the whole `data` folder and seed again |
| Uploads rejected with "content does not match extension" | Working as designed: the file isn't what its extension says (e.g. a renamed `.exe`) |
| Logged out unexpectedly | Sessions end after 30 minutes idle or 12 hours total |
| Emoji show as boxes | Your OS has no emoji font (some minimal Linux installs). Ubuntu: `sudo apt-get install fonts-noto-color-emoji` |

---

## 12. Quick reference

```bash
source .venv/bin/activate                          # every new terminal (Windows: .\.venv\Scripts\Activate.ps1)
python -m app.cli seed-demo                        # demo users + documents
python -m app.cli create-user NAME --role owner    # add a user from the command line
uvicorn app.main:create_app --factory --port 8000  # run
pytest -q                                          # test
```
