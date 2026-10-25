import json
from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = Path(__file__).parent / "templates"

# Flash messages are chosen by key so nothing user-controlled is reflected.
MESSAGES = {
    "uploaded": ("ok", "Document uploaded."),
    "updated": ("ok", "Document details saved."),
    "version_added": ("ok", "New version uploaded."),
    "deleted": ("ok", "Document deleted. Its file contents have been destroyed; the audit trail is kept."),
    "granted": ("ok", "Access granted."),
    "grant_updated": ("ok", "Access updated."),
    "revoked": ("ok", "Access revoked. It takes effect immediately."),
    "grant_user_not_found": ("error", "No active user with that username."),
    "grant_self": ("error", "You already own this document."),
    "grant_bad_permission": ("error", "Choose read or edit."),
    "grant_bad_date": ("error", "Expiry must be a valid date in the future."),
    "delete_unconfirmed": ("error", "Tick the confirmation box to delete."),
    "password_changed": ("ok", "Password changed. Other sessions were signed out."),
    "must_change": ("warn", "You must set a new password before continuing."),
    "signed_out": ("ok", "Signed out."),
    "user_created": ("ok", "User created. They must change their password at first sign-in."),
    "user_updated": ("ok", "User updated."),
    "user_error_self": ("error", "You cannot do that to your own account."),
    "user_error_owns_docs": ("error", "This user still owns documents. Transfer them first."),
    "transferred": ("ok", "Ownership transferred."),
    "transfer_error": ("error", "Target must be an active user with the owner role."),
    "category_created": ("ok", "Category created."),
    "category_error": ("error", "Category name must be 1-64 characters and unique."),
}


def fmt_dt(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value[:19].replace("T", " ") + " UTC"
    return value.strftime("%Y-%m-%d %H:%M UTC")


def fmt_size(n: int | None) -> str:
    if n is None:
        return ""
    for unit in ("B", "KB", "MB"):
        if n < 1024 or unit == "MB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def fmt_details(details_json: str) -> list[tuple[str, str]]:
    try:
        data = json.loads(details_json or "{}")
    except ValueError:
        return [("raw", details_json)]
    return [(k, v if isinstance(v, str) else json.dumps(v, default=str)) for k, v in sorted(data.items())]


def make_templates() -> Jinja2Templates:
    t = Jinja2Templates(directory=str(TEMPLATES_DIR))
    t.env.filters["dt"] = fmt_dt
    t.env.filters["size"] = fmt_size
    t.env.filters["details"] = fmt_details
    return t


def render(request: Request, template: str, context: dict | None = None, status_code: int = 200):
    sess = getattr(request.state, "session", None)
    base = {
        "user": getattr(request.state, "user", None),
        "csrf_token": sess.csrf_token if sess else "",
        "msg": MESSAGES.get(request.query_params.get("msg", "")),
    }
    return request.app.state.templates.TemplateResponse(
        request, template, {**base, **(context or {})}, status_code=status_code
    )
