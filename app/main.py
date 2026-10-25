from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import sessionmaker
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import Settings
from .db import init_db, make_engine
from .deps import LoginRequired, PasswordChangeRequired
from .routes import admin, auth, documents
from .storage import BlobStore, load_or_create_master_key
from .web import make_templates, render

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self'; style-src 'self'; script-src 'none'; "
    "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    engine = make_engine(settings.database_url)
    init_db(engine)

    app = FastAPI(title="TrustVault", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.engine = engine
    app.state.SessionLocal = sessionmaker(engine, expire_on_commit=False)
    app.state.blobs = BlobStore(settings.data_dir / "blobs", load_or_create_master_key(settings.data_dir, settings.master_key))
    app.state.templates = make_templates()

    max_body = settings.max_upload_bytes + 1024 * 1024

    @app.middleware("http")
    async def guard(request: Request, call_next):
        length = request.headers.get("content-length")
        if length and (not length.isdigit() or int(length) > max_body):
            return Response("Request too large", status_code=413)
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if settings.cookie_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if not request.url.path.startswith("/static/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc: LoginRequired):
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(PasswordChangeRequired)
    async def _pw_change(request: Request, exc: PasswordChangeRequired):
        return RedirectResponse("/account/password?msg=must_change", status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        detail = exc.detail if exc.status_code in (403, 404, 413) else "Something went wrong."
        if exc.status_code == 404 and detail == "Not Found":
            detail = "Page not found."
        return render(request, "error.html", {"status": exc.status_code, "detail": detail}, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError):
        return render(request, "error.html", {"status": 400, "detail": "The request was malformed."}, status_code=400)

    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
    app.include_router(auth.router)
    app.include_router(documents.router)
    app.include_router(admin.router)
    return app
