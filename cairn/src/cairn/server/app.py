from contextlib import asynccontextmanager
import hmac
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from cairn import __version__
from cairn.server import db
from cairn.server.routers import export, hints, intents, projects, settings

STATIC_DIR = Path(__file__).parent / "static"
PUBLIC_PATHS = frozenset({"/", "/health"})


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.configure(db.DEFAULT_DB)
    yield


app = FastAPI(
    title="Cairn",
    description="Fact-graph based collaborative exploration protocol",
    version=__version__,
    lifespan=lifespan,
)


@app.middleware("http")
async def admin_token_guard(request: Request, call_next):
    expected = os.environ.get("CAIRN_ADMIN_TOKEN", "").strip()
    path = request.url.path
    if expected and path not in PUBLIC_PATHS and not path.startswith("/static/"):
        auth = request.headers.get("authorization", "")
        token = ""
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        elif request.headers.get("x-cairn-token"):
            token = request.headers.get("x-cairn-token", "").strip()
        if not token or not hmac.compare_digest(token, expected):
            return JSONResponse({"detail": "Unauthorized"}, status_code=401)
    return await call_next(request)


@app.get("/health", include_in_schema=False)
def health():
    return {"ok": True, "version": __version__}


app.include_router(settings.router)
app.include_router(projects.router)
app.include_router(hints.router)
app.include_router(intents.router)
app.include_router(export.router)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
