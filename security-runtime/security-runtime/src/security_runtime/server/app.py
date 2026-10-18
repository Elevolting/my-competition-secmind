import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from security_runtime import __version__
from security_runtime.server import db
from security_runtime.server.routers import export, hints, intents, projects, settings

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.configure(db.DEFAULT_DB)
    yield


app = FastAPI(
    title="Fact Graph Service",
    description="Fact-graph based collaborative exploration protocol",
    version=__version__,
    lifespan=lifespan,
)


@app.middleware("http")
async def protect_browser_writes(request: Request, call_next):
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        origin = request.headers.get("origin")
        allowed = {str(request.base_url).rstrip("/")}
        allowed.update(
            f"http://{host}:{port}"
            for host in ("127.0.0.1", "localhost")
            for port in (5173, 8000)
        )
        allowed.update(
            value.strip() for value in os.environ.get("SECURITY_RUNTIME_ALLOWED_BROWSER_ORIGINS", "").split(",")
            if value.strip()
        )
        if origin is not None and origin not in allowed:
            return JSONResponse({"detail": "Browser origin is not allowed"}, status_code=403)
    return await call_next(request)


# Validate Host before accepting the request's own Origin, including reads.
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost"] + [
        value.strip() for value in os.environ.get("SECURITY_RUNTIME_ALLOWED_HOSTS", "").split(",")
        if value.strip()
    ],
)


app.include_router(settings.router)
app.include_router(projects.router)
app.include_router(hints.router)
app.include_router(intents.router)
app.include_router(export.router)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
