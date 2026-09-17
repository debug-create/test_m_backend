"""
Fable — Insider-threat behavioral transition detection API.

Run:
  pip install -r requirements.txt
  uvicorn main:app --reload

OpenAPI docs: http://127.0.0.1:8000/docs
"""

from contextlib import asynccontextmanager
import asyncio
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from api.routes import router
from api.access_routes import access_router
from config import load_settings, validate_production_settings
from database import SessionLocal, init_db
from models.db_models import Entity
from seed.scenarios import run_seed
from engine.response_service import expire_due_actions


def _validate_enforcement_mode() -> str:
    settings = load_settings()
    mode = settings.enforcement_mode
    if mode not in {"sandbox", "signed_webhook"}:
        config_name = f"FABLE_CONNECTOR_{mode.upper().replace('-', '_')}_CONFIG"
        raise RuntimeError(
            f"Enforcement mode '{mode}' requires explicit {config_name} configuration"
        )
    if mode == "signed_webhook" and (
        not settings.enforcement_webhook_url or not settings.enforcement_webhook_secret
    ):
        raise RuntimeError("signed_webhook enforcement requires URL and signing secret")
    validate_production_settings(settings)
    return mode


def _needs_seed(db: Session) -> bool:
    return db.query(Entity).count() == 0


async def _response_expiry_worker() -> None:
    """Apply persisted TTLs without coupling expiry to a read request."""
    while True:
        await asyncio.sleep(5)
        db = SessionLocal()
        try:
            expire_due_actions(db)
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    if load_settings().environment != "production":
        init_db()
    db = SessionLocal()
    try:
        if _needs_seed(db):
            print("Empty database — running seed scenarios...")
            run_seed(db)
        else:
            print("Database already seeded.")
    finally:
        db.close()
    expiry_task = (
        asyncio.create_task(_response_expiry_worker())
        if load_settings().environment != "production" else None
    )
    try:
        yield
    finally:
        if expiry_task:
            expiry_task.cancel()
            try:
                await expiry_task
            except asyncio.CancelledError:
                pass


app = FastAPI(
    title="Fable",
    description=(
        "Insider-threat behavioral transition detection system. "
        "Risk assessments are versioned snapshots derived from Events and approved "
        "ContextLedgerEntry records; nothing is hardcoded per scenario."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

_validate_enforcement_mode()

# Tests/development remain self-bootstrapping. Production must run Alembic first.
if load_settings().environment != "production":
    init_db()


cors_origins = [
    item.strip() for item in os.getenv(
        "FABLE_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",") if item.strip()
]
cors_credentials = os.getenv("FABLE_CORS_ALLOW_CREDENTIALS", "false").lower() == "true"
if "*" in cors_origins and cors_credentials:
    raise RuntimeError("Credentialed CORS cannot be combined with a wildcard origin")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=cors_credentials,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(router)
app.include_router(access_router)


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "service": "fable"}
