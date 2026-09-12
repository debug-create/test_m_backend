"""
Fable — Insider-threat behavioral transition detection API.

Run:
  pip install -r requirements.txt
  uvicorn main:app --reload

OpenAPI docs: http://127.0.0.1:8000/docs
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from api.routes import router
from database import SessionLocal, init_db
from models.db_models import Entity
from seed.scenarios import clear_all, run_seed


def _needs_seed(db: Session) -> bool:
    return db.query(Entity).count() == 0


@asynccontextmanager
async def lifespan(app: FastAPI):
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
    yield


app = FastAPI(
    title="Fable",
    description=(
        "Insider-threat behavioral transition detection system. "
        "All risk numbers are computed live from Events + ContextLedgerEntry "
        "via modules 2–6 — nothing is hardcoded per scenario."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Ensure tables exist even if lifespan hasn't run yet (e.g. some test clients)
init_db()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "service": "fable"}


@app.post("/admin/reseed", tags=["meta"])
def reseed():
    """Wipe and re-seed demo data (dev only)."""
    db = SessionLocal()
    try:
        clear_all(db)
        run_seed(db)
        return {"status": "reseeded"}
    finally:
        db.close()
