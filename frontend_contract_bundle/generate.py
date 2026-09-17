"""Regenerate sanitized frontend recording fixtures from the real API."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import hashlib
import secrets

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api.routes import router
from database import Base, get_db
from models.db_models import Case, Entity, ResponseAction, SandboxEnforcementState
from seed.scenarios import run_seed


OUT = Path(__file__).resolve().parent
TOKENS = {
    "viewer": secrets.token_urlsafe(32),
    "operator": secrets.token_urlsafe(32),
    "approver": secrets.token_urlsafe(32),
    "admin": secrets.token_urlsafe(32),
}
KEYS = {
    TOKENS["viewer"]: {"subject": "capture-viewer", "role": "viewer"},
    TOKENS["operator"]: {"subject": "capture-operator", "role": "response_operator"},
    TOKENS["approver"]: {"subject": "capture-approver", "role": "response_approver"},
    TOKENS["admin"]: {"subject": "capture-admin", "role": "admin"},
}


def _headers(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKENS[role]}"}


def _write(name: str, value) -> None:
    (OUT / name).write_text(
        json.dumps(value, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )


def generate() -> None:
    os.environ["FABLE_API_KEYS"] = json.dumps(KEYS)
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    run_seed(db)
    # Recording fixtures use stable opaque references across regenerations.
    for entity in db.query(Entity).order_by(Entity.id):
        old_ref = entity.pseudonymous_id
        stable_ref = "ent_" + hashlib.sha256(
            f"fable-contract:{entity.display_name}".encode("utf-8")
        ).hexdigest()[:16]
        entity.pseudonymous_id = stable_ref
        db.query(ResponseAction).filter(ResponseAction.entity_ref == old_ref).update(
            {"entity_ref": stable_ref}, synchronize_session=False
        )
        db.query(SandboxEnforcementState).filter(
            SandboxEnforcementState.entity_ref == old_ref
        ).update({"entity_ref": stable_ref}, synchronize_session=False)
    db.commit()
    app = FastAPI(title="Fable", version="2.0.0")
    app.include_router(router)

    def override_db():
        yield db

    app.dependency_overrides[get_db] = override_db
    client = TestClient(app)
    _write("openapi.json", app.openapi())
    _write("typescript-friendly-schema.json", app.openapi()["components"]["schemas"])
    _write("cases.json", client.get("/cases", headers=_headers("viewer")).json())

    cases = {
        entity.display_name: case.id
        for case, entity in db.query(Case, Entity).join(Entity, Case.actor_id == Entity.id)
    }
    names = {
        "Priya": "case-priya.json",
        "Devraj Malhotra": "case-devraj.json",
        "Arjun": "case-arjun.json",
        "Neha (New Hire)": "case-neha.json",
    }
    details = {}
    for label, filename in names.items():
        details[label] = client.get(
            f"/cases/{cases[label]}", headers=_headers("viewer")
        ).json()
        _write(filename, details[label])

    arjun_id = cases["Arjun"]
    _write(
        "evidence-graph-arjun.json",
        client.get(
            f"/cases/{arjun_id}/evidence-graph", headers=_headers("viewer")
        ).json(),
    )
    devraj_id = cases["Devraj Malhotra"]
    _write(
        "response-preview.json",
        client.post(
            f"/cases/{devraj_id}/response-actions/preview",
            headers=_headers("operator"),
            json={"action_type": "rate_limit_download"},
        ).json(),
    )
    created = client.post(
        f"/cases/{devraj_id}/response-actions",
        headers=_headers("operator"),
        json={
            "action_type": "isolate_device",
            "idempotency_key": "frontend-capture-isolate-device",
            "note": "Capture: explicit high-impact response request",
        },
    )
    created.raise_for_status()
    _write("action-created.json", created.json())
    action_id = created.json()["action_id"]
    approved = client.post(
        f"/response-actions/{action_id}/approve",
        headers=_headers("approver"),
        json={"note": "Capture: independent blast-radius approval"},
    )
    approved.raise_for_status()
    _write("action-approved.json", approved.json())
    executed = client.post(
        f"/response-actions/{action_id}/execute",
        headers=_headers("operator"),
    )
    executed.raise_for_status()
    _write("action-executed.json", executed.json())
    rolled_back = client.post(
        f"/response-actions/{action_id}/rollback",
        headers=_headers("operator"),
        json={"note": "Capture: restoration verified"},
    )
    rolled_back.raise_for_status()
    _write("action-rolled-back.json", rolled_back.json())
    _write(
        "late-context-original-current.json",
        {
            "case_id": arjun_id,
            "entity_ref": details["Arjun"]["actor_ref"],
            "retroactive_justification_review": details["Arjun"][
                "retroactive_justification_review"
            ],
            "original_assessment": details["Arjun"]["original_assessment"],
            "current_assessment": details["Arjun"]["current_assessment"],
        },
    )
    _write(
        "sandbox-enforcement-state.json",
        client.get(
            "/admin/enforcement-state", headers=_headers("admin")
        ).json(),
    )
    db.close()


if __name__ == "__main__":
    generate()
