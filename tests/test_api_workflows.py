"""End-to-end authorization, approval, privacy, and snapshot checks."""

import json
import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.routes import router
from database import Base, get_db
from models.db_models import AuditLog, Case, CaseAssessment, ContextLedgerEntry, Entity
from seed.scenarios import run_seed


KEYS = {
    "view-key": {"subject": "viewer-1", "role": "viewer"},
    "propose-key": {"subject": "proposer-1", "role": "context_proposer"},
    "approve-key": {"subject": "approver-1", "role": "context_approver"},
    "analyst-key": {"subject": "analyst-1", "role": "analyst"},
    "ingest-key": {"subject": "ingestor-1", "role": "ingestor"},
    "admin-key": {"subject": "admin-1", "role": "admin"},
}


def _auth(key):
    return {"Authorization": f"Bearer {key}"}


def _client(monkeypatch):
    monkeypatch.setenv("FABLE_API_KEYS", json.dumps(KEYS))
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    run_seed(session)
    app = FastAPI()
    app.include_router(router)

    def override_db():
        yield session

    app.dependency_overrides[get_db] = override_db
    return TestClient(app), session


def test_context_requires_separate_proposal_and_approval(monkeypatch):
    client, session = _client(monkeypatch)
    actor = session.query(Entity).filter(Entity.display_name == "Arjun").one()
    case = session.query(Case).filter(Case.actor_id == actor.id).one()
    context = session.query(ContextLedgerEntry).filter(ContextLedgerEntry.actor_id == actor.id).first()
    with client:
        before = client.get(f"/cases/{case.id}", headers=_auth("view-key")).json()
        proposal = client.post(
            f"/entities/{actor.pseudonymous_id}/context",
            headers=_auth("propose-key"),
            json={
                "reason": context.reason,
                "valid_from": context.valid_from.isoformat(),
                "valid_until": context.valid_until.isoformat(),
                "allowed_resources": context.allowed_resources + ["finance-archive"],
                "allowed_actions": context.allowed_actions + ["external_upload"],
                "approved_destinations": context.approved_destinations + ["https://personal-cloud.example/upload"],
                "supersedes_id": context.id,
            },
        )
        assert proposal.status_code == 202
        assert proposal.json()["approval_state"] == "pending"
        pending = client.get(f"/cases/{case.id}", headers=_auth("view-key")).json()
        assert pending["residual_risk"] == before["residual_risk"]

        approved = client.post(
            f"/context/{proposal.json()['id']}/review",
            headers=_auth("approve-key"), json={"decision": "approved", "note": "Ticket verified"},
        )
        assert approved.status_code == 200
        after = client.get(f"/cases/{case.id}", headers=_auth("view-key")).json()
        assert after["raw_deviation"] == before["raw_deviation"]
        assert after["context_coverage"] == 1.0
        # Explained bulk-download and external-upload events retain independent
        # 25% non-suppressible contributions: noisy-OR(0.25, 0.25) = 43.75%.
        assert after["residual_risk"] == 43.75
        assert sum(1 for row in after["event_risk_breakdown"] if row["critical_floor"] == 25.0) == 2
        latest = session.query(CaseAssessment).filter(
            CaseAssessment.id == case.current_assessment_id
        ).one()
        assert proposal.json()["id"] in latest.context_entry_ids
        assert latest.trigger == "context_approved"
    session.close()


def test_case_reads_do_not_recompute_or_append_assessments(monkeypatch):
    client, session = _client(monkeypatch)
    case = session.query(Case).first()
    before = session.query(CaseAssessment).filter(CaseAssessment.case_id == case.id).count()
    with client:
        assert client.get(f"/cases/{case.id}", headers=_auth("view-key")).status_code == 200
        assert client.get(f"/cases/{case.id}", headers=_auth("view-key")).status_code == 200
    after = session.query(CaseAssessment).filter(CaseAssessment.case_id == case.id).count()
    assert after == before
    session.close()


def test_default_responses_are_pseudonymous(monkeypatch):
    client, session = _client(monkeypatch)
    with client:
        entities = client.get("/entities", headers=_auth("view-key")).json()
        cases = client.get("/cases", headers=_auth("view-key")).json()
    assert entities and "entity_ref" in entities[0]
    assert "display_name" not in entities[0]
    assert cases and "actor_ref" in cases[0]
    assert "actor_name" not in cases[0]
    session.close()


def test_unauthenticated_requests_are_rejected(monkeypatch):
    client, session = _client(monkeypatch)
    with client:
        assert client.get("/entities").status_code == 401
    session.close()


def test_viewer_cannot_write(monkeypatch):
    client, session = _client(monkeypatch)
    actor = session.query(Entity).first()
    with client:
        response = client.post(
            f"/entities/{actor.pseudonymous_id}/events", headers=_auth("view-key"),
            json={"timestamp": "2026-09-15T00:00:00Z", "device_id": "d", "action": "login"},
        )
    assert response.status_code == 403
    session.close()


def test_reseed_is_admin_only_and_disabled_by_default(monkeypatch):
    client, session = _client(monkeypatch)
    monkeypatch.delenv("FABLE_ENABLE_RESEED", raising=False)
    with client:
        assert client.post("/admin/reseed", headers=_auth("view-key")).status_code == 403
        assert client.post("/admin/reseed", headers=_auth("admin-key")).status_code == 404
    session.close()


def test_context_changes_are_audited(monkeypatch):
    client, session = _client(monkeypatch)
    actor = session.query(Entity).first()
    with client:
        response = client.post(
            f"/entities/{actor.pseudonymous_id}/context", headers=_auth("propose-key"),
            json={"reason": "project", "valid_from": "2026-09-01T00:00:00Z",
                  "valid_until": "2026-10-01T00:00:00Z", "allowed_resources": [],
                  "allowed_actions": [], "approved_destinations": None},
        )
    assert response.status_code == 202
    log = session.query(AuditLog).filter(AuditLog.action == "context.propose").one()
    assert log.principal == "proposer-1"
    session.close()


def test_approved_context_content_cannot_be_edited_in_place(monkeypatch):
    client, session = _client(monkeypatch)
    entry = session.query(ContextLedgerEntry).filter(
        ContextLedgerEntry.approval_state == "approved"
    ).first()
    entry.allowed_resources = list(entry.allowed_resources or []) + ["forbidden-mutation"]
    with pytest.raises(ValueError, match="immutable"):
        session.commit()
    session.rollback()
    session.close()
