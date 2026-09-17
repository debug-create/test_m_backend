"""Adversarial API and persistence tests added by the reinforcement pass."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib
import json
import os
import subprocess
import sys

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.routes import router
from database import Base, get_db
from engine.case_builder import recompute_case
from engine.context import evaluate_context_compatibility
from models.db_models import AuditLog, Case, CaseAssessment, CaseEvent, ContextLedgerEntry, Entity, Event


NOW = datetime(2026, 9, 15, tzinfo=timezone.utc)
KEYS = {
    "viewer": {"subject": "viewer", "role": "viewer"},
    "proposer": {"subject": "shared-user", "role": "context_proposer"},
    "same-reviewer": {"subject": "shared-user", "role": "context_approver"},
    "reviewer": {"subject": "independent-reviewer", "role": "context_approver"},
    "analyst": {"subject": "analyst", "role": "analyst"},
    "ingestor": {"subject": "pipeline", "role": "ingestor"},
    "admin": {"subject": "admin", "role": "admin"},
    "expired": {"subject": "old-user", "role": "viewer", "expires_at": "2020-01-01T00:00:00Z"},
    "bad-role": {"subject": "broken", "role": "does_not_exist"},
}


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def make_client(monkeypatch, *, with_case: bool = True):
    monkeypatch.setenv("FABLE_API_KEYS", json.dumps(KEYS))
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    actor = Entity(display_name="Internal Name", role="engineering", department="Engineering", hire_date=NOW - timedelta(days=365))
    session.add(actor)
    session.flush()
    # Give baseline computation enough causal history.
    for day in range(20):
        session.add(Event(actor_id=actor.id, timestamp=NOW - timedelta(days=30-day), device_id="known", action="login", result="success"))
    event = Event(actor_id=actor.id, timestamp=NOW - timedelta(hours=2), device_id="known", action="file_access", resource_id="repo", resource_classification="internal", result="success")
    session.add(event)
    session.flush()
    case = None
    if with_case:
        case = Case(actor_id=actor.id, created_at=event.timestamp, status="open", event_ids=[event.id])
        session.add(case)
        session.commit()
        recompute_case(session, case, trigger="test_setup")
    else:
        session.commit()
    app = FastAPI()
    app.include_router(router)

    def override_db():
        yield session

    app.dependency_overrides[get_db] = override_db
    return TestClient(app), session, actor, case, event


def proposal_body(**overrides):
    body = {
        "reason": "project",
        "valid_from": (NOW - timedelta(days=1)).isoformat(),
        "valid_until": (NOW + timedelta(days=1)).isoformat(),
        "allowed_resources": ["repo"],
        "allowed_actions": ["file_access"],
        "approved_destinations": None,
    }
    body.update(overrides)
    return body


def test_same_subject_cannot_propose_and_approve(monkeypatch):
    client, session, actor, _, _ = make_client(monkeypatch)
    with client:
        proposal = client.post(f"/entities/{actor.pseudonymous_id}/context", headers=auth("proposer"), json=proposal_body())
        response = client.post(f"/context/{proposal.json()['id']}/review", headers=auth("same-reviewer"), json={"decision": "approved"})
    assert proposal.status_code == 202
    assert response.status_code == 403
    session.close()


@pytest.mark.parametrize("path,payload", [
    ("/entities/{ref}/events", {"timestamp": NOW.isoformat(), "device_id": "d", "action": "login"}),
    ("/entities/{ref}/context", proposal_body()),
    ("/cases/{case}/feedback", {"verdict": "authorized", "notes": "reviewed"}),
    ("/admin/reseed", None),
])
def test_viewer_is_denied_on_every_write_surface(monkeypatch, path, payload):
    client, session, actor, case, _ = make_client(monkeypatch)
    url = path.format(ref=actor.pseudonymous_id, case=case.id)
    with client:
        response = client.post(url, headers=auth("viewer"), json=payload)
    assert response.status_code == 403
    session.close()


@pytest.mark.parametrize("header,expected", [
    ({"Authorization": "Bearer expired"}, 401),
    ({"Authorization": "NotBearer viewer"}, 401),
    ({"Authorization": "Bearer not-configured"}, 401),
    ({"Authorization": "Bearer bad-role"}, 503),
])
def test_expired_malformed_and_unconfigured_credentials_fail_cleanly(monkeypatch, header, expected):
    client, session, _, _, _ = make_client(monkeypatch, with_case=False)
    with client:
        response = client.get("/entities", headers=header)
    assert response.status_code == expected
    assert response.status_code < 500 or response.status_code == 503
    session.close()


def test_case_assessment_is_immutable_and_api_history_stays_unchanged(monkeypatch):
    client, session, _, case, _ = make_client(monkeypatch)
    original = session.query(CaseAssessment).filter(CaseAssessment.id == case.current_assessment_id).one()
    original_result = dict(original.result)
    original.result = {"residual_risk": 999}
    with pytest.raises(ValueError, match="append-only"):
        session.commit()
    session.rollback()
    with client:
        response = client.get(f"/cases/{case.id}", headers=auth("viewer"))
    assert response.status_code == 200
    assert response.json()["residual_risk"] == original_result["residual_risk"]
    session.close()


def test_event_reassessment_appends_instead_of_editing(monkeypatch):
    client, session, actor, case, _ = make_client(monkeypatch)
    context = ContextLedgerEntry(actor_id=actor.id, reason="project", valid_from=NOW-timedelta(days=1), valid_until=NOW+timedelta(days=1), allowed_resources=["repo"], allowed_actions=["file_access"], approved_destinations=None, approved_by="manager")
    session.add(context)
    session.flush()
    case.status = "resolved"
    case.matched_context_ids = [context.id]
    session.commit()
    ids_before = [row.id for row in session.query(CaseAssessment).filter(CaseAssessment.case_id == case.id).all()]
    with client:
        response = client.post(f"/entities/{actor.pseudonymous_id}/events", headers=auth("ingestor"), json={"timestamp": NOW.isoformat(), "device_id": "unknown", "action": "file_access", "resource_id": "outside", "resource_classification": "critical"})
    ids_after = [row.id for row in session.query(CaseAssessment).filter(CaseAssessment.case_id == case.id).all()]
    assert response.status_code == 201
    assert ids_after[:len(ids_before)] == ids_before
    assert len(ids_after) == len(ids_before) + 1
    session.close()


def test_context_supersession_and_reassessment_scope(monkeypatch):
    client, session, actor, case_overlap, event_overlap = make_client(monkeypatch)
    old = ContextLedgerEntry(actor_id=actor.id, reason="project", valid_from=NOW-timedelta(days=1), valid_until=NOW+timedelta(days=1), allowed_resources=["repo"], allowed_actions=["file_access"], approved_destinations=None, approved_by="manager")
    outside_event = Event(actor_id=actor.id, timestamp=NOW-timedelta(days=100), device_id="known", action="file_access", resource_id="archive", resource_classification="internal", result="success")
    session.add_all([old, outside_event])
    session.flush()
    case_outside = Case(actor_id=actor.id, created_at=outside_event.timestamp, status="resolved", event_ids=[outside_event.id])
    session.add(case_outside)
    session.commit()
    recompute_case(session, case_outside, trigger="test_setup")
    before_overlap = session.query(CaseAssessment).filter(CaseAssessment.case_id == case_overlap.id).count()
    before_outside = session.query(CaseAssessment).filter(CaseAssessment.case_id == case_outside.id).count()
    with client:
        proposal = client.post(f"/entities/{actor.pseudonymous_id}/context", headers=auth("proposer"), json=proposal_body(supersedes_id=old.id, allowed_resources=["repo", "new-repo"]))
        review = client.post(f"/context/{proposal.json()['id']}/review", headers=auth("reviewer"), json={"decision": "approved", "note": "verified"})
    session.refresh(old)
    latest = session.query(CaseAssessment).filter(CaseAssessment.case_id == case_overlap.id).order_by(CaseAssessment.id.desc()).first()
    assert review.status_code == 200
    assert old.approval_state == "superseded"
    assert latest.context_entry_ids == [proposal.json()["id"]]
    assert session.query(CaseAssessment).filter(CaseAssessment.case_id == case_overlap.id).count() == before_overlap + 1
    assert session.query(CaseAssessment).filter(CaseAssessment.case_id == case_outside.id).count() == before_outside
    session.close()


def test_reseed_requires_flag_and_admin_and_preserves_audit(monkeypatch):
    client, session, _, _, _ = make_client(monkeypatch, with_case=False)
    session.add(AuditLog(principal="before", action="sentinel", resource_type="test", details={}))
    session.commit()
    monkeypatch.delenv("FABLE_ENABLE_RESEED", raising=False)
    with client:
        assert client.post("/admin/reseed", headers=auth("admin")).status_code == 404
        monkeypatch.setenv("FABLE_ENABLE_RESEED", "true")
        assert client.post("/admin/reseed", headers=auth("viewer")).status_code == 403
        response = client.post("/admin/reseed", headers=auth("admin"))
    assert response.status_code == 200
    assert session.query(AuditLog).filter(AuditLog.action == "sentinel").count() == 1
    assert session.query(AuditLog).filter(AuditLog.action == "admin.reseed").count() == 1
    session.close()


def test_wildcard_credentialed_cors_refuses_startup(tmp_path):
    env = dict(os.environ)
    env["FABLE_CORS_ORIGINS"] = "*"
    env["FABLE_CORS_ALLOW_CREDENTIALS"] = "true"
    result = subprocess.run([sys.executable, "-c", "import main"], cwd=os.getcwd(), env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert "Credentialed CORS" in result.stderr


def test_non_allowlisted_cors_preflight_is_rejected(monkeypatch):
    monkeypatch.setenv("FABLE_CORS_ORIGINS", "https://allowed.example")
    monkeypatch.setenv("FABLE_CORS_ALLOW_CREDENTIALS", "false")
    import main
    importlib.reload(main)
    with TestClient(main.app) as client:
        response = client.options("/entities", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.parametrize("payload", [
    {"reason": "'; DROP TABLE entities;--", "valid_from": NOW.isoformat(), "valid_until": (NOW+timedelta(days=1)).isoformat()},
    {"reason": "project", "valid_from": NOW.isoformat()},
    {"reason": "project", "valid_from": "not-a-date", "valid_until": (NOW+timedelta(days=1)).isoformat()},
    {"reason": "project", "valid_from": NOW.isoformat(), "valid_until": (NOW+timedelta(days=1)).isoformat(), "allowed_resources": ["x" * 5000]},
    {"reason": "project", "valid_from": NOW.isoformat(), "valid_until": (NOW+timedelta(days=1)).isoformat(), "unexpected": "x" * 5000},
])
def test_malformed_and_oversized_context_payloads_return_4xx(monkeypatch, payload):
    client, session, actor, _, _ = make_client(monkeypatch, with_case=False)
    with client:
        response = client.post(f"/entities/{actor.pseudonymous_id}/context", headers=auth("proposer"), json=payload)
    assert 400 <= response.status_code < 500
    session.close()


@pytest.mark.parametrize("note", ["x" * 10000, "reviewed'; DROP TABLE cases;--"])
def test_adversarial_feedback_notes_return_4xx(monkeypatch, note):
    client, session, _, case, _ = make_client(monkeypatch)
    with client:
        response = client.post(f"/cases/{case.id}/feedback", headers=auth("analyst"), json={"verdict": "authorized", "notes": note})
    assert 400 <= response.status_code < 500
    session.close()


def test_context_created_before_event_is_not_late(monkeypatch):
    client, session, actor, _, event = make_client(monkeypatch)
    entry = ContextLedgerEntry(
        actor_id=actor.id, reason="project",
        valid_from=event.timestamp-timedelta(days=1), valid_until=event.timestamp+timedelta(days=1),
        effective_from=event.timestamp-timedelta(days=1), effective_until=event.timestamp+timedelta(days=1),
        allowed_resources=["repo"], allowed_actions=["file_access"],
        approved_destinations=None, approved_by="prior-approver",
        proposed_at=event.timestamp-timedelta(days=2), reviewed_at=event.timestamp-timedelta(hours=2),
    )
    session.add(entry); session.commit()
    result = evaluate_context_compatibility(session, actor.id, [event], as_of=event.timestamp)
    assert result["breakdown"][0]["match_details"]["late_context"] is False
    session.close()


def test_late_context_marks_retroactive_review_and_preserves_original(monkeypatch):
    client, session, actor, case, _ = make_client(monkeypatch)
    original = session.query(CaseAssessment).filter(CaseAssessment.id == case.current_assessment_id).one()
    original_result = dict(original.result)
    with client:
        proposal = client.post(
            f"/entities/{actor.pseudonymous_id}/context", headers=auth("proposer"),
            json=proposal_body(),
        )
        review = client.post(
            f"/context/{proposal.json()['id']}/review", headers=auth("reviewer"),
            json={"decision": "approved", "note": "retroactive ticket"},
        )
        detail = client.get(f"/cases/{case.id}", headers=auth("viewer")).json()
    session.refresh(original)
    assert review.status_code == 200
    assert review.json()["late_context"] is True
    assert detail["retroactive_justification_review"] is True
    assert detail["original_assessment"]["id"] == original.id
    assert detail["original_assessment"]["context_coverage"] == original_result["context_coverage"]
    assert detail["current_assessment"]["id"] != original.id
    assert original.result == original_result
    session.close()
