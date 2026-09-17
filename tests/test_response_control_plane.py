"""Response policy, workflow, sandbox, graph, and API guarantees."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.routes import router
from database import Base, get_db
from engine.response_graph import build_evidence_graph
from engine.response_service import (
    _transition, create_action, execute_action, expire_due_actions, preview_action,
)
from models.db_models import (
    AuditLog, Case, Entity, ResponseAction, ResponseActionTransition,
    SandboxEnforcementState,
)
from seed.scenarios import run_seed


KEYS = {
    "viewer": {"subject": "viewer", "role": "viewer"},
    "operator": {"subject": "operator-a", "role": "response_operator"},
    "operator-b": {"subject": "operator-b", "role": "response_operator"},
    "approver": {"subject": "approver-a", "role": "response_approver"},
    "same-approver": {"subject": "operator-a", "role": "response_approver"},
    "admin": {"subject": "admin", "role": "admin"},
}


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


@pytest.fixture(scope="module")
def response_env():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    run_seed(db)
    app = FastAPI()
    app.include_router(router)

    def override_db():
        yield db

    app.dependency_overrides[get_db] = override_db
    import os
    previous = os.environ.get("FABLE_API_KEYS")
    os.environ["FABLE_API_KEYS"] = json.dumps(KEYS)
    client = TestClient(app)
    yield client, db
    if previous is None:
        os.environ.pop("FABLE_API_KEYS", None)
    else:
        os.environ["FABLE_API_KEYS"] = previous
    db.close()


def case_for(db, name: str) -> Case:
    return db.query(Case).join(Entity).filter(Entity.display_name == name).one()


def action_for(db, case: Case, action_type: str) -> ResponseAction:
    return db.query(ResponseAction).filter(
        ResponseAction.case_id == case.id,
        ResponseAction.action_type == action_type,
    ).order_by(ResponseAction.requested_at).first()


def test_seeded_detection_values_are_unchanged(response_env):
    _, db = response_env
    rows = {
        entity.display_name: (case.raw_deviation, case.context_coverage, case.residual_risk)
        for case, entity in db.query(Case, Entity).join(Entity)
    }
    assert rows == {
        "Priya": (100.0, 1.0, 25.0),
        "Devraj Malhotra": (100.0, 0.0, 100.0),
        "Arjun": (100.0, 0.5905, 100.0),
        "Neha (New Hire)": (25.0, 0.0, 25.0),
    }


def test_fully_explained_activity_cannot_trigger_hold(response_env):
    _, db = response_env
    decision = preview_action(db, case_for(db, "Priya"), "block_external_upload")
    assert decision["allow"] is False
    assert decision["policy_rule_id"] == "RP-SAFETY-DENY-001"


def test_sparse_history_cannot_trigger_containment(response_env):
    _, db = response_env
    decision = preview_action(db, case_for(db, "Neha (New Hire)"), "isolate_device")
    assert decision["allow"] is False
    assert any("Sparse" in reason for reason in decision["reasons"])


def test_policy_denial_is_persisted_as_terminal_rejection(response_env):
    _, db = response_env
    action = create_action(
        db, case_for(db, "Priya"), "disable_account", None,
        "test-priya-denied-disable", "operator-a",
    )
    db.commit()
    assert action.status == "rejected"
    assert [row.to_status for row in action.transitions] == ["proposed", "rejected"]


def test_seeded_scoped_holds_and_human_gate(response_env):
    _, db = response_env
    dev = case_for(db, "Devraj Malhotra")
    hold = action_for(db, dev, "block_external_upload")
    high_impact = action_for(db, dev, "revoke_session")
    assert hold.status == "active" and hold.automatic
    assert high_impact.status == "awaiting_approval"
    assert high_impact.approval_required and not high_impact.automatic


def test_execution_is_idempotent(response_env):
    client, db = response_env
    action = action_for(db, case_for(db, "Devraj Malhotra"), "block_external_upload")
    before = len(action.transitions)
    first = client.post(f"/response-actions/{action.action_id}/execute", headers=auth("operator"))
    second = client.post(f"/response-actions/{action.action_id}/execute", headers=auth("operator"))
    assert first.status_code == second.status_code == 200
    db.expire(action)
    assert len(action.transitions) == before
    assert action.status == "active"


def test_separation_of_duties_and_approval_execution(response_env):
    client, db = response_env
    case = case_for(db, "Devraj Malhotra")
    action = create_action(
        db, case, "isolate_device", None, "test-isolate-device",
        "operator-a", note="Explicit device isolation review",
    )
    db.commit()
    denied = client.post(
        f"/response-actions/{action.action_id}/approve", headers=auth("same-approver"),
        json={"note": "self approval is forbidden"},
    )
    assert denied.status_code == 403
    approved = client.post(
        f"/response-actions/{action.action_id}/approve", headers=auth("approver"),
        json={"note": "Independent blast-radius review completed"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    executed = client.post(
        f"/response-actions/{action.action_id}/execute", headers=auth("operator-b")
    )
    assert executed.status_code == 200
    assert executed.json()["status"] == "active"
    assert executed.json()["verification_result"]["verified"] is True


def test_human_approver_can_reject(response_env):
    client, db = response_env
    action = action_for(db, case_for(db, "Devraj Malhotra"), "revoke_session")
    response = client.post(
        f"/response-actions/{action.action_id}/reject", headers=auth("approver"),
        json={"note": "Blast radius is not acceptable"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "rejected"


def test_rollback_and_terminal_transition_guard(response_env):
    client, db = response_env
    action = action_for(db, case_for(db, "Arjun"), "block_external_upload")
    response = client.post(
        f"/response-actions/{action.action_id}/rollback", headers=auth("operator"),
        json={"note": "Demo rollback verified"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "rolled_back"
    assert client.post(
        f"/response-actions/{action.action_id}/execute", headers=auth("operator")
    ).status_code == 409


def test_ttl_expiry_rolls_back_sandbox_state(response_env):
    _, db = response_env
    action = action_for(db, case_for(db, "Neha (New Hire)"), "observe")
    expired = expire_due_actions(db, now=action.expires_at + timedelta(seconds=1))
    db.commit()
    assert action in expired and action.status == "expired"
    state = db.query(SandboxEnforcementState).filter(
        SandboxEnforcementState.applied_by_action_id == action.action_id
    ).one()
    assert state.active is False


@pytest.mark.parametrize("verification_failure", [False, True])
def test_connector_and_verification_failures_are_terminal(response_env, verification_failure):
    _, db = response_env
    case = case_for(db, "Priya")
    suffix = "verify" if verification_failure else "connector"
    action = create_action(
        db, case, "step_up_auth", None, f"test-failure-{suffix}",
        "operator-a",
    )
    execute_action(
        db, action, "operator-a",
        inject_failure=not verification_failure,
        inject_verification_failure=verification_failure,
    )
    db.commit()
    assert action.status == "failed"
    assert action.failure_reason


def test_duplicate_request_reuses_same_action(response_env):
    _, db = response_env
    case = case_for(db, "Priya")
    first = create_action(db, case, "observe", None, "test-idempotent-create", "operator-a")
    db.commit()
    second = create_action(db, case, "observe", None, "test-idempotent-create", "operator-a")
    assert second.action_id == first.action_id


def test_restart_from_executing_state_is_safe(response_env):
    _, db = response_env
    case = case_for(db, "Neha (New Hire)")
    action = create_action(
        db, case, "step_up_auth", None, "test-restart-executing", "operator-a"
    )
    _transition(db, action, "executing", "operator-a")
    db.commit()
    execute_action(db, action, "operator-b")
    db.commit()
    assert action.status == "active"
    assert action.verification_result["verified"] is True


def test_graph_is_deterministic_and_isolated(response_env):
    _, db = response_env
    arjun = case_for(db, "Arjun")
    fixed = datetime(2026, 9, 16, tzinfo=timezone.utc)
    one = build_evidence_graph(db, arjun, now=fixed)
    two = build_evidence_graph(db, arjun, now=fixed)
    assert one == two
    labels = {node["label"] for node in one["nodes"]}
    assert "https://personal-cloud.example/upload" in labels
    assert "http://exfil.evil.example/drop" not in labels
    assert isinstance(one["cycles"], list)
    assert one["evidence_paths"]


def test_invalid_cross_case_target_is_rejected(response_env):
    client, db = response_env
    arjun = case_for(db, "Arjun")
    response = client.post(
        f"/cases/{arjun.id}/response-actions/preview", headers=auth("operator"),
        json={
            "action_type": "block_external_upload",
            "target_scope": {"destination": "http://exfil.evil.example/drop"},
        },
    )
    assert response.status_code == 422


def test_preview_and_reads_do_not_mutate(response_env):
    client, db = response_env
    case = case_for(db, "Devraj Malhotra")
    before_actions = db.query(ResponseAction).count()
    before_audit = db.query(AuditLog).count()
    before_transitions = db.query(ResponseActionTransition).count()
    assert client.post(
        f"/cases/{case.id}/response-actions/preview", headers=auth("operator"),
        json={"action_type": "rate_limit_download"},
    ).status_code == 200
    assert client.get(
        f"/cases/{case.id}/response-actions", headers=auth("viewer")
    ).status_code == 200
    assert client.get(
        f"/cases/{case.id}/evidence-graph", headers=auth("viewer")
    ).status_code == 200
    assert (db.query(ResponseAction).count(), db.query(AuditLog).count(),
            db.query(ResponseActionTransition).count()) == (
        before_actions, before_audit, before_transitions
    )


def test_response_rbac_and_admin_state(response_env):
    client, db = response_env
    case = case_for(db, "Devraj Malhotra")
    assert client.post(
        f"/cases/{case.id}/response-actions/preview", headers=auth("viewer"),
        json={"action_type": "observe"},
    ).status_code == 403
    assert client.get("/admin/enforcement-state", headers=auth("viewer")).status_code == 403
    state = client.get("/admin/enforcement-state", headers=auth("admin"))
    assert state.status_code == 200
    assert state.json()["mode"] == "sandbox"


def test_non_sandbox_mode_is_refused(monkeypatch):
    from main import _validate_enforcement_mode

    monkeypatch.setenv("FABLE_ENFORCEMENT_MODE", "entra")
    monkeypatch.delenv("FABLE_CONNECTOR_ENTRA_CONFIG", raising=False)
    with pytest.raises(RuntimeError, match="requires explicit"):
        _validate_enforcement_mode()


def test_every_mutation_has_audit_and_transition_history(response_env):
    _, db = response_env
    actions = db.query(ResponseAction).all()
    assert actions
    for action in actions:
        assert action.transitions
        assert db.query(AuditLog).filter(
            AuditLog.resource_id == action.action_id
        ).count() >= 1


def test_late_context_history_preserves_original(response_env):
    client, db = response_env
    case = case_for(db, "Arjun")
    detail = client.get(f"/cases/{case.id}", headers=auth("viewer")).json()
    assert detail["retroactive_justification_review"] is True
    assert detail["original_assessment"]["id"] != detail["current_assessment"]["id"]
    assert detail["current_assessment"]["residual_risk"] == 100.0
