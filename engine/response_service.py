"""Deterministic persisted response workflow.

This is a state machine rather than LangGraph: all nodes are deterministic and
the persisted action/transition records provide restart and retry safety.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import uuid
from typing import Any

from sqlalchemy.orm import Session

from config import RESPONSE_SCORING_VERSION
from engine.response_graph import (
    build_evidence_graph, preview_blast_radius, valid_scope_values,
)
from engine.response_policy import evaluate_response_policy
from engine import sandbox_enforcement
from models.db_models import (
    AuditLog, Case, Entity, Event, ResponseAction, ResponseActionTransition,
)


ALLOWED_TRANSITIONS = {
    "proposed": {"auto_authorized", "awaiting_approval", "rejected"},
    "auto_authorized": {"executing", "expired", "rejected"},
    "awaiting_approval": {"approved", "rejected"},
    "approved": {"executing", "expired"},
    "executing": {"active", "failed"},
    "active": {"expired", "rolled_back", "failed"},
    "expired": set(),
    "rolled_back": set(),
    "failed": set(),
    "rejected": set(),
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _transition(
    db: Session, action: ResponseAction, to_status: str, principal: str,
    *, note: str | None = None, details: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> None:
    if to_status not in ALLOWED_TRANSITIONS.get(action.status, set()):
        raise ValueError(f"Invalid response transition: {action.status} -> {to_status}")
    timestamp = now or utcnow()
    previous = action.status
    action.status = to_status
    db.add(ResponseActionTransition(
        action_id=action.action_id, from_status=previous, to_status=to_status,
        principal=principal, timestamp=timestamp, note=note, details=details or {},
    ))
    db.add(AuditLog(
        timestamp=timestamp, principal=principal, action=f"response.{to_status}",
        resource_type="response_action", resource_id=action.action_id,
        details={"from_status": previous, "note": note, **(details or {})},
        succeeded=to_status != "failed",
    ))
    db.flush()


def _case_payload(case: Case) -> tuple[dict[str, Any], dict[str, Any]]:
    assessments = sorted(case.assessments, key=lambda item: (item.created_at, item.id))
    current = {
        "residual_risk": case.residual_risk, "context_coverage": case.context_coverage,
        "confidence": case.confidence, "data_quality": case.data_quality,
        "retroactive_justification_review": bool(case.retroactive_justification_review),
        "event_risk_breakdown": case.event_risk_breakdown or [],
        "explanation_breakdown": case.explanation_breakdown or [],
    }
    original = (assessments[0].result or {}) if assessments else dict(current)
    return current, original


def _default_scope(db: Session, case: Case, action_type: str) -> dict[str, str]:
    events = db.query(Event).filter(Event.id.in_(case.event_ids or [-1])).order_by(
        Event.timestamp.desc(), Event.id.desc()
    ).all()
    unresolved = {
        row["event_id"] for row in (case.event_risk_breakdown or [])
        if float(row.get("context_credit", 0.0)) < 1.0
    }
    relevant = [event for event in events if event.id in unresolved] or events
    actor = db.query(Entity).filter(Entity.id == case.actor_id).one()
    if action_type == "block_external_upload":
        event = next((item for item in relevant if item.action == "external_upload" and item.destination), None)
        return {"destination": event.destination, "session": event.device_id} if event else {}
    if action_type == "freeze_privilege_change":
        event = next((item for item in relevant if item.action == "privilege_change"), None)
        return {"permission": event.resource_id or "unspecified", "session": event.device_id} if event else {}
    if action_type == "rate_limit_download":
        event = next((item for item in relevant if item.action == "file_download"), None)
        return {"resource": event.resource_id, "session": event.device_id} if event and event.resource_id else {}
    if action_type == "revoke_session":
        return {"session": relevant[0].device_id} if relevant else {}
    if action_type == "isolate_device":
        return {"device": relevant[0].device_id} if relevant else {}
    if action_type in {"disable_account", "observe"}:
        return {"entity_ref": actor.pseudonymous_id}
    if action_type == "step_up_auth":
        return {"session": relevant[0].device_id} if relevant else {}
    return {}


def preview_action(
    db: Session, case: Case, action_type: str, target_scope: dict[str, Any] | None = None,
    *, now: datetime | None = None,
) -> dict[str, Any]:
    graph = build_evidence_graph(db, case, now=now)
    scope = dict(target_scope or _default_scope(db, case, action_type))
    invalid = sorted(
        value for key, value in scope.items()
        if value not in valid_scope_values(graph)
    )
    if invalid:
        raise ValueError(f"Target identifiers are not present in case evidence: {invalid}")
    blast = preview_blast_radius(graph, scope, case.explanation_breakdown or [])
    current, original = _case_payload(case)
    existing = [{
        "action_id": item.action_id, "action_type": item.action_type,
        "target_scope": item.target_scope, "status": item.status,
    } for item in case.response_actions]
    decision = evaluate_response_policy(
        current_assessment=current, original_assessment=original,
        requested_action=action_type, target_scope=scope,
        blast_radius=blast, existing_active_actions=existing,
    )
    actor = db.query(Entity).filter(Entity.id == case.actor_id).one()
    return {
        "case_id": case.id, "entity_ref": actor.pseudonymous_id,
        "requested_action": action_type, **decision.to_dict(),
    }


def create_action(
    db: Session, case: Case, action_type: str, target_scope: dict[str, Any] | None,
    idempotency_key: str, requested_by: str, *, note: str | None = None,
    now: datetime | None = None,
) -> ResponseAction:
    existing = db.query(ResponseAction).filter(
        ResponseAction.idempotency_key == idempotency_key
    ).first()
    if existing:
        if (existing.case_id, existing.action_type, existing.requested_by) == (
            case.id, action_type, requested_by
        ):
            return existing
        raise ValueError("Idempotency key is already bound to a different request")
    timestamp = now or utcnow()
    preview = preview_action(db, case, action_type, target_scope, now=timestamp)
    action = ResponseAction(
        action_id=f"rsp_{uuid.uuid4().hex}", case_id=case.id,
        entity_ref=preview["entity_ref"], action_type=action_type, status="proposed",
        mode="sandbox", requested_by=requested_by, requested_at=timestamp,
        assessment_id=case.current_assessment_id, scoring_version=RESPONSE_SCORING_VERSION,
        trigger_event_ids=preview["trigger_event_ids"],
        policy_rule_id=preview["policy_rule_id"],
        policy_decision="allow" if preview["allow"] else "deny",
        policy_reasons=preview["reasons"],
        evidence_categories=preview["evidence_categories"],
        target_scope=preview["target_scope"], blast_radius=preview["blast_radius"],
        approval_required=preview["approval_required"], automatic=preview["automatic"],
        idempotency_key=idempotency_key,
        expires_at=(timestamp + timedelta(seconds=preview["ttl_seconds"]))
        if preview["ttl_seconds"] else None,
    )
    db.add(action)
    db.flush()
    db.add(ResponseActionTransition(
        action_id=action.action_id, from_status=None, to_status="proposed",
        principal=requested_by, timestamp=timestamp, note=note,
    ))
    if not preview["allow"]:
        _transition(db, action, "rejected", requested_by, note=note,
                    details={"policy_reasons": preview["reasons"]}, now=timestamp)
    elif preview["approval_required"]:
        _transition(db, action, "awaiting_approval", requested_by, note=note, now=timestamp)
    else:
        _transition(db, action, "auto_authorized", "response-policy",
                    details={"policy_rule_id": action.policy_rule_id}, now=timestamp)
    return action


def approve_action(
    db: Session, action: ResponseAction, approved_by: str, note: str,
    *, now: datetime | None = None,
) -> ResponseAction:
    if action.requested_by == approved_by:
        raise PermissionError("A requester cannot approve their own high-impact response")
    if action.status != "awaiting_approval":
        raise ValueError(f"Action is not awaiting approval (status={action.status})")
    timestamp = now or utcnow()
    action.approved_by = approved_by
    action.approved_at = timestamp
    _transition(db, action, "approved", approved_by, note=note, now=timestamp)
    return action


def reject_action(
    db: Session, action: ResponseAction, rejected_by: str, note: str,
    *, now: datetime | None = None,
) -> ResponseAction:
    _transition(db, action, "rejected", rejected_by, note=note, now=now)
    return action


def execute_action(
    db: Session, action: ResponseAction, principal: str, *, now: datetime | None = None,
    inject_failure: bool = False, inject_verification_failure: bool = False,
) -> ResponseAction:
    if action.status == "active":
        return action
    timestamp = now or utcnow()
    if action.status != "executing":
        _transition(db, action, "executing", principal, now=timestamp)
    try:
        result, verification = sandbox_enforcement.execute(
            db, action, now=timestamp, inject_failure=inject_failure,
            inject_verification_failure=inject_verification_failure,
        )
        action.execution_result = result
        action.verification_result = verification
        if not verification["verified"]:
            raise RuntimeError("Sandbox verification failed")
        action.executed_at = timestamp
        _transition(db, action, "active", principal, details=verification, now=timestamp)
    except Exception as exc:
        action.failed_at = timestamp
        action.failure_reason = str(exc)
        _transition(db, action, "failed", principal,
                    details={"failure_reason": str(exc)}, now=timestamp)
    return action


def rollback_action(
    db: Session, action: ResponseAction, principal: str, *, note: str | None = None,
    now: datetime | None = None,
) -> ResponseAction:
    if action.status != "active":
        raise ValueError(f"Only an active action can be rolled back (status={action.status})")
    timestamp = now or utcnow()
    action.rollback_result = sandbox_enforcement.rollback(db, action, now=timestamp)
    action.rolled_back_at = timestamp
    _transition(db, action, "rolled_back", principal, note=note, now=timestamp)
    return action


def expire_due_actions(db: Session, *, now: datetime | None = None) -> list[ResponseAction]:
    timestamp = now or utcnow()
    due = db.query(ResponseAction).filter(
        ResponseAction.status == "active",
        ResponseAction.expires_at.is_not(None),
        ResponseAction.expires_at <= timestamp,
    ).order_by(ResponseAction.action_id).all()
    for action in due:
        action.rollback_result = sandbox_enforcement.rollback(db, action, now=timestamp)
        _transition(db, action, "expired", "response-expiry", now=timestamp)
    return due
