from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import uuid
from typing import Any

from sqlalchemy.orm import Session

from access_control.audit import append_audit
from access_control.outbox import enqueue
from access_control.policy import POLICY_VERSION, evaluate_access_policy
from models.db_models import (
    AccessEvidence, AccessGrant, AccessNotification, AccessRequest,
    AccessRequestTransition, ApprovalDecision, Case, ResponseAction,
)


ALLOWED_TRANSITIONS = {
    "PAUSED": {"EVIDENCE_READY", "MORE_CONTEXT_REQUIRED", "DENIED"},
    "EVIDENCE_READY": {
        "AI_REVIEW_PENDING", "MORE_CONTEXT_REQUIRED", "AWAITING_APPROVAL", "DENIED",
    },
    "AI_REVIEW_PENDING": {"AI_REVIEWED", "MORE_CONTEXT_REQUIRED", "DENIED"},
    "AI_REVIEWED": {"MORE_CONTEXT_REQUIRED", "AWAITING_APPROVAL", "DENIED"},
    "MORE_CONTEXT_REQUIRED": {"EVIDENCE_READY", "DENIED"},
    "AWAITING_APPROVAL": {"APPROVED", "MORE_CONTEXT_REQUIRED", "DENIED"},
    "APPROVED": {"ENFORCING"},
    "ENFORCING": {"ACTIVE", "ENFORCEMENT_FAILED"},
    "ACTIVE": {"REVOKING", "EXPIRED"},
    "REVOKING": {"REVOKED", "ENFORCEMENT_FAILED"},
    "DENIED": set(), "REVOKED": set(), "EXPIRED": set(),
    "ENFORCEMENT_FAILED": {"REVOKING"},
}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def transition(
    db: Session, request: AccessRequest, state: str, actor: str,
    *, reason: str | None = None, metadata: dict[str, Any] | None = None,
    correlation_id: str | None = None, now: datetime | None = None,
) -> None:
    if state not in ALLOWED_TRANSITIONS.get(request.workflow_state, set()):
        raise ValueError(f"Invalid access transition: {request.workflow_state} -> {state}")
    timestamp = now or now_utc()
    prior = request.workflow_state
    request.workflow_state = state
    request.external_status = {
        "PAUSED": "paused", "ACTIVE": "active", "DENIED": "denied",
        "REVOKED": "revoked", "EXPIRED": "expired",
        "ENFORCEMENT_FAILED": "enforcement_failed",
    }.get(state, "in_review")
    request.updated_at = timestamp
    request.version += 1
    if state in {"DENIED", "REVOKED", "EXPIRED"}:
        request.resolved_at = timestamp
    db.add(AccessRequestTransition(
        request_id=request.id, tenant_id=request.tenant_id,
        from_state=prior, to_state=state, actor=actor, timestamp=timestamp,
        reason=reason, metadata_json=metadata or {},
    ))
    append_audit(
        db, tenant_id=request.tenant_id, actor=actor,
        action=f"access.state.{state.lower()}", aggregate_type="access_request",
        aggregate_id=request.id, correlation_id=correlation_id or uuid.uuid4().hex,
        details={"from_state": prior, "reason": reason, **(metadata or {})},
        now=timestamp,
    )


def notify(
    db: Session, request: AccessRequest, notification_type: str,
    recipient: str, message: str,
) -> AccessNotification:
    row = AccessNotification(
        id=f"ntf_{uuid.uuid4().hex}", tenant_id=request.tenant_id,
        recipient=recipient, notification_type=notification_type,
        request_id=request.id, message=message,
    )
    db.add(row)
    enqueue(
        db, tenant_id=request.tenant_id, aggregate_type="access_request",
        aggregate_id=request.id, job_type="NOTIFICATION",
        payload={"notification_id": row.id},
        deduplication_key=f"notify:{row.id}",
    )
    return row


def create_request(
    db: Session, *, tenant_id: str, requester: str, payload: dict[str, Any],
    idempotency_key: str, is_admin: bool,
) -> AccessRequest:
    existing = db.query(AccessRequest).filter(
        AccessRequest.tenant_id == tenant_id,
        AccessRequest.idempotency_key == idempotency_key,
    ).first()
    if existing:
        return existing
    if payload.get("break_glass") and not is_admin:
        raise PermissionError("Break-glass requests require an admin")
    request = AccessRequest(
        id=f"arq_{uuid.uuid4().hex}", tenant_id=tenant_id,
        requester_identity=requester, idempotency_key=idempotency_key,
        external_status="paused", workflow_state="PAUSED", **payload,
    )
    db.add(request)
    db.flush()
    db.add(AccessRequestTransition(
        request_id=request.id, tenant_id=tenant_id, from_state=None,
        to_state="PAUSED", actor=requester, reason="Access is paused before exposure",
    ))
    append_audit(
        db, tenant_id=tenant_id, actor=requester, action="access.request.created",
        aggregate_type="access_request", aggregate_id=request.id,
        correlation_id=uuid.uuid4().hex,
        details={"resource": request.resource_id, "permission": request.requested_permission},
    )
    notify(
        db, request, "new_paused_request", "resource-reviewers",
        f"Paused access request {request.id} requires evidence review",
    )
    return request


def add_evidence(
    db: Session, request: AccessRequest, payload: dict[str, Any], actor: str,
) -> AccessEvidence:
    if payload["effective_until"] <= payload["effective_from"]:
        raise ValueError("effective_until must be after effective_from")
    canonical = json.dumps({
        key: value.isoformat() if hasattr(value, "isoformat") else value
        for key, value in payload.items()
    }, sort_keys=True)
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    existing = db.query(AccessEvidence).filter(
        AccessEvidence.tenant_id == request.tenant_id,
        AccessEvidence.request_id == request.id,
        AccessEvidence.evidence_hash == digest,
    ).first()
    if existing:
        return existing
    verified = payload["verification_status"] == "verified"
    row = AccessEvidence(
        id=f"evd_{uuid.uuid4().hex}", tenant_id=request.tenant_id,
        request_id=request.id, evidence_hash=digest,
        verified_at=now_utc() if verified else None,
        verifier=actor if verified else None, **payload,
    )
    db.add(row)
    db.flush()
    if verified and request.workflow_state in {"PAUSED", "MORE_CONTEXT_REQUIRED"}:
        transition(db, request, "EVIDENCE_READY", actor, reason="Verified evidence attached")
    append_audit(
        db, tenant_id=request.tenant_id, actor=actor,
        action="access.evidence.attached", aggregate_type="access_request",
        aggregate_id=request.id, correlation_id=uuid.uuid4().hex,
        details={"evidence_id": row.id, "evidence_hash": digest,
                 "verification_status": row.verification_status},
    )
    return row


def policy_inputs(db: Session, request: AccessRequest, is_admin: bool = False) -> dict[str, Any]:
    evidence = [{
        "evidence_type": item.evidence_type,
        "verification_status": item.verification_status,
        "identity_scope": item.identity_scope or [],
        "resource_scope": item.resource_scope or [],
        "action_scope": item.action_scope or [],
    } for item in request.evidence]
    residual = 0.0
    critical: list[str] = []
    if request.linked_case_id:
        case = db.query(Case).filter(Case.id == request.linked_case_id).first()
        if case:
            residual = case.residual_risk
            critical = sorted({
                reason for row in (case.event_risk_breakdown or [])
                if float(row.get("context_credit", 0)) < 1
                for reason in (row.get("critical_reasons") or [])
            })
    active_actions = db.query(ResponseAction).filter(
        ResponseAction.entity_ref == request.subject_identity,
        ResponseAction.status.in_(["auto_authorized", "approved", "executing", "active"]),
    ).count()
    return {
        "subject_identity": request.subject_identity,
        "resource_id": request.resource_id,
        "resource_sensitivity": request.resource_sensitivity,
        "requested_action": request.requested_action,
        "requested_permission": request.requested_permission,
        "requested_duration_seconds": request.requested_duration_seconds,
        "business_justification": request.business_justification,
        "existing_entitlements": request.existing_entitlements or [],
        "device_trust": request.device_trust,
        "authentication_strength": request.authentication_strength,
        "location_trust": request.location_trust,
        "residual_risk": residual,
        "unresolved_critical_reasons": critical,
        "conflicting_containment": active_actions > 0,
        "evidence": evidence,
        "break_glass": request.break_glass,
        "is_admin": is_admin,
    }


def evaluate_request(
    db: Session, request: AccessRequest, actor: str, *, is_admin: bool = False,
) -> dict[str, Any]:
    if request.workflow_state not in {"PAUSED", "EVIDENCE_READY", "MORE_CONTEXT_REQUIRED"}:
        raise ValueError(f"Request cannot be evaluated from {request.workflow_state}")
    decision = evaluate_access_policy(policy_inputs(db, request, is_admin=is_admin)).to_dict()
    request.policy_decision = decision
    request.updated_at = now_utc()
    request.version += 1
    if decision["blocking_reasons"]:
        transition(db, request, "DENIED", "access-policy",
                   reason="Deterministic policy denial", metadata=decision)
    elif decision["missing_evidence"]:
        if request.workflow_state != "MORE_CONTEXT_REQUIRED":
            transition(db, request, "MORE_CONTEXT_REQUIRED", "access-policy",
                       reason="Verified scoped evidence is incomplete", metadata=decision)
        notify(db, request, "more_context_required", request.requester_identity,
               f"Request {request.id} needs additional verified context")
    else:
        if request.workflow_state == "PAUSED":
            transition(db, request, "EVIDENCE_READY", "access-policy",
                       reason="Deterministic eligibility established", metadata=decision)
        notify(db, request, "approval_required", "resource-reviewers",
               f"Eligible scoped request {request.id} awaits human approval")
    return decision


def request_ai_review(db: Session, request: AccessRequest, actor: str) -> None:
    if not request.policy_decision or not request.policy_decision.get("eligibility"):
        raise ValueError("Deterministic policy must establish eligibility before AI review")
    if request.workflow_state not in {"EVIDENCE_READY", "AI_REVIEWED"}:
        raise ValueError(f"AI review cannot start from {request.workflow_state}")
    transition(db, request, "AI_REVIEW_PENDING", actor, reason="Advisory review queued")
    request.ai_review_status = "pending"
    enqueue(
        db, tenant_id=request.tenant_id, aggregate_type="access_request",
        aggregate_id=request.id, job_type="AI_REVIEW", payload={"request_id": request.id},
        deduplication_key=f"ai-review:{request.id}:{request.version}",
    )


def record_approval(
    db: Session, request: AccessRequest, *, actor: str, actor_role: str,
    decision: str, note: str, expected_version: int,
) -> ApprovalDecision:
    if request.version != expected_version:
        raise RuntimeError("Optimistic lock conflict")
    if request.requester_identity == actor:
        raise PermissionError("Requester cannot approve their own access request")
    if not request.policy_decision or not request.policy_decision.get("eligibility"):
        raise PermissionError("Deterministic policy has not authorized human review")
    if actor_role not in request.policy_decision["required_approver_roles"]:
        raise PermissionError("Caller does not satisfy a required approver role")
    if request.workflow_state in {"EVIDENCE_READY", "AI_REVIEWED"}:
        transition(db, request, "AWAITING_APPROVAL", actor, reason="Human approval started")
    if request.workflow_state != "AWAITING_APPROVAL":
        raise ValueError(f"Approval is invalid from {request.workflow_state}")
    record = ApprovalDecision(
        id=f"apd_{uuid.uuid4().hex}", tenant_id=request.tenant_id,
        request_id=request.id, approver_identity=actor, approver_role=actor_role,
        decision=decision, note=note, policy_version=POLICY_VERSION,
    )
    db.add(record)
    db.flush()
    append_audit(
        db, tenant_id=request.tenant_id, actor=actor,
        action=f"access.approval.{decision}", aggregate_type="access_request",
        aggregate_id=request.id, correlation_id=uuid.uuid4().hex,
        details={"approver_role": actor_role, "decision_id": record.id},
    )
    if decision == "deny":
        transition(db, request, "DENIED", actor, reason=note)
        return record
    approvals = {
        item.approver_role for item in request.approvals if item.decision == "approve"
    } | {actor_role}
    required = set(request.policy_decision["required_approver_roles"])
    if required.issubset(approvals):
        transition(db, request, "APPROVED", actor, reason="Required approvals complete")
        create_grant(db, request, actor)
    return record


def create_grant(db: Session, request: AccessRequest, actor: str) -> AccessGrant:
    if request.grant:
        return request.grant
    decision = request.policy_decision
    grant = AccessGrant(
        id=f"grt_{uuid.uuid4().hex}", tenant_id=request.tenant_id,
        request_id=request.id, exact_resource=request.resource_id,
        exact_permission=decision["maximum_permission"],
        allowed_actions=[request.requested_action],
        denied_actions=["*"] if request.requested_action == "" else [],
        maximum_ttl_seconds=min(
            request.requested_duration_seconds, decision["maximum_duration_seconds"]
        ),
        required_authentication_strength=(
            "phishing_resistant" if "phishing_resistant_auth" in decision["required_controls"]
            else "mfa"
        ),
        approvers=[
            {"identity": item.approver_identity, "role": item.approver_role}
            for item in request.approvals if item.decision == "approve"
        ],
        idempotency_key=f"grant:{request.id}",
    )
    db.add(grant)
    db.flush()
    transition(db, request, "ENFORCING", actor, reason="Least-privilege grant prepared")
    enqueue(
        db, tenant_id=request.tenant_id, aggregate_type="access_grant",
        aggregate_id=grant.id, job_type="ENFORCEMENT",
        payload={"request_id": request.id, "grant_id": grant.id},
        deduplication_key=f"enforce:{grant.id}",
    )
    return grant


def request_revocation(
    db: Session, request: AccessRequest, actor: str, reason: str,
) -> None:
    if request.workflow_state != "ACTIVE":
        raise ValueError(f"Revocation is invalid from {request.workflow_state}")
    request.grant.revocation_reason = reason
    transition(db, request, "REVOKING", actor, reason=reason)
    enqueue(
        db, tenant_id=request.tenant_id, aggregate_type="access_grant",
        aggregate_id=request.grant.id, job_type="REVOCATION",
        payload={"request_id": request.id, "grant_id": request.grant.id},
        deduplication_key=f"revoke:{request.grant.id}:{request.version}",
    )


def request_more_context(
    db: Session, request: AccessRequest, actor: str, note: str,
) -> None:
    if request.workflow_state not in {
        "EVIDENCE_READY", "AI_REVIEWED", "AWAITING_APPROVAL", "AI_REVIEW_PENDING",
    }:
        raise ValueError(f"More context cannot be requested from {request.workflow_state}")
    transition(db, request, "MORE_CONTEXT_REQUIRED", actor, reason=note)
    notify(db, request, "more_context_required", request.requester_identity, note)
