"""Tenant-scoped versioned API for context-aware just-in-time access."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response
from sqlalchemy.orm import Session

from access_control.audit import verify_audit_chain
from access_control.schemas import (
    AccessRequestCreate, AccessRequestOut, ApprovalCreate, ContextRequest,
    EvidenceCreate, NotificationOut, RevokeCreate,
)
from access_control.service import (
    add_evidence, create_request, evaluate_request, record_approval,
    request_ai_review, request_more_context, request_revocation,
)
from access_control.enforcement import configured_enforcement_provider
from config import load_settings
from database import get_db
from models.db_models import (
    AccessAIReview, AccessGrant, AccessNotification, AccessRequest, AuditRecord,
    MutationIdempotency, TransactionalOutbox,
)
from security import Principal, require_scope


access_router = APIRouter(
    prefix="/api/v1", tags=["jit-access"],
    dependencies=[Depends(require_scope("access:read"))],
)


def problem(status: int, title: str, detail: str, *, type_name: str = "about:blank"):
    raise HTTPException(status, {
        "type": type_name, "title": title, "status": status, "detail": detail,
    })


def _request_or_404(db: Session, tenant_id: str, request_id: str, *, lock: bool = False):
    query = db.query(AccessRequest).filter(
        AccessRequest.id == request_id, AccessRequest.tenant_id == tenant_id
    )
    if lock:
        query = query.with_for_update()
    row = query.first()
    if not row:
        problem(404, "Not Found", "Access request not found")
    return row


def _required_idempotency(value: str | None) -> str:
    if not value or len(value) < 8 or len(value) > 128:
        problem(400, "Idempotency-Key required",
                "Mutation requests require an Idempotency-Key header of 8-128 characters")
    return value


def _idempotency_replay(
    db: Session, principal: Principal, operation: str, key: str, body: Any,
) -> dict[str, Any] | None:
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
    row = db.query(MutationIdempotency).filter(
        MutationIdempotency.tenant_id == principal.tenant_id,
        MutationIdempotency.operation == operation,
        MutationIdempotency.idempotency_key == key,
    ).first()
    if row:
        if row.request_hash != digest:
            problem(409, "Idempotency conflict", "Key was used with a different request")
        return row.response_body
    db.add(MutationIdempotency(
        tenant_id=principal.tenant_id, operation=operation,
        idempotency_key=key, request_hash=digest,
    ))
    db.flush()
    return None


def _idempotency_finish(
    db: Session, principal: Principal, operation: str, key: str, payload: dict[str, Any],
    status: int = 200,
) -> None:
    row = db.query(MutationIdempotency).filter(
        MutationIdempotency.tenant_id == principal.tenant_id,
        MutationIdempotency.operation == operation,
        MutationIdempotency.idempotency_key == key,
    ).one()
    row.response_body = payload
    row.response_status = status


def _available_actions(request: AccessRequest, principal: Principal) -> list[str]:
    actions = []
    if "access:evidence" in principal.scopes and request.workflow_state in {
        "PAUSED", "MORE_CONTEXT_REQUIRED"
    }:
        actions.append("attach_evidence")
    if "access:evaluate" in principal.scopes and request.workflow_state in {
        "PAUSED", "EVIDENCE_READY", "MORE_CONTEXT_REQUIRED"
    }:
        actions.append("evaluate")
    if "access:ai_review" in principal.scopes and request.workflow_state == "EVIDENCE_READY":
        actions.append("request_ai_review")
    if "access:approve" in principal.scopes and request.workflow_state in {
        "EVIDENCE_READY", "AI_REVIEWED", "AWAITING_APPROVAL"
    }:
        actions.extend(["approve", "deny"])
    if "access:revoke" in principal.scopes and request.workflow_state == "ACTIVE":
        actions.append("revoke")
    return actions


def _out(request: AccessRequest, principal: Principal) -> dict[str, Any]:
    grant = request.grant
    verification = None
    if grant:
        verification = {
            "state": grant.enforcement_state,
            "connector_reference": grant.connector_reference,
            "activated_at": grant.activated_at,
            "expires_at": grant.expires_at,
        }
    return {
        "id": request.id, "tenant_id": request.tenant_id,
        "subject_identity": request.subject_identity,
        "requester_identity": request.requester_identity,
        "resource_id": request.resource_id,
        "resource_sensitivity": request.resource_sensitivity,
        "requested_action": request.requested_action,
        "requested_permission": request.requested_permission,
        "business_justification": request.business_justification,
        "requested_duration_seconds": request.requested_duration_seconds,
        "linked_case_id": request.linked_case_id,
        "external_status": request.external_status,
        "workflow_state": request.workflow_state,
        "created_at": request.created_at, "updated_at": request.updated_at,
        "resolved_at": request.resolved_at, "version": request.version,
        "policy_decision": request.policy_decision,
        "ai_review_status": request.ai_review_status,
        "ai_advisory_only": True,
        "required_approvers": (request.policy_decision or {}).get(
            "required_approver_roles", []
        ),
        "available_actions": _available_actions(request, principal),
        "requested_scope": {
            "resource": request.resource_id, "action": request.requested_action,
            "permission": request.requested_permission,
            "duration_seconds": request.requested_duration_seconds,
        },
        "approved_scope": ({
            "resource": grant.exact_resource, "permission": grant.exact_permission,
            "allowed_actions": grant.allowed_actions,
            "maximum_ttl_seconds": grant.maximum_ttl_seconds,
        } if grant else None),
        "unaffected_resources": [],
        "enforcement_verification": verification,
    }


@access_router.post("/access-requests", response_model=AccessRequestOut, status_code=201)
def create_access_request(
    body: AccessRequestCreate, response: Response,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("access:create")),
):
    key = _required_idempotency(idempotency_key)
    data = body.model_dump(mode="json")
    replay = _idempotency_replay(db, principal, "create_access_request", key, data)
    if replay:
        response.status_code = 200
        return replay
    try:
        request = create_request(
            db, tenant_id=principal.tenant_id, requester=principal.subject,
            payload=body.model_dump(), idempotency_key=key,
            is_admin=principal.role == "admin",
        )
        payload = _out(request, principal)
        _idempotency_finish(db, principal, "create_access_request", key, payload, 201)
        db.commit()
        return payload
    except PermissionError as exc:
        db.rollback()
        problem(403, "Forbidden", str(exc))


@access_router.get("/access-requests", response_model=list[AccessRequestOut])
def list_access_requests(
    state: str | None = None, resource_id: str | None = None,
    limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("access:read")),
):
    query = db.query(AccessRequest).filter(
        AccessRequest.tenant_id == principal.tenant_id
    )
    if state:
        query = query.filter(AccessRequest.workflow_state == state)
    if resource_id:
        query = query.filter(AccessRequest.resource_id == resource_id)
    rows = query.order_by(
        AccessRequest.created_at.desc(), AccessRequest.id.desc()
    ).offset(offset).limit(limit).all()
    return [_out(row, principal) for row in rows]


@access_router.get("/access-requests/{request_id}", response_model=AccessRequestOut)
def get_access_request(
    request_id: str, db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("access:read")),
):
    return _out(_request_or_404(db, principal.tenant_id, request_id), principal)


@access_router.get("/access-requests/{request_id}/history")
def get_access_request_history(
    request_id: str, db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("access:read")),
):
    request = _request_or_404(db, principal.tenant_id, request_id)
    audits = db.query(AuditRecord).filter(
        AuditRecord.tenant_id == principal.tenant_id,
        AuditRecord.aggregate_id == request.id,
    ).order_by(AuditRecord.timestamp, AuditRecord.id).all()
    return {
        "request_id": request.id,
        "transitions": [{
            "from_state": row.from_state, "to_state": row.to_state,
            "actor": row.actor, "timestamp": row.timestamp, "reason": row.reason,
        } for row in request.transitions],
        "approvals": [{
            "approver_identity": row.approver_identity,
            "approver_role": row.approver_role, "decision": row.decision,
            "note": row.note, "created_at": row.created_at,
        } for row in request.approvals],
        "audit_records": [{
            "id": row.id, "timestamp": row.timestamp, "actor": row.actor,
            "action": row.action, "record_hash": row.record_hash,
            "previous_record_hash": row.previous_record_hash,
        } for row in audits],
        "audit_chain_valid": verify_audit_chain(audits),
    }


def _mutation_setup(db, principal, request_id, operation, key, body):
    request = _request_or_404(db, principal.tenant_id, request_id, lock=True)
    replay = _idempotency_replay(db, principal, f"{operation}:{request_id}", key, body)
    return request, replay


@access_router.post("/access-requests/{request_id}/evidence", status_code=201)
def attach_access_evidence(
    request_id: str, body: EvidenceCreate, response: Response,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("access:evidence")),
):
    key = _required_idempotency(idempotency_key)
    if body.verification_status == "verified" and "access:evidence:verify" not in principal.scopes:
        problem(403, "Forbidden", "Caller cannot mark evidence as verified")
    request, replay = _mutation_setup(
        db, principal, request_id, "evidence", key, body.model_dump(mode="json")
    )
    if replay:
        response.status_code = 200
        return replay
    try:
        row = add_evidence(db, request, body.model_dump(), principal.subject)
        payload = {"id": row.id, "request_id": row.request_id,
                   "verification_status": row.verification_status,
                   "evidence_hash": row.evidence_hash}
        _idempotency_finish(db, principal, f"evidence:{request_id}", key, payload, 201)
        db.commit()
        return payload
    except ValueError as exc:
        db.rollback()
        problem(409, "Invalid transition", str(exc))


@access_router.post("/access-requests/{request_id}/evaluate")
def evaluate_access_request(
    request_id: str, response: Response,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("access:evaluate")),
):
    key = _required_idempotency(idempotency_key)
    request, replay = _mutation_setup(db, principal, request_id, "evaluate", key, {})
    if replay:
        return replay
    try:
        decision = evaluate_request(
            db, request, principal.subject, is_admin=principal.role == "admin"
        )
        payload = {"request": _out(request, principal), "policy_decision": decision}
        _idempotency_finish(db, principal, f"evaluate:{request_id}", key, payload)
        db.commit()
        return payload
    except ValueError as exc:
        db.rollback()
        problem(409, "Invalid transition", str(exc))


@access_router.post("/access-requests/{request_id}/ai-review", status_code=202)
def queue_ai_review(
    request_id: str, response: Response,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("access:ai_review")),
):
    key = _required_idempotency(idempotency_key)
    request, replay = _mutation_setup(db, principal, request_id, "ai_review", key, {})
    if replay:
        response.status_code = 200
        return replay
    try:
        request_ai_review(db, request, principal.subject)
        payload = {"request_id": request.id, "state": request.workflow_state,
                   "ai_advisory_only": True}
        _idempotency_finish(db, principal, f"ai_review:{request_id}", key, payload, 202)
        db.commit()
        return payload
    except ValueError as exc:
        db.rollback()
        problem(409, "Invalid transition", str(exc))


@access_router.post("/access-requests/{request_id}/request-context")
def ask_for_context(
    request_id: str, body: ContextRequest,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("access:request_context")),
):
    key = _required_idempotency(idempotency_key)
    request, replay = _mutation_setup(
        db, principal, request_id, "request_context", key, body.model_dump()
    )
    if replay:
        return replay
    try:
        request_more_context(db, request, principal.subject, body.note)
        payload = _out(request, principal)
        _idempotency_finish(db, principal, f"request_context:{request_id}", key, payload)
        db.commit()
        return payload
    except ValueError as exc:
        db.rollback()
        problem(409, "Invalid transition", str(exc))


def _approval(
    request_id, body, key, db, principal, decision,
):
    request, replay = _mutation_setup(
        db, principal, request_id, decision, key, body.model_dump()
    )
    if replay:
        return replay
    if principal.role == "resource_owner" and request.resource_id not in principal.resource_scopes:
        problem(403, "Forbidden", "Resource owner is not scoped to this resource")
    try:
        record_approval(
            db, request, actor=principal.subject, actor_role=principal.role,
            decision=decision, note=body.note, expected_version=body.expected_version,
        )
        payload = _out(request, principal)
        _idempotency_finish(db, principal, f"{decision}:{request_id}", key, payload)
        db.commit()
        return payload
    except PermissionError as exc:
        db.rollback()
        problem(403, "Forbidden", str(exc))
    except RuntimeError as exc:
        db.rollback()
        problem(409, "Version conflict", str(exc))
    except ValueError as exc:
        db.rollback()
        problem(409, "Invalid transition", str(exc))


@access_router.post("/access-requests/{request_id}/approve", response_model=AccessRequestOut)
def approve_access(
    request_id: str, body: ApprovalCreate,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("access:approve")),
):
    if body.decision != "approve":
        problem(422, "Invalid decision", "Use the deny endpoint for denials")
    return _approval(
        request_id, body, _required_idempotency(idempotency_key),
        db, principal, "approve",
    )


@access_router.post("/access-requests/{request_id}/deny", response_model=AccessRequestOut)
def deny_access(
    request_id: str, body: ApprovalCreate,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("access:deny")),
):
    if body.decision != "deny":
        problem(422, "Invalid decision", "Use the approve endpoint for approvals")
    return _approval(
        request_id, body, _required_idempotency(idempotency_key),
        db, principal, "deny",
    )


@access_router.post("/access-requests/{request_id}/revoke", response_model=AccessRequestOut)
def revoke_access(
    request_id: str, body: RevokeCreate,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("access:revoke")),
):
    key = _required_idempotency(idempotency_key)
    request, replay = _mutation_setup(
        db, principal, request_id, "revoke", key, body.model_dump()
    )
    if replay:
        return replay
    if request.version != body.expected_version:
        db.rollback()
        problem(409, "Version conflict", "Optimistic lock version does not match")
    try:
        request_revocation(db, request, principal.subject, body.note)
        payload = _out(request, principal)
        _idempotency_finish(db, principal, f"revoke:{request_id}", key, payload)
        db.commit()
        return payload
    except ValueError as exc:
        db.rollback()
        problem(409, "Invalid transition", str(exc))


@access_router.get("/access-requests/{request_id}/grant")
def get_access_grant(
    request_id: str, db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("access:read")),
):
    request = _request_or_404(db, principal.tenant_id, request_id)
    if not request.grant:
        problem(404, "Not Found", "No access grant exists")
    grant = request.grant
    return {
        "id": grant.id, "request_id": grant.request_id,
        "exact_resource": grant.exact_resource,
        "exact_permission": grant.exact_permission,
        "allowed_actions": grant.allowed_actions,
        "denied_actions": grant.denied_actions,
        "maximum_ttl_seconds": grant.maximum_ttl_seconds,
        "activated_at": grant.activated_at, "expires_at": grant.expires_at,
        "required_authentication_strength": grant.required_authentication_strength,
        "approvers": grant.approvers, "enforcement_state": grant.enforcement_state,
        "connector_reference": grant.connector_reference,
        "revocation_reason": grant.revocation_reason,
    }


@access_router.get("/notifications", response_model=list[NotificationOut])
def list_notifications(
    limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("access:read")),
):
    rows = db.query(AccessNotification).filter(
        AccessNotification.tenant_id == principal.tenant_id,
    ).order_by(
        AccessNotification.created_at.desc(), AccessNotification.id.desc()
    ).offset(offset).limit(limit).all()
    return rows


@access_router.post("/notifications/{notification_id}/acknowledge")
def acknowledge_notification(
    notification_id: str,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("access:read")),
):
    key = _required_idempotency(idempotency_key)
    replay = _idempotency_replay(
        db, principal, f"ack:{notification_id}", key, {}
    )
    if replay:
        return replay
    row = db.query(AccessNotification).filter(
        AccessNotification.id == notification_id,
        AccessNotification.tenant_id == principal.tenant_id,
    ).first()
    if not row:
        db.rollback()
        problem(404, "Not Found", "Notification not found")
    row.acknowledged_at = datetime.now(timezone.utc)
    payload = {"id": row.id, "acknowledged_at": row.acknowledged_at}
    _idempotency_finish(db, principal, f"ack:{notification_id}", key, payload)
    db.commit()
    return payload


@access_router.get("/admin/access-policy")
def access_policy_info(
    principal: Principal = Depends(require_scope("access:admin")),
):
    return {
        "policy_version": "jit-access-v1", "default_decision": "pause_or_deny",
        "maximum_ttls": {"public": 86400, "internal": 28800,
                         "restricted": 14400, "critical": 3600},
        "ai_advisory_only": True,
    }


@access_router.get("/admin/access-health")
def access_health(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("access:admin")),
):
    settings = load_settings()
    return {
        "database": db.bind.dialect.name if db.bind else "unknown",
        "outbox_pending": db.query(TransactionalOutbox).filter(
            TransactionalOutbox.tenant_id == principal.tenant_id,
            TransactionalOutbox.status.in_(["pending", "retry"]),
        ).count(),
        "groq_enabled": settings.groq_enabled,
        "enforcement": configured_enforcement_provider().health(),
    }
