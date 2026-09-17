"""Durable transactional-outbox worker for JIT access jobs."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import time
import uuid

import httpx
from sqlalchemy.orm import Session

from access_control.ai_review import configured_review_provider
from access_control.audit import append_audit
from access_control.enforcement import configured_enforcement_provider
from access_control.outbox import claim_jobs, complete_job, enqueue, retry_job
from access_control.service import notify, transition
from config import load_settings
from database import SessionLocal, init_db
from models.db_models import (
    AccessAIReview, AccessGrant, AccessNotification, AccessRequest,
    TransactionalOutbox,
)


def _ai_payload(request: AccessRequest) -> dict:
    decision = request.policy_decision or {}
    return {
        "request_id": request.id, "tenant_id": request.tenant_id,
        "subject_ref": request.subject_identity,
        "requester_role": "authenticated_requester",
        "resource_id": request.resource_id,
        "resource_sensitivity": request.resource_sensitivity,
        "requested_action": request.requested_action,
        "requested_permission": request.requested_permission,
        "requested_duration_seconds": request.requested_duration_seconds,
        "business_context_summary": request.business_justification,
        "evidence_types": sorted({
            item.evidence_type for item in request.evidence
            if item.verification_status == "verified"
        }),
        "device_trust": request.device_trust,
        "authentication_strength": request.authentication_strength,
        "location_trust": request.location_trust,
        "policy_decision": decision,
    }


def _process_ai(db: Session, job: TransactionalOutbox) -> None:
    request = db.query(AccessRequest).filter(
        AccessRequest.id == job.payload["request_id"],
        AccessRequest.tenant_id == job.tenant_id,
    ).one()
    provider = configured_review_provider()
    result = provider.review(_ai_payload(request))
    cached = db.query(AccessAIReview).filter(
        AccessAIReview.tenant_id == request.tenant_id,
        AccessAIReview.sanitized_input_hash == result.sanitized_input_hash,
        AccessAIReview.status == "completed",
    ).order_by(AccessAIReview.created_at.desc()).first()
    output = cached.output if cached else result.output
    status = "completed" if cached else result.status
    row = AccessAIReview(
        id=f"air_{uuid.uuid4().hex}", tenant_id=request.tenant_id,
        request_id=request.id, provider="cache" if cached else result.provider,
        model=result.model, prompt_version=result.prompt_version,
        sanitized_input_hash=result.sanitized_input_hash, output=output,
        latency_ms=0 if cached else result.latency_ms,
        token_usage={} if cached else result.token_usage,
        confidence=(output or {}).get("confidence") if output else None,
        status=status, failure_reason=result.failure_reason,
    )
    db.add(row)
    request.ai_review_status = status
    transition(
        db, request, "AI_REVIEWED", "jit-worker",
        reason="Advisory AI review completed" if status == "completed"
        else "AI review unavailable; no result fabricated",
        metadata={"ai_review_id": row.id, "ai_advisory_only": True},
    )
    if status != "completed" and request.resource_sensitivity == "critical":
        transition(
            db, request, "MORE_CONTEXT_REQUIRED", "jit-worker",
            reason="Critical access fails closed when advisory review is unavailable",
        )
    else:
        transition(
            db, request, "AWAITING_APPROVAL", "jit-worker",
            reason="Deterministic policy remains authoritative",
        )


def _process_enforcement(db: Session, job: TransactionalOutbox) -> None:
    request = db.query(AccessRequest).filter(
        AccessRequest.id == job.payload["request_id"],
        AccessRequest.tenant_id == job.tenant_id,
    ).one()
    grant = request.grant
    provider = configured_enforcement_provider()
    correlation = uuid.uuid4().hex
    result = provider.activate(grant, correlation)
    if not result["success"]:
        grant.enforcement_state = "failed"
        transition(db, request, "ENFORCEMENT_FAILED", "jit-worker",
                   reason="Enforcement provider rejected activation")
        notify(db, request, "enforcement_failure", request.requester_identity,
               f"Access request {request.id} could not be enforced")
        return
    grant.connector_reference = result["connector_reference"]
    grant.enforcement_state = "active"
    grant.activated_at = datetime.now(timezone.utc)
    grant.expires_at = grant.activated_at + __import__("datetime").timedelta(
        seconds=grant.maximum_ttl_seconds
    )
    verification = provider.verify(grant, correlation)
    if not verification["verified"]:
        grant.enforcement_state = "verification_failed"
        transition(db, request, "ENFORCEMENT_FAILED", "jit-worker",
                   reason="Enforcement verification failed")
        return
    transition(
        db, request, "ACTIVE", "jit-worker", reason="Grant activated and verified",
        metadata={"connector_reference": grant.connector_reference, "verification": verification},
    )
    enqueue(
        db, tenant_id=request.tenant_id, aggregate_type="access_grant",
        aggregate_id=grant.id, job_type="EXPIRY",
        payload={"request_id": request.id, "grant_id": grant.id},
        deduplication_key=f"expire:{grant.id}", available_at=grant.expires_at,
    )
    notify(db, request, "access_activated", request.requester_identity,
           f"Scoped access {grant.id} is active until {grant.expires_at.isoformat()}")


def _process_revoke(db: Session, job: TransactionalOutbox, *, expired: bool = False) -> None:
    request = db.query(AccessRequest).filter(
        AccessRequest.id == job.payload["request_id"],
        AccessRequest.tenant_id == job.tenant_id,
    ).one()
    if request.workflow_state in {"REVOKED", "EXPIRED"}:
        return
    grant = request.grant
    provider = configured_enforcement_provider()
    result = provider.revoke(grant, uuid.uuid4().hex)
    if not result["verified"]:
        grant.enforcement_state = "revocation_failed"
        if request.workflow_state != "REVOKING":
            transition(db, request, "REVOKING", "jit-worker", reason="Expiry revocation started")
        transition(db, request, "ENFORCEMENT_FAILED", "jit-worker",
                   reason="Revocation verification failed")
        return
    grant.enforcement_state = "expired" if expired else "revoked"
    if expired:
        transition(db, request, "EXPIRED", "jit-worker", reason="Grant TTL expired")
        kind = "access_expired"
    else:
        transition(db, request, "REVOKED", "jit-worker",
                   reason=grant.revocation_reason or "Reviewer revoked grant")
        kind = "access_revoked"
    notify(db, request, kind, request.requester_identity,
           f"Temporary access {grant.id} is no longer active")


def _deliver_notification(db: Session, job: TransactionalOutbox) -> None:
    row = db.query(AccessNotification).filter(
        AccessNotification.id == job.payload["notification_id"],
        AccessNotification.tenant_id == job.tenant_id,
    ).one()
    settings = load_settings()
    if not settings.notification_webhook_url:
        row.delivery_status = "in_app"
        return
    if not settings.notification_webhook_url.startswith("https://"):
        raise ValueError("Notification webhook must use HTTPS")
    body = json.dumps({
        "notification_id": row.id, "type": row.notification_type,
        "request_id": row.request_id, "message": row.message,
    }, sort_keys=True, separators=(",", ":")).encode()
    timestamp = str(int(time.time()))
    signature = hmac.new(
        (settings.notification_webhook_secret or "").encode(),
        timestamp.encode() + b"." + body, hashlib.sha256,
    ).hexdigest()
    response = httpx.post(
        settings.notification_webhook_url, content=body, timeout=10,
        headers={
            "Content-Type": "application/json", "X-Fable-Timestamp": timestamp,
            "X-Fable-Signature": f"sha256={signature}",
            "Idempotency-Key": row.id,
        },
    )
    response.raise_for_status()
    row.delivery_status = "delivered"
    row.external_reference = response.headers.get("X-External-Reference")


def process_outbox_once(
    db: Session, worker_id: str = "jit-worker", *, now: datetime | None = None,
    limit: int = 20,
) -> int:
    jobs = claim_jobs(db, worker_id, limit=limit, now=now)
    processed = 0
    for job in jobs:
        try:
            if job.job_type == "AI_REVIEW":
                _process_ai(db, job)
            elif job.job_type == "ENFORCEMENT":
                _process_enforcement(db, job)
            elif job.job_type == "REVOCATION":
                _process_revoke(db, job)
            elif job.job_type == "EXPIRY":
                _process_revoke(db, job, expired=True)
            elif job.job_type == "NOTIFICATION":
                _deliver_notification(db, job)
            else:
                raise ValueError(f"Unknown job type: {job.job_type}")
            complete_job(db, job, now=now)
            processed += 1
        except Exception as exc:
            retry_job(db, job, type(exc).__name__, now=now)
    db.commit()
    return processed


def run_worker() -> None:
    init_db()
    worker_id = os.getenv("FABLE_WORKER_ID", f"worker-{uuid.uuid4().hex[:8]}")
    while True:
        db = SessionLocal()
        try:
            count = process_outbox_once(db, worker_id)
        finally:
            db.close()
        time.sleep(0.25 if count else 2)


if __name__ == "__main__":
    run_worker()
