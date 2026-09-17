from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import uuid
from typing import Any

from sqlalchemy.orm import Session

from models.db_models import AuditRecord


def append_audit(
    db: Session, *, tenant_id: str, actor: str, action: str,
    aggregate_type: str, aggregate_id: str, correlation_id: str,
    details: dict[str, Any] | None = None, now: datetime | None = None,
) -> AuditRecord:
    timestamp = now or datetime.now(timezone.utc)
    previous = db.query(AuditRecord).filter(
        AuditRecord.tenant_id == tenant_id
    ).order_by(AuditRecord.timestamp.desc(), AuditRecord.id.desc()).with_for_update().first()
    previous_hash = previous.record_hash if previous else None
    canonical = json.dumps({
        "tenant_id": tenant_id, "timestamp": timestamp.isoformat(), "actor": actor,
        "action": action, "aggregate_type": aggregate_type,
        "aggregate_id": aggregate_id, "correlation_id": correlation_id,
        "details": details or {}, "previous_record_hash": previous_hash,
    }, sort_keys=True, separators=(",", ":"), default=str)
    record = AuditRecord(
        id=f"aud_{uuid.uuid4().hex}", tenant_id=tenant_id, timestamp=timestamp,
        actor=actor, action=action, aggregate_type=aggregate_type,
        aggregate_id=aggregate_id, correlation_id=correlation_id,
        details=details or {}, previous_record_hash=previous_hash,
        record_hash=hashlib.sha256(canonical.encode()).hexdigest(),
    )
    db.add(record)
    db.flush()
    return record


def verify_audit_chain(records: list[AuditRecord]) -> bool:
    previous_hash = None
    for record in sorted(records, key=lambda item: (item.timestamp, item.id)):
        if record.previous_record_hash != previous_hash:
            return False
        canonical = json.dumps({
            "tenant_id": record.tenant_id,
            "timestamp": record.timestamp.replace(tzinfo=timezone.utc).isoformat()
            if record.timestamp.tzinfo is None else record.timestamp.isoformat(),
            "actor": record.actor, "action": record.action,
            "aggregate_type": record.aggregate_type,
            "aggregate_id": record.aggregate_id,
            "correlation_id": record.correlation_id,
            "details": record.details or {},
            "previous_record_hash": record.previous_record_hash,
        }, sort_keys=True, separators=(",", ":"), default=str)
        if hashlib.sha256(canonical.encode()).hexdigest() != record.record_hash:
            return False
        previous_hash = record.record_hash
    return True
