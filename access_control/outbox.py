from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import uuid
from typing import Any

from sqlalchemy.orm import Session

from models.db_models import TransactionalOutbox


def enqueue(
    db: Session, *, tenant_id: str, aggregate_type: str, aggregate_id: str,
    job_type: str, payload: dict[str, Any], deduplication_key: str,
    available_at: datetime | None = None,
) -> TransactionalOutbox:
    existing = db.query(TransactionalOutbox).filter(
        TransactionalOutbox.tenant_id == tenant_id,
        TransactionalOutbox.deduplication_key == deduplication_key,
    ).first()
    if existing:
        return existing
    row = TransactionalOutbox(
        id=f"job_{uuid.uuid4().hex}", tenant_id=tenant_id,
        aggregate_type=aggregate_type, aggregate_id=aggregate_id,
        job_type=job_type, payload=payload, deduplication_key=deduplication_key,
        available_at=available_at or datetime.now(timezone.utc),
    )
    db.add(row)
    db.flush()
    return row


def claim_jobs(
    db: Session, worker_id: str, *, limit: int = 20,
    now: datetime | None = None, lease_seconds: int = 60,
) -> list[TransactionalOutbox]:
    timestamp = now or datetime.now(timezone.utc)
    query = db.query(TransactionalOutbox).filter(
        TransactionalOutbox.status.in_(["pending", "retry"]),
        TransactionalOutbox.available_at <= timestamp,
        (TransactionalOutbox.lease_expires_at.is_(None))
        | (TransactionalOutbox.lease_expires_at < timestamp),
    ).order_by(TransactionalOutbox.available_at, TransactionalOutbox.id)
    if db.bind and db.bind.dialect.name == "postgresql":
        query = query.with_for_update(skip_locked=True)
    rows = query.limit(limit).all()
    for row in rows:
        row.status = "processing"
        row.locked_by = worker_id
        row.lease_expires_at = timestamp + timedelta(seconds=lease_seconds)
        row.attempts += 1
    db.flush()
    return rows


def complete_job(db: Session, row: TransactionalOutbox, now: datetime | None = None) -> None:
    row.status = "completed"
    row.processed_at = now or datetime.now(timezone.utc)
    row.locked_by = None
    row.lease_expires_at = None
    row.last_error = None


def retry_job(
    db: Session, row: TransactionalOutbox, error: str, *, now: datetime | None = None,
) -> None:
    timestamp = now or datetime.now(timezone.utc)
    row.status = "retry" if row.attempts < 5 else "failed"
    row.available_at = timestamp + timedelta(seconds=min(300, 2 ** row.attempts))
    row.locked_by = None
    row.lease_expires_at = None
    row.last_error = error[:1000]


def publish_completed_to_redis(rows: list[TransactionalOutbox], redis_url: str) -> int:
    """Optional event fan-out; DB outbox remains the durable source of truth."""
    import redis

    client = redis.Redis.from_url(redis_url, decode_responses=True)
    count = 0
    for row in rows:
        client.xadd("fable:jit-events", {
            "id": row.id, "tenant_id": row.tenant_id, "job_type": row.job_type,
            "aggregate_id": row.aggregate_id, "payload": json.dumps(row.payload),
        })
        count += 1
    return count
