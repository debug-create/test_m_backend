"""SQLAlchemy ORM models."""

from datetime import datetime, timezone
import secrets

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import relationship
from sqlalchemy import inspect as sa_inspect

from database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Entity(Base):
    __tablename__ = "entities"

    id = Column(Integer, primary_key=True, index=True)
    pseudonymous_id = Column(String(64), nullable=True, unique=True, index=True)
    display_name = Column(String(128), nullable=False, unique=True)
    role = Column(String(64), nullable=False)
    department = Column(String(64), nullable=False)
    hire_date = Column(DateTime, nullable=False)
    # Read-only regime latch for change-point detector (Task 2)
    regime_state = Column(String(16), nullable=False, default="nominal")
    regime_feature = Column(String(64), nullable=True, default="overall_deviation")
    # Supporting state needed to resume a latched detector across requests.
    regime_baseline = Column(Float, nullable=True)
    regime_last_evaluated_at = Column(DateTime, nullable=True)

    events = relationship("Event", back_populates="actor")
    context_entries = relationship("ContextLedgerEntry", back_populates="actor")
    cases = relationship("Case", back_populates="actor")


@event.listens_for(Entity, "before_insert")
def _assign_pseudonymous_id(mapper, connection, target) -> None:
    if not target.pseudonymous_id:
        target.pseudonymous_id = f"ent_{secrets.token_hex(8)}"


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    actor_id = Column(Integer, ForeignKey("entities.id"), nullable=False, index=True)
    device_id = Column(String(64), nullable=False)
    action = Column(String(32), nullable=False)
    resource_id = Column(String(128), nullable=True)
    resource_classification = Column(String(32), nullable=True)
    destination = Column(String(128), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    volume = Column(Integer, nullable=True)
    result = Column(String(16), nullable=False, default="success")

    actor = relationship("Entity", back_populates="events")


class ContextLedgerEntry(Base):
    __tablename__ = "context_ledger"

    id = Column(Integer, primary_key=True, index=True)
    actor_id = Column(Integer, ForeignKey("entities.id"), nullable=False, index=True)
    reason = Column(String(32), nullable=False)
    valid_from = Column(DateTime, nullable=False)
    valid_until = Column(DateTime, nullable=False)
    effective_from = Column(DateTime, nullable=True)
    effective_until = Column(DateTime, nullable=True)
    allowed_resources = Column(JSON, nullable=False, default=list)
    allowed_actions = Column(JSON, nullable=False, default=list)
    approved_destinations = Column(JSON, nullable=True)
    approved_by = Column(String(128), nullable=False)
    # Content is append-only. Corrections create a pending successor and an
    # authorized reviewer changes only lifecycle metadata.
    approval_state = Column(String(16), nullable=False, default="approved", index=True)
    supersedes_id = Column(Integer, ForeignKey("context_ledger.id"), nullable=True)
    proposed_by = Column(String(128), nullable=True)
    proposed_at = Column(DateTime, nullable=False, default=utcnow)
    reviewed_by = Column(String(128), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_note = Column(Text, nullable=True)
    late_context = Column(Boolean, nullable=False, default=False)

    actor = relationship("Entity", back_populates="context_entries")


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    actor_id = Column(Integer, ForeignKey("entities.id"), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    status = Column(String(32), nullable=False, default="open")
    # Persisted current projection; GET routes never recompute assessment state.
    raw_deviation = Column(Float, nullable=False, default=0.0)
    context_coverage = Column(Float, nullable=False, default=0.0)
    residual_risk = Column(Float, nullable=False, default=0.0)
    confidence = Column(String(16), nullable=False, default="moderate")
    data_quality = Column(String(16), nullable=False, default="sufficient")
    residual_unresolved_count = Column(Integer, nullable=False, default=0)
    primary_cause = Column(Text, nullable=True)
    evidence = Column(JSON, nullable=False, default=list)
    matched_context_ids = Column(JSON, nullable=False, default=list)
    unmatched_behavior = Column(JSON, nullable=False, default=list)
    # Supporting JSON for API detail (event ids, breakdown, weights, etc.)
    event_ids = Column(JSON, nullable=False, default=list)
    change_point_timestamps = Column(JSON, nullable=False, default=list)
    explanation_breakdown = Column(JSON, nullable=False, default=list)
    baseline_weights = Column(JSON, nullable=False, default=dict)
    feature_snapshot = Column(JSON, nullable=False, default=dict)
    fusion_components = Column(JSON, nullable=False, default=dict)
    event_risk_breakdown = Column(JSON, nullable=False, default=list)
    retroactive_justification_review = Column(Boolean, nullable=False, default=False)
    current_assessment_id = Column(Integer, nullable=True)

    actor = relationship("Entity", back_populates="cases")
    feedback = relationship("AnalystFeedback", back_populates="case")
    event_links = relationship("CaseEvent", back_populates="case", cascade="all, delete-orphan")
    assessments = relationship("CaseAssessment", back_populates="case", cascade="all, delete-orphan")
    response_actions = relationship("ResponseAction", back_populates="case")


class CaseEvent(Base):
    """Relational evidence membership; prevents dangling JSON-only case links."""

    __tablename__ = "case_events"
    __table_args__ = (UniqueConstraint("case_id", "event_id"),)

    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    event_id = Column(Integer, ForeignKey("events.id", ondelete="RESTRICT"), nullable=False, index=True)
    added_at = Column(DateTime, nullable=False, default=utcnow)

    case = relationship("Case", back_populates="event_links")
    event = relationship("Event")


class CaseAssessment(Base):
    """Immutable, versioned output of one case computation."""

    __tablename__ = "case_assessments"

    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    trigger = Column(String(32), nullable=False)
    input_event_ids = Column(JSON, nullable=False, default=list)
    context_entry_ids = Column(JSON, nullable=False, default=list)
    result = Column(JSON, nullable=False, default=dict)

    case = relationship("Case", back_populates="assessments")


class AuditLog(Base):
    """Append-only record of security-sensitive API operations."""

    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False, default=utcnow, index=True)
    principal = Column(String(128), nullable=False, index=True)
    action = Column(String(64), nullable=False)
    resource_type = Column(String(64), nullable=False)
    resource_id = Column(String(128), nullable=True)
    details = Column(JSON, nullable=False, default=dict)
    succeeded = Column(Boolean, nullable=False, default=True)


class ResponseAction(Base):
    """Persisted response request; its state history is append-only."""

    __tablename__ = "response_actions"

    action_id = Column(String(64), primary_key=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True)
    entity_ref = Column(String(64), nullable=False, index=True)
    action_type = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False, default="proposed", index=True)
    mode = Column(String(64), nullable=False, default="sandbox")
    requested_by = Column(String(128), nullable=False)
    requested_at = Column(DateTime, nullable=False, default=utcnow)
    approved_by = Column(String(128), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    executed_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    rolled_back_at = Column(DateTime, nullable=True)
    failed_at = Column(DateTime, nullable=True)
    assessment_id = Column(Integer, ForeignKey("case_assessments.id"), nullable=True)
    scoring_version = Column(String(64), nullable=False)
    trigger_event_ids = Column(JSON, nullable=False, default=list)
    policy_rule_id = Column(String(64), nullable=False)
    policy_decision = Column(String(32), nullable=False)
    policy_reasons = Column(JSON, nullable=False, default=list)
    evidence_categories = Column(JSON, nullable=False, default=list)
    target_scope = Column(JSON, nullable=False, default=dict)
    blast_radius = Column(JSON, nullable=False, default=dict)
    approval_required = Column(Boolean, nullable=False, default=False)
    automatic = Column(Boolean, nullable=False, default=False)
    idempotency_key = Column(String(128), nullable=False, unique=True, index=True)
    execution_result = Column(JSON, nullable=True)
    verification_result = Column(JSON, nullable=True)
    rollback_result = Column(JSON, nullable=True)
    failure_reason = Column(Text, nullable=True)

    case = relationship("Case", back_populates="response_actions")
    transitions = relationship(
        "ResponseActionTransition", back_populates="response_action",
        cascade="all, delete-orphan", order_by="ResponseActionTransition.id",
    )


class ResponseActionTransition(Base):
    """Immutable state transition audit for a response action."""

    __tablename__ = "response_action_transitions"

    id = Column(Integer, primary_key=True)
    action_id = Column(
        String(64), ForeignKey("response_actions.action_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    from_status = Column(String(32), nullable=True)
    to_status = Column(String(32), nullable=False)
    principal = Column(String(128), nullable=False)
    timestamp = Column(DateTime, nullable=False, default=utcnow)
    note = Column(Text, nullable=True)
    details = Column(JSON, nullable=False, default=dict)

    response_action = relationship("ResponseAction", back_populates="transitions")


class SandboxEnforcementState(Base):
    """Current simulated control state. This never claims external enforcement."""

    __tablename__ = "sandbox_enforcement_state"
    __table_args__ = (UniqueConstraint("control_type", "target_key"),)

    id = Column(Integer, primary_key=True)
    control_type = Column(String(32), nullable=False, index=True)
    target_key = Column(String(256), nullable=False, index=True)
    entity_ref = Column(String(64), nullable=False, index=True)
    active = Column(Boolean, nullable=False, default=True)
    state = Column(JSON, nullable=False, default=dict)
    applied_by_action_id = Column(
        String(64), ForeignKey("response_actions.action_id"), nullable=False,
    )
    updated_at = Column(DateTime, nullable=False, default=utcnow)


class AccessRequest(Base):
    __tablename__ = "access_requests"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key"),
    )

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    subject_identity = Column(String(128), nullable=False, index=True)
    requester_identity = Column(String(128), nullable=False, index=True)
    resource_id = Column(String(256), nullable=False, index=True)
    resource_sensitivity = Column(String(32), nullable=False)
    requested_action = Column(String(64), nullable=False)
    requested_permission = Column(String(128), nullable=False)
    business_justification = Column(Text, nullable=False)
    requested_duration_seconds = Column(Integer, nullable=False)
    existing_entitlements = Column(JSON, nullable=False, default=list)
    device_trust = Column(String(32), nullable=False, default="unknown")
    authentication_strength = Column(String(32), nullable=False, default="single_factor")
    location_trust = Column(String(32), nullable=False, default="unknown")
    linked_case_id = Column(Integer, ForeignKey("cases.id"), nullable=True)
    external_status = Column(String(64), nullable=False, default="paused")
    workflow_state = Column(String(32), nullable=False, default="PAUSED", index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow)
    resolved_at = Column(DateTime, nullable=True)
    version = Column(Integer, nullable=False, default=1)
    idempotency_key = Column(String(128), nullable=False)
    policy_decision = Column(JSON, nullable=True)
    ai_review_status = Column(String(32), nullable=False, default="not_requested")
    break_glass = Column(Boolean, nullable=False, default=False)

    evidence = relationship("AccessEvidence", cascade="all, delete-orphan")
    approvals = relationship("ApprovalDecision", cascade="all, delete-orphan")
    transitions = relationship(
        "AccessRequestTransition", cascade="all, delete-orphan",
        order_by="AccessRequestTransition.id",
    )
    ai_reviews = relationship("AccessAIReview", cascade="all, delete-orphan")
    grant = relationship("AccessGrant", uselist=False, cascade="all, delete-orphan")


class AccessRequestTransition(Base):
    __tablename__ = "access_request_transitions"

    id = Column(Integer, primary_key=True)
    request_id = Column(
        String(64), ForeignKey("access_requests.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    tenant_id = Column(String(64), nullable=False, index=True)
    from_state = Column(String(32), nullable=True)
    to_state = Column(String(32), nullable=False)
    actor = Column(String(128), nullable=False)
    timestamp = Column(DateTime, nullable=False, default=utcnow)
    reason = Column(Text, nullable=True)
    metadata_json = Column(JSON, nullable=False, default=dict)


class AccessEvidence(Base):
    __tablename__ = "access_evidence"
    __table_args__ = (UniqueConstraint("tenant_id", "request_id", "evidence_hash"),)

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    request_id = Column(
        String(64), ForeignKey("access_requests.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    evidence_type = Column(String(64), nullable=False)
    source = Column(String(128), nullable=False)
    external_reference = Column(String(256), nullable=False)
    source_created_at = Column(DateTime, nullable=False)
    verified_at = Column(DateTime, nullable=True)
    verifier = Column(String(128), nullable=True)
    effective_from = Column(DateTime, nullable=False)
    effective_until = Column(DateTime, nullable=False)
    identity_scope = Column(JSON, nullable=False, default=list)
    resource_scope = Column(JSON, nullable=False, default=list)
    action_scope = Column(JSON, nullable=False, default=list)
    evidence_hash = Column(String(64), nullable=False)
    verification_status = Column(String(32), nullable=False, default="pending")
    created_at = Column(DateTime, nullable=False, default=utcnow)


class AccessGrant(Base):
    __tablename__ = "access_grants"

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    request_id = Column(
        String(64), ForeignKey("access_requests.id", ondelete="RESTRICT"),
        nullable=False, unique=True, index=True,
    )
    exact_resource = Column(String(256), nullable=False)
    exact_permission = Column(String(128), nullable=False)
    allowed_actions = Column(JSON, nullable=False, default=list)
    denied_actions = Column(JSON, nullable=False, default=list)
    maximum_ttl_seconds = Column(Integer, nullable=False)
    activated_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    required_authentication_strength = Column(String(32), nullable=False)
    approvers = Column(JSON, nullable=False, default=list)
    enforcement_state = Column(String(32), nullable=False, default="pending")
    connector_reference = Column(String(256), nullable=True)
    revocation_reason = Column(Text, nullable=True)
    idempotency_key = Column(String(128), nullable=False, unique=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow)


class ApprovalDecision(Base):
    __tablename__ = "approval_decisions"
    __table_args__ = (
        UniqueConstraint("request_id", "approver_identity", "approver_role"),
    )

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    request_id = Column(
        String(64), ForeignKey("access_requests.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    approver_identity = Column(String(128), nullable=False)
    approver_role = Column(String(64), nullable=False)
    decision = Column(String(32), nullable=False)
    note = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    policy_version = Column(String(64), nullable=False)


class AccessAIReview(Base):
    __tablename__ = "access_ai_reviews"

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    request_id = Column(
        String(64), ForeignKey("access_requests.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    provider = Column(String(64), nullable=False)
    model = Column(String(128), nullable=False)
    prompt_version = Column(String(64), nullable=False)
    sanitized_input_hash = Column(String(64), nullable=False, index=True)
    output = Column(JSON, nullable=True)
    latency_ms = Column(Integer, nullable=True)
    token_usage = Column(JSON, nullable=True)
    confidence = Column(Float, nullable=True)
    status = Column(String(32), nullable=False)
    failure_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class AuditRecord(Base):
    __tablename__ = "audit_records"
    __table_args__ = (UniqueConstraint("tenant_id", "record_hash"),)

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, default=utcnow, index=True)
    actor = Column(String(128), nullable=False)
    action = Column(String(128), nullable=False)
    aggregate_type = Column(String(64), nullable=False)
    aggregate_id = Column(String(64), nullable=False, index=True)
    correlation_id = Column(String(64), nullable=False, index=True)
    details = Column(JSON, nullable=False, default=dict)
    previous_record_hash = Column(String(64), nullable=True)
    record_hash = Column(String(64), nullable=False)


class TransactionalOutbox(Base):
    __tablename__ = "transactional_outbox"
    __table_args__ = (UniqueConstraint("tenant_id", "deduplication_key"),)

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    aggregate_type = Column(String(64), nullable=False)
    aggregate_id = Column(String(64), nullable=False, index=True)
    job_type = Column(String(64), nullable=False, index=True)
    payload = Column(JSON, nullable=False)
    status = Column(String(32), nullable=False, default="pending", index=True)
    attempts = Column(Integer, nullable=False, default=0)
    available_at = Column(DateTime, nullable=False, default=utcnow, index=True)
    locked_by = Column(String(128), nullable=True)
    lease_expires_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    deduplication_key = Column(String(256), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    processed_at = Column(DateTime, nullable=True)


class AccessNotification(Base):
    __tablename__ = "access_notifications"

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    recipient = Column(String(128), nullable=False, index=True)
    notification_type = Column(String(64), nullable=False)
    request_id = Column(String(64), ForeignKey("access_requests.id"), nullable=False)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    acknowledged_at = Column(DateTime, nullable=True)
    delivery_status = Column(String(32), nullable=False, default="pending")
    external_reference = Column(String(256), nullable=True)


class MutationIdempotency(Base):
    __tablename__ = "mutation_idempotency"
    __table_args__ = (UniqueConstraint("tenant_id", "operation", "idempotency_key"),)

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    operation = Column(String(128), nullable=False)
    idempotency_key = Column(String(128), nullable=False)
    request_hash = Column(String(64), nullable=False)
    response_status = Column(Integer, nullable=True)
    response_body = Column(JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)


_IMMUTABLE_CONTEXT_FIELDS = (
    "actor_id", "reason", "valid_from", "valid_until", "effective_from", "effective_until", "allowed_resources",
    "allowed_actions", "approved_destinations", "supersedes_id", "proposed_by",
    "proposed_at",
)


@event.listens_for(ContextLedgerEntry, "before_update")
def _prevent_context_content_update(mapper, connection, target) -> None:
    state = sa_inspect(target)
    changed = [name for name in _IMMUTABLE_CONTEXT_FIELDS if state.attrs[name].history.has_changes()]
    if changed:
        raise ValueError(f"Context content is immutable; create a successor revision ({', '.join(changed)})")


@event.listens_for(CaseAssessment, "before_update")
@event.listens_for(CaseAssessment, "before_delete")
def _prevent_assessment_mutation(mapper, connection, target) -> None:
    raise ValueError("Case assessments are append-only")


@event.listens_for(AuditLog, "before_update")
@event.listens_for(AuditLog, "before_delete")
def _prevent_audit_mutation(mapper, connection, target) -> None:
    raise ValueError("Audit records are append-only")


@event.listens_for(ResponseActionTransition, "before_update")
@event.listens_for(ResponseActionTransition, "before_delete")
def _prevent_response_transition_mutation(mapper, connection, target) -> None:
    raise ValueError("Response action transitions are append-only")


@event.listens_for(ApprovalDecision, "before_update")
@event.listens_for(ApprovalDecision, "before_delete")
@event.listens_for(AuditRecord, "before_update")
@event.listens_for(AuditRecord, "before_delete")
@event.listens_for(AccessRequestTransition, "before_update")
@event.listens_for(AccessRequestTransition, "before_delete")
def _prevent_jit_history_mutation(mapper, connection, target) -> None:
    raise ValueError("JIT access history is append-only")


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    verdict = Column(String(32), nullable=False)
    notes = Column(Text, nullable=True)
    timestamp = Column(DateTime, nullable=False, default=utcnow)

    case = relationship("Case", back_populates="feedback")


class CohortThreshold(Base):
    """Adjustable per-role ranking threshold (not a model retrain)."""

    __tablename__ = "cohort_thresholds"

    id = Column(Integer, primary_key=True, index=True)
    role = Column(String(64), nullable=False, unique=True, index=True)
    threshold = Column(Float, nullable=False, default=40.0)
    updated_at = Column(DateTime, nullable=False, default=utcnow)
