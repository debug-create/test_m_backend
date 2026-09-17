from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _safe_text(value: str) -> str:
    lowered = value.lower()
    if len(value) > 4000 or "\x00" in value:
        raise ValueError("invalid text")
    if any(marker in lowered for marker in (
        "ignore previous instructions", "system prompt", "<script", "javascript:"
    )):
        raise ValueError("instruction-shaped or executable text is not accepted")
    return value


class AccessRequestCreate(StrictModel):
    subject_identity: str = Field(min_length=3, max_length=128)
    resource_id: str = Field(min_length=1, max_length=256)
    resource_sensitivity: Literal["public", "internal", "restricted", "critical"]
    requested_action: str = Field(min_length=1, max_length=64)
    requested_permission: str = Field(min_length=1, max_length=128)
    business_justification: str = Field(min_length=10, max_length=4000)
    requested_duration_seconds: int = Field(ge=60, le=86400)
    linked_case_id: int | None = None
    existing_entitlements: list[str] = Field(default_factory=list, max_length=100)
    device_trust: Literal["trusted", "untrusted", "unknown"] = "unknown"
    authentication_strength: Literal["single_factor", "mfa", "phishing_resistant"] = "single_factor"
    location_trust: Literal["trusted", "untrusted", "unknown"] = "unknown"
    break_glass: bool = False

    _validate_justification = field_validator("business_justification")(_safe_text)


class EvidenceCreate(StrictModel):
    evidence_type: Literal[
        "ticket", "incident", "project", "resource_owner_sponsorship",
        "identity_verification", "device_attestation", "location_attestation",
    ]
    source: str = Field(min_length=2, max_length=128)
    external_reference: str = Field(min_length=2, max_length=256)
    source_created_at: datetime
    effective_from: datetime
    effective_until: datetime
    identity_scope: list[str] = Field(default_factory=list, max_length=100)
    resource_scope: list[str] = Field(default_factory=list, max_length=100)
    action_scope: list[str] = Field(default_factory=list, max_length=100)
    verification_status: Literal["pending", "verified", "rejected"] = "pending"


class ContextRequest(StrictModel):
    note: str = Field(min_length=3, max_length=2000)
    _validate_note = field_validator("note")(_safe_text)


class ApprovalCreate(ContextRequest):
    decision: Literal["approve", "deny"]
    expected_version: int = Field(ge=1)


class RevokeCreate(ContextRequest):
    expected_version: int = Field(ge=1)


class BreakGlassCreate(ContextRequest):
    duration_seconds: int = Field(ge=60, le=900)
    expected_version: int = Field(ge=1)


class AIReviewOutput(StrictModel):
    recommendation: Literal["APPROVE_SCOPED", "REQUEST_MORE_CONTEXT", "DENY_AND_ESCALATE"]
    risk_summary: str
    recommended_permission: str
    recommended_duration_seconds: int = Field(ge=0, le=86400)
    required_controls: list[str]
    reason_codes: list[str]
    missing_evidence: list[str]
    confidence: float = Field(ge=0, le=1)
    human_explanation: str


class AccessRequestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    subject_identity: str
    requester_identity: str
    resource_id: str
    resource_sensitivity: str
    requested_action: str
    requested_permission: str
    business_justification: str
    requested_duration_seconds: int
    linked_case_id: int | None
    external_status: str
    workflow_state: str
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None
    version: int
    policy_decision: dict[str, Any] | None
    ai_review_status: str
    ai_advisory_only: bool = True
    required_approvers: list[str] = Field(default_factory=list)
    available_actions: list[str] = Field(default_factory=list)
    requested_scope: dict[str, Any]
    approved_scope: dict[str, Any] | None = None
    unaffected_resources: list[str] = Field(default_factory=list)
    enforcement_verification: dict[str, Any] | None = None


class NotificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    notification_type: str
    request_id: str
    message: str
    created_at: datetime
    acknowledged_at: datetime | None
    delivery_status: str
