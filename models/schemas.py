"""Pydantic v2 request/response schemas."""

from datetime import datetime
import re
from typing import Annotated, Any, Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from models.enums import (
    ActionType,
    CaseStatus,
    ConfidenceLevel,
    ContextReason,
    DataQuality,
    EventResult,
    ExplanationStatus,
    FeedbackVerdict,
    RegimeState,
    ResourceClassification,
    ResponseActionStatus,
    ResponseActionType,
)


ShortText = Annotated[str, Field(min_length=1, max_length=256)]
DeviceText = Annotated[str, Field(min_length=1, max_length=128)]


def _safe_note(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if len(value) > 2000:
        raise ValueError("text exceeds 2000 characters")
    if "\x00" in value or re.search(r"(?:;\s*(?:drop|delete|update|insert|alter)\b|--|/\*)", value, re.I):
        raise ValueError("unsafe control or query-shaped text")
    return value


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class EntityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    entity_ref: str
    role: str
    department: str
    hire_date: datetime
    regime_state: RegimeState = RegimeState.nominal
    regime_feature: Optional[str] = "overall_deviation"


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    actor_ref: str
    device_id: str
    action: ActionType
    resource_id: Optional[str] = None
    resource_classification: Optional[ResourceClassification] = None
    destination: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    volume: Optional[int] = None
    result: EventResult


class EventCreate(StrictRequest):
    timestamp: datetime
    device_id: DeviceText
    action: ActionType
    resource_id: Optional[ShortText] = None
    resource_classification: Optional[ResourceClassification] = None
    destination: Optional[ShortText] = None
    latitude: Optional[float] = Field(None, ge=-90, le=90)
    longitude: Optional[float] = Field(None, ge=-180, le=180)
    volume: Optional[int] = Field(None, ge=0)
    result: EventResult = EventResult.success


class ContextLedgerEntryCreate(StrictRequest):
    reason: ContextReason
    effective_from: datetime = Field(validation_alias=AliasChoices("effective_from", "valid_from"))
    effective_until: datetime = Field(validation_alias=AliasChoices("effective_until", "valid_until"))
    allowed_resources: list[ShortText] = Field(default_factory=list, max_length=100)
    allowed_actions: list[ShortText] = Field(default_factory=list, max_length=50)
    approved_destinations: Optional[list[ShortText]] = Field(None, max_length=100)
    # Corrections are new immutable proposals referring to the old entry.
    supersedes_id: Optional[int] = None


class ContextLedgerEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor_ref: str
    reason: ContextReason
    valid_from: datetime
    valid_until: datetime
    effective_from: datetime
    effective_until: datetime
    allowed_resources: list[str]
    allowed_actions: list[str]
    approved_destinations: Optional[list[str]] = None
    approved_by: str
    approval_state: str
    supersedes_id: Optional[int] = None
    proposed_by: Optional[str] = None
    proposed_at: datetime
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_note: Optional[str] = None
    created_at: datetime
    approved_at: Optional[datetime] = None
    late_context: bool = False


class ContextReview(StrictRequest):
    decision: str = Field(pattern="^(approved|rejected)$")
    note: Optional[str] = Field(None, max_length=2000)

    _validate_note = field_validator("note")(_safe_note)


class EventExplanation(BaseModel):
    event_id: int
    timestamp: datetime
    action: str
    resource_id: Optional[str] = None
    destination: Optional[str] = None
    status: ExplanationStatus
    matched_context_ids: list[int] = Field(default_factory=list)
    match_details: dict[str, Any] = Field(default_factory=dict)


class EventRiskContribution(BaseModel):
    event_id: int
    raw_risk: float
    context_credit: float
    residual_before_floor: float
    critical_floor: float
    critical_reasons: list[str] = Field(default_factory=list)
    residual_contribution: float
    marginal_case_contribution: float
    categories: dict[str, Any] = Field(default_factory=dict)


class CaseSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor_ref: str
    created_at: datetime
    status: CaseStatus
    raw_deviation: float
    context_coverage: float
    residual_risk: float
    confidence: ConfidenceLevel
    data_quality: DataQuality = DataQuality.sufficient
    residual_unresolved_count: int = 0
    primary_cause: Optional[str] = None
    hard_rule_flag: bool = False


class CaseDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor_ref: str
    created_at: datetime
    status: CaseStatus
    raw_deviation: float
    context_coverage: float
    residual_risk: float
    confidence: ConfidenceLevel
    data_quality: DataQuality = DataQuality.sufficient
    residual_unresolved_count: int = 0
    primary_cause: Optional[str] = None
    evidence: list[str]
    matched_context_ids: list[int]
    unmatched_behavior: list[str]
    event_ids: list[int]
    change_point_timestamps: list[str]
    explanation_breakdown: list[EventExplanation]
    baseline_weights: dict[str, Any]
    feature_snapshot: dict[str, Any]
    fusion_components: dict[str, Any] = Field(default_factory=dict)
    event_risk_breakdown: list[EventRiskContribution] = Field(default_factory=list)
    retroactive_justification_review: bool = False
    original_assessment: dict[str, Any] = Field(default_factory=dict)
    current_assessment: dict[str, Any] = Field(default_factory=dict)


class FeedbackCreate(StrictRequest):
    verdict: FeedbackVerdict
    notes: Optional[str] = Field(None, max_length=2000)

    _validate_notes = field_validator("notes")(_safe_note)


class FeedbackOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int
    verdict: FeedbackVerdict
    notes: Optional[str] = None
    timestamp: datetime
    case_status: CaseStatus
    cohort_threshold_adjustment: dict[str, Any]


class CounterfactualComponent(BaseModel):
    component: str
    description: str
    residual_risk_without: float
    delta: float


class CounterfactualOut(BaseModel):
    case_id: int
    residual_risk: float
    components: list[CounterfactualComponent]


class ShiftMapNode(BaseModel):
    id: str
    type: str  # entity | resource | device | destination
    label: str
    meta: dict[str, Any] = Field(default_factory=dict)


class ShiftMapEdge(BaseModel):
    id: str
    source: str
    target: str
    timestamp: datetime
    action: str
    explanation_status: ExplanationStatus
    event_id: int


class ShiftMapData(BaseModel):
    case_id: int
    actor_ref: str
    change_point_timestamps: list[str]
    nodes: list[ShiftMapNode]
    edges: list[ShiftMapEdge]
    domains: list[str]


class ResponseActionRequest(StrictRequest):
    action_type: ResponseActionType
    target_scope: dict[str, ShortText] = Field(default_factory=dict)
    idempotency_key: Annotated[str, Field(min_length=8, max_length=128)]
    note: Optional[str] = Field(None, max_length=2000)

    _validate_note = field_validator("note")(_safe_note)


class ResponseActionPreviewRequest(StrictRequest):
    action_type: ResponseActionType
    target_scope: dict[str, ShortText] = Field(default_factory=dict)


class ResponseActionDecision(StrictRequest):
    note: Annotated[str, Field(min_length=3, max_length=2000)]

    _validate_note = field_validator("note")(_safe_note)


class ResponseActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    action_id: str
    case_id: int
    entity_ref: str
    action_type: ResponseActionType
    status: ResponseActionStatus
    mode: str
    requested_by: str
    requested_at: datetime
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    rolled_back_at: Optional[datetime] = None
    failed_at: Optional[datetime] = None
    assessment_id: Optional[int] = None
    scoring_version: str
    trigger_event_ids: list[int]
    policy_rule_id: str
    policy_decision: str
    policy_reasons: list[str]
    evidence_categories: list[str]
    target_scope: dict[str, Any]
    blast_radius: dict[str, Any]
    approval_required: bool
    automatic: bool
    idempotency_key: str
    execution_result: Optional[dict[str, Any]] = None
    verification_result: Optional[dict[str, Any]] = None
    rollback_result: Optional[dict[str, Any]] = None
    failure_reason: Optional[str] = None
    transitions: list[dict[str, Any]] = Field(default_factory=list)


class ResponsePreviewOut(BaseModel):
    case_id: int
    entity_ref: str
    requested_action: ResponseActionType
    recommended_action: ResponseActionType
    allow: bool
    automatic: bool
    approval_required: bool
    policy_rule_id: str
    reasons: list[str]
    target_scope: dict[str, Any]
    ttl_seconds: Optional[int] = None
    blast_radius: dict[str, Any]
    rollback_plan: dict[str, Any]
    evidence_categories: list[str]
    trigger_event_ids: list[int]


class EvidenceGraphOut(BaseModel):
    case_id: int
    entity_ref: str
    generated_at: datetime
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    evidence_paths: list[list[str]]
    cycles: list[list[str]]
