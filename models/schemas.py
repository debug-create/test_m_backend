"""Pydantic v2 request/response schemas."""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

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
)


class EntityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    display_name: str
    role: str
    department: str
    hire_date: datetime
    regime_state: RegimeState = RegimeState.nominal
    regime_feature: Optional[str] = "overall_deviation"


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    actor_id: int
    device_id: str
    action: ActionType
    resource_id: Optional[str] = None
    resource_classification: Optional[ResourceClassification] = None
    destination: Optional[str] = None
    volume: Optional[int] = None
    result: EventResult


class EventCreate(BaseModel):
    timestamp: datetime
    device_id: str
    action: ActionType
    resource_id: Optional[str] = None
    resource_classification: Optional[ResourceClassification] = None
    destination: Optional[str] = None
    volume: Optional[int] = Field(None, ge=0)
    result: EventResult = EventResult.success


class ContextLedgerEntryCreate(BaseModel):
    reason: ContextReason
    valid_from: datetime
    valid_until: datetime
    allowed_resources: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    approved_destinations: Optional[list[str]] = None
    approved_by: str
    # If set, update existing entry instead of creating
    id: Optional[int] = None


class ContextLedgerEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor_id: int
    reason: ContextReason
    valid_from: datetime
    valid_until: datetime
    allowed_resources: list[str]
    allowed_actions: list[str]
    approved_destinations: Optional[list[str]] = None
    approved_by: str


class EventExplanation(BaseModel):
    event_id: int
    timestamp: datetime
    action: str
    resource_id: Optional[str] = None
    destination: Optional[str] = None
    status: ExplanationStatus
    matched_context_ids: list[int] = Field(default_factory=list)
    match_details: dict[str, Any] = Field(default_factory=dict)


class CaseSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor_id: int
    actor_name: Optional[str] = None
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
    actor_id: int
    actor_name: Optional[str] = None
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
    fusion_components: dict[str, float] = Field(default_factory=dict)


class FeedbackCreate(BaseModel):
    verdict: FeedbackVerdict
    notes: Optional[str] = None


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
    actor_id: int
    change_point_timestamps: list[str]
    nodes: list[ShiftMapNode]
    edges: list[ShiftMapEdge]
    domains: list[str]
