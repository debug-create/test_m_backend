"""Shared enumerations for Fable."""

from enum import Enum


class ActionType(str, Enum):
    login = "login"
    file_access = "file_access"
    file_download = "file_download"
    repo_access = "repo_access"
    privilege_change = "privilege_change"
    external_upload = "external_upload"
    permission_request = "permission_request"


class ResourceClassification(str, Enum):
    public = "public"
    internal = "internal"
    restricted = "restricted"
    critical = "critical"


class EventResult(str, Enum):
    success = "success"
    failure = "failure"


class ContextReason(str, Enum):
    role_change = "role_change"
    project = "project"
    travel = "travel"
    maintenance = "maintenance"
    contract = "contract"


class CaseStatus(str, Enum):
    open = "open"
    reviewing = "reviewing"
    resolved = "resolved"
    reopened = "reopened"


class ConfidenceLevel(str, Enum):
    low = "low"
    moderate = "moderate"
    high = "high"


class DataQuality(str, Enum):
    sufficient = "sufficient"
    sparse = "sparse"
    insufficient = "insufficient"


class RegimeState(str, Enum):
    nominal = "nominal"
    latched = "latched"


class FeedbackVerdict(str, Enum):
    authorized = "authorized"
    policy_violation = "policy_violation"
    compromised = "compromised"
    benign_unusual = "benign_unusual"
    insufficient_evidence = "insufficient_evidence"


class ExplanationStatus(str, Enum):
    explained = "explained"
    partially_explained = "partially_explained"
    unexplained = "unexplained"
    indeterminate = "indeterminate"


class ResponseActionType(str, Enum):
    observe = "observe"
    step_up_auth = "step_up_auth"
    block_external_upload = "block_external_upload"
    freeze_privilege_change = "freeze_privilege_change"
    rate_limit_download = "rate_limit_download"
    revoke_session = "revoke_session"
    isolate_device = "isolate_device"
    disable_account = "disable_account"


class ResponseActionStatus(str, Enum):
    proposed = "proposed"
    auto_authorized = "auto_authorized"
    awaiting_approval = "awaiting_approval"
    approved = "approved"
    executing = "executing"
    active = "active"
    expired = "expired"
    rolled_back = "rolled_back"
    failed = "failed"
    rejected = "rejected"
