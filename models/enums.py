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
