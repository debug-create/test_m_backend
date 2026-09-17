"""Pure deterministic JIT access policy. AI output is never an input."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any


POLICY_VERSION = "jit-access-v1"
SENSITIVITY_TTL = {
    "public": 86400,
    "internal": 28800,
    "restricted": 14400,
    "critical": 3600,
}


@dataclass(frozen=True)
class AccessPolicyDecision:
    policy_decision_id: str
    eligibility: bool
    maximum_permission: str | None
    maximum_duration_seconds: int
    required_controls: list[str]
    required_approver_roles: list[str]
    missing_evidence: list[str]
    blocking_reasons: list[str]
    allowed_resources: list[str]
    explicitly_denied_resources: list[str]
    policy_version: str = POLICY_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_access_policy(inputs: dict[str, Any]) -> AccessPolicyDecision:
    verified = [item for item in inputs.get("evidence", [])
                if item.get("verification_status") == "verified"]
    evidence_types = {item["evidence_type"] for item in verified}
    resource = inputs["resource_id"]
    action = inputs["requested_action"]
    subject = inputs["subject_identity"]
    scoped = [
        item for item in verified
        if (not item.get("identity_scope") or subject in item["identity_scope"])
        and (not item.get("resource_scope") or resource in item["resource_scope"])
        and (not item.get("action_scope") or action in item["action_scope"])
    ]
    scoped_types = {item["evidence_type"] for item in scoped}
    sensitivity = inputs["resource_sensitivity"]
    required = ["mfa"]
    approvers = ["reviewer"]
    missing: list[str] = []
    blocked: list[str] = []

    if sensitivity in {"restricted", "critical"}:
        required.append("trusted_device")
        if inputs.get("device_trust") != "trusted":
            blocked.append("DEVICE_NOT_TRUSTED")
        if not scoped_types.intersection({"ticket", "incident", "project"}):
            missing.append("VERIFIED_BUSINESS_CONTEXT")
    if sensitivity == "critical":
        required[0] = "phishing_resistant_auth"
        approvers = ["resource_owner", "reviewer"]
        if "resource_owner_sponsorship" not in scoped_types:
            missing.append("RESOURCE_OWNER_SPONSORSHIP")
        if inputs.get("authentication_strength") != "phishing_resistant":
            blocked.append("STEP_UP_AUTH_REQUIRED")
    elif inputs.get("authentication_strength") not in {"mfa", "phishing_resistant"}:
        blocked.append("MFA_REQUIRED")
    if inputs.get("location_trust") == "untrusted":
        blocked.append("UNTRUSTED_LOCATION")

    critical_reasons = set(inputs.get("unresolved_critical_reasons", []))
    if critical_reasons.intersection({
        "external_upload", "external_destination", "privilege_change",
        "credential_theft",
    }):
        blocked.append("UNRESOLVED_CRITICAL_SECURITY_EVIDENCE")
    if inputs.get("conflicting_containment"):
        blocked.append("ACTIVE_CONTAINMENT_CONFLICT")
    if sensitivity not in SENSITIVITY_TTL:
        blocked.append("UNKNOWN_RESOURCE_SENSITIVITY")
    if not scoped and sensitivity != "public":
        missing.append("VERIFIED_SCOPED_EVIDENCE")

    break_glass = bool(inputs.get("break_glass"))
    if break_glass:
        if not inputs.get("is_admin"):
            blocked.append("BREAK_GLASS_ADMIN_REQUIRED")
        if len(inputs.get("business_justification", "").strip()) < 20:
            blocked.append("BREAK_GLASS_JUSTIFICATION_REQUIRED")
        approvers = ["admin"]
        required.extend(["post_event_review", "enhanced_monitoring"])

    maximum_duration = min(
        int(inputs["requested_duration_seconds"]),
        900 if break_glass else SENSITIVITY_TTL.get(sensitivity, 0),
    )
    eligible = not blocked and not missing
    canonical = json.dumps({
        "resource": resource, "action": action, "eligible": eligible,
        "blocked": sorted(set(blocked)), "missing": sorted(set(missing)),
        "version": POLICY_VERSION,
    }, sort_keys=True)
    decision_id = "pol_" + hashlib.sha256(canonical.encode()).hexdigest()[:20]
    return AccessPolicyDecision(
        policy_decision_id=decision_id,
        eligibility=eligible,
        maximum_permission=inputs["requested_permission"] if eligible else None,
        maximum_duration_seconds=maximum_duration,
        required_controls=sorted(set(required)),
        required_approver_roles=approvers,
        missing_evidence=sorted(set(missing)),
        blocking_reasons=sorted(set(blocked)),
        allowed_resources=[resource] if eligible else [],
        explicitly_denied_resources=[] if eligible else [resource],
    )
