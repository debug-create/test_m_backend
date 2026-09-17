"""Pure deterministic policy for bounded response actions.

This module reads committed assessment facts. It does not score behavior, call an
LLM, mutate persistence, or execute a connector.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from config import (
    RESPONSE_DEFAULT_TTL_MINUTES,
    RESPONSE_MIN_INDEPENDENT_CATEGORIES,
    RESPONSE_PRIORITY_THRESHOLD,
    RESPONSE_STEP_UP_TTL_MINUTES,
)


TIER0 = {"observe"}
TIER1 = {"step_up_auth"}
TIER2 = {"block_external_upload", "freeze_privilege_change", "rate_limit_download"}
TIER3 = {"revoke_session", "isolate_device", "disable_account"}
TERMINAL_STATUSES = {"expired", "rolled_back", "failed", "rejected"}


@dataclass(frozen=True)
class PolicyDecision:
    recommended_action: str
    allow: bool
    automatic: bool
    approval_required: bool
    policy_rule_id: str
    reasons: list[str]
    target_scope: dict[str, Any]
    ttl_seconds: int | None
    blast_radius: dict[str, Any]
    rollback_plan: dict[str, Any]
    evidence_categories: list[str]
    trigger_event_ids: list[int]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _supporting_evidence(case: dict[str, Any]) -> tuple[list[str], list[int], bool]:
    categories: set[str] = set()
    trigger_ids: list[int] = []
    decisive = False
    for row in case.get("event_risk_breakdown") or []:
        credit = float(row.get("context_credit", 0.0))
        raw = float(row.get("raw_risk", 0.0))
        reasons = row.get("critical_reasons") or []
        if credit < 1.0 and (raw >= 0.5 or reasons):
            trigger_ids.append(int(row["event_id"]))
            for name, detail in (row.get("categories") or {}).items():
                if float(detail.get("combined", 0.0)) > 0:
                    categories.add(name)
            decisive = decisive or bool(reasons)
    return sorted(categories), sorted(set(trigger_ids)), decisive


def _recommend(case: dict[str, Any]) -> str:
    rows = case.get("event_risk_breakdown") or []
    reasons = {reason for row in rows if float(row.get("context_credit", 0)) < 1
               for reason in (row.get("critical_reasons") or [])}
    if "external_upload" in reasons or "external_destination" in reasons:
        return "block_external_upload"
    if "privilege_change" in reasons:
        return "freeze_privilege_change"
    if "bulk_download" in reasons:
        return "rate_limit_download"
    if case.get("data_quality") in {"sparse", "insufficient"} or case.get("confidence") == "low":
        return "step_up_auth"
    return "observe"


def evaluate_response_policy(
    *,
    current_assessment: dict[str, Any],
    original_assessment: dict[str, Any],
    requested_action: str,
    target_scope: dict[str, Any],
    blast_radius: dict[str, Any],
    existing_active_actions: list[dict[str, Any]],
) -> PolicyDecision:
    """Return an auditable policy decision without side effects."""
    del original_assessment  # accepted explicitly; current committed facts govern action.
    categories, trigger_ids, decisive = _supporting_evidence(current_assessment)
    recommended = _recommend(current_assessment)
    duplicate = next(
        (item for item in existing_active_actions
         if item.get("action_type") == requested_action
         and item.get("target_scope") == target_scope
         and item.get("status") in {"auto_authorized", "approved", "executing", "active"}),
        None,
    )
    base = dict(
        recommended_action=recommended,
        target_scope=target_scope,
        blast_radius=blast_radius,
        evidence_categories=categories,
        trigger_event_ids=trigger_ids,
    )
    if duplicate:
        return PolicyDecision(
            **base, allow=False, automatic=False, approval_required=False,
            policy_rule_id="RP-DUPLICATE-001",
            reasons=[f"Equivalent control already exists as {duplicate['action_id']}"],
            ttl_seconds=None, rollback_plan={},
        )
    conflict_pairs = {
        frozenset({"step_up_auth", "revoke_session"}),
        frozenset({"step_up_auth", "disable_account"}),
        frozenset({"revoke_session", "disable_account"}),
        frozenset({"isolate_device", "disable_account"}),
    }
    requested_values = set(target_scope.values())
    conflict = next((
        item for item in existing_active_actions
        if item.get("status") in {"auto_authorized", "approved", "executing", "active"}
        and frozenset({requested_action, item.get("action_type")}) in conflict_pairs
        and (requested_values & set((item.get("target_scope") or {}).values())
             or "disable_account" in {requested_action, item.get("action_type")})
    ), None)
    if conflict:
        return PolicyDecision(
            **base, allow=False, automatic=False, approval_required=False,
            policy_rule_id="RP-CONFLICT-001",
            reasons=[f"Conflicts with active control {conflict['action_id']}"],
            ttl_seconds=None, rollback_plan={},
        )
    if requested_action in TIER0:
        return PolicyDecision(
            **base, allow=True, automatic=True, approval_required=False,
            policy_rule_id="RP-OBSERVE-001",
            reasons=["Observation changes audit/monitoring state only"],
            ttl_seconds=RESPONSE_DEFAULT_TTL_MINUTES * 60,
            rollback_plan={"operation": "expire"},
        )
    if requested_action in TIER1:
        return PolicyDecision(
            **base, allow=True, automatic=True, approval_required=False,
            policy_rule_id="RP-VERIFY-001",
            reasons=["Step-up verification is narrow, reversible, and time-limited"],
            ttl_seconds=RESPONSE_STEP_UP_TTL_MINUTES * 60,
            rollback_plan={"operation": "clear_step_up_requirement"},
        )

    priority = float(current_assessment.get("residual_risk", 0.0))
    confidence = current_assessment.get("confidence", "low")
    data_quality = current_assessment.get("data_quality", "insufficient")
    coverage = float(current_assessment.get("context_coverage", 0.0))
    safeguards: list[str] = []
    if priority < RESPONSE_PRIORITY_THRESHOLD:
        safeguards.append(f"Priority {priority:.4f} is below {RESPONSE_PRIORITY_THRESHOLD:.1f}")
    if not trigger_ids:
        safeguards.append("No unresolved high-risk or critical event supports containment")
    if len(categories) < RESPONSE_MIN_INDEPENDENT_CATEGORIES and not decisive:
        safeguards.append("Independent evidence threshold is not met")
    if confidence == "low" and not decisive:
        safeguards.append("Low confidence requires an independently decisive hard rule")
    if data_quality in {"sparse", "insufficient"} and not decisive:
        safeguards.append("Sparse or insufficient history cannot independently trigger containment")
    if coverage == 1.0 and not trigger_ids:
        safeguards.append("Activity is fully covered by approved prior context")
    if not target_scope:
        safeguards.append("A narrow target scope is required")
    if safeguards:
        return PolicyDecision(
            **base, allow=False, automatic=False,
            approval_required=requested_action in TIER3,
            policy_rule_id="RP-SAFETY-DENY-001", reasons=safeguards,
            ttl_seconds=None, rollback_plan={},
        )

    if requested_action in TIER2:
        return PolicyDecision(
            **base, allow=True, automatic=True, approval_required=False,
            policy_rule_id="RP-PROTECTIVE-HOLD-001",
            reasons=[
                "Priority threshold met",
                "Unresolved critical/high-risk evidence is present",
                "Scope is bounded and rollback is available",
                "Independent-category or decisive-hard-rule requirement met",
            ],
            ttl_seconds=RESPONSE_DEFAULT_TTL_MINUTES * 60,
            rollback_plan={"operation": "deactivate_control", "automatic_on_expiry": True},
        )
    if requested_action in TIER3:
        return PolicyDecision(
            **base, allow=True, automatic=False, approval_required=True,
            policy_rule_id="RP-HUMAN-CONTAINMENT-001",
            reasons=["High-impact containment requires independent human approval"],
            ttl_seconds=RESPONSE_DEFAULT_TTL_MINUTES * 60,
            rollback_plan={"operation": "restore_prior_sandbox_state"},
        )
    return PolicyDecision(
        **base, allow=False, automatic=False, approval_required=False,
        policy_rule_id="RP-UNKNOWN-001", reasons=["Unsupported action type"],
        ttl_seconds=None, rollback_plan={},
    )
