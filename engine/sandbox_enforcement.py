"""Persisted deterministic sandbox enforcement adapter.

No state in this module represents Okta, Entra, firewall, endpoint, or cloud
enforcement. It is an explicitly simulated control plane for tests and demos.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from models.db_models import AuditLog, ResponseAction, SandboxEnforcementState


CONTROL_TYPES = {
    "observe": ("monitoring", "entity_ref"),
    "step_up_auth": ("step_up_auth", "session"),
    "block_external_upload": ("upload_destination", "destination"),
    "freeze_privilege_change": ("privilege_change", "permission"),
    "rate_limit_download": ("download_rate_limit", "resource"),
    "revoke_session": ("session", "session"),
    "isolate_device": ("device_isolation", "device"),
    "disable_account": ("account_status", "entity_ref"),
}


def _now(value: datetime | None) -> datetime:
    return value or datetime.now(timezone.utc)


def _target(action: ResponseAction) -> tuple[str, str]:
    control_type, key = CONTROL_TYPES[action.action_type]
    value = (action.target_scope or {}).get(key)
    if value is None and key == "entity_ref":
        value = action.entity_ref
    if value is None:
        raise ValueError(f"target_scope.{key} is required for {action.action_type}")
    return control_type, str(value)


def execute(
    db: Session, action: ResponseAction, *, now: datetime | None = None,
    inject_failure: bool = False, inject_verification_failure: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    timestamp = _now(now)
    if inject_failure:
        raise RuntimeError("Injected sandbox connector failure")
    control_type, target_key = _target(action)
    state = db.query(SandboxEnforcementState).filter(
        SandboxEnforcementState.control_type == control_type,
        SandboxEnforcementState.target_key == target_key,
    ).first()
    idempotent = state is not None and state.active and state.applied_by_action_id == action.action_id
    if state is None:
        state = SandboxEnforcementState(
            control_type=control_type, target_key=target_key,
            entity_ref=action.entity_ref, applied_by_action_id=action.action_id,
        )
        db.add(state)
    if not idempotent:
        state.active = True
        state.applied_by_action_id = action.action_id
        state.updated_at = timestamp
        state.state = {
            "simulated": True,
            "action_type": action.action_type,
            "expires_at": action.expires_at.isoformat() if action.expires_at else None,
        }
    db.flush()
    result = {
        "adapter": "sandbox", "simulated": True, "control_type": control_type,
        "target_key": target_key, "applied": True, "idempotent_replay": idempotent,
    }
    verified = bool(state.active and state.applied_by_action_id == action.action_id)
    if inject_verification_failure:
        verified = False
    verification = {
        "verified": verified, "control_type": control_type,
        "target_key": target_key, "observed_active": bool(state.active),
    }
    db.add(AuditLog(
        timestamp=timestamp, principal="sandbox-adapter", action="response.enforce",
        resource_type="response_action", resource_id=action.action_id,
        details={"execution": result, "verification": verification}, succeeded=verified,
    ))
    db.flush()
    return result, verification


def rollback(
    db: Session, action: ResponseAction, *, now: datetime | None = None,
) -> dict[str, Any]:
    timestamp = _now(now)
    control_type, target_key = _target(action)
    state = db.query(SandboxEnforcementState).filter(
        SandboxEnforcementState.control_type == control_type,
        SandboxEnforcementState.target_key == target_key,
        SandboxEnforcementState.applied_by_action_id == action.action_id,
    ).first()
    was_active = bool(state and state.active)
    if state:
        state.active = False
        state.updated_at = timestamp
        state.state = {**(state.state or {}), "rolled_back_at": timestamp.isoformat()}
    result = {
        "adapter": "sandbox", "simulated": True, "control_type": control_type,
        "target_key": target_key, "rolled_back": True, "was_active": was_active,
    }
    db.add(AuditLog(
        timestamp=timestamp, principal="sandbox-adapter", action="response.rollback.enforce",
        resource_type="response_action", resource_id=action.action_id,
        details=result, succeeded=True,
    ))
    db.flush()
    return result


def enforcement_state(db: Session) -> list[dict[str, Any]]:
    rows = db.query(SandboxEnforcementState).order_by(
        SandboxEnforcementState.control_type, SandboxEnforcementState.target_key
    ).all()
    return [{
        "control_type": row.control_type, "target_key": row.target_key,
        "entity_ref": row.entity_ref, "active": row.active,
        "state": row.state, "applied_by_action_id": row.applied_by_action_id,
        "updated_at": row.updated_at,
    } for row in rows]
