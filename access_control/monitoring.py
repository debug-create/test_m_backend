from __future__ import annotations

from sqlalchemy.orm import Session

from access_control.service import notify, request_revocation
from models.db_models import AccessRequest, Case, Event


def monitor_event_against_active_grants(
    db: Session, event: Event, subject_ref: str, tenant_id: str,
) -> list[str]:
    """Detect scope drift; revocation remains durable even when AI is unavailable."""
    violations: list[str] = []
    requests = db.query(AccessRequest).filter(
        AccessRequest.tenant_id == tenant_id,
        AccessRequest.subject_identity == subject_ref,
        AccessRequest.workflow_state == "ACTIVE",
    ).all()
    for request in requests:
        grant = request.grant
        within = (
            event.resource_id == grant.exact_resource
            and event.action in (grant.allowed_actions or [])
        )
        if within:
            continue
        violations.append(request.id)
        notify(
            db, request, "scope_violation", "resource-reviewers",
            f"Scope violation detected for active grant {grant.id}",
        )
        hold_type = {
            "external_upload": "block_external_upload",
            "privilege_change": "freeze_privilege_change",
            "file_download": "rate_limit_download",
        }.get(event.action)
        if hold_type and request.linked_case_id:
            from engine.response_service import create_action, execute_action
            case = db.query(Case).filter(Case.id == request.linked_case_id).first()
            if case:
                scope = {
                    "block_external_upload": {
                        "destination": event.destination, "session": event.device_id,
                    },
                    "freeze_privilege_change": {
                        "permission": event.resource_id or "unspecified",
                        "session": event.device_id,
                    },
                    "rate_limit_download": {
                        "resource": event.resource_id, "session": event.device_id,
                    },
                }[hold_type]
                try:
                    hold = create_action(
                        db, case, hold_type, scope,
                        f"jit-scope-violation:{request.id}:{event.id}",
                        "continuous-monitor",
                        note="Active JIT grant scope violation",
                    )
                    if hold.status == "auto_authorized":
                        execute_action(db, hold, "continuous-monitor")
                except ValueError:
                    pass
        request_revocation(
            db, request, "continuous-monitor",
            f"Event {event.id} exceeded approved resource/action scope",
        )
    return violations
