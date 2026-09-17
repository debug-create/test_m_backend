"""Bearer-key authentication and scope-based authorization.

Keys are configured at runtime with FABLE_API_KEYS as JSON, for example:
{"viewer-key":{"subject":"soc-viewer","role":"viewer"}}
No built-in or fallback credential exists.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from config import load_settings


ROLE_SCOPES = {
    "viewer": {"read"},
    "ingestor": {"read", "events:write"},
    "analyst": {
        "read", "feedback:write", "access:read", "access:create",
        "access:evidence", "access:evaluate", "access:ai_review",
        "access:request_context",
    },
    "reviewer": {
        "read", "access:read", "access:approve", "access:deny",
        "access:revoke", "access:request_context", "access:evidence",
        "access:evidence:verify",
    },
    "resource_owner": {
        "read", "access:read", "access:approve", "access:deny",
        "access:revoke", "access:request_context", "access:evidence",
        "access:evidence:verify",
    },
    "context_proposer": {"read", "context:propose"},
    "context_approver": {"read", "context:approve"},
    "response_operator": {
        "read", "response:preview", "response:request", "response:execute",
        "response:rollback",
    },
    "response_approver": {"read", "response:approve"},
    "admin": {
        "read", "events:write", "feedback:write", "context:propose",
        "context:approve", "admin:reseed", "audit:read", "response:preview",
        "response:request", "response:approve", "response:execute",
        "response:rollback", "enforcement:read",
        "access:read", "access:create", "access:evidence", "access:evaluate",
        "access:evidence:verify",
        "access:ai_review", "access:request_context", "access:approve",
        "access:deny", "access:revoke", "access:admin",
    },
}


@dataclass(frozen=True)
class Principal:
    subject: str
    role: str
    scopes: frozenset[str]
    tenant_id: str = "default"
    resource_scopes: tuple[str, ...] = ()


bearer = HTTPBearer(auto_error=False)


def _configured_keys() -> dict[str, dict]:
    raw = os.getenv("FABLE_API_KEYS", "")
    if not raw:
        raise HTTPException(503, "Authentication is not configured")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(503, "Authentication configuration is invalid") from exc
    if not isinstance(parsed, dict) or not parsed:
        raise HTTPException(503, "Authentication configuration is invalid")
    return parsed


def authenticate(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(401, "Bearer token required", headers={"WWW-Authenticate": "Bearer"})

    settings = load_settings()
    if settings.auth_mode == "oidc":
        try:
            import jwt
            jwk_client = jwt.PyJWKClient(settings.oidc_jwks_url)
            signing_key = jwk_client.get_signing_key_from_jwt(credentials.credentials)
            claims = jwt.decode(
                credentials.credentials, signing_key.key,
                algorithms=["RS256", "ES256"], audience=settings.oidc_audience,
                issuer=settings.oidc_issuer,
            )
            role = str(claims.get("role", ""))
            subject = str(claims["sub"])
            tenant_id = str(claims.get("tenant_id", settings.tenant_default))
            resources = tuple(str(item) for item in claims.get("resources", []))
        except Exception as exc:
            raise HTTPException(
                401, "Invalid bearer token", headers={"WWW-Authenticate": "Bearer"}
            ) from exc
        if role not in ROLE_SCOPES:
            raise HTTPException(403, "Token role is not authorized")
        return Principal(
            subject=subject, role=role, scopes=frozenset(ROLE_SCOPES[role]),
            tenant_id=tenant_id, resource_scopes=resources,
        )

    record = None
    for candidate, value in _configured_keys().items():
        if secrets.compare_digest(credentials.credentials, candidate):
            record = value
    if record is None:
        raise HTTPException(401, "Invalid bearer token", headers={"WWW-Authenticate": "Bearer"})

    if isinstance(record, str):
        role, subject = record, record
        tenant_id = settings.tenant_default
        resources = ()
    else:
        role = str(record.get("role", ""))
        subject = str(record.get("subject", role))
        tenant_id = str(record.get("tenant_id", settings.tenant_default))
        resources = tuple(str(item) for item in record.get("resources", []))
        expires_at = record.get("expires_at")
        if expires_at is not None:
            try:
                if isinstance(expires_at, (int, float)):
                    expiry = datetime.fromtimestamp(float(expires_at), tz=timezone.utc)
                else:
                    expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError, OverflowError) as exc:
                raise HTTPException(503, "Authentication expiry configuration is invalid") from exc
            if expiry <= datetime.now(timezone.utc):
                raise HTTPException(401, "Bearer token has expired", headers={"WWW-Authenticate": "Bearer"})
    if role not in ROLE_SCOPES:
        raise HTTPException(503, "Authentication role is invalid")
    return Principal(
        subject=subject, role=role, scopes=frozenset(ROLE_SCOPES[role]),
        tenant_id=tenant_id, resource_scopes=resources,
    )


def require_scope(scope: str) -> Callable:
    def dependency(principal: Principal = Depends(authenticate)) -> Principal:
        if scope not in principal.scopes:
            raise HTTPException(403, f"Missing required scope: {scope}")
        return principal

    return dependency
