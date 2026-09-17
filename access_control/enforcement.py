"""JIT grant enforcement-provider contracts and implementations."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict

from config import load_settings
from models.db_models import AccessGrant


class ConnectorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    success: bool
    connector_reference: str
    state: str
    verified: bool


class EnforcementProvider(Protocol):
    name: str
    def activate(self, grant: AccessGrant, correlation_id: str) -> dict[str, Any]: ...
    def verify(self, grant: AccessGrant, correlation_id: str) -> dict[str, Any]: ...
    def revoke(self, grant: AccessGrant, correlation_id: str) -> dict[str, Any]: ...
    def health(self) -> dict[str, Any]: ...


class SandboxEnforcementProvider:
    name = "sandbox"

    def activate(self, grant: AccessGrant, correlation_id: str) -> dict[str, Any]:
        return {
            "success": True, "connector_reference": f"sandbox:{grant.id}",
            "state": "active", "verified": True, "simulated": True,
            "correlation_id": correlation_id,
        }

    def verify(self, grant: AccessGrant, correlation_id: str) -> dict[str, Any]:
        return {
            "success": grant.enforcement_state == "active",
            "connector_reference": grant.connector_reference or f"sandbox:{grant.id}",
            "state": grant.enforcement_state,
            "verified": grant.enforcement_state == "active",
            "simulated": True, "correlation_id": correlation_id,
        }

    def revoke(self, grant: AccessGrant, correlation_id: str) -> dict[str, Any]:
        return {
            "success": True, "connector_reference": grant.connector_reference or f"sandbox:{grant.id}",
            "state": "revoked", "verified": True, "simulated": True,
            "correlation_id": correlation_id,
        }

    def health(self) -> dict[str, Any]:
        return {"healthy": True, "provider": self.name, "simulated": True}


@dataclass
class SignedWebhookEnforcementProvider:
    url: str
    secret: str
    timeout_seconds: float = 10
    max_retries: int = 2
    client: httpx.Client | None = None
    name: str = "signed_webhook"

    def __post_init__(self) -> None:
        parsed = urlparse(self.url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username:
            raise ValueError("Enforcement webhook must be an allowlisted HTTPS URL")
        self.client = self.client or httpx.Client(timeout=self.timeout_seconds)

    def _call(
        self, operation: str, grant: AccessGrant, correlation_id: str,
    ) -> dict[str, Any]:
        body = {
            "operation": operation, "grant_id": grant.id,
            "tenant_id": grant.tenant_id, "resource": grant.exact_resource,
            "permission": grant.exact_permission,
            "allowed_actions": grant.allowed_actions,
            "expires_at": grant.expires_at.isoformat() if grant.expires_at else None,
            "idempotency_key": f"{grant.idempotency_key}:{operation}",
            "correlation_id": correlation_id,
        }
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        signature = hmac.new(
            self.secret.encode(), timestamp.encode() + b"." + nonce.encode() + b"." + encoded,
            hashlib.sha256,
        ).hexdigest()
        response = None
        for attempt in range(self.max_retries + 1):
            response = self.client.post(
                self.url, content=encoded,
                headers={
                    "Content-Type": "application/json",
                    "X-Fable-Timestamp": timestamp,
                    "X-Fable-Nonce": nonce,
                    "X-Fable-Signature": f"sha256={signature}",
                    "Idempotency-Key": body["idempotency_key"],
                    "X-Correlation-ID": correlation_id,
                },
            )
            if response.status_code != 429 and response.status_code < 500:
                break
            if attempt < self.max_retries:
                time.sleep(0.25 * (2 ** attempt))
        assert response is not None
        response.raise_for_status()
        return ConnectorResponse.model_validate(response.json()).model_dump()

    def activate(self, grant: AccessGrant, correlation_id: str) -> dict[str, Any]:
        return self._call("activate", grant, correlation_id)

    def verify(self, grant: AccessGrant, correlation_id: str) -> dict[str, Any]:
        return self._call("verify", grant, correlation_id)

    def revoke(self, grant: AccessGrant, correlation_id: str) -> dict[str, Any]:
        return self._call("revoke", grant, correlation_id)

    def health(self) -> dict[str, Any]:
        response = self.client.get(self.url, headers={"X-Fable-Operation": "health"})
        return {"healthy": response.is_success, "provider": self.name}


def configured_enforcement_provider() -> EnforcementProvider:
    settings = load_settings()
    if settings.enforcement_mode == "sandbox":
        return SandboxEnforcementProvider()
    if settings.enforcement_mode == "signed_webhook":
        if not settings.enforcement_webhook_url or not settings.enforcement_webhook_secret:
            raise RuntimeError("Signed webhook enforcement is not fully configured")
        return SignedWebhookEnforcementProvider(
            settings.enforcement_webhook_url,
            settings.enforcement_webhook_secret,
            timeout_seconds=settings.groq_timeout_seconds,
        )
    raise RuntimeError(f"Unsupported enforcement provider: {settings.enforcement_mode}")
