"""Fable runtime and detector configuration."""

from dataclasses import dataclass
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_URL = os.getenv("FABLE_DATABASE_URL", f"sqlite:///{BASE_DIR / 'fable.db'}")

# Suspicious sequence window (hours)
SUSPICIOUS_SEQUENCE_WINDOW_HOURS = 48

# Page-Hinkley detector defaults
PH_DELTA = 0.05
PH_LAMBDA = 2.5
PH_ALPHA = 0.01  # forgetting factor for running mean

# History / cohort thresholds
MIN_PERSONAL_HISTORY_DAYS = 14
ROLE_CHANGE_BLEND_DAYS = 30
MIN_COHORT_SIZE = 3
CLUSTER_EXCLUSION_DAYS = 7

# Baseline mixing defaults
ALPHA_ESTABLISHED = 0.65
BETA_ESTABLISHED = 0.25
GAMMA_ESTABLISHED = 0.10

ALPHA_NEW = 0.10
BETA_NEW = 0.70
GAMMA_NEW = 0.20

# Feature windows (seconds)
WINDOW_15M = 15 * 60
WINDOW_24H = 24 * 3600
WINDOW_7D = 7 * 24 * 3600
WINDOW_30D = 30 * 24 * 3600

SENSITIVE_CLASSIFICATIONS = {"restricted", "critical"}
DOWNLOAD_ACTIONS = {"file_download", "external_upload"}

# Response-policy constants. Detection scores are read-only inputs to this layer.
RESPONSE_PRIORITY_THRESHOLD = 75.0
RESPONSE_DEFAULT_TTL_MINUTES = 15
RESPONSE_STEP_UP_TTL_MINUTES = 5
RESPONSE_MIN_INDEPENDENT_CATEGORIES = 2
RESPONSE_SCORING_VERSION = "event-fusion-v2"


@dataclass(frozen=True)
class ProductionSettings:
    environment: str
    database_url: str
    redis_url: str | None
    auth_mode: str
    oidc_issuer: str | None
    oidc_audience: str | None
    oidc_jwks_url: str | None
    enforcement_mode: str
    enforcement_webhook_url: str | None
    enforcement_webhook_secret: str | None
    notification_webhook_url: str | None
    notification_webhook_secret: str | None
    groq_enabled: bool
    groq_model: str
    groq_timeout_seconds: float
    groq_max_retries: int
    groq_max_concurrency: int
    groq_confidence_threshold: float
    groq_prompt_version: str
    tenant_default: str
    debug: bool


def load_settings() -> ProductionSettings:
    truthy = {"1", "true", "yes", "on"}
    return ProductionSettings(
        environment=os.getenv("FABLE_ENV", "development").lower(),
        database_url=os.getenv("FABLE_DATABASE_URL", DATABASE_URL),
        redis_url=os.getenv("FABLE_REDIS_URL"),
        auth_mode=os.getenv("FABLE_AUTH_MODE", "api_key").lower(),
        oidc_issuer=os.getenv("FABLE_OIDC_ISSUER"),
        oidc_audience=os.getenv("FABLE_OIDC_AUDIENCE"),
        oidc_jwks_url=os.getenv("FABLE_OIDC_JWKS_URL"),
        enforcement_mode=os.getenv("FABLE_ENFORCEMENT_MODE", "sandbox").lower(),
        enforcement_webhook_url=os.getenv("FABLE_ENFORCEMENT_WEBHOOK_URL"),
        enforcement_webhook_secret=os.getenv("FABLE_ENFORCEMENT_WEBHOOK_SECRET"),
        notification_webhook_url=os.getenv("FABLE_NOTIFICATION_WEBHOOK_URL"),
        notification_webhook_secret=os.getenv("FABLE_NOTIFICATION_WEBHOOK_SECRET"),
        groq_enabled=os.getenv("GROQ_ENABLED", "false").lower() in truthy,
        groq_model=os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"),
        groq_timeout_seconds=float(os.getenv("GROQ_TIMEOUT_SECONDS", "10")),
        groq_max_retries=int(os.getenv("GROQ_MAX_RETRIES", "2")),
        groq_max_concurrency=int(os.getenv("GROQ_MAX_CONCURRENCY", "4")),
        groq_confidence_threshold=float(os.getenv("GROQ_CONFIDENCE_THRESHOLD", "0.7")),
        groq_prompt_version=os.getenv("GROQ_PROMPT_VERSION", "jit-review-v1"),
        tenant_default=os.getenv("FABLE_DEFAULT_TENANT", "default"),
        debug=os.getenv("FABLE_DEBUG", "false").lower() in truthy,
    )


def validate_production_settings(settings: ProductionSettings | None = None) -> None:
    value = settings or load_settings()
    if value.environment != "production":
        return
    errors = []
    if not value.database_url.startswith(("postgresql://", "postgresql+psycopg://")):
        errors.append("production requires PostgreSQL")
    if not value.redis_url:
        errors.append("production requires FABLE_REDIS_URL")
    if value.auth_mode != "oidc" or not all(
        [value.oidc_issuer, value.oidc_audience, value.oidc_jwks_url]
    ):
        errors.append("production requires complete OIDC configuration")
    if value.enforcement_mode != "signed_webhook":
        errors.append("production requires signed_webhook enforcement")
    if not value.enforcement_webhook_url or not value.enforcement_webhook_secret:
        errors.append("production enforcement webhook is incomplete")
    if value.enforcement_webhook_secret in {"secret", "changeme", "default"}:
        errors.append("default webhook signing secret is forbidden")
    if value.debug:
        errors.append("debug mode is forbidden in production")
    if os.getenv("FABLE_ENABLE_RESEED", "").lower() in {"1", "true", "yes"}:
        errors.append("demo reseeding is forbidden in production")
    if errors:
        raise RuntimeError("Invalid production configuration: " + "; ".join(errors))
