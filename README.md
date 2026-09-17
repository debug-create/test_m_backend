# Fable

Fable is a FastAPI backend for evidence-based behavioral-transition detection.
It compares activity with personal and cohort baselines, detects change points,
checks events against approved business context, and preserves uncertainty without
making an accusation.

The scoring path is deterministic and contains no LLM. This repository currently
uses SQLite for local development and demonstration.

## Quick start

Requirements: Python 3.10 or newer.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

$env:FABLE_API_KEYS = '{"viewer-demo":{"subject":"soc-viewer","role":"viewer"},"ingestor-demo":{"subject":"event-pipeline","role":"ingestor"},"proposer-demo":{"subject":"context-owner","role":"context_proposer"},"approver-demo":{"subject":"risk-approver","role":"context_approver"},"analyst-demo":{"subject":"soc-analyst","role":"analyst"},"admin-demo":{"subject":"local-admin","role":"admin"}}'

python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

The application creates or additively migrates `fable.db`. An empty database is
populated with demonstration scenarios at startup.

- Health: <http://127.0.0.1:8000/health>
- Swagger: <http://127.0.0.1:8000/docs>
- ReDoc: <http://127.0.0.1:8000/redoc>

Confirm authenticated access:

```powershell
curl.exe http://127.0.0.1:8000/entities `
  -H "Authorization: Bearer viewer-demo"
```

## Security model

All domain routes require a bearer key. `/health` is the only public route. There
are no built-in or fallback credentials. Set `FABLE_API_KEYS` to a JSON object whose
values identify a subject and role:

```powershell
$env:FABLE_API_KEYS = '{"local-view":{"subject":"soc-viewer","role":"viewer"},"local-admin":{"subject":"local-admin","role":"admin"}}'
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Supported roles and privileges:

| Role | Privileges |
|---|---|
| `viewer` | Read entities, events, context, and cases |
| `ingestor` | Read and ingest events |
| `analyst` | Read and submit case feedback |
| `context_proposer` | Read and propose context revisions |
| `context_approver` | Read and approve/reject context revisions |
| `response_operator` | Preview, request, execute, and roll back bounded responses |
| `response_approver` | Independently approve or reject high-impact responses |
| `admin` | All privileges, including audit-log access |

Context uses separation of duties: the proposer cannot review the same proposal.
Context content is append-only; a correction supplies `supersedes_id`, and only an
approved revision participates in an assessment. Proposals and reviews are audited.

`POST /admin/reseed` requires the `admin` role and is absent unless
`FABLE_ENABLE_RESEED=true` is explicitly set. It is intended only for local demos.

Use long, randomly generated keys and inject the JSON through a secret manager in a
deployed environment. Never commit actual keys to the repository.

## Privacy and CORS

API responses use stable opaque `entity_ref`/`actor_ref` values. Stored employee
names are not returned by the default API. CORS defaults to the two local frontend
origins on port 3000, credentials are disabled, and allowed methods/headers are
restricted. Configure comma-separated origins with `FABLE_CORS_ORIGINS`. The app
refuses to start if wildcard origins are combined with credentials.

## Risk semantics

Each assessment preserves three independent values:

- `raw_deviation`: noisy-OR of individual event raw risks.
- `context_coverage`: `Σ(event risk × context credit) / Σ(event risk)`.
- `residual_risk`: noisy-OR of event residual contributions.

For event `e`, `residual_e = raw_e × (1 − context_credit_e)`. Explained,
partially explained, and unexplained/indeterminate events receive credits `1`,
`0.5`, and `0`. Context is never a subtractive case-level term, and low-risk
explained events cannot mask a high-risk unexplained event.

Privilege changes, downloads of at least 1,000 volume units, and external uploads
retain a 25% event residual floor even when explained. Indeterminate events receive
zero credit and remain counted in `residual_unresolved_count`.

Event raw risk uses max within correlated categories and noisy-OR only across the
identity, resource-access, privilege, data-movement, and temporal-sequence
categories. Each category exposes its raw fields, signals, combination, and source.
The identity category includes the persisted offline Isolation Forest and login-risk
signal together, preventing correlated evidence from being counted twice.

Case evidence is relationally linked through `case_events`. Every computation adds
an immutable `case_assessments` snapshot containing its event and approved-context
inputs. GET routes return the current committed snapshot and do not recompute or
mutate database state.

Event explanation states are:

| State | Coverage credit | Meaning |
|---|---:|---|
| `explained` | `1.0` | An approved context revision covers the event |
| `partially_explained` | `0.5` | Context covers only part of the event |
| `unexplained` | `0.0` | No approved context covers the event |
| `indeterminate` | `0.0` | Required data or history is unavailable |

## Persistence and assessment history

The persistence model avoids JSON-only evidence relationships:

```text
Entity ──< Event
  │
  ├──< ContextLedgerEntry (append-only revisions)
  │
  └──< Case ──< CaseEvent >── Event
             └──< CaseAssessment (append-only snapshots)
```

`Case` stores the current projection for efficient ranking. `CaseAssessment` is the
historical source of how each projection was produced, including input event IDs,
considered approved-context IDs, the trigger, and the complete result. Reads use the
current committed projection. Event ingestion and approved context transitions are
the operations that create new assessments.

Case detail returns `original_assessment` and `current_assessment` side by side.
Context revisions expose explicit effective dates, creation/approval provenance,
and `late_context`. A late revision that increases coverage by at least 0.25 sets
`retroactive_justification_review=true`; it does not erase the original assessment.

Behavioral peers are assigned by deterministic k-means using only data at least
seven days old. Clusters smaller than three fall back to the broader role group so
recent drift cannot normalize itself or create an unstable comparison cohort.

## Autonomous response control plane

Fable implements a **Policy-bounded autonomous protective hold**. The response
layer consumes committed assessment snapshots and never changes detection,
context matching, cohort assignment, or scoring.

The deterministic ladder is:

| Tier | Actions | Authorization |
|---|---|---|
| Observe | `observe` | Automatic, audit/monitoring only |
| Verify | `step_up_auth` | Automatic, five-minute sandbox TTL |
| Protective hold | `block_external_upload`, `freeze_privilege_change`, `rate_limit_download` | Automatic only when every policy safeguard passes; 15-minute TTL |
| Human containment | `revoke_session`, `isolate_device`, `disable_account` | Different response approver required; never autonomous |

Automatic protective holds require residual priority of at least 75, an unresolved
high-risk or critical event, sufficient confidence (unless a decisive hard rule is
present), two independent evidence categories or one decisive hard rule, a narrow
evidence-backed target, and rollback/expiry. Sparse history, anomaly alone, or fully
covered pre-approved activity cannot independently authorize containment. Late
context does not silently cancel an active hold.

All enforcement is a persisted simulation by default. The sandbox records session,
destination, privilege, download-rate, device, account, monitoring, and step-up
state; verifies every change; supports idempotent retry, rollback, and injected time
for expiry. A lifespan worker applies due TTL expirations without making GET requests
mutate state. The adapter does not claim to operate Okta, Entra, a firewall, endpoint
agent, or cloud account.

NetworkX builds evidence graphs from persisted case events and performs deterministic
shortest-path and cycle analysis for blast-radius previews. Returned paths are
observed activity/evidence paths, not proven causality.

The workflow is a persisted deterministic state machine rather than LangGraph.
Every node is already deterministic, so adding LangGraph would increase dependency
and runtime risk without adding a safe orchestration capability. No LLM authorizes
or executes actions.

## API outline

Except for `/health`, send `Authorization: Bearer <key>`.

| Method | Path | Required privilege |
|---|---|---|
| `GET` | `/entities`, `/entities/{entity_ref}` | read |
| `GET` | `/entities/{entity_ref}/events` | read |
| `POST` | `/entities/{entity_ref}/events` | event ingestion |
| `GET` | `/entities/{entity_ref}/context` | read |
| `POST` | `/entities/{entity_ref}/context` | context proposal |
| `POST` | `/context/{entry_id}/review` | context approval |
| `GET` | `/cases`, `/cases/{case_id}` | read |
| `GET` | `/cases/{case_id}/counterfactual` | read |
| `POST` | `/cases/{case_id}/feedback` | analyst feedback |
| `GET` | `/cases/{case_id}/shift-map-data` | read |
| `GET` | `/cases/{case_id}/response-actions` | read |
| `POST` | `/cases/{case_id}/response-actions/preview` | response preview |
| `POST` | `/cases/{case_id}/response-actions` | response request |
| `POST` | `/response-actions/{action_id}/approve`, `/reject` | response approval |
| `POST` | `/response-actions/{action_id}/execute`, `/rollback` | response operation |
| `GET` | `/cases/{case_id}/evidence-graph` | read |
| `GET` | `/admin/enforcement-state` | admin enforcement-state read |
| `GET` | `/admin/audit` | audit access |
| `POST` | `/admin/reseed` | admin plus feature flag |

## Context revision example

First obtain an `entity_ref` from `GET /entities`. Then create a proposal. Replace
`ent_example` and `supersedes_id` with values returned by the API:

```bash
curl -X POST http://127.0.0.1:8000/entities/ent_example/context \
  -H "Authorization: Bearer proposer-demo" \
  -H "Content-Type: application/json" \
  -d '{
    "reason":"project",
    "effective_from":"2026-09-01T00:00:00Z",
    "effective_until":"2026-10-01T00:00:00Z",
    "allowed_resources":["migration-repo"],
    "allowed_actions":["repo_access"],
    "approved_destinations":null,
    "supersedes_id":2
  }'
```

The response is `202 Accepted` and remains `pending` until a different principal
with the context-approval role reviews it.

Approve it with a different bearer key:

```bash
curl -X POST http://127.0.0.1:8000/context/7/review \
  -H "Authorization: Bearer approver-demo" \
  -H "Content-Type: application/json" \
  -d '{"decision":"approved","note":"Change ticket verified"}'
```

Approval activates the revision, marks its predecessor as superseded, reassesses
only cases whose evidence overlaps the affected validity window, and appends an
audit record. Rejection records the review but does not affect assessments.

## Local reseed

Reseeding is deliberately off by default. To enable it for a local demo:

```powershell
$env:FABLE_ENABLE_RESEED = "true"
curl.exe -X POST http://127.0.0.1:8000/admin/reseed `
  -H "Authorization: Bearer admin-demo"
```

The endpoint deletes and recreates domain demonstration data while retaining the
audit history. Without both the feature flag and an admin key, it cannot run.

## Verification

```powershell
python -m pytest -q
```

The 175-test suite covers authorization, role enforcement, disabled destructive
operations, pseudonymous responses, the proposal/approval workflow, audit records,
non-mutating reads, immutable assessment history, uncertainty handling, exact-zero
full coverage for non-critical events, temporal guards, neutral narratives,
change-point behavior, response
policy, state transitions, sandbox verification, rollback/expiry, and graph isolation.

SQLite remains appropriate for the local demonstration. A production deployment
should move authentication to an identity provider, store key material in a secret
manager, use a migration framework, and use a production database.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `FABLE_API_KEYS` | unset | Required bearer-key/role JSON configuration |
| `FABLE_ENABLE_RESEED` | `false` | Enables the destructive local-demo reseed route |
| `FABLE_CORS_ORIGINS` | local port-3000 origins | Comma-separated browser origins |
| `FABLE_CORS_ALLOW_CREDENTIALS` | `false` | Enables browser credential handling |
| `FABLE_ENFORCEMENT_MODE` | `sandbox` | Selects enforcement adapter; this build implements sandbox only |

Wildcard CORS may be used only without credentials. Starting the application with
both wildcard origins and credentials enabled raises an error.

## Project layout

```text
api/routes.py             Authenticated HTTP routes and approval workflow
engine/behavior.py        Multi-window feature extraction
engine/baseline.py        Personal baseline and stable k-means behavioral cohorts
engine/changepoint.py     Page-Hinkley detection and latch state
engine/context.py         Per-event context classification and coverage
engine/fusion.py          Event-level categorized fusion, floors, and residual risk
engine/ml_signals.py      Cached inference from the persisted Isolation Forest
engine/case_builder.py    Assessment snapshots, ranking, feedback, shift maps
engine/response_policy.py Pure deterministic authorization policy
engine/response_graph.py  NetworkX evidence paths and blast-radius computation
engine/response_service.py Persisted response state machine and transitions
engine/sandbox_enforcement.py Simulated, verified, reversible enforcement
models/db_models.py       Relational persistence and immutability guards
models/schemas.py         Request and response contracts
security.py               Bearer authentication and role scopes
seed/scenarios.py         Local demonstration data
ml/train_models.py        Explicit offline synthetic-data training entry point
ml/*.joblib               Persisted deterministic non-LLM model artifact
tests/                    Unit, invariant, and end-to-end security tests
frontend_contract_bundle/ Sanitized OpenAPI and frontend recording fixtures
```

See [API_CONTRACT.md](API_CONTRACT.md) for request contracts and status behavior.

## Production notes

The current bearer-key implementation is intentionally small and suitable for a
controlled demo. Before production deployment:

- integrate an organizational identity provider and short-lived tokens;
- move from SQLite to a production database with managed schema migrations;
- send audit records to append-only external storage or a SIEM;
- enforce TLS at the ingress and rotate all secrets;
- define retention and access policies for event and assessment data;
- add rate limiting, request-size limits, monitoring, and backup recovery tests.
