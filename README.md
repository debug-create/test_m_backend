# Fable

Fable is a FastAPI backend that turns behavioral evidence and verified business context into auditable risk assessments, bounded response actions, and temporary just-in-time (JIT) access decisions. Detection is deterministic; the optional Groq review is advisory and cannot grant access or override policy.

The repository supports a local SQLite demo and includes PostgreSQL/Alembic persistence code. It has no checked-in Vercel configuration, so the live deployment cannot be reproduced or verified from this repository alone.

## Quick start

Python 3.10 or newer is required.

```powershell
cd test_m_backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:FABLE_API_KEYS = '{"viewer-demo":{"subject":"soc-viewer","role":"viewer"},"ingestor-demo":{"subject":"event-pipeline","role":"ingestor"},"analyst-demo":{"subject":"soc-analyst","role":"analyst"},"reviewer-demo":{"subject":"risk-reviewer","role":"reviewer"},"owner-demo":{"subject":"resource-owner","role":"resource_owner","resources":["finance-archive"]},"proposer-demo":{"subject":"context-owner","role":"context_proposer"},"approver-demo":{"subject":"risk-approver","role":"context_approver"},"operator-demo":{"subject":"response-operator","role":"response_operator"},"response-approver-demo":{"subject":"response-approver","role":"response_approver"},"admin-demo":{"subject":"local-admin","role":"admin"}}'
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Development startup calls `init_db()`, creates/additively updates `fable.db`, and calls `seed.scenarios.run_seed()` when `entities` is empty. `/health`, `/docs`, `/redoc`, and `/openapi.json` are public.

JIT work is stored in `transactional_outbox` but is not processed by the API process. Run the worker separately when testing AI review, enforcement, expiry, revocation, or notification delivery:

```powershell
.\.venv\Scripts\Activate.ps1
python -m access_control.worker
```

Run tests with `python -m pytest -q`.

## Verified live example

`tests/test_api_workflows.py::test_context_requires_separate_proposal_and_approval` submits and approves an immutable context successor for Arjun. The pending proposal changes no score; approval appends a `CaseAssessment` and produces:

| Stage | `raw_deviation` | `context_coverage` | `residual_risk` |
|---|---:|---:|---:|
| Before approval | `100.0000` | `0.5905` | `100.0000` |
| After approval | `100.0000` | `1.0000` | `43.7500` |

The remaining `43.75` is deliberate. The explained bulk download and external upload each retain `CRITICAL_EVENT_FLOOR = 0.25`, so noisy-OR gives `1 - (1 - 0.25) * (1 - 0.25) = 0.4375`.

## How it works

1. `engine/behavior.py`: `compute_feature_vector()` evaluates `WINDOWS = {15m, 24h, 7d, 30d}` and exposes `24h` as `primary`. `FEATURE_KEYS` are `login_hour_irregularity`, `new_device_count`, `new_resource_count`, `sensitive_access_ratio`, `download_volume_vs_baseline`, `privilege_change_count`, `external_destination_novelty`, `suspicious_sequence_flag`, and `suspicious_sequence_magnitude`. `login_risk_features()` caps geo velocity at `max_velocity / 900.0` and failure burst at `max_failed_burst / 5.0`; `compute_login_risk()` uses `1 - Π(1 - value)`. The remaining public calculations are `login_hour_irregularity()`, `new_device_count()`, `new_resource_count()`, `sensitive_access_ratio()`, `download_volume_vs_baseline()`, `privilege_change_count()`, `external_destination_novelty()`, and `suspicious_sequence_flag()`.

2. `engine/baseline.py`: `compute_behavioral_cluster()` uses `StandardScaler` and `KMeans(random_state=20260915, n_init=10)` on data at least `CLUSTER_EXCLUSION_DAYS = 7` days old. `compute_weights()` uses established `alpha/beta/gamma = 0.65/0.25/0.10`, new-actor `0.10/0.70/0.20`, and blends them for `ROLE_CHANGE_BLEND_DAYS = 30`; `MIN_PERSONAL_HISTORY_DAYS = 14` and `MIN_COHORT_SIZE = 3`. `compute_baseline_deviation()` calculates `combined = alpha*d_personal + beta*d_cohort + gamma*b_resource_raw`, `S_t = mean(personal_devs)`, `P_t = mean(cohort_devs)`, and the same weighted formula for `overall_deviation`. Supporting functions are `actor_history_days()`, `recent_role_change()`, `_feature_distribution_for_actors()`, and `_resource_access_rates()`.

3. `engine/changepoint.py`: `PageHinkleyDetector.update()` applies `_mean = alpha*x + (1-alpha)*_mean`, upward `_cum += x - _mean - delta`, and emits when `_cum - _min_cum > threshold`. `detect()` latches after a shift; `_try_rearm()` requires a sustained return toward `_baseline_mean`. `detect_change_points()` defaults to `PH_DELTA = 0.05`, `PH_LAMBDA = 2.5`, and `PH_ALPHA = 0.01`.

4. `engine/context.py`: `match_event_against_entry()` checks time/resource/action/destination. Full matches score `1.0`; destination-only misses score `0.5`; explicit resource/action misses score `0.0`. `classify_event()` preserves missing-data uncertainty as `indeterminate`. `evaluate_context_compatibility()` computes direct `C_t = Σ(context credit) / event count`, leaving indeterminate events in the denominator. `check_auto_reopen()` reopens resolved cases for new out-of-context events.

5. `engine/fusion.py`: `CLASSIFICATION_SCORE` is `public=0.25`, `internal=0.5`, `restricted=0.75`, `critical=1.0`; `CRITICAL_EVENT_FLOOR = 0.25`; `BULK_DOWNLOAD_THRESHOLD = 1000`. `event_category_risk()` groups signals into `identity`, `resource_access`, `privilege`, `data_movement`, and `temporal_sequence`. `combine_signal_categories()` takes `max()` within a category and noisy-OR across categories. `fuse_event_residuals()` applies `before_floor = raw*(1-credit)`, `residual = max(before_floor, floor)`, noisy-OR across events, and risk-weighted coverage `weighted_credit/raw_total`. `compute_risk_for_events()` connects baseline, context, Isolation Forest `M_t`, login risk `L_t`, fusion, confidence, data quality, and narratives. `fuse()` is the constituent counterfactual path; `counterfactual_breakdown()` reruns it with one component zeroed.

6. `engine/case_builder.py`: `build_deviation_series()`, `collect_transition_events()`, and `select_unusual_events()` form candidate evidence. `detect_and_build_cases()` uses a change point or a 48-hour fallback requiring `raw_deviation >= 35`. `create_or_update_case()` and `recompute_case()` update the projection; `_record_assessment()` appends immutable `CaseAssessment` and relational `CaseEvent` records. `rank_cases()` sorts by residual risk with default threshold `40.0`. `apply_feedback()` adjusts a role threshold by `+2.0`, `-3.0`, or `+0.5`, bounded to `10..90`. `build_shift_map()` builds graph data.

7. `engine/narrative.py`: `assert_no_verdict_language()` raises `VerdictLanguageError` for `malicious`, `suspicious`, `rogue`, `attacker`, `guilty`, `innocent`, `safe`, `threat actor`, `criminal`, or `compromised`. `sanitize_narrative_list()` applies it to a list.

8. Response and JIT layers: `engine/response_policy.py`, `response_service.py`, `response_graph.py`, and `sandbox_enforcement.py` consume committed assessments. Response constants are priority `75.0`, hold TTL `15` minutes, step-up TTL `5` minutes, minimum independent categories `2`, and scoring version `event-fusion-v2`. Under `access_control/`, `evaluate_access_policy()` is authoritative; `service.py` implements state transitions and grants; `ai_review.py` implements strict-schema Groq review; `outbox.py` and `worker.py` persist/process jobs; `enforcement.py` supplies simulated and signed-webhook providers; `monitoring.py` detects scope drift; `audit.py` maintains a SHA-256 hash chain.

An access request is `PAUSED` before permission exists. A protective hold interrupts an existing action; `revoke_session` terminates a session; `disable_account` is a separate high-impact response requiring approval.

## Implemented features

- Deterministic multi-window features, k-means cohorts, persisted Isolation Forest scoring, Page-Hinkley latching, per-event context matching, event fusion, critical floors, counterfactuals, shift maps, and NetworkX evidence graphs.
- Relational case evidence and append-only assessment/response histories.
- API-key auth, optional OIDC validation, role scopes, tenant-scoped JIT queries, self-approval rejection, and two-role approval for critical resources.
- JIT state machine, optimistic versions, idempotency records, bounded grants, notifications, durable outbox jobs, expiry, revocation, and scope monitoring.
- Advisory Groq JSON-schema review with input allowlisting, timeout/retry, per-process concurrency/rate/circuit controls, validation, and hash caching.
- Simulated enforcement plus an outbound HMAC-signed HTTPS provider.
- SQLite bootstrap and an Alembic baseline for PostgreSQL schema creation.

## API surface

Auth is attached with `APIRouter` dependencies, not application-wide middleware.

| Method/path in `api/routes.py` | Body/query | Response |
|---|---|---|
| `GET /entities`; `GET /entities/{entity_ref}` | — | `list[EntityOut]`; `EntityOut` |
| `GET/POST /entities/{entity_ref}/events` | POST `EventCreate` | `list[EventOut]`; `EventOut` (`201`) |
| `GET/POST /entities/{entity_ref}/context` | POST `ContextLedgerEntryCreate` | list/single `ContextLedgerEntryOut` (`202` on POST) |
| `POST /context/{entry_id}/review` | `ContextReview` | `ContextLedgerEntryOut` |
| `GET /cases`; `GET /cases/{case_id}` | optional `max_cases_per_day>=1` on list | `list[CaseSummary]`; `CaseDetail` |
| `GET /cases/{case_id}/counterfactual` | — | `CounterfactualOut` |
| `POST /cases/{case_id}/feedback` | `FeedbackCreate` | `FeedbackOut` |
| `GET /cases/{case_id}/shift-map-data` | — | `ShiftMapData` |
| `GET /cases/{case_id}/response-actions` | — | `list[ResponseActionOut]` |
| `POST /cases/{case_id}/response-actions/preview` | `ResponseActionPreviewRequest` | `ResponsePreviewOut` |
| `POST /cases/{case_id}/response-actions` | `ResponseActionRequest` | `ResponseActionOut` (`201`) |
| `POST /response-actions/{action_id}/approve`, `/reject`, `/rollback` | `ResponseActionDecision` | `ResponseActionOut` |
| `POST /response-actions/{action_id}/execute` | — | `ResponseActionOut` |
| `GET /cases/{case_id}/evidence-graph` | — | `EvidenceGraphOut` |
| `GET /admin/enforcement-state` | — | `mode`, `simulated`, `controls` |
| `GET /admin/audit` | `limit=100`, range `1..500` | audit record fields |
| `POST /admin/reseed` | — | `status`; `404` unless enabled |

Exact request fields: `EventCreate(timestamp, device_id, action, resource_id, resource_classification, destination, latitude, longitude, volume, result)`; `ContextLedgerEntryCreate(reason, effective_from, effective_until, allowed_resources, allowed_actions, approved_destinations, supersedes_id)`; `ContextReview(decision, note)`; `FeedbackCreate(verdict, notes)`; `ResponseActionPreviewRequest(action_type, target_scope)`; `ResponseActionRequest(action_type, target_scope, idempotency_key, note)`; `ResponseActionDecision(note)`.

The `/api/v1` JIT routes are `POST/GET /access-requests`, `GET /access-requests/{request_id}`, `GET .../history`, `POST .../evidence`, `POST .../evaluate`, `POST .../ai-review`, `POST .../request-context`, `POST .../approve`, `POST .../deny`, `POST .../revoke`, `GET .../grant`, `GET /notifications`, `POST /notifications/{notification_id}/acknowledge`, `GET /admin/access-policy`, and `GET /admin/access-health`. Lists accept `limit`/`offset`; access requests also accept `state`/`resource_id`. JIT mutations require `Idempotency-Key`.

JIT bodies are `AccessRequestCreate(subject_identity, resource_id, resource_sensitivity, requested_action, requested_permission, business_justification, requested_duration_seconds, linked_case_id, existing_entitlements, device_trust, authentication_strength, location_trust, break_glass)`, `EvidenceCreate(evidence_type, source, external_reference, source_created_at, effective_from, effective_until, identity_scope, resource_scope, action_scope, verification_status)`, `ContextRequest(note)`, `ApprovalCreate(note, decision, expected_version)`, and `RevokeCreate(note, expected_version)`.

`AccessRequestOut` returns `id`, `tenant_id`, both identities, resource/sensitivity/action/permission/justification/duration, `linked_case_id`, external/workflow states, timestamps, `version`, `policy_decision`, `ai_review_status`, `ai_advisory_only`, `required_approvers`, `available_actions`, requested/approved scope, `unaffected_resources`, and `enforcement_verification`. History returns transitions, approvals, audit hashes, and `audit_chain_valid`; grant and notification endpoints return their persisted model fields.

## Models and schemas

`models/db_models.py` defines 22 SQLAlchemy models: `Entity`, `Event`, `ContextLedgerEntry`, `Case`, `CaseEvent`, `CaseAssessment`, `AuditLog`, `ResponseAction`, `ResponseActionTransition`, `SandboxEnforcementState`, `AccessRequest`, `AccessRequestTransition`, `AccessEvidence`, `AccessGrant`, `ApprovalDecision`, `AccessAIReview`, `AuditRecord`, `TransactionalOutbox`, `AccessNotification`, `MutationIdempotency`, `AnalystFeedback`, and `CohortThreshold`.

`models/schemas.py` defines `StrictRequest`, `EntityOut`, `EventOut`, `EventCreate`, `ContextLedgerEntryCreate`, `ContextLedgerEntryOut`, `ContextReview`, `EventExplanation`, `EventRiskContribution`, `CaseSummary`, `CaseDetail`, `FeedbackCreate`, `FeedbackOut`, `CounterfactualComponent`, `CounterfactualOut`, `ShiftMapNode`, `ShiftMapEdge`, `ShiftMapData`, `ResponseActionRequest`, `ResponseActionPreviewRequest`, `ResponseActionDecision`, `ResponseActionOut`, `ResponsePreviewOut`, and `EvidenceGraphOut`. JIT-only schemas are in `access_control/schemas.py`: `StrictModel`, `AccessRequestCreate`, `EvidenceCreate`, `ContextRequest`, `ApprovalCreate`, `RevokeCreate`, `BreakGlassCreate`, `AIReviewOutput`, `AccessRequestOut`, and `NotificationOut`.

Exact response/support schema fields:

- `EntityOut(entity_ref, role, department, hire_date, regime_state, regime_feature)` and `EventOut(id, timestamp, actor_ref, device_id, action, resource_id, resource_classification, destination, latitude, longitude, volume, result)`.
- `ContextLedgerEntryOut(id, actor_ref, reason, valid_from, valid_until, effective_from, effective_until, allowed_resources, allowed_actions, approved_destinations, approved_by, approval_state, supersedes_id, proposed_by, proposed_at, reviewed_by, reviewed_at, review_note, created_at, approved_at, late_context)`.
- `EventExplanation(event_id, timestamp, action, resource_id, destination, status, matched_context_ids, match_details)` and `EventRiskContribution(event_id, raw_risk, context_credit, residual_before_floor, critical_floor, critical_reasons, residual_contribution, marginal_case_contribution, categories)`.
- `CaseSummary(id, actor_ref, created_at, status, raw_deviation, context_coverage, residual_risk, confidence, data_quality, residual_unresolved_count, primary_cause, hard_rule_flag)`. `CaseDetail` has the same fields except `hard_rule_flag`, plus `evidence`, `matched_context_ids`, `unmatched_behavior`, `event_ids`, `change_point_timestamps`, `explanation_breakdown`, `baseline_weights`, `feature_snapshot`, `fusion_components`, `event_risk_breakdown`, `retroactive_justification_review`, `original_assessment`, and `current_assessment`.
- `FeedbackOut(id, case_id, verdict, notes, timestamp, case_status, cohort_threshold_adjustment)`, `CounterfactualComponent(component, description, residual_risk_without, delta)`, and `CounterfactualOut(case_id, residual_risk, components)`.
- `ShiftMapNode(id, type, label, meta)`, `ShiftMapEdge(id, source, target, timestamp, action, explanation_status, event_id)`, and `ShiftMapData(case_id, actor_ref, change_point_timestamps, nodes, edges, domains)`.
- `ResponseActionOut(action_id, case_id, entity_ref, action_type, status, mode, requested_by, requested_at, approved_by, approved_at, executed_at, expires_at, rolled_back_at, failed_at, assessment_id, scoring_version, trigger_event_ids, policy_rule_id, policy_decision, policy_reasons, evidence_categories, target_scope, blast_radius, approval_required, automatic, idempotency_key, execution_result, verification_result, rollback_result, failure_reason, transitions)`.
- `ResponsePreviewOut(case_id, entity_ref, requested_action, recommended_action, allow, automatic, approval_required, policy_rule_id, reasons, target_scope, ttl_seconds, blast_radius, rollback_plan, evidence_categories, trigger_event_ids)` and `EvidenceGraphOut(case_id, entity_ref, generated_at, nodes, edges, evidence_paths, cycles)`.
- `BreakGlassCreate(note, duration_seconds, expected_version)` and `AIReviewOutput(recommendation, risk_summary, recommended_permission, recommended_duration_seconds, required_controls, reason_codes, missing_evidence, confidence, human_explanation)`.
- `NotificationOut(id, notification_type, request_id, message, created_at, acknowledged_at, delivery_status)`. `AccessRequestOut` fields are listed in the API section above.

Enums and exact values:

- `ActionType`: `login`, `file_access`, `file_download`, `repo_access`, `privilege_change`, `external_upload`, `permission_request`.
- `ResourceClassification`: `public`, `internal`, `restricted`, `critical`; `EventResult`: `success`, `failure`; `ContextReason`: `role_change`, `project`, `travel`, `maintenance`, `contract`.
- `CaseStatus`: `open`, `reviewing`, `resolved`, `reopened`; `ConfidenceLevel`: `low`, `moderate`, `high`; `DataQuality`: `sufficient`, `sparse`, `insufficient`; `RegimeState`: `nominal`, `latched`.
- `FeedbackVerdict`: `authorized`, `policy_violation`, `compromised`, `benign_unusual`, `insufficient_evidence`; `ExplanationStatus`: `explained`, `partially_explained`, `unexplained`, `indeterminate`.
- `ResponseActionType`: `observe`, `step_up_auth`, `block_external_upload`, `freeze_privilege_change`, `rate_limit_download`, `revoke_session`, `isolate_device`, `disable_account`.
- `ResponseActionStatus`: `proposed`, `auto_authorized`, `awaiting_approval`, `approved`, `executing`, `active`, `expired`, `rolled_back`, `failed`, `rejected`.

JIT states are stored strings, not an enum: `PAUSED`, `EVIDENCE_READY`, `AI_REVIEW_PENDING`, `AI_REVIEWED`, `MORE_CONTEXT_REQUIRED`, `AWAITING_APPROVAL`, `APPROVED`, `ENFORCING`, `ACTIVE`, `DENIED`, `REVOKING`, `REVOKED`, `EXPIRED`, `ENFORCEMENT_FAILED`.

## Seed and tests

Regenerated from `seed/scenarios.py` in memory on 2026-09-17:

| Scenario | Stored/case events | Explanation counts | Raw / coverage / residual |
|---|---:|---|---|
| Priya | `102 / 12` | 12 explained | `100 / 1.0000 / 25` |
| Devraj Malhotra | `93 / 6` | 6 unexplained | `100 / 0 / 100` |
| Arjun | `91 / 8` | 5 explained, 3 unexplained | `100 / 0.5905 / 100` |
| Neha (New Hire) | `3 / 3` | 3 indeterminate | `25 / 0 / 25` |

These agree with `API_CONTRACT.md`. The seed also creates nine peers, three role thresholds at `40.0`, Arjun's late/corrective context history, active scoped upload holds for Devraj and Arjun, Devraj's session revocation awaiting approval, and Neha's active observation.

There are 10 `tests/test*.py` files and 123 `test_*` functions: `test_api_workflows.py` 8, `test_changepoint.py` 3, `test_context_edit.py` 0 (manual script), `test_fusion_semantics.py` 6, `test_jit_access.py` 60, `test_ml_signals.py` 6, `test_pipeline_guards.py` 4, `test_reinforcement_invariants.py` 3, `test_reinforcement_security.py` 13, and `test_response_control_plane.py` 20. `smoke_api.py` is a separate manual script. Parametrization expands these to 238 collected cases.

Audit run on 2026-09-17 after the idempotency serialization fix: `234 passed, 3 failed, 1 error`. The setup error was host temp-directory permission. The remaining failures are in the JIT stale-lease, scope-monitoring fixture, and worker queue-order tests; the established detection/context/fusion/response tests passed.

## Deployment status and known limitations

`requirements.txt`, `.env.example`, `alembic.ini`, `migrations/env.py`, and `migrations/versions/20260917_01_production_baseline.py` exist. No `vercel.json` or `.vercel` project metadata exists; Vercel commands, runtime entry point, environment mapping, database connection, and worker scheduling are external to this repository.

- Empty databases are automatically demo-seeded in `lifespan()` even in production; only explicit `/admin/reseed` is production-blocked.
- CORS defaults to the two local port-3000 origins, credentials off, methods `GET/POST/OPTIONS`, and headers `Authorization/Content-Type`. Because `Idempotency-Key` is not allowed, browser JIT mutations fail preflight.
- Only JIT request/notification lists have offset pagination. Notification reads are tenant-scoped but not recipient-scoped. `unaffected_resources` is always `[]`.
- The JIT policy receives but does not use `existing_entitlements` or numeric residual risk, and does not evaluate department or computed blast radius.
- `GROQ_CONFIDENCE_THRESHOLD` and Redis fan-out are configured but unused in the active path. AI rate/circuit controls are process-local; cost/trace metrics are not exported.
- The signed webhook requires HTTPS and signs outbound calls, but has no configured host allowlist beyond URL validation. No real IAM/PAM/SOAR endpoint is configured or proven.
- Errors are inconsistent: JIT problem objects are nested under FastAPI's `detail`; validation/auth/legacy errors use other shapes, so responses are not uniformly top-level RFC 7807.
- PostgreSQL validation and a baseline migration exist, but production migration, backup/recovery, concurrency, and external enforcement are not demonstrated here.

## Documentation drift found

The previous README's `175`-test claim was wrong, and its statements that production persistence/migrations were only future work and sandbox was the sole enforcement implementation were stale. It also omitted the `/api/v1` JIT subsystem.

`API_CONTRACT.md` correctly records the four seed scores/counts, but incorrectly says `/health` is the sole public route, all errors are RFC 7807, and sandbox is the only implemented adapter with non-sandbox startup rejected. It also omits the CORS/`Idempotency-Key` conflict and production empty-database auto-seeding.
