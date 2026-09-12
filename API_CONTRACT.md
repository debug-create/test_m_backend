# Fable Backend API Contract

This document records the API as exercised against the local server and a cleanly
reseeded demo database on 2026-09-12. The database was reseeded before capture and
again after the mutating examples. The named demo records are:

| Actor | Entity ID | Case ID | Expected live characteristic |
|---|---:|---:|---|
| Priya | 10 | 1 | Fully contextualized; residual risk `0.3225` |
| Devraj Malhotra | 11 | 2 | No matching context; residual risk `98.4043` |
| Arjun | 12 | 3 | Partially contextualized; residual risk `42.1029` before the edit demo |
| Neha (New Hire) | 13 | 4 | Sparse data; 3 indeterminate events |

## Local server and base URL

Install dependencies from the project root and run:

```bash
pip install -r requirements.txt
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Base URL: `http://127.0.0.1:8000`

JSON requests should send `Content-Type: application/json`. Datetimes are ISO 8601.
Responses currently serialize database datetimes without a timezone suffix in some
top-level records and with `Z`/`+00:00` in some calculated nested records; clients
should parse all of these as ISO 8601 rather than depending on one spelling.

## CORS

The application is configured with `allow_origins=["*"]`,
`allow_credentials=True`, `allow_methods=["*"]`, and `allow_headers=["*"]`.
Therefore all browser origins are currently accepted. A live preflight from
`Origin: http://localhost:3000` returned `200`, echoed that origin, included
`Access-Control-Allow-Credentials: true`, and advertised
`DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT`.

## Common error format

An unknown record returns, for example:

```json
{"detail":"Entity not found"}
```

Validation failures return FastAPI's `422` structure, for example:

```json
{"detail":[{"type":"greater_than_equal","loc":["query","max_cases_per_day"],"msg":"Input should be greater than or equal to 1","input":"0","ctx":{"ge":1}}]}
```

No route deliberately returns `400`. Unhandled database or scoring failures may
surface as `500`; there is no custom `500` response schema.

## Domain endpoints

### `GET /health`

Returns service health. No parameters or request body.

```bash
curl http://127.0.0.1:8000/health
```

```json
{"status":"ok","service":"fable"}
```

Status codes: `200` on success; an unhandled server failure can return `500`.

### `POST /admin/reseed`

Deletes the current demo records and recreates peer data and all four scenarios.
No parameters or request body.

```bash
curl -X POST http://127.0.0.1:8000/admin/reseed
```

```json
{"status":"reseeded"}
```

Status codes: `200` on success; `500` on an unhandled database/seeding failure.
This development endpoint has no authentication and is destructive.

### `GET /entities`

Returns all entities ordered by ID. No parameters or request body. The live response
contained 13 records: nine peer-baseline entities plus these four named records:

```bash
curl http://127.0.0.1:8000/entities
```

```json
[
  {"id":10,"display_name":"Priya","role":"security","department":"Security","hire_date":"2026-01-13T09:00:00","regime_state":"nominal","regime_feature":"overall_deviation"},
  {"id":11,"display_name":"Devraj Malhotra","role":"engineering","department":"Engineering","hire_date":"2025-06-27T09:00:00","regime_state":"nominal","regime_feature":"overall_deviation"},
  {"id":12,"display_name":"Arjun","role":"engineering","department":"Engineering","hire_date":"2025-10-05T09:00:00","regime_state":"nominal","regime_feature":"overall_deviation"},
  {"id":13,"display_name":"Neha (New Hire)","role":"engineering","department":"Engineering","hire_date":"2026-09-08T09:00:00","regime_state":"nominal","regime_feature":"overall_deviation"}
]
```

The JSON above is the exact four-record demo subset of the actual 13-record response;
IDs `1`–`9` are `Dev Peer A/B/C`, `Sec Peer A/B/C`, and `Fin Peer A/B/C`.

Status codes: `200`; unhandled server failures may return `500`.

### `GET /entities/{entity_id}`

Returns one entity, including its read-only detector regime state.

- Path: `entity_id` — required integer.
- No query parameters or body.

```bash
curl http://127.0.0.1:8000/entities/10
```

```json
{"id":10,"display_name":"Priya","role":"security","department":"Security","hire_date":"2026-01-13T09:00:00","regime_state":"nominal","regime_feature":"overall_deviation"}
```

Status codes: `200`; `404` when the entity does not exist; `422` when the path value
is not an integer; `500` for an unhandled server failure.

### `GET /entities/{entity_id}/events`

Returns the entity's events in ascending timestamp order.

- Path: `entity_id` — required integer.
- No query parameters or body.

```bash
curl http://127.0.0.1:8000/entities/13/events
```

```json
[
  {"id":986,"timestamp":"2026-09-10T09:00:00","actor_id":13,"device_id":"neha-laptop","action":"login","resource_id":null,"resource_classification":"internal","destination":null,"volume":null,"result":"success"},
  {"id":987,"timestamp":"2026-09-11T09:00:00","actor_id":13,"device_id":"neha-laptop","action":"login","resource_id":null,"resource_classification":"internal","destination":null,"volume":null,"result":"success"},
  {"id":988,"timestamp":"2026-09-12T11:00:00","actor_id":13,"device_id":"neha-laptop","action":"file_access","resource_id":"new-team-share","resource_classification":null,"destination":null,"volume":null,"result":"success"}
]
```

Status codes: `200`; `404` for an unknown entity; `422` for a non-integer ID; `500`
for an unhandled server failure.

### `POST /entities/{entity_id}/events`

Ingests one event, checks auto-reopen, and advances change-point detection.

- Path: `entity_id` — required integer.
- Body object:
  - `timestamp`: required ISO-8601 datetime.
  - `device_id`: required string.
  - `action`: required action enum.
  - `resource_id`: optional string or `null`.
  - `resource_classification`: optional classification enum or `null`.
  - `destination`: optional string or `null`.
  - `volume`: optional non-negative integer or `null`.
  - `result`: optional result enum; defaults to `success`.

```bash
curl -X POST http://127.0.0.1:8000/entities/12/events \
  -H "Content-Type: application/json" \
  -d '{"timestamp":"2026-08-28T10:00:00Z","device_id":"arjun-laptop","action":"file_access","resource_id":"payroll-private","resource_classification":"critical","destination":null,"volume":null,"result":"success"}'
```

Captured response before the final cleanup reseed:

```json
{"id":989,"timestamp":"2026-08-28T10:00:00","actor_id":12,"device_id":"arjun-laptop","action":"file_access","resource_id":"payroll-private","resource_classification":"critical","destination":null,"volume":null,"result":"success"}
```

Status codes: `201` when created; `404` for an unknown entity; `422` for an invalid
body, enum, datetime, negative volume, or path ID; `500` for an unhandled persistence
or detection failure. The response contains the event only, not any affected case.

### `GET /entities/{entity_id}/context`

Returns context-ledger entries ordered by `valid_from`.

- Path: `entity_id` — required integer.
- No query parameters or body.

```bash
curl http://127.0.0.1:8000/entities/12/context
```

```json
[
  {"id":2,"actor_id":12,"reason":"project","valid_from":"2026-08-26T09:00:00","valid_until":"2026-09-15T09:00:00","allowed_resources":["migration-repo"],"allowed_actions":["login","repo_access","file_access","file_download"],"approved_destinations":["s3://corp-migration-backup"],"approved_by":"eng-manager"}
]
```

Status codes: `200`; `404` for an unknown entity; `422` for a non-integer ID; `500`
for an unhandled server failure.

### `POST /entities/{entity_id}/context`

Creates a context entry when `id` is absent or updates that actor's entry when `id`
is present, then recomputes all of the actor's cases.

- Path: `entity_id` — required integer.
- Body object:
  - `id`: optional integer; include to update.
  - `reason`: required context-reason enum.
  - `valid_from`, `valid_until`: required ISO-8601 datetimes.
  - `allowed_resources`: optional string array; defaults to `[]`.
  - `allowed_actions`: optional string array; defaults to `[]`.
  - `approved_destinations`: optional string array or `null`.
  - `approved_by`: required string.

```bash
curl -X POST http://127.0.0.1:8000/entities/12/context \
  -H "Content-Type: application/json" \
  -d '{"id":2,"reason":"project","valid_from":"2026-08-26T09:00:00","valid_until":"2026-09-15T09:00:00","allowed_resources":["migration-repo","finance-archive"],"allowed_actions":["login","repo_access","file_access","file_download","external_upload"],"approved_destinations":["s3://corp-migration-backup","https://personal-cloud.example/upload"],"approved_by":"eng-manager"}'
```

```json
{"id":2,"actor_id":12,"reason":"project","valid_from":"2026-08-26T09:00:00","valid_until":"2026-09-15T09:00:00","allowed_resources":["migration-repo","finance-archive"],"allowed_actions":["login","repo_access","file_access","file_download","external_upload"],"approved_destinations":["s3://corp-migration-backup","https://personal-cloud.example/upload"],"approved_by":"eng-manager"}
```

Status codes: `200`; `404` when the actor does not exist or the supplied entry ID does
not belong to that actor; `422` for invalid/missing fields, enum values, datetimes, or
path ID; `500` for an unhandled persistence/recomputation failure. There is currently
no validation that `valid_until` is later than `valid_from`.

### `GET /cases`

Recomputes, ranks, and returns active `open`, `reopened`, and `reviewing` cases.

- Query: `max_cases_per_day` — optional integer, minimum `1`. It currently caps the
  globally ranked result rather than grouping by calendar day; hard-rule cases are
  appended even when this exceeds the cap.
- No body.

```bash
curl http://127.0.0.1:8000/cases
```

```json
[
  {"id":2,"actor_id":11,"actor_name":"Devraj Malhotra","created_at":"2026-08-30T15:00:00","status":"open","raw_deviation":98.4043,"context_coverage":0.0,"residual_risk":98.4043,"confidence":"high","data_quality":"sufficient","residual_unresolved_count":0,"primary_cause":"asset sensitivity","hard_rule_flag":true},
  {"id":3,"actor_id":12,"actor_name":"Arjun","created_at":"2026-08-28T05:00:00","status":"open","raw_deviation":85.5876,"context_coverage":0.5081,"residual_risk":42.1029,"confidence":"high","data_quality":"sufficient","residual_unresolved_count":0,"primary_cause":"asset sensitivity","hard_rule_flag":true},
  {"id":4,"actor_id":13,"actor_name":"Neha (New Hire)","created_at":"2026-09-12T21:00:00","status":"open","raw_deviation":12.5638,"context_coverage":0.0,"residual_risk":12.5638,"confidence":"low","data_quality":"sparse","residual_unresolved_count":3,"primary_cause":"self-baseline deviation","hard_rule_flag":false},
  {"id":1,"actor_id":10,"actor_name":"Priya","created_at":"2026-09-06T03:00:00","status":"open","raw_deviation":38.1386,"context_coverage":0.9915,"residual_risk":0.3225,"confidence":"high","data_quality":"sufficient","residual_unresolved_count":0,"primary_cause":"asset sensitivity","hard_rule_flag":false}
]
```

Status codes: `200`; `422` when the query value is non-integer or below `1`; `500`
for an unhandled recomputation failure.

### `GET /cases/{case_id}`

Recomputes and returns complete case detail. The real Arjun responses are in the
live-recompute section below; the following compact complete diagnostic example is
Neha's case.

- Path: `case_id` — required integer.
- No query parameters or body.

```bash
curl http://127.0.0.1:8000/cases/4
```

```json
{
  "id":4,"actor_id":13,"actor_name":"Neha (New Hire)","created_at":"2026-09-12T21:00:00","status":"open",
  "raw_deviation":12.5638,"context_coverage":0.0,"residual_risk":12.5638,"confidence":"low","data_quality":"sparse","residual_unresolved_count":3,
  "primary_cause":"self-baseline deviation","evidence":[],"matched_context_ids":[],"unmatched_behavior":[],"event_ids":[986,987,988],"change_point_timestamps":[],
  "explanation_breakdown":[
    {"event_id":986,"timestamp":"2026-09-10T09:00:00Z","action":"login","resource_id":null,"destination":null,"status":"indeterminate","matched_context_ids":[],"match_details":{"reason":"insufficient_history_no_applicable_context","history_days":2.5,"min_required_days":14}},
    {"event_id":987,"timestamp":"2026-09-11T09:00:00Z","action":"login","resource_id":null,"destination":null,"status":"indeterminate","matched_context_ids":[],"match_details":{"reason":"insufficient_history_no_applicable_context","history_days":2.5,"min_required_days":14}},
    {"event_id":988,"timestamp":"2026-09-12T11:00:00Z","action":"file_access","resource_id":"new-team-share","destination":null,"status":"indeterminate","matched_context_ids":[],"match_details":{"reason":"missing_resource_classification","resource_id":"new-team-share"}}
  ],
  "baseline_weights":{"alpha":0.1,"beta":0.7,"gamma":0.2,"history_days":2.5,"cohort_size":6,"cohort_confidence":"high","uncertainty_band":1.0,"role_change_active":false,"role_change_entry_id":null,"rationale":"New entity (2.5d < 14d history): α low, β high"},
  "feature_snapshot":{"as_of":"2026-09-12T21:00:00+00:00","windows":{"15m":{"login_hour_irregularity":0.0,"new_device_count":0.0,"new_resource_count":0.0,"sensitive_access_ratio":0.0,"download_volume_vs_baseline":0.0,"privilege_change_count":0.0,"external_destination_novelty":0.0,"suspicious_sequence_flag":0.0,"suspicious_sequence_magnitude":0.0,"event_count":0.0},"24h":{"login_hour_irregularity":0.0,"new_device_count":0.0,"new_resource_count":1.0,"sensitive_access_ratio":0.0,"download_volume_vs_baseline":0.0,"privilege_change_count":0.0,"external_destination_novelty":0.0,"suspicious_sequence_flag":0.0,"suspicious_sequence_magnitude":0.0,"event_count":1.0},"7d":{"login_hour_irregularity":0.0,"new_device_count":1.0,"new_resource_count":1.0,"sensitive_access_ratio":0.0,"download_volume_vs_baseline":0.0,"privilege_change_count":0.0,"external_destination_novelty":0.0,"suspicious_sequence_flag":0.0,"suspicious_sequence_magnitude":0.0,"event_count":3.0},"30d":{"login_hour_irregularity":0.0,"new_device_count":1.0,"new_resource_count":1.0,"sensitive_access_ratio":0.0,"download_volume_vs_baseline":0.0,"privilege_change_count":0.0,"external_destination_novelty":0.0,"suspicious_sequence_flag":0.0,"suspicious_sequence_magnitude":0.0,"event_count":3.0}},"primary":{"login_hour_irregularity":0.0,"new_device_count":0.0,"new_resource_count":1.0,"sensitive_access_ratio":0.0,"download_volume_vs_baseline":0.0,"privilege_change_count":0.0,"external_destination_novelty":0.0,"suspicious_sequence_flag":0.0,"suspicious_sequence_magnitude":0.0,"event_count":1.0}},
  "fusion_components":{"S_t":0.1111,"P_t":0.1111,"Q_t":0.0,"A_t":0.0,"I_t":0.0,"C_t":0.0,"W_S":0.2,"W_P":0.12,"W_Q":0.22,"W_A":0.28,"W_I":0.18,"W_C":0.75,"linear_score":0.0228,"linear_raw":0.0228}
}
```

Status codes: `200`; `404` for an unknown case; `422` for a non-integer ID; `500`
for an unhandled recomputation failure.

### `GET /cases/{case_id}/counterfactual`

Re-runs scoring six times, zeroing one component on each pass.

```bash
curl http://127.0.0.1:8000/cases/3/counterfactual
```

```json
{"case_id":3,"residual_risk":42.1029,"components":[{"component":"privilege_escalation","description":"Identity/privilege risk (I_t) zeroed","residual_risk_without":42.1029,"delta":0.0},{"component":"sensitive_access","description":"Asset sensitivity (A_t) zeroed","residual_risk_without":12.3462,"delta":29.7567},{"component":"suspicious_sequence","description":"Sequence risk (Q_t) zeroed","residual_risk_without":42.1029,"delta":0.0},{"component":"self_deviation","description":"Self-baseline deviation (S_t) zeroed","residual_risk_without":15.2061,"delta":26.8968},{"component":"peer_deviation","description":"Peer/cohort deviation (P_t) zeroed","residual_risk_without":23.8935,"delta":18.2094},{"component":"context","description":"Context credit (C_t) zeroed — equivalent to raw path","residual_risk_without":85.5876,"delta":-43.4847}]}
```

Status codes: `200`; `404` for an unknown case; `422` for a non-integer ID; `500`
for an unhandled recomputation failure.

### `POST /cases/{case_id}/feedback`

Stores analyst feedback, changes case status, and adjusts the actor role's cohort
ranking threshold.

- Path: `case_id` — required integer.
- Body: `verdict` required feedback-verdict enum; `notes` optional string or `null`.

```bash
curl -X POST http://127.0.0.1:8000/cases/3/feedback \
  -H "Content-Type: application/json" \
  -d '{"verdict":"authorized","notes":"Migration scope confirmed with manager."}'
```

```json
{"id":1,"case_id":3,"verdict":"authorized","notes":"Migration scope confirmed with manager.","timestamp":"2026-09-12T14:16:10.696394","case_status":"resolved","cohort_threshold_adjustment":{"role":"engineering","previous_threshold":40.0,"new_threshold":42.0,"delta":2.0,"note":"Per-role-cohort ranking threshold adjusted. This is NOT a model retrain — only a stored numeric threshold used when ranking/filtering future cases for this role cohort."}}
```

Status codes: `200`; `404` for an unknown case; `422` for an invalid verdict, body,
or path ID; `500` for an unhandled persistence failure.

### `GET /cases/{case_id}/shift-map-data`

Returns graph nodes and event edges for a case visualization.

```bash
curl http://127.0.0.1:8000/cases/4/shift-map-data
```

```json
{"case_id":4,"actor_id":13,"change_point_timestamps":[],"nodes":[{"id":"entity:13","type":"entity","label":"Neha (New Hire)","meta":{"role":"engineering","department":"Engineering"}},{"id":"device:neha-laptop","type":"device","label":"neha-laptop","meta":{}},{"id":"resource:new-team-share","type":"resource","label":"new-team-share","meta":{"classification":null}}],"edges":[{"id":"e986-device","source":"entity:13","target":"device:neha-laptop","timestamp":"2026-09-10T09:00:00Z","action":"login","explanation_status":"indeterminate","event_id":986},{"id":"e987-device","source":"entity:13","target":"device:neha-laptop","timestamp":"2026-09-11T09:00:00Z","action":"login","explanation_status":"indeterminate","event_id":987},{"id":"e988-device","source":"entity:13","target":"device:neha-laptop","timestamp":"2026-09-12T11:00:00Z","action":"file_access","explanation_status":"indeterminate","event_id":988},{"id":"e988-resource","source":"entity:13","target":"resource:new-team-share","timestamp":"2026-09-12T11:00:00Z","action":"file_access","explanation_status":"indeterminate","event_id":988}],"domains":["Engineering","unknown"]}
```

Status codes: `200`; `404` for an unknown case; `422` for a non-integer ID; `500`
for an unhandled recomputation failure.

## Live context-edit recomputation

The following sequence was executed through the running HTTP server immediately after
a clean reseed. The final database was reseeded again afterward.

```bash
curl http://127.0.0.1:8000/cases/3
# POST the expanded context body shown above
curl http://127.0.0.1:8000/cases/3
```

The complete responses have large unchanged baseline/feature subtrees. This table is
a lossless listing of every field that changed; all fields not shown were byte-for-byte
equal JSON values between the two captured responses.

| JSON field | Before context edit | After context edit |
|---|---|---|
| `context_coverage` | `0.5081` | `0.9647` |
| `residual_risk` | `42.1029` | `3.022` |
| `evidence` | 7 entries: baseline, peer, asset, `Context explains 5/8`, and 3 unmatched entries | 4 entries: baseline, peer, asset, `Context explains 8/8` |
| `unmatched_behavior` | Three finance-archive strings | `[]` |
| Breakdown events `983`, `984`, `985`: `status` | `unexplained` | `explained` |
| Breakdown events `983`, `984`, `985`: `matched_context_ids` | `[]` | `[2]` |
| Events `983`, `984`: `resource_match` | `false` | `true` |
| Event `985`: resource/action/destination matches | `false / false / false` | `true / true / true` |
| Events `983`, `984`, `985`: match `score` | `0.0` | `1.0` |
| `fusion_components.C_t` | `0.4` | `1.0` |
| `fusion_components.linear_score` | `0.2545` | `-0.1955` |

Side-by-side top-level response JSON (the nested arrays shown are the actual changed
values; unchanged IDs, diagnostics, baseline weights, feature snapshot, and positive
fusion inputs remain as documented in the CaseDetail example/schema):

| Before | After |
|---|---|
| <pre>{
  "id": 3,
  "actor_id": 12,
  "actor_name": "Arjun",
  "status": "open",
  "raw_deviation": 85.5876,
  "context_coverage": 0.5081,
  "residual_risk": 42.1029,
  "confidence": "high",
  "data_quality": "sufficient",
  "residual_unresolved_count": 0,
  "primary_cause": "asset sensitivity",
  "evidence": [
    "Self-baseline deviation elevated (S_t=16.33)",
    "Peer/cohort deviation elevated (P_t=15.63)",
    "High asset sensitivity in involved events (A_t=0.84)",
    "Context explains 5/8 events (C_t=0.40)",
    "Unmatched: file_access on finance-archive at 2026-08-27T15:00:00+00:00",
    "Unmatched: file_download on finance-archive at 2026-08-27T16:00:00+00:00",
    "Unmatched: external_upload on finance-archive at 2026-08-27T17:00:00+00:00"
  ],
  "unmatched_behavior": [
    "file_access on finance-archive at 2026-08-27T15:00:00+00:00",
    "file_download on finance-archive at 2026-08-27T16:00:00+00:00",
    "external_upload on finance-archive at 2026-08-27T17:00:00+00:00"
  ],
  "finance_event_statuses": {
    "983": "unexplained",
    "984": "unexplained",
    "985": "unexplained"
  },
  "fusion_components": {"C_t": 0.4, "linear_score": 0.2545}
}</pre> | <pre>{
  "id": 3,
  "actor_id": 12,
  "actor_name": "Arjun",
  "status": "open",
  "raw_deviation": 85.5876,
  "context_coverage": 0.9647,
  "residual_risk": 3.022,
  "confidence": "high",
  "data_quality": "sufficient",
  "residual_unresolved_count": 0,
  "primary_cause": "asset sensitivity",
  "evidence": [
    "Self-baseline deviation elevated (S_t=16.33)",
    "Peer/cohort deviation elevated (P_t=15.63)",
    "High asset sensitivity in involved events (A_t=0.84)",
    "Context explains 8/8 events (C_t=1.00)"
  ],
  "unmatched_behavior": [],
  "finance_event_statuses": {
    "983": "explained",
    "984": "explained",
    "985": "explained"
  },
  "fusion_components": {"C_t": 1.0, "linear_score": -0.1955}
}</pre> |

`raw_deviation` stays `85.5876` because it is explicitly calculated with context
disabled. The context-only change raises coverage and lowers residual risk.

## Enum and finite-value reference

| Field | Complete accepted/returned set |
|---|---|
| `action` | `login`, `file_access`, `file_download`, `repo_access`, `privilege_change`, `external_upload`, `permission_request` |
| `resource_classification` | `public`, `internal`, `restricted`, `critical`, or `null` |
| event `result` | `success`, `failure` |
| context `reason` | `role_change`, `project`, `travel`, `maintenance`, `contract` |
| case `status` | `open`, `reviewing`, `resolved`, `reopened` |
| `confidence` | `low`, `moderate`, `high` |
| `data_quality` | `insufficient`, `sparse`, `sufficient` |
| context/explanation `status` | `explained`, `partially_explained`, `unexplained`, `indeterminate` |
| entity `regime_state` | `nominal`, `latched` |
| feedback `verdict` | `authorized`, `policy_violation`, `compromised`, `benign_unusual`, `insufficient_evidence` |
| shift-map node `type` | `entity`, `device`, `resource`, `destination` |
| counterfactual `component` | `privilege_escalation`, `sensitive_access`, `suspicious_sequence`, `self_deviation`, `peer_deviation`, `context` |
| `primary_cause` currently generated values | `self-baseline deviation`, `peer-cohort deviation`, `observed access sequence`, `asset sensitivity`, `identity/privilege risk` |
| feature window key | `15m`, `24h`, `7d`, `30d` |
| cohort confidence | `low`, `high` |

Feedback-to-status behavior: `authorized` and `benign_unusual` resolve a case;
`policy_violation` and `compromised` set it to reviewing;
`insufficient_evidence` sets it to open.

## Response field reference

### Health, entity, event, and context

| Field | Meaning |
|---|---|
| `status` (health) | Health marker, currently `ok`. |
| `service` | Service identifier, currently `fable`. |
| `id` | Stable database identifier for the returned record. |
| `display_name` | Human-readable entity name. |
| `role` | Entity's current role/cohort key. |
| `department` | Entity's organizational department. |
| `hire_date` | Recorded employment start datetime. |
| `regime_state` | Whether change-point detection is nominal or suppressing duplicate plateau alerts. |
| `regime_feature` | Feature tracked by the regime latch. |
| `timestamp` | Event or feedback occurrence datetime. |
| `actor_id` | Entity that owns the event, context, or case. |
| `device_id` | Device associated with an event. |
| `action` | Normalized event action. |
| `resource_id` | Resource touched by an event, or `null`. |
| `resource_classification` | Sensitivity class of the resource, or `null` when unavailable. |
| `destination` | Transfer destination, or `null`. |
| `volume` | Transfer volume in the source event's units, or `null`. |
| `result` | Event success/failure result. |
| `reason` | Business reason for a context grant. |
| `valid_from`, `valid_until` | Inclusive validity boundaries of a context entry. |
| `allowed_resources` | Resources authorized by the entry; an empty list means unconstrained by resource. |
| `allowed_actions` | Actions authorized by the entry; an empty list means unconstrained by action. |
| `approved_destinations` | Approved destinations; `null` means no destination constraint, while `[]` approves none. |
| `approved_by` | Approver recorded on the context entry. |

### Case summary and detail

| Field | Meaning |
|---|---|
| `actor_name` | Display name joined onto a case response. |
| `created_at` | Case evaluation/creation boundary. |
| `status` | Current workflow state of the case. |
| `raw_deviation` | 0–100 fused behavioral deviation calculated with context credit forced to zero. |
| `context_coverage` | Fraction of raw risk removed by matching context: `(raw - residual) / raw`, bounded to 0–1. |
| `residual_risk` | 0–100 fused risk remaining after context credit. |
| `confidence` | Reliability of this assessment given completeness of the case events. |
| `data_quality` | Structural amount of usable actor history, calculated independently of confidence. |
| `residual_unresolved_count` | Number of indeterminate events, outside explained/unexplained coverage. |
| `primary_cause` | Largest positive weighted fusion contributor, expressed neutrally. |
| `hard_rule_flag` | True when an unexplained event touches a critical resource. Present on summaries. |
| `evidence` | Neutral generated evidence statements. |
| `matched_context_ids` | Distinct context-entry IDs contributing an explained/partial match. |
| `unmatched_behavior` | Human-readable descriptions of unexplained events. |
| `event_ids` | Event IDs bundled into the case. |
| `change_point_timestamps` | Detected or recorded behavioral transition times. |
| `explanation_breakdown` | Independent context classification for every case event. |
| `baseline_weights` | Hierarchical baseline weights and their supporting metadata. |
| `feature_snapshot` | Event-derived behavioral features at the case evaluation boundary. |
| `fusion_components` | Exact signals, weights, and linear values used by fusion. |

### Event explanation and matching

| Field | Meaning |
|---|---|
| `event_id` | Event being explained. |
| explanation `status` | Explained, partial, unexplained, or indeterminate classification. |
| explanation `matched_context_ids` | Entries that explained or partially explained the event. |
| `match_details` | Best-match diagnostics or an indeterminate reason object. |
| `entry_id` | Context entry evaluated as the best match. |
| `time_match` | Whether the event falls inside the context validity interval. |
| `resource_match` | Resource constraint result; `null` when not applicable. |
| `action_match` | Action constraint result; `null` when not applicable. |
| `destination_match` | Destination constraint result; `null` when not applicable. |
| `applicable` | Constraint names applied to this match. |
| `matched` | Applied constraints that passed. |
| match `score` | `1.0` explained, `0.5` partial destination match, or `0.0` unexplained. |
| match `reason` | Machine-readable reason for an indeterminate event. |
| `history_days` | Usable actor-history duration at evaluation time. |
| `min_required_days` | Minimum history needed to avoid the short-history indeterminate rule. |

### Baseline, features, and fusion

| Field | Meaning |
|---|---|
| `alpha` | Personal-baseline mixing weight. |
| `beta` | Role-cohort mixing weight. |
| `gamma` | Resource-rarity mixing weight. |
| `cohort_size` | Number of actors in the current role cohort. |
| `cohort_confidence` | Structural cohort-size quality marker. |
| `uncertainty_band` | Multiplier widening uncertainty for a small cohort. |
| `role_change_active` | Whether recent role-change blending applies. |
| `role_change_entry_id` | Supporting role-change context ID, or `null`. |
| `rationale` | Human-readable explanation of the selected baseline weights. |
| `as_of` | Temporal boundary; later events cannot influence the snapshot. |
| `windows` | Feature maps for 15m, 24h, 7d, and 30d. |
| `primary` | The 24-hour feature map used by baseline/fusion. |
| `login_hour_irregularity` | Login-time dispersion relative to history. |
| `new_device_count` | Devices unseen before the window. |
| `new_resource_count` | Resources unseen before the window. |
| `sensitive_access_ratio` | Fraction of events touching restricted/critical resources. |
| `download_volume_vs_baseline` | Window transfer volume divided by historical equivalent-window volume. |
| `privilege_change_count` | Privilege-change events in the window. |
| `external_destination_novelty` | Fraction of destinations unseen for the actor or peers. |
| `suspicious_sequence_flag` | Numeric 0/1 indicator for privilege→access→transfer ordering. |
| `suspicious_sequence_magnitude` | Strength of that sequence based on timing and sensitivity. |
| `event_count` | Events inside the feature window. |
| `S_t`, `P_t` | Unnormalized self- and peer-deviation signals. |
| `Q_t` | Sequence-risk signal. |
| `A_t` | Asset-sensitivity signal. |
| `I_t` | Identity/privilege signal. |
| `C_t` | Severity-weighted context compatibility. |
| `W_S`…`W_C` | Manually configured fusion weights for the corresponding signals. |
| `linear_raw` | Weighted positive evidence before context subtraction. |
| `linear_score` | Weighted evidence after context subtraction, before logistic conversion. |

### Counterfactual, feedback, and shift map

| Field | Meaning |
|---|---|
| counterfactual `components` | One result for each signal removed and recomputed. |
| `component` | Machine key for the removed factor. |
| `description` | Neutral description of the recomputation. |
| `residual_risk_without` | Recomputed residual risk with that factor zeroed. |
| `delta` | Base residual risk minus `residual_risk_without`; context removal is normally negative. |
| feedback `verdict` | Analyst-selected outcome. |
| `notes` | Optional analyst notes. |
| `case_status` | Case status after applying feedback. |
| `cohort_threshold_adjustment` | Details of the role threshold change. |
| `previous_threshold`, `new_threshold` | Threshold before and after feedback. |
| threshold `delta` | `new_threshold - previous_threshold`. |
| threshold `note` | Explanation that the adjustment is not model retraining. |
| `nodes` | Unique graph nodes for the entity, devices, resources, and destinations. |
| node `type`, `label`, `meta` | Node category, display label, and type-specific metadata. |
| `edges` | Timestamped entity-to-node relationships derived from events. |
| `source`, `target` | Graph node IDs connected by an edge. |
| `explanation_status` | Context status used to color/label the edge. |
| `domains` | Sorted department/resource-classification labels represented in the graph. |

## Framework-generated endpoints

These were also called successfully:

| Method/path | Live result | Purpose |
|---|---|---|
| `GET /openapi.json` | `200 application/json` | Generated OpenAPI 3 schema for all routes and models. |
| `GET /docs` | `200 text/html` | Swagger UI. |
| `GET /docs/oauth2-redirect` | `200 text/html` | Swagger OAuth redirect helper; no OAuth security scheme is configured. |
| `GET /redoc` | `200 text/html` | ReDoc UI. |
| `OPTIONS <domain path>` | `200 text/plain` for valid CORS preflight | Handled by CORS middleware. |

These generated HTML/schema responses are supplied by FastAPI and are not stable
application data contracts; frontend code should use the JSON domain endpoints.

## Known incomplete or surprising endpoint behavior

All declared domain endpoints returned their documented success response during live
verification. No endpoint currently exists in code but consistently fails.

Frontend integrators should nevertheless account for these limitations:

- `/admin/reseed` is unauthenticated and destructively replaces all demo records.
- There is no endpoint to create/delete entities, delete context entries, list
  feedback, or fetch cohort thresholds.
- `POST /entities/{id}/events` returns only the event; callers must refetch the entity
  and cases to observe latch, new-case, or auto-reopen effects.
- `POST /entities/{id}/context` has no validity-range ordering check.
- `max_cases_per_day` is currently a global top-N cap, despite its name.
- Feedback changes a stored cohort threshold, but the case-list response does not
  expose that threshold.
- Resolved cases are excluded from `GET /cases`; fetch one directly by ID if needed.
- There is no pagination on entity, event, context, or case collections.
- Authentication and authorization are not implemented.
