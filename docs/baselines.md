# Behavioral Baselines

Per-identity "normal" profiles, built from event history, used to flag when
a new event deviates from what's been seen before (blueprint L2, §7.1).

## Design

- **Query-computed, not incrementally maintained.** `app/baselines/profile.py`'s
  `build_profile()` re-derives an identity's profile from its event history
  on every call rather than keeping a separate materialized record that
  could drift out of sync. Fine at this project's scale; worth revisiting
  only if ingestion volume ever makes it the bottleneck.
- **Point-in-time correctness.** Ingestion (`app/api/events.py`) builds the
  profile from events strictly *before* the incoming event's timestamp,
  before that event is inserted - so a deviation check never leaks
  information from the future, and replaying an already-ingested event
  produces the same result deterministically.
- **Cold-start guard.** `MIN_HISTORY_FOR_BASELINE` (3) suppresses deviation
  checks until an identity has enough history that "new" is meaningful -
  otherwise every identity's first few events would all look anomalous.
- **Deviation types and weights** (`app/baselines/deviation.py`):

  | Type | Weight | Trigger |
  |---|---|---|
  | `new_country` | 20 | `geo_country` not in the identity's known countries |
  | `volume_anomaly` | 25 | `bytes_transferred` > 3x the identity's prior max |
  | `new_device` | 15 | `device_id` not in known devices |
  | `new_app` | 15 | `app_id` not in known apps |
  | `new_auth_protocol` | 15 | `auth_protocol` not in known protocols |
  | `new_ip` | 10 | `ip_address` not in known IPs |
  | `unusual_login_hour` | 10 | event's UTC hour outside the identity's usual hours |

  Deviation weights contribute to the behavioral component of correlated
  incident scores. See [correlation scoring](correlation.md).

## What's NOT here

Peer-group baselines (comparing an identity to others with a similar role)
are a blueprint stretch goal, not built. Volume anomaly detection is a
simple 3x-prior-max multiplier, not a statistical model (mean/stddev) - a
reasonable place to improve later if false positives on legitimately bursty
identities appear in evaluation.

## API & dashboard

- `GET /api/identities` - every identity seen, with event counts.
- `GET /api/identities/{actor_id}` - profile (known devices/IPs/countries/
  apps/resources/auth-protocols/login-hours, volume stats), recent events,
  recent deviations, recent detection matches, recent session ids.
- `GET /api/events/{id}/deviations` - deviations flagged for one event.
- Dashboard: `/identities` (list), `/identities/{actor_id}` (detail) -
  blueprint §9.1's "Identity profile" page. `/events` also shows a
  per-event Deviations column alongside the Detections column.

## Testing

- `tests/unit/test_baseline_profile.py` - `build_profile()` against an
  isolated in-memory DB: accumulation, actor scoping, the `before` cutoff,
  volume/login-hour aggregation.
- `tests/unit/test_baseline_deviation.py` - `evaluate_deviations()` against
  hand-built profiles: cold-start suppression, each deviation type firing
  and not firing, missing-field safety.
- `tests/integration/test_baselines.py` - real ingestion traffic: no
  deviations until history exists, a new-device event correctly flagged
  once it does, replay idempotency, the identity API/dashboard reflecting
  real state.
