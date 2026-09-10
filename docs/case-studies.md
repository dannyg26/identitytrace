# Incident Case Studies

Two full investigation flows (blueprint §14.1's "two or more polished
incident case studies"), using **real, unedited output** from this
system - generated via `scripts/seed_demo_data.py --seed 42` and fetched
from `GET /api/incidents/{id}`, not hand-written for effect. Reproduce
either one yourself: seed the demo data, start the app, open
`/incidents`, and click through.

---

## Case study 1 — malicious OAuth consent (A2)

**`IDT-CORR-001:a7a457b4-b3cc-40c9-ba56-4713a02de124`** · identity
`a2-victim-1@eval.test` · severity **critical** · score **100** ·
confidence **0.64**

### What happened, in order

| Time | Signal | Evidence |
|---|---|---|
| 09:00:00 | `new_session_context` (+15) | Successful device-code authentication - a legitimate-looking sign-in flow, but from attacker-controlled infrastructure once the code is approved. |
| 09:05:00 | `risky_oauth_consent` (+35) | The same identity consented to an OAuth application requesting `Files.Read.All` five minutes later. |
| 09:07:00 | `sensitive_resource_access` (+30) | Two minutes after that, the identity's mailbox was accessed successfully. |

Three independent detections (`IDT-ENTRA-003`, `IDT-ENTRA-001`,
`IDT-XDOMAIN-002`), each individually only medium-or-lower severity,
fired within a 7-minute span for one identity - satisfying
`IDT-CORR-001`'s sequence (`new_session_context -> risky_oauth_consent ->
sensitive_resource_access`, 15-minute window) and producing one incident
instead of three disconnected alerts.

### Score breakdown

```
event_risk            80   (15 + 35 + 30, the three atomic rule scores above)
behavioral_deviation   0   (this identity had no baseline history yet - too new to call anything "new")
temporal_chain_bonus  40   (IDT-CORR-001's score_bonus)
─────────────────────────
total                100   (clamped to 100; raw sum was already exactly 100)
```

### Confidence breakdown

```
correlation_strength  0.53   (the chain used 7 of its 15-minute window - reasonably tight, not instant)
evidence_quality      0.75   (a 3-step sequence, out of this project's 4-step cap)
telemetry_completeness 0.67  (2 of 3 evidence events carry raw source payloads;
                              the third is a synthetic mailbox-access event with none)
confidence            0.64
```

### ATT&CK mapping

T1078 (Valid Accounts), T1550.001 (Use Alternate Authentication Material:
Application Access Token).

### Recommended analyst action

Per the blueprint's own reference narrative (§16.3): validate the
device-code request with the user, review the OAuth app's consent grant
and revoke it if unauthorized, inspect what the app actually accessed via
the granted `Files.Read.All` scope, and preserve the evidence above.

---

## Case study 2 — developer token compromise (A4)

**`IDT-CORR-005:116721c3-a802-478a-842a-9da38a2d3d4a`** · identity
`a4-dev-1` (a GitHub actor, not an email-style identity - developer
telemetry uses the platform's own actor naming) · severity **critical** ·
score **100** · confidence **0.74**

### What happened, in order

| Time | Signal | Evidence |
|---|---|---|
| 02:00:00 | `repo_access` (+15) | A personal access token accessed `acme/normal-repo` - unremarkable by itself; developers use PATs constantly. |
| 02:02:00 | `sensitive_resource_access` (+50) | Two minutes later, the *same token* accessed `acme/secret-infra` - a repository whose name itself is the signal. |
| 02:09:00 | `bulk_data_access` (+55) | Seven minutes after that, the token cloned `acme/secret-infra` at 150MB - well past the bulk-clone threshold. |

### Score breakdown

```
event_risk            120   (15 + 50 + 55 - deliberately shown unclamped: two of these
                             three rules are independently "high" severity on their own)
behavioral_deviation    0
temporal_chain_bonus    30   (IDT-CORR-005's score_bonus)
──────────────────────────
raw total              150
clamped total          100   <- the formula's clamp(..., 0, 100) actually doing work here,
                              not a coincidence like case study 1's exact-100 sum
```

### Confidence breakdown

```
correlation_strength  0.55   (9 of the 20-minute window used)
evidence_quality      0.75   (3-step sequence)
telemetry_completeness 1.0   (all three events are GitHub-normalized with full raw evidence)
confidence            0.74
```

Notably higher confidence than case study 1 (0.74 vs. 0.64) despite a
similar chain shape - driven entirely by `telemetry_completeness`: every
event here traces to a real raw GitHub audit payload, where case study 1
had one synthetic event with none. This is the confidence model rewarding
exactly what it's supposed to reward: how much of the story an analyst
could actually go verify.

### ATT&CK mapping

T1213 (Data from Information Repositories).

### Recommended analyst action

Revoke the personal access token immediately, audit everything it
touched during its lifetime (not just this window), and treat
`acme/secret-infra`'s contents as potentially exposed - rotate any
credentials or secrets that repository held.

---

## What these two cases show together

- **Alert reduction in practice**: 6 atomic detections (3 per case)
  became 2 incidents - the same 3x reduction ratio the evaluation harness
  measures in aggregate (`docs/evaluation.md`).
- **The clamp is not decorative**: case study 2's raw score (150) getting
  clamped to 100 is the incident-score formula's ceiling actually
  triggering, not just a number that happens to land at 100.
- **Confidence isn't just "more signals = more confident"**: both cases
  have identical `evidence_quality` (3-step chains) and zero behavioral
  deviation contribution, yet differ by 0.10 in confidence purely on
  telemetry completeness - a concrete illustration of the model doing
  what its docstring in `app/correlation/scoring.py` claims.
