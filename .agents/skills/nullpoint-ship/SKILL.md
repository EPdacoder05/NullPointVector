---
name: nullpoint-ship
description: >-
  NullPoint product/engineering guardrails: locked decisions, feedback-loop
  (ephemeral vs gated durable), Call Directory vs SIP, multi-tenant safety,
  DRY/scripts policy, and verify-before-claim. Use when working in Yahoo_Phish /
  NullPoint, Signal Deck, PhishGuard/SmishGuard/VishGuard, iOS Guard, or when
  the user mentions grading, benchmarks, CallKit, Funnel, or pilot ship cuts.
---

# NullPoint ship skill

## Always first
Read `docs/AI_DEV_CHECKPOINT.md`. Update its "Last updated" when the session ends.

## Locked UI (do not change without explicit ask)
- **Cascade modal** `APPLY TO OTHER MAIL FROM THIS SENDER?` — bugfixes only.
- Provider junk after Block is **async** (`provider_action_queue` + BackgroundTasks / `drain_provider_queue.py`). Never inline per-sibling IMAP in the grade request.
- Predict overrides go through `common/policy_pipeline.py` (single-pass signals). Do not re-stack sequential re-parses in `predict()`.
- **Known-good = domain + auth_pass always.** Never short-circuit on domain alone (spoofed brand From must hit ML). Cap1/GitHub/Chime — same rule. Cap1 is not special.
- **Payment-brand spoof:** PayPal/Venmo/Zelle/Cash App ask without that brand in From/URLs → hard malice (`policy_pipeline._payment_brand_spoof`).
- **User report loop:** `POST /app/report` → `user_reports` (personal) + fleet promotion thresholds (review 3 / auto 8, conf cap 0.75). UI: **Report this** flag separate from Block / Needs review / Mark safe. Do not merge into the triage row.
- **Tag pills:** `.reason-tags` is **block + inline-block pills** (never flex-grow). Stretch bugs = wrong layout model or stale CSS cache — bump `?v=` in `base.html` after CSS changes.
- **IMAP ingest dedup** via `common/ingest_dedup.py` (Message-ID + ingest_fp unique indexes). API `Idempotency-Key` does **not** cover IMAP polls — do not assume it does.
- Call path: **Call Directory + Message Filter** (+ optional Live Caller ID Lookup later). **No Twilio. No SIP/Telnyx/MVNO as product path** — we will not become a telecom. Number check = our DB + vendor reputation (IPQS etc., fail-open). Voicemail/share is optional assist, not the granny path.
- Credit/OSINT: outsourced vendors only; fail-open.
- Hot path ML: TF-IDF + SGD (+ structural). LLMs = explain assist only.
- Reputation vendor errors **fail open**.
- Never commit `.env`; secrets in chat are burned.
- Model promotion only through golden gate (`channel_trainer` / nightly). Never bypass a failing gate.

## Feedback loop (cemented)
1. **Grade → Postgres** (`label` 0/1, `is_threat` aligned). Triage lists use `label IS NULL`.
2. **→ feedback.jsonl** durable buffer (`common/grading.record_grade`).
3. **→ ephemeral `partial_fit`** (`common.ml.partial_fit_safe`) for toast Δw only — process memory.
4. **→ nightly gated retrain** promotes champion only on GATE PASS.
Do **not** treat single-sample partial_fit as production weight authority (poison/drift).

## INTEGER vs BOOLEAN `is_threat`
Column is `INTEGER` 0/1. Use `is_threat = 1`, never `= TRUE` (Postgres type error). Prefer keeping INTEGER for consistency with `label`; migrating to BOOLEAN is cosmetic unless starting a greenfield table.

## Multi-tenant (required before pilot users)
- Namespaced mailboxes + personal allow/block by `account_sub`.
- Shared campaign intel separate from personal lists; seeds need source + kill switch.
- Never show operator A’s Yahoo / blocks to operator B.
- OAuth-first mail; Yahoo = guided app-password (not raw account password).

## Scripts policy (DRY)
- Prefer one script per job family (`refresh_benchmarks`, `weekly_benchmarks`, `nightly_retrain`, `seed_*` only for one-shot campaigns).
- Do not add parallel “Claude paste” phone_threats stacks if `get_vish_directory` + messages/campaign JSON already serve Call Directory — extend those hooks.
- Before new helpers: grep for `_PHONE_RE`, `normalize_number`, `score_number`, `format_local`.

## iOS autonomy truth
Apple does not emit carrier incoming-call webhooks to third-party apps. Sell: fat backend directory + Call Directory sync; Live Caller ID Lookup for unknowns later. SMS Message Filter = true RTI on-device. Email can poll closer to streamful (~1 min) without becoming a carrier.

## Channel honesty (locked product boundary)
| Channel | Real-time? | How |
|---|---|---|
| SMS / Smish | Yes (best RTI) | iOS Message Filter / Android RECEIVE_SMS — content on device |
| Email / Phish | Near-stream | Poll (target 1 min); IMAP IDLE later |
| Calls / Vish | Pre-ring number only | Call Directory + Live Lookup + vendor reputation; **no live carrier audio** without owning telephony (out of scope) |

## Verify before claiming
Use curl/pytest commands in checkpoint §1/§8. After UI routes: `docker compose restart app`.

## Trade secret posture
Closed source. Protect models, golden sets, campaign packs, unpublished process. Copyright ≠ stopping feature clones; ship product + data + gate metrics.
