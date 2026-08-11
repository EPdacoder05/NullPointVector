# NullPoint

Multi-channel phishing / smishing / vishing detection. Operator console: **Signal Deck**.

Locked product surface (do not re-litigate):
- Channels labeled Phishing / Smishing / Vishing
- UI: gold/brass + forest green; Jinja + hand-written CSS/JS only (no npm/CDN, no purple, no emoji UI)
- Call path: Call Directory + Message Filter (+ optional Live Caller ID later). No Twilio / SIP / Telnyx product track
- Credit/OSINT outsourced (Plaid / Array / IPQS / HIBP); vendor errors **fail open**
- Model promotion only through the golden-eval gate

**Source of truth for state and open work:** [`docs/AI_DEV_CHECKPOINT.md`](docs/AI_DEV_CHECKPOINT.md)

## Quick start

```bash
cp .env.example .env   # fill secrets locally — never commit .env
docker compose up -d --build
```

| URL | What |
|-----|------|
| http://localhost:8088/app | Signal Deck (nginx ingress — use this) |
| http://localhost:8088/docs | API OpenAPI |
| http://localhost:8088/health | Liveness |

Restart the app container after adding routes (`docker compose restart app`); the bind mount does not hot-reload Python.

## Architecture (pilot)

```
browser / iOS Guard
        │
   nginx :8088  ─── /app → FastAPI Signal Deck
                 └─ /api → FastAPI REST
        │
   Postgres + pgvector · Redis (rate limit / idempotency)
        │
   PhishGuard · SmishGuard · VishGuard  (TF-IDF + SGD + structural features)
        │
   policy_pipeline → known-good (domain + auth_pass) → marketing cap → ML
```

Legacy Dash (`:8050`) was removed. Single ingress is `:8088`.

## Feedback loop

1. Grade in Signal Deck → Postgres `label` + `feedback.jsonl`
2. Ephemeral `partial_fit` for toast Δw only
3. Nightly gated retrain promotes champion only on GATE PASS

## Verify

```bash
pytest -q test/test_pills.py test/test_message_tags.py test/test_policy_pipeline.py \
  test/test_user_reports.py test/test_safe_domains.py test/test_account_delete.py \
  test/test_new_tags.py
# ML gate (heavier):
pytest -q test/test_model_gate.py test/test_trainer_gate.py
```

## Repo layout

| Path | Role |
|------|------|
| `web/` | Signal Deck (Jinja + static) |
| `api/` | FastAPI REST |
| `common/` | Shared policy, grading, ML features, mail helpers |
| `PhishGuard/` `SmishGuard/` `VishGuard/` | Channel detectors + golden eval |
| `Autobot/` | IMAP ingest / stream monitor |
| `ios/` | NullPoint Guard (Call Directory + SMS Filter) |
| `scripts/` | One-shot backfill / benchmarks / nightly |
| `docs/AI_DEV_CHECKPOINT.md` | Resume anchor |

`archive/` (hackbook labs) was retired — do not resurrect CI jobs that build it.

## Deploy notes

See [`DEPLOYMENT.md`](DEPLOYMENT.md) for LAN / ngrok / cloud ingress. Production shape is unchanged: one proxy in front of the app container.
