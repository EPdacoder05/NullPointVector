# NullPoint

I built NullPoint to catch phishing, smishing, and vishing before they hit grandma — and to let an operator **grade** what the model got wrong without silently poisoning production.

Console: **Signal Deck** (brass + forest, Jinja + hand CSS/JS, no purple, no emoji UI, no npm).

**Try it:** [epdacoder05.github.io/NullPointVector](https://epdacoder05.github.io/NullPointVector/) — paste a message, see tags + a verdict. Paste-analyze uses the same public policy/lexicon layer as production. Champion SGD weights stay private.

I’d rather hold a borderline message than miss a threat. False positives annoy people; false negatives empty accounts. The golden gate still budgets FPR so we don’t become a spam filter that cries wolf.

## What I locked (on purpose)

- Channels labeled Phishing / Smishing / Vishing
- Call path: Call Directory + Message Filter. I will not become a telecom (no Twilio / SIP / Telnyx product track)
- Credit/OSINT outsourced (Plaid / Array / IPQS / HIBP); vendor errors **fail open**
- Known-good = domain **+ auth_pass always**. Spoofed Cap1/PayPal still hits ML
- Model promotion only through the golden-eval gate

Internal state lives in [`docs/AI_DEV_CHECKPOINT.md`](docs/AI_DEV_CHECKPOINT.md). What I keep off git: [`docs/TRADE_SECRETS.md`](docs/TRADE_SECRETS.md).

Friends-and-family ship (public URL, signup, Gmail OAuth, IPQS, TestFlight): [`docs/PILOT_SHIP.md`](docs/PILOT_SHIP.md). Privacy: `/app/privacy`.

## Run it locally

```bash
cp .env.example .env   # fill secrets — never commit .env
docker compose up -d --build
```

| URL | What |
|-----|------|
| http://localhost:8088/app | Signal Deck |
| http://localhost:8088/docs | API |
| http://localhost:8088/health | Liveness |

After adding routes: `docker compose restart app` (bind mount does not hot-reload Python).

## How it thinks

```
browser / iOS Guard
        │
   nginx :8088  ─── /app → Signal Deck
                 └─ /api → REST
        │
   Postgres + pgvector · Redis
        │
   policy (malice → known-good+auth → marketing) → TF-IDF + SGD
```

Grade in the Deck → Postgres + feedback buffer → ephemeral `partial_fit` (toast Δw only) → nightly gated retrain. GATE FAIL keeps the old champion.

## Tests I actually run

```bash
pytest -q test/test_pills.py test/test_message_tags.py test/test_policy_pipeline.py \
  test/test_user_reports.py test/test_safe_domains.py test/test_account_delete.py \
  test/test_new_tags.py
pytest -q test/test_model_gate.py test/test_trainer_gate.py
```

## Layout

| Path | Role |
|------|------|
| `web/` | Signal Deck |
| `api/` | FastAPI |
| `common/` | Policy, grading, features |
| `PhishGuard/` `SmishGuard/` `VishGuard/` | Channel detectors + golden eval |
| `Autobot/` | IMAP ingest |
| `ios/` | NullPoint Guard |
| `pages/` | Public GitHub Pages demo |
| `docs/AI_DEV_CHECKPOINT.md` | Resume anchor for me / agents |

LAN / ngrok / cloud: [`DEPLOYMENT.md`](DEPLOYMENT.md).
