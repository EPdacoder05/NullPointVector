# Pre-CallKit Readiness & Roadblocks

Decision doc: **what must be true before spending on the Apple CallKit integration
and leaning on Smish/Vish in production.** Status as of this milestone.

---

## Done & verified this milestone (not a roadblock)

| Area | Evidence |
|---|---|
| API security (JWT, RBAC, rate-limit, idempotency, pagination) | smoke gate green |
| Model quality gates | Phish 97.5% acc / 100% recall; **Smish 100%**; **Vish 93.8% acc / 87.5% recall** — all PASS the golden gate |
| Anti-poisoning trainer gate | green |
| Security suite | 50/50 (+ argon2 backend added, + server-side **pepper** on top of Argon2 auto-salting) |
| Self-heal / no data loss | Durable DLQ (Redis + disk), bounded retry, auto-replay drainer. **Live drill:** DB stopped → `analyze` still 200 + threat buffered → DB back → drainer replayed → 0 lost |
| Redundancy basics | `restart: unless-stopped` on app/db, health-gated deps, opt-in `autoheal` sidecar, Redis AOF, persistent volumes |
| Premium console | `/app` — Phish/Smish/Vish views, live verdicts + feed (no npm/CDN) |
| Future-proofing | FastAPI `lifespan` migration (no deprecated hooks) |

---

## Hard roadblocks — resolve BEFORE CallKit spend

### R1. CallKit → VishGuard data contract — **RESOLVED: HYBRID (c), implemented**
Decision locked: **hybrid** = reputation (every call, number-only) + transcription
(voicemail/opt-in, content). Backend is built + tested (13 tests green):
- `common/reputation/*` — vendor-agnostic, env-keyed provider framework
  (local + FTC/Nomorobo/Hiya/Truecaller/Robokiller), Redis-cached, fail-safe.
- `common/vish/{contract,adapter}.py` — `CallEvent`→`ScreenResult` fusion → one
  CallKit action (allow/label/silence/block) with consumer reasons.
- `POST /api/v1/vish/screen` — live, smoke-tested both paths.
- Spec for the iOS team: `docs/CALLKIT_DATA_CONTRACT.md`.
**Remaining for R1 = your action items** (Apple Dev account + Xcode CallDirectory
extension) and **vendor API keys** (drop in env → providers auto-enable).

### R2. scikit-learn pin + champion artifact regeneration
Model pkls were trained on sklearn 1.7.2; the image can resolve a newer sklearn →
`InconsistentVersionWarning` → **silent retrain on every boot** (cold-start cost +
non-reproducible verdicts). Affects Phish **and** Smish/Vish identically. Pin
sklearn and regenerate/version the artifacts so they load deterministically.
*(Still pending — top reproducibility/cold-start item.)*

### R3. Expand Smish/Vish golden sets — **infra built, data expansion pending**
Generalized champion/challenger training loop now exists for both channels:
`common/ml/training/` (ChannelTrainer + golden eval with Wilson CIs + gate). The
CIs make the problem explicit: even Smish at 100% has recall CI **[0.68, 1.0]** on
n=16, and the Vish gate correctly **blocks promotion** at recall 0.875 (<0.90).
Seed expansion is wired via `seed_connectors.py` (local drop-ins at
`data/seed/<channel>/*.jsonl` + env-keyed HTTP feeds). **Remaining: feed in the
external corpora** (Robokiller/Cloaked/FTC/Phishy_Bizz) to grow each held-out set
to a few hundred and fix the Vish false negative, then retrain through the gate.

---

## P1 — scale hardening (can follow CallKit, needed before "millions")

- **R4. DB is single-instance.** DLQ covers transient blips (proven), but a total
  DB loss = downtime until restore. For real HA add a Postgres replica / managed
  HA (RDS/Cloud SQL). Current posture = self-heal + buffer, **not** failover.
- **R5. Ingest queue is in-process.** Confirmed-but-unpersisted threats are
  dead-lettered (safe); records still *in* the worker queue at a hard crash are
  not durable. For at-least-once at scale, front the consumer with Redis
  Streams/Kafka (the `RTIConsumer` is already designed to sit behind one).
- **R6. Stream load test.** Validate throughput + backpressure + batch rate-limit
  at target rate before claiming millions-scale (the `stream-verify` task).

---

## Security must-do before any public ship
- **Rotate `.env` secrets.** It contains real-looking Yahoo/Gmail/Outlook app
  passwords + `ENCRYPTION_KEY`. Rotate and move to a secret manager.
- **Set `PASSWORD_PEPPER`** in the production environment (hashing falls back to
  no-pepper if unset, by design, but prod should set it).
- **`autoheal` uses the Docker socket** (root-equivalent) — keep it opt-in on VMs;
  in k8s use liveness probes instead.

---

## Bottom line

Nothing structurally blocks shipping the **web** product today. CallKit gates:
- **R1 (data contract)** — RESOLVED: hybrid built + tested. Remaining = your Apple
  account/Xcode work + vendor API keys.
- **R2 (sklearn pin)** — ~done; one follow-up: anomaly IF manifolds still show a
  1.8.0→1.9.0 `InconsistentVersionWarning`, regenerate them with the SGD models.
- **R3 (bigger Smish/Vish eval)** — training loop + gate + seed connectors built;
  remaining = feed external corpora to expand golden sets + fix the Vish FN.
