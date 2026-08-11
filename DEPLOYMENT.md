# Deployment & Networking — Learning Guide

This explains **exactly** how the stack is exposed, in three escalating stages:

1. **Local / LAN** — reachable on your WiFi (phones, other laptops).
2. **ngrok** — a temporary public HTTPS URL for demos.
3. **Cloud** — the production shape. The app does **not** change between stages;
   only the thing *in front of* it does.

The mental model that ties all three together:

```
                          ┌──────────────────────────┐
   client (browser/app) → │  INGRESS (one entry point) │ → app container
                          └──────────────────────────┘
                                     │  routes by path
                          ┌──────────┴───────────┐
                          ▼                       ▼
                   Signal Deck            FastAPI API
                   /app  (:8088)          /api /health /docs
                                          (app also :8000 internal)
```

The **ingress** is:
- **LAN:** the published Docker port (`proxy` on `:8088`).
- **ngrok:** ngrok's edge → tunnels to the same `proxy`.
- **Cloud:** a managed load balancer / Kubernetes `ingress-nginx` → same `proxy`
  (or the LB replaces nginx entirely).

> Because there is **one ingress** routing by path (`/api/*` → API, everything
> else → UI), the UI and API are *same-origin*. That removes CORS headaches and
> is the standard production layout.

---

## Stage 0 — Run the stack

```bash
docker compose up -d --build       # db + app(API+UI+monitor) + proxy
```

| URL | What |
|-----|------|
| http://localhost:8088/app     | Signal Deck (through the proxy — use this) |
| http://localhost:8088/docs    | API Swagger |
| http://localhost:8088/health  | API health JSON |
| http://localhost:8088/metrics | Prometheus metrics |
| http://localhost:8000/docs    | API direct (dev only, bypasses proxy) |

Always demo through **`:8088`** — it's the only thing that also works over LAN,
ngrok, and cloud unchanged. Legacy Dash `:8050` was removed.

---

## Stage 1 — LAN (same WiFi)

Everything already binds `0.0.0.0` inside the containers and the proxy publishes
`:8088`, so any device on your WiFi can reach it.

1. **Find your machine's LAN IP:**
   ```bash
   ipconfig getifaddr en0      # macOS WiFi (try en1 if blank)
   # Linux: hostname -I | awk '{print $1}'
   ```
   Example: `192.168.1.237`.

2. **On your phone/other laptop (same WiFi):** open
   `http://192.168.1.237:8088/app`

3. **If it won't connect** it's almost always the host firewall:
   - macOS: System Settings → Network → Firewall → allow Docker/incoming.
   - The router must not have "client isolation" / "AP isolation" enabled.

**Why this works:** Docker `ports: "8088:80"` binds the host's `0.0.0.0:8088`,
so the host accepts connections from the LAN and forwards them into the proxy
container. No tunnel, no internet — packets stay on your WiFi.

> LAN exposure is still real exposure to everyone on that network. Signal Deck
> requires login for triage/report; the API is JWT-gated. Don't do this on public/coffee-shop WiFi.

---

## Stage 2 — ngrok (temporary public HTTPS URL)

ngrok gives the **proxy** a public `https://<random>.ngrok-free.app` URL. ngrok
terminates TLS at its edge, so you get HTTPS for free without certificates.

1. **Get a token:** sign up at https://dashboard.ngrok.com → copy your authtoken.

2. **Put it in `.env`:**
   ```bash
   echo 'NGROK_AUTHTOKEN=2abc...your-token' >> .env
   ```

3. **Start the tunnel (compose profile, off by default):**
   ```bash
   docker compose --profile tunnel up -d
   ```

4. **Get the public URL** (either):
   ```bash
   curl -s http://localhost:4040/api/tunnels | python3 -c "import sys,json;print(json.load(sys.stdin)['tunnels'][0]['public_url'])"
   ```
   or open the ngrok inspector at http://localhost:4040 .

5. Share that `https://...ngrok-free.app` URL. `/` is the dashboard, `/docs` is
   the API — same routing as local.

**Why tunnel the proxy and not the app?** So the public surface is the *single
ingress* — identical to cloud. One URL, path-routed, same-origin.

### 🔒 Security — REQUIRED before sharing publicly

A public URL means the **whole internet** can hit it.

- **Change the admin password.** Default is `changeme`:
  ```bash
  # .env
  API_ADMIN_USER=you
  API_ADMIN_PASSWORD=a-long-random-passphrase
  ```
- **Keep `DASH_DEBUG` off** (default). With debug on, Werkzeug's debugger allows
  remote code execution — never expose it.
- **Gate the dashboard with HTTP basic-auth** at the tunnel edge. Edit the
  `ngrok` command in `docker-compose.yml`:
  ```yaml
  command: ["http", "proxy:80", "--log=stdout", "--basic-auth", "demo:somepassword"]
  ```
- ngrok free URLs rotate and show an interstitial; that's fine for demos.

---

## Stage 3 — Cloud (production shape)

The app is already cloud-ready because it's **stateless containers behind one
ingress, configured by env vars**. Going to the cloud is a sequence of swaps,
not a rewrite. Do them in this order:

### 3.1 Build & ship the image
- Build for the cloud's CPU arch and push to a registry:
  ```bash
  docker build -t <registry>/yahoo_phish:<tag> .
  docker push <registry>/yahoo_phish:<tag>
  ```
  (GitHub Container Registry / ECR / GCR / Docker Hub.)

### 3.2 Managed Postgres (replace the `db` container)
- Use RDS / Cloud SQL / Neon with `pgvector` enabled.
- Set `DATABASE_URL` (the app already reads it). Drop the `db` service.

### 3.3 Ingress + TLS + DNS (replace ngrok)
- Put a **managed load balancer** or **k8s `ingress-nginx`** in front. It plays
  the exact role the local `proxy` plays — same path routing.
- Real certificate via ACM / cert-manager (Let's Encrypt) for `https://yourdomain`.
- Point DNS at the LB.
- Set `API_ALLOWED_ORIGINS=https://yourdomain` (or a regex) for any
  cross-origin/native clients.

### 3.4 Make it horizontally scalable (the "millions" part)
These are the only stateful in-process pieces today; externalize them so you can
run **N replicas** behind the LB:

| In-process now | Swap to | Why |
|---|---|---|
| Rate limiter (in-memory token bucket) | **Redis** | shared counter across replicas |
| Idempotency store (in-memory) | **Redis / Postgres** | replay-safety across replicas |
| RTI consumer (in-proc queue) | **Kafka / SQS** consumers | fan-out across many pods |
| 1 uvicorn process | **gunicorn -k uvicorn workers** (or HPA on replicas) | use all cores |

- Run the API with multiple workers:
  ```bash
  gunicorn api.main:app -k uvicorn.workers.UvicornWorker -w 4 -b 0.0.0.0:8000
  ```
- Scale the RTI stream monitor as its own deployment; partition by channel/shard.

### 3.5 Secrets & config (12-factor)
- No secrets in `.env` committed to git. Use the cloud's secret manager
  (AWS Secrets Manager / GCP Secret Manager / k8s Secrets).
- Required: `DATABASE_URL`, `JWT_SECRET`, `API_ADMIN_PASSWORD(_HASH)`,
  `API_ALLOWED_ORIGINS`.

### 3.6 Observability
- Scrape `/metrics` with Prometheus; dashboards in Grafana.
- Ship structured logs to the cloud log sink.
- Alert on: error rate, p95 latency, anomaly EXTREME volume, drift/PSI.

---

## What changes per stage (cheat sheet)

| Concern | LAN | ngrok | Cloud |
|---|---|---|---|
| Ingress | Docker port `:8088` | ngrok edge → proxy | LB / k8s ingress → proxy |
| TLS | none (http) | ngrok edge (https) | ACM / cert-manager |
| DNS | LAN IP | ngrok subdomain | your domain |
| Auth | API only | **+ basic-auth + real admin pw** | IdP / OAuth + real admin pw |
| Postgres | container | container | managed (RDS/CloudSQL) |
| Rate-limit/idempotency | in-memory | in-memory | **Redis** |
| API processes | 1 (reload) | 1 | gunicorn workers × replicas |
| RTI consumer | in-proc | in-proc | Kafka/SQS + worker pods |

The single rule: **demo and deploy through the ingress, never the raw ports.**

---

## Quick commands

```bash
# Local + LAN
docker compose up -d --build
ipconfig getifaddr en0                       # your LAN IP → http://<ip>:8088

# Public demo
echo 'NGROK_AUTHTOKEN=...' >> .env
docker compose --profile tunnel up -d
curl -s localhost:4040/api/tunnels | python3 -c "import sys,json;print(json.load(sys.stdin)['tunnels'][0]['public_url'])"

# Tear down
docker compose --profile tunnel down
```

---

## Performance, complexity & CAP (read this before scaling)

### Complexity budget (what is O(what))

| Path | Time | Space | Notes |
|------|------|-------|-------|
| Classifier (`predict`) | **O(T)** tokens | O(1) per request | TF-IDF transform + sparse dot product; ~**sub-ms** on CPU |
| Anomaly (when gated ON) | **O(T)** embed + **O(log n)** IF score | LRU cache O(cache_size) | MiniLM embed dominates (~1–30ms); IsolationForest score is cheap |
| Anomaly gating (default) | **O(1)** decision | O(1) | Skip embed when classifier ≥85% phish or ≥92% safe |
| Rate limit | **O(1)** per key | O(1) per key | Token bucket; Redis adds one RTT (~sub-ms LAN) |
| Idempotency | **O(1)** per key | O(1) per key TTL | SET NX / GET; Redis shared across replicas |
| Threat list pagination | **O(log N)** | O(page_size) | Keyset cursor, not OFFSET |
| DB vector search | **O(log N)** approx | O(top_k) | IVFFlat index on pgvector |
| RTI consumer queue | **O(1)** submit | **O(maxsize)** bounded | Backpressure; never unbounded RAM |

**Rule:** hot RTI path should stay **classifier-only** for obvious verdicts; reserve the embed path for gray zone + novel surfacing.

### Latency findings (measured on this host, May 2026)

| Channel | Fast path (gated) | Full path (anomaly) |
|---------|-------------------|---------------------|
| phishing | ~0.4ms avg | ~30–45ms (embed) |
| smishing | ~0.3ms avg | ~30ms (embed) |
| vishing | ~0.3ms avg | ~30ms (embed) |

After **anomaly gating + embedding LRU cache**, repeat traffic on the fast path is sub-millisecond. Novel/gray-zone traffic pays the embed cost — that is the correct tradeoff.

### Memory & concurrency at scale

| Component | Single instance | N replicas |
|-----------|-----------------|------------|
| ML models (per worker) | ~200–400MB RAM | **× workers × replicas** — largest cost |
| Redis | 256MB cap (LRU evict) | Shared; rate-limit + idempotency |
| Postgres | grows with threats | Managed RDS + read replicas for analytics |
| Embedding cache | 8192 entries (~12MB) | Per-process; use Redis cache layer at scale |

**Gunicorn workers:** `API_WORKERS=2` default. More workers = more parallel CPU but **each worker loads MiniLM + sklearn**. For millions of RTI msgs/sec, split into:
- **Stateless API pods** (classifier-only fast path, horizontal scale)
- **Anomaly worker pool** (batch embed + IF score, Kafka/SQS partitioned by channel)
- **Never** block the RTI hot path on a 60s model fit

### Caching & offload stack

1. **Anomaly gating** — skip embed on high-confidence classifier verdicts (already on).
2. **Embedding LRU** (`EMBED_CACHE_SIZE=8192`) — O(1) repeat lookups.
3. **Model warm-up at startup** — `warm_anomaly()` off hot path.
4. **Redis** — shared rate-limit + idempotency across replicas (CP on Redis).
5. **Next at scale:** Redis embedding cache (cross-pod), batch `encode()` in RTI consumer, optional GPU/MPS for embed tier.

### CAP theorem — what we chose

| Store | CAP posture | Why |
|-------|-------------|-----|
| **Postgres** | **CP** (consistent + partition-tolerant) | Threat records must not duplicate or lose writes; sacrifice availability under partition |
| **Redis** (rate/idempotency) | **CP** | Limits must be exact across pods; brief unavailability → fail closed (429) not unlimited |
| **In-memory fallback** | **AP** (single pod only) | Dev/single-instance; breaks consistency when you scale horizontally |
| **RTI consumer queue** | **Bounded AP** | `DROP_NEW` under overload sheds load vs OOM; `BLOCK` applies backpressure |

You cannot have perfect consistency, availability, and partition tolerance simultaneously. This stack **prioritizes CP on auth/limits/threats** and **bounded AP on ingestion** (drop or block under overload rather than corrupt state).

### Smish tuning result (step 3)

Added **OTP delivery vs OTP theft** structural features + legit OTP seed pairs. Golden smish gate went from **FAIL (12% FPR)** → **PASS (100% acc, 0% FPR)** on held-out set. Next tuning loop: expand golden set, wire drift/PSI alerts on the KPI tab, threshold calibration per channel.
