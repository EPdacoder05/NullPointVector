"""
Checkout / billing — Stripe-ready with local mock (NoW-inspired controls).

Best practices ported (not a full NoW clone):
  * Server-side price authority (never trust client amounts)
  * Payload shape / depth guards
  * Checkout velocity limit (Redis when available, else process-local)
  * Hash-chained payment audit events (tamper evidence)
  * Explicitly gated local mock sessions for development only
  * Trial abuse risk score (fingerprint + IP + UA) for Pro 7-day trial

Billing mutations remain disabled until BILLING_ENABLED=true. Production never
accepts mock sessions, even if BILLING_MOCK is accidentally set.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
from typing import Any, Optional

logger = logging.getLogger("billing")

# TODO(BILLING_MOCK): set BILLING_MOCK=false + STRIPE_* keys to leave mock path.
_VELOCITY: dict[str, list[float]] = {}
_VELOCITY_WINDOW = 10 * 60
_VELOCITY_MAX = 8
_PRODUCTION_BILLING_READY = False


def billing_enabled() -> bool:
    """Billing mutations are opt-in until the live merchant gate is verified."""
    requested = os.getenv("BILLING_ENABLED", "false").strip().lower() in (
        "1", "true", "yes",
    )
    if not requested:
        return False
    # Webhook replay/idempotency and subscription lifecycle reconciliation are
    # not complete. An environment toggle must not accidentally charge users.
    if _production() and not _PRODUCTION_BILLING_READY:
        return False
    return True


def _production() -> bool:
    from common.config import is_production_environment
    return is_production_environment()


def stripe_configured() -> bool:
    return bool(os.getenv("STRIPE_SECRET_KEY", "").strip())


def use_mock() -> bool:
    """True only for an explicitly non-production development simulation."""
    if _production():
        return False
    flag = os.getenv("BILLING_MOCK", "true").strip().lower()
    if flag in ("1", "true", "yes"):
        return True
    return not stripe_configured()


def _stable_stringify(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def hash_audit_record(*, previous_hash: str, event_type: str, stream_id: str,
                      payload: dict, timestamp: str) -> str:
    canonical = "|".join([
        previous_hash or "",
        event_type,
        stream_id,
        _stable_stringify(payload),
        timestamp,
    ])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def ensure_billing_tables(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS payment_audit_events (
                id BIGSERIAL PRIMARY KEY,
                stream_id VARCHAR(128) NOT NULL,
                event_type VARCHAR(64) NOT NULL,
                provider VARCHAR(32) NOT NULL DEFAULT 'stripe',
                event_payload JSONB NOT NULL,
                previous_hash VARCHAR(64),
                event_hash VARCHAR(64) NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_payment_audit_stream
              ON payment_audit_events (stream_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS billing_entitlements (
                account_sub TEXT PRIMARY KEY,
                plan_slug TEXT NOT NULL,
                interval TEXT NOT NULL DEFAULT 'monthly',
                status TEXT NOT NULL DEFAULT 'active',
                trial_ends_at TIMESTAMPTZ,
                session_id TEXT,
                source TEXT NOT NULL DEFAULT 'mock',
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS trial_fingerprints (
                fingerprint TEXT PRIMARY KEY,
                account_sub TEXT,
                risk_score INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 1,
                last_ip TEXT,
                last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            """
        )
    conn.commit()


def append_audit_event(conn, *, stream_id: str, event_type: str,
                       payload: dict, provider: str = "stripe") -> str:
    ensure_billing_tables(conn)
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT event_hash FROM payment_audit_events
            WHERE stream_id = %s ORDER BY id DESC LIMIT 1
            """,
            (stream_id,),
        )
        row = cur.fetchone()
        previous = (row[0] if row else "") or ""
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        event_hash = hash_audit_record(
            previous_hash=previous, event_type=event_type,
            stream_id=stream_id, payload=payload, timestamp=ts,
        )
        cur.execute(
            """
            INSERT INTO payment_audit_events
              (stream_id, event_type, provider, event_payload, previous_hash, event_hash)
            VALUES (%s, %s, %s, %s::jsonb, %s, %s)
            """,
            (stream_id, event_type, provider, json.dumps(payload), previous or None, event_hash),
        )
    conn.commit()
    return event_hash


def plan_by_slug(slug: str) -> Optional[dict]:
    from common.plans import list_plans
    for p in list_plans():
        if p["slug"] == slug:
            return p
    return None


def validate_checkout_payload(body: dict) -> tuple[bool, str]:
    """Reject unsafe / oversized payloads (NoW-style shape guard)."""
    if not isinstance(body, dict):
        return False, "payload must be an object"
    if len(body) > 20:
        return False, "too many keys"
    plan = str(body.get("plan") or "").strip().lower()
    interval = str(body.get("interval") or "monthly").strip().lower()
    email = str(body.get("email") or "").strip()
    if plan not in ("essential", "pro"):
        return False, "unknown plan" if plan != "enterprise" else "contact_sales"
    if interval not in ("monthly", "annual"):
        return False, "bad interval"
    if email and ("@" not in email or len(email) > 254):
        return False, "bad email"
    # Never accept client-supplied price.
    if "price" in body or "amount" in body or "unit_amount" in body:
        return False, "client price not allowed"
    return True, ""


def check_velocity(key: str) -> bool:
    """Return True if under limit, False if blocked."""
    now = time.time()
    try:
        import redis
        url = os.getenv("REDIS_URL", "").strip()
        if url:
            r = redis.from_url(url, socket_connect_timeout=0.4)
            rk = f"np:checkout:vel:{key}"
            n = r.incr(rk)
            if n == 1:
                r.expire(rk, _VELOCITY_WINDOW)
            return n <= _VELOCITY_MAX
    except Exception:
        pass
    bucket = [t for t in _VELOCITY.get(key, []) if now - t < _VELOCITY_WINDOW]
    bucket.append(now)
    _VELOCITY[key] = bucket
    return len(bucket) <= _VELOCITY_MAX


def trial_risk_score(*, ip: str, user_agent: str, fingerprint: str,
                     want_trial: bool) -> dict:
    """Internal risk score for free-trial abuse (0–100). Higher = riskier."""
    if not want_trial:
        return {"score": 0, "allow": True, "reasons": []}
    score = 0
    reasons = []
    fp = (fingerprint or "").strip()
    if not fp or len(fp) < 8:
        score += 35
        reasons.append("missing_device_fingerprint")
    ua = (user_agent or "").lower()
    if not ua or "mozilla" not in ua and "applewebkit" not in ua:
        score += 15
        reasons.append("odd_user_agent")
    if ip in ("", "127.0.0.1", "::1", "unknown"):
        score += 10
        reasons.append("local_or_unknown_ip")
    # Prior trial attempts on same fingerprint.
    try:
        from Autobot.VectorDB.NullPoint_Vector import connect_db
        conn = connect_db()
        if conn:
            try:
                ensure_billing_tables(conn)
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT attempts, risk_score FROM trial_fingerprints WHERE fingerprint=%s",
                        (fp or "none",),
                    )
                    row = cur.fetchone()
                    if row and int(row[0]) >= 2:
                        score += 40
                        reasons.append("repeat_trial_fingerprint")
                    elif row:
                        score += 15
                        reasons.append("prior_trial_attempt")
            finally:
                conn.close()
    except Exception as e:
        logger.debug("trial fingerprint lookup skipped: %s", e)
    allow = score < 70
    return {"score": min(100, score), "allow": allow, "reasons": reasons}


def record_trial_fingerprint(fingerprint: str, account_sub: str, ip: str, risk: int) -> None:
    if not fingerprint:
        return
    try:
        from Autobot.VectorDB.NullPoint_Vector import connect_db
        conn = connect_db()
        if not conn:
            return
        try:
            ensure_billing_tables(conn)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO trial_fingerprints (fingerprint, account_sub, risk_score, attempts, last_ip)
                    VALUES (%s, %s, %s, 1, %s)
                    ON CONFLICT (fingerprint) DO UPDATE SET
                      attempts = trial_fingerprints.attempts + 1,
                      risk_score = GREATEST(trial_fingerprints.risk_score, EXCLUDED.risk_score),
                      last_ip = EXCLUDED.last_ip,
                      last_seen = NOW()
                    """,
                    (fingerprint, account_sub or None, int(risk), ip or None),
                )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        logger.warning("trial fingerprint record failed: %s", e)


def resolve_amount_cents(plan: dict, interval: str) -> int:
    dollars = plan["price_annual"] if interval == "annual" else plan["price_monthly"]
    return int(round(float(dollars) * 100))


def start_checkout(*, plan_slug: str, interval: str, email: str,
                   account_sub: str, base_url: str, client_ip: str,
                   user_agent: str, fingerprint: str, want_trial: bool) -> dict:
    """Create checkout session (mock or Stripe). Returns redirect URL + meta."""
    plan = plan_by_slug(plan_slug)
    if not plan:
        return {"ok": False, "error": "unknown_plan"}
    if plan.get("sales_only") or plan_slug == "enterprise":
        return {"ok": False, "error": "contact_sales"}
    if not billing_enabled():
        return {"ok": False, "error": "billing_disabled"}
    if _production() and (
        not stripe_configured()
        or not os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
    ):
        return {"ok": False, "error": "billing_not_configured"}

    if want_trial and plan_slug != "pro":
        return {"ok": False, "error": "trial_pro_only"}
    if want_trial and int(plan.get("trial_days") or 0) <= 0:
        return {"ok": False, "error": "no_trial_on_plan"}

    risk = trial_risk_score(
        ip=client_ip, user_agent=user_agent, fingerprint=fingerprint, want_trial=want_trial)
    if want_trial and not risk["allow"]:
        return {"ok": False, "error": "trial_blocked", "trial_risk": risk}

    vel_key = f"{client_ip}:{plan_slug}"
    if not check_velocity(vel_key):
        return {"ok": False, "error": "velocity_limit"}

    amount = resolve_amount_cents(plan, interval)
    stream_id = f"checkout:{(account_sub or email or 'anon')[:64]}"
    session_id = f"local_{secrets.token_hex(12)}" if use_mock() else ""

    payload = {
        "plan": plan_slug,
        "interval": interval,
        "amount_cents": amount,
        "email": email or None,
        "account_sub": account_sub or None,
        "trial": want_trial,
        "trial_risk": risk,
        "mock": use_mock(),
    }

    conn = None
    try:
        from Autobot.VectorDB.NullPoint_Vector import connect_db
        conn = connect_db()
        if conn:
            append_audit_event(
                conn, stream_id=stream_id, event_type="checkout_started", payload=payload,
                provider="mock" if use_mock() else "stripe",
            )
    except Exception as e:
        logger.warning("checkout audit start failed: %s", e)

    if use_mock():
        # TODO(BILLING_MOCK): replace with stripe.checkout.sessions.create
        url = f"{base_url.rstrip('/')}/app/checkout/success?session_id={session_id}"
        if want_trial:
            record_trial_fingerprint(fingerprint, account_sub, client_ip, risk["score"])
        if conn:
            try:
                append_audit_event(
                    conn, stream_id=stream_id, event_type="checkout_session_created",
                    payload={**payload, "session_id": session_id, "degraded": True},
                    provider="mock",
                )
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        return {
            "ok": True,
            "url": url,
            "session_id": session_id,
            "degraded": True,
            "mock": True,
            "amount_cents": amount,
            "trial_risk": risk,
        }

    # Live Stripe path (keys present, BILLING_MOCK off)
    try:
        import stripe
        stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
        line_items = [{
            "price_data": {
                "currency": "usd",
                # A Stripe trial delays collection; it must not turn the
                # recurring subscription price into a permanent $0 price.
                "unit_amount": amount,
                "product_data": {
                    "name": f"NullPoint {plan['name']} ({interval})",
                    "metadata": {"plan": plan_slug, "interval": interval},
                },
                "recurring": {"interval": "year" if interval == "annual" else "month"},
            },
            "quantity": 1,
        }]
        # Prefer Price IDs from env when you create them in Stripe Dashboard.
        price_env = os.getenv(f"STRIPE_PRICE_{plan_slug.upper()}_{interval.upper()}", "").strip()
        if price_env and not want_trial:
            line_items = [{"price": price_env, "quantity": 1}]

        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=line_items,
            success_url=f"{base_url.rstrip('/')}/app/checkout/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{base_url.rstrip('/')}/app/pricing",
            customer_email=email or None,
            metadata={
                "plan": plan_slug, "interval": interval,
                "account_sub": account_sub or "", "trial": str(want_trial).lower(),
            },
            subscription_data=(
                {"trial_period_days": int(plan["trial_days"])} if want_trial else None
            ),
            automatic_payment_methods={"enabled": True},
        )
        if want_trial:
            record_trial_fingerprint(fingerprint, account_sub, client_ip, risk["score"])
        if conn:
            append_audit_event(
                conn, stream_id=stream_id, event_type="checkout_session_created",
                payload={**payload, "session_id": session.id},
                provider="stripe",
            )
            conn.close()
        return {
            "ok": True,
            "url": session.url,
            "session_id": session.id,
            "degraded": False,
            "mock": False,
            "amount_cents": amount,
            "trial_risk": risk,
        }
    except Exception as e:
        logger.error("stripe checkout failed: %s", e)
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        return {"ok": False, "error": "stripe_unavailable"}


def verify_and_entitle(*, session_id: str, account_sub: str) -> dict:
    """Verify an account-bound session, then write its entitlement idempotently."""
    if not billing_enabled():
        return {"ok": False, "error": "billing_disabled"}
    if not account_sub:
        return {"ok": False, "error": "login_required"}
    if not session_id:
        return {"ok": False, "error": "missing_session"}

    degraded = session_id.startswith("local_")
    plan_slug = "pro"
    interval = "monthly"
    status = "active"
    source = "mock" if degraded else "stripe"

    try:
        from Autobot.VectorDB.NullPoint_Vector import connect_db
        conn = connect_db()
        if not conn:
            return {"ok": False, "error": "billing_store_unavailable"}
        try:
            ensure_billing_tables(conn)
            stream_id = f"checkout:{(account_sub or 'anon')[:64]}"
            if degraded:
                # A caller-chosen local_* value must never grant access. Match
                # the exact server-created session to this authenticated account.
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT event_payload FROM payment_audit_events
                        WHERE stream_id = %s
                          AND event_type = 'checkout_session_created'
                          AND provider = 'mock'
                          AND event_payload->>'session_id' = %s
                        ORDER BY id DESC LIMIT 1
                        """,
                        (stream_id, session_id),
                    )
                    row = cur.fetchone()
                if not row or not row[0]:
                    return {"ok": False, "error": "invalid_session"}
                payload = row[0] if isinstance(row[0], dict) else json.loads(row[0])
                if payload.get("account_sub") != account_sub:
                    return {"ok": False, "error": "session_owner_mismatch"}
                plan_slug = str(payload.get("plan") or "")
                interval = str(payload.get("interval") or "")
                status = "trialing" if payload.get("trial") else "active"
            elif stripe_configured():
                import stripe
                stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
                sess = stripe.checkout.Session.retrieve(
                    session_id, expand=["subscription"],
                )
                meta = sess.get("metadata") or {}
                if meta.get("account_sub") != account_sub:
                    return {"ok": False, "error": "session_owner_mismatch"}
                if sess.get("status") != "complete":
                    return {"ok": False, "error": "checkout_incomplete"}
                subscription = sess.get("subscription") or {}
                sub_status = (
                    subscription.get("status")
                    if hasattr(subscription, "get") else None
                )
                if sub_status not in ("active", "trialing"):
                    return {"ok": False, "error": "subscription_inactive"}
                plan_slug = str(meta.get("plan") or "")
                interval = str(meta.get("interval") or "")
                status = str(sub_status)
            else:
                return {"ok": False, "error": "billing_not_configured"}

            if not plan_by_slug(plan_slug) or interval not in ("monthly", "annual"):
                return {"ok": False, "error": "invalid_entitlement_metadata"}

            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO billing_entitlements
                      (account_sub, plan_slug, interval, status, session_id, source)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (account_sub) DO UPDATE SET
                      plan_slug = EXCLUDED.plan_slug,
                      interval = EXCLUDED.interval,
                      status = EXCLUDED.status,
                      session_id = EXCLUDED.session_id,
                      source = EXCLUDED.source,
                      updated_at = NOW()
                    """,
                    (account_sub or "anonymous", plan_slug, interval, status, session_id, source),
                )
            append_audit_event(
                conn, stream_id=stream_id, event_type="checkout_verified",
                payload={"session_id": session_id, "plan": plan_slug,
                         "status": status, "degraded": degraded},
                provider=source,
            )
            return {
                "ok": True, "degraded": degraded, "plan": plan_slug,
                "interval": interval, "status": status, "persisted": True,
            }
        finally:
            conn.close()
    except Exception as e:
        logger.error("entitle failed: %s", e)
        return {"ok": False, "error": "entitlement_unavailable"}


def verify_stripe_webhook(payload: bytes, sig_header: str) -> dict:
    """Verify Stripe-Signature. Reject unsigned / bad payloads (live merchant path).

    Mock mode: accept only when BILLING_MOCK and header is `mock_ok`.
    """
    if not billing_enabled():
        return {"ok": False, "error": "billing_disabled"}
    if use_mock():
        if (sig_header or "").strip() == "mock_ok":
            try:
                return {"ok": True, "mock": True, "event": json.loads(payload.decode() or "{}")}
            except Exception:
                return {"ok": False, "error": "bad_mock_json"}
        return {"ok": False, "error": "mock_requires_sig_mock_ok"}

    secret = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
    if not secret:
        return {"ok": False, "error": "billing_not_configured"}
    if not sig_header:
        return {"ok": False, "error": "missing_stripe_signature"}
    try:
        import stripe
        stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
        event = stripe.Webhook.construct_event(payload, sig_header, secret)
        return {"ok": True, "mock": False, "event": event}
    except Exception as e:
        logger.warning("stripe webhook verify failed: %s", e)
        return {"ok": False, "error": "invalid_signature"}
