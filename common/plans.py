"""
Subscription plans — DB-backed catalog for pricing + role-gated feature flags.

Plans seed into Postgres on first read; if DB is down, FALLBACK_PLANS keeps the
pricing page and feature gates online (fail-open for availability).
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

# role_min: lowest JWT role that unlocks the plan's feature set in the console.
FALLBACK_PLANS: list[dict[str, Any]] = [
    {
        "slug": "essential",
        "name": "Essential",
        "tagline": "Individual users and early adopters",
        "price_monthly": 9.99,
        "price_annual": 99.00,
        "trial_days": 0,
        "featured": False,
        "sales_only": False,
        "cta": "Get Essential",
        "role_min": "customer",
        "features": [
            "Email, SMS, and voice threat checks",
            "Weekly security summaries",
            "Alert history and clear reports",
            "7-day scan history window",
            "Multi-device coverage",
            "On-device Call Directory sync",
        ],
        "compare": {
            "phishing": "On",
            "smishing": "On",
            "vishing": "On",
            "devices": "Multi-device",
            "alerting": "Weekly digest",
            "explainability": "Plain-language verdict",
            "osint": "—",
            "credit": "—",
            "history": "7-day window",
            "api": "—",
            "identity": "Single account",
            "support": "Standard",
            "trial": "None (paid)",
            "idps": "Batch scan",
        },
    },
    {
        "slug": "pro",
        "name": "Pro",
        "tagline": "Power users, families, and serious personal protection",
        "price_monthly": 19.99,
        "price_annual": 199.00,
        "trial_days": 7,
        "featured": True,
        "sales_only": False,
        "cta": "Start 7-day Pro trial",
        "role_min": "customer",
        "features": [
            "Real-time multi-channel alerts",
            "Family plan — shared household monitoring",
            "Calibrated ML + anomaly fusion",
            "Dark-web exposure reports (OSINT)",
            "Credit-signal checks from consented data",
            "Unlimited scan history and exports",
            "Priority support",
        ],
        "compare": {
            "phishing": "Calibrated SGD + anomaly fusion",
            "smishing": "URL intel + thread explainability",
            "vishing": "Hybrid reputation + transcript path",
            "devices": "Family seats",
            "alerting": "Real-time push + digest",
            "explainability": "Deep contextual analysis",
            "osint": "SpyCloud/Constella-class breach intel (or IPQS/HIBP)",
            "credit": "Array soft-pull + optional Plaid Check cash-flow",
            "history": "Unlimited + CSV/PDF",
            "api": "—",
            "identity": "Family sharing",
            "support": "Priority",
            "trial": "7 days (abuse-gated)",
            "idps": "Near-real-time stream",
        },
    },
    {
        "slug": "enterprise",
        "name": "Enterprise",
        "tagline": "Developers, teams, and compliance-heavy organizations",
        # No public list price — sales-led only. Zeros stay in DB for NOT NULL cols.
        "price_monthly": 0.0,
        "price_annual": 0.0,
        "trial_days": 0,
        "featured": False,
        "sales_only": True,
        "cta": "Contact sales",
        "role_min": "enterprise",
        "features": [
            "Team seats and admin controls",
            "SSO and role-based access",
            "Audit logs and compliance packs",
            "Private API and webhook hooks",
            "Custom rules and policy packs",
            "Expedited support queue",
        ],
        "compare": {
            "phishing": "Tenant-scoped models + policy overrides",
            "smishing": "Org allow/block lists + webhook events",
            "vishing": "Directory sync + fleet device tokens",
            "devices": "Fleet / MDM-ready",
            "alerting": "Real-time IDPS stream + SIEM webhooks",
            "explainability": "Full audit trail + export",
            "osint": "Bulk SpyCloud/Constella + scheduled runs",
            "credit": "Array/bureau API + retention controls",
            "history": "Unlimited + compliance packs",
            "api": "Private REST + webhooks",
            "identity": "SSO / RBAC / enterprise roles",
            "support": "Expedited queue",
            "trial": "Sales-led pilot",
            "idps": "Streaming IDPS (vs batch)",
        },
    },
]

COMPARE_ROWS = [
    ("phishing", "Phishing (email)"),
    ("smishing", "Smishing (SMS)"),
    ("vishing", "Vishing (voice)"),
    ("devices", "Devices"),
    ("alerting", "Alerting"),
    ("idps", "IDPS processing"),
    ("explainability", "Explainability"),
    ("osint", "Dark-web / OSINT reports"),
    ("credit", "Credit-signal checks"),
    ("history", "History and exports"),
    ("api", "API / integrations"),
    ("identity", "Identity and access"),
    ("support", "Support"),
    ("trial", "Trial"),
]


def ensure_plans_table(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS subscription_plans (
                slug TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                tagline TEXT NOT NULL DEFAULT '',
                price_monthly NUMERIC(10,2) NOT NULL,
                price_annual NUMERIC(10,2) NOT NULL,
                trial_days INTEGER NOT NULL DEFAULT 0,
                featured BOOLEAN NOT NULL DEFAULT FALSE,
                sales_only BOOLEAN NOT NULL DEFAULT FALSE,
                cta TEXT NOT NULL DEFAULT '',
                role_min TEXT NOT NULL DEFAULT 'customer',
                features JSONB NOT NULL DEFAULT '[]'::jsonb,
                compare JSONB NOT NULL DEFAULT '{}'::jsonb,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            """
        )
        cur.execute(
            """
            ALTER TABLE subscription_plans
              ADD COLUMN IF NOT EXISTS sales_only BOOLEAN NOT NULL DEFAULT FALSE;
            """
        )
    conn.commit()


def seed_plans(conn) -> None:
    ensure_plans_table(conn)
    with conn.cursor() as cur:
        for p in FALLBACK_PLANS:
            cur.execute(
                """
                INSERT INTO subscription_plans
                  (slug, name, tagline, price_monthly, price_annual, trial_days,
                   featured, sales_only, cta, role_min, features, compare)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)
                ON CONFLICT (slug) DO UPDATE SET
                  name = EXCLUDED.name,
                  tagline = EXCLUDED.tagline,
                  price_monthly = EXCLUDED.price_monthly,
                  price_annual = EXCLUDED.price_annual,
                  trial_days = EXCLUDED.trial_days,
                  featured = EXCLUDED.featured,
                  sales_only = EXCLUDED.sales_only,
                  cta = EXCLUDED.cta,
                  role_min = EXCLUDED.role_min,
                  features = EXCLUDED.features,
                  compare = EXCLUDED.compare,
                  updated_at = NOW();
                """,
                (
                    p["slug"], p["name"], p["tagline"],
                    p["price_monthly"], p["price_annual"], p["trial_days"],
                    p["featured"], bool(p.get("sales_only")), p["cta"], p["role_min"],
                    json.dumps(p["features"]), json.dumps(p["compare"]),
                ),
            )
    conn.commit()


def list_plans() -> list[dict[str, Any]]:
    """Return plan catalog (DB first, static fallback)."""
    try:
        from Autobot.VectorDB.NullPoint_Vector import connect_db
        conn = connect_db()
        if not conn:
            return [dict(p) for p in FALLBACK_PLANS]
        try:
            seed_plans(conn)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT slug, name, tagline, price_monthly, price_annual,
                           trial_days, featured, sales_only, cta, role_min,
                           features, compare
                    FROM subscription_plans
                    ORDER BY CASE slug
                      WHEN 'essential' THEN 1
                      WHEN 'pro' THEN 2
                      WHEN 'enterprise' THEN 3
                      ELSE 9 END
                    """
                )
                rows = cur.fetchall()
            out = []
            for r in rows:
                out.append({
                    "slug": r[0], "name": r[1], "tagline": r[2],
                    "price_monthly": float(r[3]), "price_annual": float(r[4]),
                    "trial_days": int(r[5]), "featured": bool(r[6]),
                    "sales_only": bool(r[7]),
                    "cta": r[8], "role_min": r[9],
                    "features": r[10] if isinstance(r[10], list) else json.loads(r[10] or "[]"),
                    "compare": r[11] if isinstance(r[11], dict) else json.loads(r[11] or "{}"),
                })
            return out or [dict(p) for p in FALLBACK_PLANS]
        finally:
            conn.close()
    except Exception as e:
        logger.warning("plans catalog fallback: %s", e)
        return [dict(p) for p in FALLBACK_PLANS]


def plan_for_role(role: str) -> Optional[dict[str, Any]]:
    """Best plan unlocked by a JWT role (enterprise > admin > …)."""
    rank = {"viewer": 0, "customer": 1, "analyst": 2, "admin": 3, "enterprise": 4}
    r = rank.get(role, 0)
    unlocked = [p for p in list_plans() if rank.get(p.get("role_min", "customer"), 1) <= r]
    return unlocked[-1] if unlocked else list_plans()[0]
