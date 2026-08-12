"""Postgres row-level security helpers for multi-tenant tables.

Table owner / pool user is often a superuser (local Docker `EPNP`), and
Postgres does not apply RLS to superusers even with FORCE. We therefore:

1. ENABLE + FORCE RLS + tenant policies on personal tables
2. Create NOLOGIN role `nullpoint_rls` (NOSUPERUSER)
3. `SET LOCAL ROLE nullpoint_rls` + `set_config('app.account_sub'|bypass)` per txn

Policies allow a row when bypass=1 OR account_sub/email matches the setting.
Ingest / fleet cross-tenant paths must pass bypass=True deliberately.
release_conn clears settings (and RESET ROLE) before put-back.
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("tenant_rls")

_RLS_ROLE = "nullpoint_rls"

# Per-table policy bodies (applied only when the relation exists).
_TABLE_POLICIES: tuple[tuple[str, str, str], ...] = (
    (
        "user_mailboxes",
        "mailboxes_tenant",
        "account_sub = current_setting('app.account_sub', true)",
    ),
    (
        "user_reports",
        "reports_tenant",
        "account_sub = current_setting('app.account_sub', true)",
    ),
    (
        "deck_accounts",
        "accounts_tenant",
        "email = current_setting('app.account_sub', true)",
    ),
)

# Exported for unit tests (shape check): describes the tables and GUCs protected by RLS.
POLICY_SUMMARY = {
    "role": _RLS_ROLE,
    "gucs": ["app.rls_bypass", "app.account_sub"],
    "tables": [t[0] for t in _TABLE_POLICIES],
}


def _table_exists(cur, name: str) -> bool:
    cur.execute(
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_schema = 'public' AND table_name = %s",
        (name,),
    )
    return cur.fetchone() is not None


def _ensure_rls_role(cur) -> None:
    """NOSUPERUSER role so FORCE RLS actually binds the app session."""
    cur.execute(
        f"""
        DO $$ BEGIN
          CREATE ROLE {_RLS_ROLE} NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOINHERIT NOLOGIN;
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
        """
    )
    # Pool user must be allowed to SET ROLE into it.
    cur.execute("SELECT current_user")
    me = cur.fetchone()[0]
    cur.execute(f'GRANT {_RLS_ROLE} TO "{me}"')
    cur.execute(f"GRANT USAGE ON SCHEMA public TO {_RLS_ROLE}")
    cur.execute(
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {_RLS_ROLE}"
    )
    cur.execute(
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {_RLS_ROLE}"
    )
    cur.execute(
        f"""
        ALTER DEFAULT PRIVILEGES IN SCHEMA public
          GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {_RLS_ROLE}
        """
    )
    cur.execute(
        f"""
        ALTER DEFAULT PRIVILEGES IN SCHEMA public
          GRANT USAGE, SELECT ON SEQUENCES TO {_RLS_ROLE}
        """
    )


def ensure_rls(conn) -> None:
    """Idempotent: role + ENABLE/FORCE RLS + tenant policies on personal tables."""
    if not conn:
        return
    try:
        with conn.cursor() as cur:
            _ensure_rls_role(cur)
            for table, policy, tenant_pred in _TABLE_POLICIES:
                if not _table_exists(cur, table):
                    continue
                # Fresh grants if table was created after role bootstrap.
                cur.execute(
                    f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {_RLS_ROLE}"
                )
                cur.execute(
                    """
                    SELECT c.relname FROM pg_class c
                    JOIN pg_depend d ON d.objid = c.oid
                    JOIN pg_class t ON d.refobjid = t.oid
                    JOIN pg_namespace n ON n.oid = t.relnamespace
                    WHERE c.relkind = 'S' AND n.nspname = 'public' AND t.relname = %s
                    """,
                    (table,),
                )
                for (seq,) in cur.fetchall() or []:
                    cur.execute(
                        f'GRANT USAGE, SELECT ON SEQUENCE "{seq}" TO {_RLS_ROLE}'
                    )
                bypass = "current_setting('app.rls_bypass', true) = '1'"
                using = f"({bypass} OR {tenant_pred})"
                cur.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
                cur.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
                cur.execute(f"DROP POLICY IF EXISTS {policy} ON {table}")
                cur.execute(
                    f"""
                    CREATE POLICY {policy} ON {table}
                      FOR ALL
                      USING {using}
                      WITH CHECK {using}
                    """
                )
        conn.commit()
    except Exception as e:
        logger.error("ensure_rls failed: %s", e)
        try:
            conn.rollback()
        except Exception as rollback_err:
            logger.warning("ensure_rls rollback failed: %s", rollback_err)
        raise


def set_tenant(conn, account_sub: Optional[str] = None, *, bypass: bool = False) -> None:
    """Bind this transaction to a tenant (or bypass for ingest/admin)."""
    if not conn:
        return
    sub = (account_sub or "").strip()
    with conn.cursor() as cur:
        # Drop to NOSUPERUSER for this txn so FORCE RLS applies.
        cur.execute(f"SET LOCAL ROLE {_RLS_ROLE}")
        if bypass:
            cur.execute("SELECT set_config('app.rls_bypass', '1', true)")
            cur.execute("SELECT set_config('app.account_sub', '', true)")
        else:
            cur.execute("SELECT set_config('app.rls_bypass', '0', true)")
            cur.execute("SELECT set_config('app.account_sub', %s, true)", (sub,))


def clear_tenant(conn) -> None:
    """Clear local settings / role before returning a pooled connection."""
    if not conn:
        return
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('app.rls_bypass', '', true)")
            cur.execute("SELECT set_config('app.account_sub', '', true)")
            cur.execute("RESET ROLE")
        conn.rollback()
    except Exception as e:
        logger.warning("clear_tenant failed: %s", e)
        try:
            conn.rollback()
        except Exception as rollback_err:
            logger.warning("clear_tenant rollback failed: %s", rollback_err)
