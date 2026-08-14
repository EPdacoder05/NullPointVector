"""Async provider mailbox actions (junk/trash) — Postgres queue, no Celery.

Grade UI returns immediately. Primary may optionally run best-effort inline;
siblings (and retries) drain via process_provider_queue() from a cron or
FastAPI BackgroundTasks.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("provider_sync")


def ensure_provider_queue(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_action_queue (
                id BIGSERIAL PRIMARY KEY,
                account_sub TEXT,
                mailbox_id BIGINT,
                message_id BIGINT NOT NULL,
                provider TEXT NOT NULL DEFAULT '',
                provider_uid TEXT,
                uidvalidity TEXT,
                folder TEXT,
                action TEXT NOT NULL DEFAULT 'junk',
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                lease_until TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (message_id, action)
            );
            ALTER TABLE provider_action_queue ADD COLUMN IF NOT EXISTS account_sub TEXT;
            ALTER TABLE provider_action_queue ADD COLUMN IF NOT EXISTS mailbox_id BIGINT;
            ALTER TABLE provider_action_queue ADD COLUMN IF NOT EXISTS provider_uid TEXT;
            ALTER TABLE provider_action_queue ADD COLUMN IF NOT EXISTS uidvalidity TEXT;
            ALTER TABLE provider_action_queue ADD COLUMN IF NOT EXISTS folder TEXT;
            ALTER TABLE provider_action_queue
              ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
            ALTER TABLE provider_action_queue ADD COLUMN IF NOT EXISTS lease_until TIMESTAMPTZ;
            DO $$ BEGIN
              ALTER TABLE provider_action_queue
                ADD CONSTRAINT provider_actions_new_rows_need_owner
                CHECK (account_sub IS NOT NULL AND btrim(account_sub) <> ''
                       AND mailbox_id IS NOT NULL) NOT VALID;
            EXCEPTION WHEN duplicate_object THEN NULL;
            END $$;
            CREATE INDEX IF NOT EXISTS idx_provider_queue_retryable_v2
              ON provider_action_queue (status, next_attempt_at, created_at)
              WHERE account_sub IS NOT NULL AND mailbox_id IS NOT NULL
                AND status IN ('pending', 'processing');
            """
        )
    conn.commit()
    from common.tenant_rls import ensure_rls
    ensure_rls(conn)


def enqueue_provider_moves(message_ids: list, *, account_sub: str,
                           action: str = "junk") -> dict[str, Any]:
    """Idempotent enqueue. Returns counts. Never raises to UI."""
    out = {"queued": 0, "skipped": 0, "error": None}
    if action not in ("junk", "trash"):
        out["error"] = "bad_action"
        return out
    try:
        from common.tenant_rls import require_account_sub
        sub = require_account_sub(account_sub)
    except ValueError:
        out["error"] = "tenant_required"
        return out
    try:
        from Autobot.VectorDB.NullPoint_Vector import get_conn, release_conn
    except Exception as e:
        logger.warning("provider queue import failed: %s", e)
        out["error"] = "queue_unavailable"
        return out
    conn = get_conn()
    if not conn:
        out["error"] = "no_db"
        return out
    try:
        ensure_provider_queue(conn)
        from common.tenant_rls import set_tenant
        set_tenant(conn, sub)
        with conn.cursor() as cur:
            for mid in message_ids or []:
                try:
                    mid_i = int(mid)
                except (TypeError, ValueError):
                    out["skipped"] += 1
                    continue
                cur.execute(
                    """
                    SELECT mailbox_id, provider, provider_uid, uidvalidity, folder
                    FROM messages
                    WHERE id = %s AND account_sub = %s
                    LIMIT 1
                    """,
                    (mid_i, sub),
                )
                row = cur.fetchone()
                if not row or not all((row[0], row[1], row[2], row[4])):
                    out["skipped"] += 1
                    continue
                mailbox_id, provider, provider_uid, uidvalidity, folder = row
                cur.execute(
                    """
                    INSERT INTO provider_action_queue
                      (account_sub, mailbox_id, message_id, provider, provider_uid,
                       uidvalidity, folder, action, status, next_attempt_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pending', NOW())
                    ON CONFLICT (message_id, action) DO UPDATE SET
                      status = CASE
                        WHEN provider_action_queue.status = 'ok' THEN provider_action_queue.status
                        ELSE 'pending'
                      END,
                      next_attempt_at = NOW(),
                      lease_until = NULL,
                      updated_at = NOW()
                    WHERE provider_action_queue.account_sub = EXCLUDED.account_sub
                    """,
                    (sub, int(mailbox_id), mid_i, str(provider)[:32], str(provider_uid),
                     str(uidvalidity or ""), str(folder), action),
                )
                if cur.rowcount:
                    out["queued"] += 1
                else:
                    out["skipped"] += 1
                    continue
                # Mirror into messages.metadata.provider_actions JSONB
                try:
                    cur.execute(
                        """
                        UPDATE messages SET metadata = jsonb_set(
                          COALESCE(metadata, '{}'::jsonb),
                          '{provider_actions}',
                          COALESCE(metadata->'provider_actions', '{}'::jsonb) ||
                          jsonb_build_object(
                            %s::text,
                            jsonb_build_object(
                              'action', %s::text,
                              'status', 'pending',
                              'queued_at', NOW()::text
                            )
                          )
                        )
                        WHERE id = %s AND account_sub = %s
                        """,
                        (provider or "default", action, mid_i, sub),
                    )
                except Exception:
                    pass
        conn.commit()
    except Exception as e:
        logger.warning("enqueue_provider_moves: %s", e)
        out["error"] = "queue_failed"
        try:
            conn.rollback()
        except Exception:
            pass
    finally:
        release_conn(conn)
    return out


def _patch_message_status(conn, message_id: int, account_sub: str,
                          provider: str, action: str,
                          status: str, err: Optional[str] = None) -> None:
    key = (provider or "default")[:32]
    payload = {
        "action": action,
        "status": status,
        "synced_at": datetime.now(timezone.utc).isoformat(),
    }
    if err:
        payload["error"] = err[:200]
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE messages SET metadata = jsonb_set(
              COALESCE(metadata, '{}'::jsonb),
              '{provider_actions}',
              COALESCE(metadata->'provider_actions', '{}'::jsonb) ||
              jsonb_build_object(%s::text, %s::jsonb)
            )
            WHERE id = %s AND account_sub = %s
            """,
            (key, json.dumps(payload), int(message_id), account_sub),
        )


def process_provider_queue(*, limit: int = 20) -> dict[str, Any]:
    """Drain pending junk/trash moves. Safe for cron every ~2 min."""
    from common.mail_actions import move_many_to_junk

    stats = {"processed": 0, "ok": 0, "failed": 0}
    try:
        from Autobot.VectorDB.NullPoint_Vector import get_conn, release_conn
    except Exception as e:
        logger.warning("provider queue import failed: %s", e)
        return {**stats, "error": "queue_unavailable"}
    conn = get_conn()
    if not conn:
        return {**stats, "error": "no_db"}
    try:
        ensure_provider_queue(conn)
        from common.tenant_rls import set_tenant
        set_tenant(conn, bypass=True)
        with conn.cursor() as cur:
            cur.execute(
                """
                WITH picked AS (
                    SELECT id
                    FROM provider_action_queue
                    WHERE account_sub IS NOT NULL
                      AND btrim(account_sub) <> ''
                      AND mailbox_id IS NOT NULL
                      AND attempts < 5
                      AND next_attempt_at <= NOW()
                      AND (
                        status = 'pending'
                        OR (status = 'processing' AND lease_until < NOW())
                      )
                    ORDER BY created_at ASC
                    FOR UPDATE SKIP LOCKED
                    LIMIT %s
                )
                UPDATE provider_action_queue AS q
                SET status = 'processing', attempts = q.attempts + 1,
                    lease_until = NOW() + INTERVAL '5 minutes', updated_at = NOW()
                FROM picked
                WHERE q.id = picked.id
                RETURNING q.id, q.message_id, q.account_sub, q.mailbox_id,
                          q.provider, q.action, q.attempts
                """,
                (max(1, min(int(limit), 100)),),
            )
            rows = cur.fetchall()
        conn.commit()  # durable lease before external provider I/O
        for qid, mid, account_sub, mailbox_id, provider, action, attempts in rows:
            stats["processed"] += 1
            # trash not yet implemented on all fetchers — map to junk
            result = move_many_to_junk([mid], account_sub=account_sub)
            ok = bool(result.get("moved"))
            err = None
            if not ok:
                r0 = (result.get("results") or [{}])[0]
                err = r0.get("error") or "move_failed"
            set_tenant(conn, bypass=True)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE provider_action_queue
                    SET status = %s, last_error = %s, lease_until = NULL,
                        next_attempt_at = CASE WHEN %s = 'pending'
                          THEN NOW() + (%s * INTERVAL '1 second')
                          ELSE next_attempt_at END,
                        updated_at = NOW()
                    WHERE id = %s
                    """,
                    (
                        "ok" if ok else ("pending" if int(attempts or 0) < 5 else "failed"),
                        err,
                        "ok" if ok else ("pending" if int(attempts or 0) < 5 else "failed"),
                        min(300, 2 ** max(1, int(attempts or 1))),
                        int(qid),
                    ),
                )
            try:
                _patch_message_status(
                    conn, int(mid), str(account_sub), provider or "", action or "junk",
                    "ok" if ok else "failed", err,
                )
            except Exception:
                pass
            if ok:
                stats["ok"] += 1
            else:
                stats["failed"] += 1
            conn.commit()
    except Exception as e:
        logger.warning("process_provider_queue: %s", e)
        stats["error"] = "queue_failed"
        try:
            conn.rollback()
        except Exception:
            pass
    finally:
        release_conn(conn)
    return stats
