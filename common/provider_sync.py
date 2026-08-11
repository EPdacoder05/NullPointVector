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
                message_id BIGINT NOT NULL,
                provider TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL DEFAULT 'junk',
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (message_id, action)
            );
            CREATE INDEX IF NOT EXISTS idx_provider_queue_pending
              ON provider_action_queue (status, created_at)
              WHERE status = 'pending';
            """
        )
    conn.commit()


def enqueue_provider_moves(message_ids: list, *, action: str = "junk") -> dict[str, Any]:
    """Idempotent enqueue. Returns counts. Never raises to UI."""
    out = {"queued": 0, "skipped": 0, "error": None}
    if action not in ("junk", "trash"):
        out["error"] = "bad_action"
        return out
    try:
        from Autobot.VectorDB.NullPoint_Vector import get_conn, release_conn
    except Exception as e:
        out["error"] = str(e)
        return out
    conn = get_conn()
    if not conn:
        out["error"] = "no_db"
        return out
    try:
        ensure_provider_queue(conn)
        with conn.cursor() as cur:
            for mid in message_ids or []:
                try:
                    mid_i = int(mid)
                except (TypeError, ValueError):
                    out["skipped"] += 1
                    continue
                # Resolve provider from metadata when present
                provider = ""
                try:
                    cur.execute("SELECT metadata FROM messages WHERE id=%s", (mid_i,))
                    row = cur.fetchone()
                    meta = (row[0] if row else None) or {}
                    if isinstance(meta, dict):
                        provider = (meta.get("provider") or meta.get("source") or "")[:32]
                except Exception:
                    provider = ""
                cur.execute(
                    """
                    INSERT INTO provider_action_queue (message_id, provider, action, status)
                    VALUES (%s, %s, %s, 'pending')
                    ON CONFLICT (message_id, action) DO UPDATE SET
                      status = CASE
                        WHEN provider_action_queue.status = 'ok' THEN provider_action_queue.status
                        ELSE 'pending'
                      END,
                      updated_at = NOW()
                    """,
                    (mid_i, provider, action),
                )
                out["queued"] += 1
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
                        WHERE id = %s
                        """,
                        (provider or "default", action, mid_i),
                    )
                except Exception:
                    pass
        conn.commit()
    except Exception as e:
        logger.warning("enqueue_provider_moves: %s", e)
        out["error"] = str(e)
        try:
            conn.rollback()
        except Exception:
            pass
    finally:
        release_conn(conn)
    return out


def _patch_message_status(conn, message_id: int, provider: str, action: str,
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
            WHERE id = %s
            """,
            (key, json.dumps(payload), int(message_id)),
        )


def process_provider_queue(*, limit: int = 20) -> dict[str, Any]:
    """Drain pending junk/trash moves. Safe for cron every ~2 min."""
    from common.mail_actions import move_many_to_junk

    stats = {"processed": 0, "ok": 0, "failed": 0}
    try:
        from Autobot.VectorDB.NullPoint_Vector import get_conn, release_conn
    except Exception as e:
        return {**stats, "error": str(e)}
    conn = get_conn()
    if not conn:
        return {**stats, "error": "no_db"}
    try:
        ensure_provider_queue(conn)
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, message_id, provider, action, attempts
                FROM provider_action_queue
                WHERE status = 'pending' AND attempts < 5
                ORDER BY created_at ASC
                LIMIT %s
                """,
                (max(1, min(int(limit), 100)),),
            )
            rows = cur.fetchall()
        for qid, mid, provider, action, attempts in rows:
            stats["processed"] += 1
            # trash not yet implemented on all fetchers — map to junk
            result = move_many_to_junk([mid])
            ok = bool(result.get("moved"))
            err = None
            if not ok:
                r0 = (result.get("results") or [{}])[0]
                err = r0.get("error") or "move_failed"
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE provider_action_queue
                    SET status = %s, attempts = %s, last_error = %s, updated_at = NOW()
                    WHERE id = %s
                    """,
                    ("ok" if ok else "failed", int(attempts or 0) + 1,
                     err, int(qid)),
                )
            try:
                _patch_message_status(
                    conn, int(mid), provider or "", action or "junk",
                    "ok" if ok else "failed", err,
                )
            except Exception:
                pass
            if ok:
                stats["ok"] += 1
            else:
                stats["failed"] += 1
                # Keep pending for retry if no_imap_id is not permanent? mark failed
                if err == "no_imap_id":
                    pass  # already failed — won't retry forever (attempts++)
                else:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE provider_action_queue SET status='pending'
                            WHERE id=%s AND attempts < 5
                            """,
                            (int(qid),),
                        )
        conn.commit()
    except Exception as e:
        logger.warning("process_provider_queue: %s", e)
        stats["error"] = str(e)
        try:
            conn.rollback()
        except Exception:
            pass
    finally:
        release_conn(conn)
    return stats
