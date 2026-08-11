"""Fail-open provider mailbox side-effects (IMAP junk move).

Grade/feedback must succeed even when IMAP is down — never hang the UI.
Bulk Block used to reconnect per id (10× login) and stall the cascade modal.
"""
from __future__ import annotations

import logging
import socket
from typing import Any, Optional

logger = logging.getLogger("mail_actions")

# Hard caps so Block + Apply never freezes Signal Deck.
_MAX_JUNK_MOVES = 3
_IMAP_TIMEOUT_S = 8


def _ids_with_imap(ids: list) -> list[tuple[int, str, str]]:
    """Return [(msg_id, provider, imap_id), ...] without decrypting bodies."""
    out: list[tuple[int, str, str]] = []
    try:
        from Autobot.VectorDB.NullPoint_Vector import get_conn, release_conn
    except Exception as e:
        logger.warning("mail_actions db import: %s", e)
        return out
    conn = get_conn()
    if not conn:
        return out
    try:
        clean = []
        for x in ids or []:
            try:
                clean.append(int(x))
            except (TypeError, ValueError):
                continue
        if not clean:
            return out
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, metadata
                FROM messages
                WHERE id = ANY(%s)
                """,
                (clean,),
            )
            for mid, meta in cur.fetchall():
                meta = meta or {}
                if not isinstance(meta, dict):
                    continue
                imap_id = meta.get("imap_id")
                provider = (meta.get("provider") or meta.get("source") or "").strip().lower()
                if imap_id and provider:
                    out.append((int(mid), provider, str(imap_id)))
    except Exception as e:
        logger.warning("imap id lookup failed: %s", e)
    finally:
        release_conn(conn)
    return out


def move_message_to_junk(msg_id: int) -> dict[str, Any]:
    """Best-effort: move one stored message to provider junk/spam."""
    batch = move_many_to_junk([msg_id])
    results = batch.get("results") or []
    if results:
        return results[0]
    return {"ok": False, "error": "no_result", "id": msg_id}


def move_many_to_junk(ids: list) -> dict[str, Any]:
    """Fail-open batch with one connection + timeout. Never block grade forever."""
    candidates = _ids_with_imap(ids)[:_MAX_JUNK_MOVES]
    if not candidates:
        return {
            "moved": 0,
            "attempted": 0,
            "results": [{"ok": False, "error": "no_imap_id", "id": i} for i in (ids or [])[:5]],
            "note": "no_imap_id_or_capped",
        }

    # Group by provider — one login per provider
    by_prov: dict[str, list[tuple[int, str]]] = {}
    for mid, prov, imap_id in candidates:
        by_prov.setdefault(prov, []).append((mid, imap_id))

    results: list[dict[str, Any]] = []
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(_IMAP_TIMEOUT_S)
        from PhishGuard.providers.email_fetcher.registry import EmailFetcherRegistry

        for provider, items in by_prov.items():
            fetcher = None
            try:
                fetcher = EmailFetcherRegistry.get_fetcher(provider)
                if not fetcher or not fetcher.connect():
                    for mid, _ in items:
                        results.append({
                            "ok": False, "error": "connect_failed",
                            "id": mid, "provider": provider,
                        })
                    continue
                for mid, imap_id in items:
                    try:
                        ok = bool(fetcher.move_to_junk(str(imap_id)))
                        results.append({
                            "ok": ok, "id": mid, "provider": provider,
                            "imap_id": imap_id,
                            "error": None if ok else "move_failed",
                        })
                    except Exception as e:
                        logger.warning("move_to_junk [%s/%s]: %s", provider, mid, e)
                        results.append({
                            "ok": False, "error": "exception",
                            "id": mid, "provider": provider,
                        })
            except Exception as e:
                logger.warning("junk batch provider %s: %s", provider, e)
                for mid, _ in items:
                    results.append({
                        "ok": False, "error": "exception",
                        "id": mid, "provider": provider,
                    })
            finally:
                if fetcher is not None:
                    try:
                        fetcher.disconnect()
                    except Exception:
                        pass
    finally:
        try:
            socket.setdefaulttimeout(old_timeout)
        except Exception:
            pass

    moved = sum(1 for r in results if r.get("ok"))
    return {
        "moved": moved,
        "attempted": len(results),
        "results": results,
        "capped": len(ids or []) > _MAX_JUNK_MOVES,
    }
