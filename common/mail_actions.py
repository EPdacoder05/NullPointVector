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


def _ids_with_imap(ids: list, *, account_sub: str) -> list[dict[str, Any]]:
    """Resolve exact owned mailbox UIDs without decrypting message bodies."""
    from common.tenant_rls import require_account_sub

    sub = require_account_sub(account_sub)
    out: list[dict[str, Any]] = []
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
        from common.tenant_rls import set_tenant
        set_tenant(conn, sub)
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, mailbox_id, provider, provider_uid, uidvalidity, folder
                FROM messages
                WHERE account_sub = %s AND id = ANY(%s)
                """,
                (sub, clean),
            )
            for mid, mailbox_id, provider, provider_uid, uidvalidity, folder in cur.fetchall():
                provider = (provider or "").strip().lower()
                provider_uid = str(provider_uid or "").strip()
                folder = str(folder or "").strip()
                if not mailbox_id or not provider or not provider_uid or not folder:
                    continue
                out.append({
                    "id": int(mid),
                    "mailbox_id": int(mailbox_id),
                    "provider": provider,
                    "provider_uid": provider_uid,
                    "uidvalidity": str(uidvalidity or ""),
                    "folder": folder,
                })
    except Exception as e:
        logger.warning("imap id lookup failed: %s", e)
    finally:
        release_conn(conn)
    return out


def move_message_to_junk(msg_id: int, *, account_sub: str) -> dict[str, Any]:
    """Best-effort: move one stored message to provider junk/spam."""
    batch = move_many_to_junk([msg_id], account_sub=account_sub)
    results = batch.get("results") or []
    if results:
        return results[0]
    return {"ok": False, "error": "no_result", "id": msg_id}


def move_many_to_junk(ids: list, *, account_sub: str) -> dict[str, Any]:
    """Fail-open batch with one connection + timeout. Never block grade forever."""
    try:
        candidates = _ids_with_imap(ids, account_sub=account_sub)[:_MAX_JUNK_MOVES]
    except ValueError:
        return {"moved": 0, "attempted": 0, "results": [], "error": "tenant_required"}
    if not candidates:
        return {
            "moved": 0,
            "attempted": 0,
            "results": [{"ok": False, "error": "no_provider_identity", "id": i} for i in (ids or [])[:5]],
            "note": "no_provider_identity_or_capped",
        }

    # One login per exact mailbox. Provider-only grouping could mutate another
    # connected mailbox when a user has several accounts at the same provider.
    groups: dict[tuple[str, int, str, str], list[dict[str, Any]]] = {}
    for item in candidates:
        key = (
            item["provider"], item["mailbox_id"], item["folder"], item["uidvalidity"],
        )
        groups.setdefault(key, []).append(item)

    results: list[dict[str, Any]] = []
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(_IMAP_TIMEOUT_S)
        from PhishGuard.providers.email_fetcher.registry import EmailFetcherRegistry

        for (provider, mailbox_id, folder, uidvalidity), items in groups.items():
            fetcher = None
            try:
                fetcher = EmailFetcherRegistry.get_fetcher(
                    provider, account_sub=account_sub, mailbox_id=mailbox_id,
                )
                if not fetcher or not fetcher.connect():
                    for item in items:
                        results.append({
                            "ok": False, "error": "connect_failed",
                            "id": item["id"], "provider": provider,
                        })
                    continue
                for item in items:
                    try:
                        ok = bool(fetcher.move_to_junk(
                            item["provider_uid"], folder=folder,
                            uidvalidity=uidvalidity,
                        ))
                        results.append({
                            "ok": ok, "id": item["id"], "provider": provider,
                            "error": None if ok else "move_failed",
                        })
                    except Exception as e:
                        logger.warning("move_to_junk [%s/%s]: %s", provider, item["id"], e)
                        results.append({
                            "ok": False, "error": "exception",
                            "id": item["id"], "provider": provider,
                        })
            except Exception as e:
                logger.warning("junk batch provider %s: %s", provider, e)
                for item in items:
                    results.append({
                        "ok": False, "error": "exception",
                        "id": item["id"], "provider": provider,
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
