"""IMAP folder names for ingest lanes.

Inbox is the user-visible stream. Provider Junk/Spam is treated as an isolated
threat sandbox (Yahoo already decided those are junk). Phishy_Bizz is our
own holding folder — created over IMAP when missing so the operator does not
have to make it by hand.
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("imap_folders")

SANDBOX_CANDIDATES = ("Phishy_Bizz", "Phishy bizz", "Phishy Bizz")
YAHOO_JUNK = ("Bulk Mail", "Spam", "Junk")
GMAIL_JUNK = ("[Gmail]/Spam", "Spam", "Junk")
OUTLOOK_JUNK = ("Junk", "Junk Email", "Spam")

JUNK_LANES = frozenset({
    "junk", "spam", "bulk mail", "bulk", "[gmail]/spam", "junk email",
})
SANDBOX_LANES = frozenset({
    "sandbox", "phishy_bizz", "phishy bizz",
})


def ingest_lane_for(folder: str) -> str:
    name = (folder or "INBOX").strip().lower()
    if name == "inbox":
        return "inbox"
    if name in JUNK_LANES:
        return "junk"
    if name in SANDBOX_LANES:
        return "sandbox"
    return "inbox"


def _select_ok(conn, name: str) -> bool:
    quoted = f'"{name}"' if " " in name else name
    try:
        status, _ = conn.select(quoted, readonly=True)
        return status == "OK"
    except Exception:
        try:
            status, _ = conn.select(name, readonly=True)
            return status == "OK"
        except Exception:
            return False


def first_existing(conn, names: tuple[str, ...]) -> Optional[str]:
    if not conn:
        return None
    for name in names:
        if _select_ok(conn, name):
            return name
    return None


def ensure_sandbox_folder(conn) -> Optional[str]:
    """Return the mailbox's Phishy_Bizz folder, creating it when IMAP allows."""
    existing = first_existing(conn, SANDBOX_CANDIDATES)
    if existing:
        return existing
    if not conn:
        return None
    try:
        status, _ = conn.create("Phishy_Bizz")
        if status == "OK" or _select_ok(conn, "Phishy_Bizz"):
            logger.info("created IMAP folder Phishy_Bizz")
            return "Phishy_Bizz"
    except Exception as e:
        logger.warning("IMAP CREATE Phishy_Bizz failed: %s", e)
    return first_existing(conn, SANDBOX_CANDIDATES)
