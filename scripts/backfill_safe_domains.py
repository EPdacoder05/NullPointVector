"""One-shot: clear known-good false positives already in messages.

Never clear on domain alone (spoofs share brand From domains). Re-score with
the detector; only clear when predict returns safe at very low confidence and
the domain is on the known-good list (auth-gated path inside predict).
"""
from Autobot.VectorDB.NullPoint_Vector import get_conn, release_conn
from common.safe_domains import domain_is_known_good
from PhishGuard.phish_mlm.phishing_detector import detector

conn = get_conn()
cur = conn.cursor()
cur.execute(
    """
    SELECT id, sender, subject, preprocessed_text, metadata FROM messages
    WHERE (label IS NULL OR label <> 0) AND confidence >= 0.5
    ORDER BY id DESC LIMIT 8000
    """
)
rows = cur.fetchall()
cleared = 0
for mid, sender, subject, body, meta in rows:
    email = {
        "from": sender or "",
        "subject": subject or "",
        "body": body or "",
        "headers": (meta or {}).get("headers") if isinstance(meta, dict) else {},
    }
    if isinstance(meta, dict) and meta.get("authentication_results"):
        email.setdefault("headers", {})
        if isinstance(email["headers"], dict):
            email["headers"]["authentication_results"] = meta["authentication_results"]
    pred, conf = detector.predict(email)
    if pred == 0 and conf <= 0.05 and domain_is_known_good(sender or "")[0]:
        cur.execute(
            """
            UPDATE messages
            SET label = 0, is_threat = 0, confidence = %s,
                metadata = jsonb_set(
                    COALESCE(metadata, '{}'::jsonb),
                    '{review_status}', '"safe_domain_backfill"'::jsonb)
            WHERE id = %s
            """,
            (float(conf), mid),
        )
        cleared += 1
conn.commit()
print(f"scanned={len(rows)} cleared={cleared}")
for s in [
    "GitHub <noreply@github.com>",
    "Google <no-reply@accounts.google.com>",
    "scammer@paypa1-alerts.top",
]:
    print(s, "->", detector.predict({"from": s, "subject": "hi", "body": "verify now http://evil.top"}))
release_conn(conn)
