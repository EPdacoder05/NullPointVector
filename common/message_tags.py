"""Threat mood taxonomy + spam-vs-malice tags for Signal Deck.

Mood: Happy lure, Fear/urgency, Impersonation, Relationship/NSFW, Blackmail,
Social engineering — plus coarse sentiment and spam/malice depth.

Rules/lexicon — not a second hot-path LLM. Multiple tags allowed.
"""
from __future__ import annotations

import re
from typing import Dict, List


_POS = (
    "thank you", "thanks for", "congratulations", "welcome", "confirmed",
    "successfully", "approved", "great news", "pleased to", "looking forward",
)
_NEG = (
    "unable to", "unfortunately", "suspended", "failed", "denied", "rejected",
    "urgent", "immediately", "act now", "final notice", "legal action",
    "arrest", "warrant", "compromised", "unauthorized", "hacked",
)
_HAPPY = ("congrats", "congratulations", "you won", "prize", "gift card", "free reward", "selected")
_FEAR = ("urgent", "immediately", "expires", "suspend", "locked", "verify now",
         "act now", "final notice", "arrest", "lawsuit", "warrant", "hacked")
_IMPERSONATE = ("paypal", "microsoft", "apple", "amazon", "irs", "bank", "netflix",
                "google", "chase", "fedex", "ups", "chime", "slack")
_RELATIONSHIP = ("nude", "nsfw", "lonely", "date me", "sweetheart", "honey", "sexy")
_BLACKMAIL = ("blackmail", "expose you", "send this to", "pay or we", "embarrassing")
_SE = ("wire transfer", "gift card", "verify your account", "click here", "confirm your identity")
_RECRUIT = ("applied", "role", "hiring", "interview", "twic", "clearance", "soc analyst",
            "job id", "duration:", "recruiter", "cloud performance")
_SPAM = ("unsubscribe", "opt out", "opt-out", "manage preferences", "view in browser",
         "newsletter", "% off", "shop now", "you are receiving this")
_MALICE_MONEY = ("wire transfer", "gift card", "cash app", "zelle", "venmo me",
                 "routing number", "send bitcoin", "crypto wallet", "seed phrase")
_ADVANCE_FEE = (
    "pay a small fee", "processing fee", "unlock your funds", "claim your inheritance",
    "pay to release", "clearance fee", "western union fee",
)
_MALICE_PII = ("ssn", "social security", "date of birth", "mother's maiden",
               "password reset", "verify your password", "full ssn", "drivers license")
_MERGE_FRAUD = ("[[candidateemail]]", "{{candidate", "address on file is .")


def categorize_message(*, subject: str = "", body: str = "", sender: str = "") -> List[Dict[str, str]]:
    text = f"{subject or ''}\n{body or ''}".lower()
    sender_l = (sender or "").lower()
    tags: List[Dict[str, str]] = []

    def add(code: str, label: str) -> None:
        if any(t["code"] == code for t in tags):
            return
        tags.append({"code": code, "label": label})

    if re.search(r"@(gmail|yahoo|hotmail|outlook|icloud)\.com\b", sender_l):
        if any(w in text for w in _RECRUIT):
            add("RECRUIT_GMAIL", "Recruit via free mail")
    if any(t in text for t in _MERGE_FRAUD) and any(w in text for w in _RECRUIT):
        add("JOB_SCAM", "Job scam / merge")
    if "bcc" in text or "hello all" in text:
        add("BLAST", "Mass / BCC blast")

    if any(w in text for w in _HAPPY):
        add("HAPPY_LURE", "Happy / prize")
    if any(w in text for w in _FEAR):
        add("FEAR_URGENCY", "Fear / urgency")
    if any(w in text for w in _IMPERSONATE) and any(
            w in text for w in ("verify", "locked", "suspend", "unusual", "confirm")):
        add("IMPERSONATION", "Brand spoof")
    if any(w in text for w in _RELATIONSHIP):
        add("RELATIONSHIP_NSFW", "Romance / NSFW")
    if any(w in text for w in _BLACKMAIL):
        add("BLACKMAIL", "Blackmail")
    if any(w in text for w in _SE) or len([c for c in tags if c["code"] in (
            "HAPPY_LURE", "FEAR_URGENCY", "IMPERSONATION", "RELATIONSHIP_NSFW", "BLACKMAIL")]) >= 2:
        add("SOCIAL_ENG", "Social eng")

    # Spam vs malice depth (can stack with mood)
    spamish = any(w in text for w in _SPAM)
    money = any(w in text for w in _MALICE_MONEY)
    pii = any(w in text for w in _MALICE_PII)
    if spamish and not money and not pii and "JOB_SCAM" not in {t["code"] for t in tags}:
        add("SPAM_LIST", "Spam list")
    if money:
        add("MALICE_MONEY", "Money ask")
    if any(w in text for w in _ADVANCE_FEE):
        add("ADVANCE_FEE", "Advance fee")
    if pii:
        add("MALICE_PII", "PII / creds ask")
    if money or pii or "JOB_SCAM" in {t["code"] for t in tags} or "ADVANCE_FEE" in {t["code"] for t in tags}:
        add("THREAT_MALICE", "Threat: malice")
    elif spamish:
        add("THREAT_SPAM", "Threat: spam")

    if any(w in text for w in ("security alert", "sign-in", "new login", "password reset")):
        add("SECURITY", "Security alert")
    if any(w in text for w in ("invoice", "billing", "receipt", "shipped")):
        add("TXN", "Transactional")
    if spamish or any(w in text for w in ("shop now", "% off", "newsletter")):
        add("MARKETING", "Marketing")
    if any(w in text for w in ("thank you for your interest", "unable to proceed")):
        add("REJECTION", "App status")

    pos_hits = sum(1 for w in _POS if w in text)
    neg_hits = sum(1 for w in _NEG if w in text)
    if any(t["code"] in (
            "FEAR_URGENCY", "BLACKMAIL", "RELATIONSHIP_NSFW", "RECRUIT_GMAIL",
            "JOB_SCAM", "MALICE_MONEY", "MALICE_PII",
    ) for t in tags):
        add("SENT_NEG", "Sent: negative")
    elif pos_hits > neg_hits and pos_hits > 0:
        add("SENT_POS", "Sent: positive")
    elif not tags:
        add("SENT_UNK", "Sent: unclear")
    else:
        add("SENT_NEUT", "Sent: neutral")

    return tags[:10]
