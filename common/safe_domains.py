"""
Known-good sender domains — short-circuit false positives.

Short-circuit ONLY when:
  1. From-domain is on the known-good list, AND
  2. Receiver auth stamps prove trust (SPF/DKIM/DMARC pass / aligned).

Spoofed brand From: with auth fail (or no auth at all) must NOT skip ML —
that is exactly the golden pump_fake slice ("Was this you?" from apple.com
with spf=fail). Domain-alone short-circuit was failing the gate (pump recall 0.5).
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple

# Exact registrable domains (and common subdomains) we never auto-quarantine
# when authentication also passes.
KNOWN_GOOD_DOMAINS = frozenset({
    "github.com", "notifications.github.com",
    "google.com", "accounts.google.com", "gmail.com",
    "mail.google.com", "googlemail.com",
    "linkedin.com", "e.linkedin.com",
    "microsoft.com", "office365.com", "outlook.com", "hotmail.com", "live.com",
    "apple.com", "icloud.com", "me.com",
    "amazon.com", "amazon.co.uk", "amazonaws.com", "aws.amazon.com",
    "builder.aws.com", "awsapps.com", "amazonses.com",
    "paypal.com",
    "medium.com",
    "glassdoor.com",
    "realpython.com",
    "cursor.com", "mail.cursor.com",
    "discord.com",
    "studentaid.gov", "emailsurveys.studentaid.gov",
    "chase.com", "mcmap.chase.com",
    "experian.com", "s.usa.experian.com",
    "pulumi.com",
    "replit.com",
    "quillbot.com", "mail.quillbot.com",
    "hellofresh.com", "g.hellofresh.com",
    "blizzard.com",
    "webull.com", "doc.webull.com",
    "nerdwallet.com", "mail.nerdwallet.com",
    "casio-usa.com",
    "x.ai",
    "vrbo.com", "eg.vrbo.com",
    "fox.com", "m.fox.com",
    "dcsg.com", "e.dcsg.com",
    "workablemail.com", "candidates.workablemail.com",
    "randstadusa.com",
    "wgu.edu",
    "certmetrics.com",
    "proxyvote.com",
    "pearson.com", "e.pearson.com", "pearsonvue.com",
    "vanillagift.com", "shop.vanillagift.com",
    # BNPL / fintech noreply — auth_pass required (see is_known_good_sender)
    "sezzle.com", "mail.sezzle.com", "notifications.sezzle.com",
    # Retail / membership marketing (auth_pass still required)
    "costco.com", "digital.costco.com", "email.costco.com",
    "teksynap.com", "mail.teksynap.com",
    "dunhamssports.com", "email.dunhamssports.com",
    # Fintech / messaging / AI product noreply (auth_pass still required)
    "chime.com", "notify.chime.com", "mail.chime.com",
    "slack.com", "email.slack.com", "slack-mails.com",
    "anthropic.com", "mail.anthropic.com", "claude.ai",
    "amazon.jobs", "mail.amazon.jobs",
    "stripe.com", "mail.stripe.com",
    "notion.so", "mail.notion.so",
    "tldrnewsletter.com", "mail.tldrnewsletter.com",
    # Retail mailers (auth_pass still required)
    "kroger.com", "e.krogermail.com", "krogermail.com",
    # Coaching / scheduling SaaS (auth_pass still required)
    "strawberry.me", "mail.strawberry.me",
    # Banks / card issuers — auth_pass still required (spoofed From falls to ML)
    "capitalone.com", "notification.capitalone.com", "click-notification.capitalone.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "citibank.com",
})

_EMAIL_RE = re.compile(r"[\w.+-]+@([\w.-]+\.[a-zA-Z]{2,})")
_AUTH_VERDICT_RE = re.compile(
    r"(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)",
    re.IGNORECASE,
)


def extract_domain(sender: str) -> Optional[str]:
    if not sender:
        return None
    m = _EMAIL_RE.search(sender.lower())
    if not m:
        return None
    return m.group(1).rstrip(".").lower()


def _registered_domain(host: str) -> str:
    if not host:
        return ""
    host = host.lower().strip().strip(".").split(":")[0].split("/")[0]
    parts = [p for p in host.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _email_domain(addr: str) -> str:
    if not addr:
        return ""
    m = re.search(r"@([A-Za-z0-9.\-]+)", addr)
    if m:
        return _registered_domain(m.group(1))
    return ""


def sender_auth_verdict(email_data: Optional[Dict[str, Any]]) -> Tuple[bool, bool, bool]:
    """
    Return (auth_present, auth_pass, auth_fail) from receiver stamps.

    Mirrors PhishGuard's aggregate DMARC-style verdict so allowlist and ML
    agree on what "trusted sender" means.
    """
    if not isinstance(email_data, dict):
        return False, False, False
    headers = email_data.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}

    def _h(*keys: str) -> str:
        for k in keys:
            v = headers.get(k) or email_data.get(k)
            if v:
                return str(v)
        return ""

    ar = _h(
        "authentication_results",
        "Authentication-Results",
        "authentication-results",
    ).lower()
    spf_hdr = _h("received_spf", "Received-SPF", "received-spf").lower()
    dkim_sig = _h("dkim_signature", "DKIM-Signature", "dkim-signature")
    return_path = _h("return_path", "Return-Path", "return-path")
    from_addr = str(email_data.get("from") or email_data.get("sender") or "")

    verdicts = {"spf": "", "dkim": "", "dmarc": ""}
    for mech, result in _AUTH_VERDICT_RE.findall(ar):
        verdicts[mech.lower()] = result.lower()
    if not verdicts["spf"] and spf_hdr:
        head = spf_hdr[:16]
        if "pass" in head:
            verdicts["spf"] = "pass"
        elif "fail" in head:
            verdicts["spf"] = "fail"

    dkim_domain = ""
    m = re.search(r"header\.d=([A-Za-z0-9.\-]+)", ar)
    if m:
        dkim_domain = _registered_domain(m.group(1))
    elif dkim_sig:
        m = re.search(r"d=([A-Za-z0-9.\-]+)", dkim_sig)
        if m:
            dkim_domain = _registered_domain(m.group(1))

    from_dom = _email_domain(from_addr)
    rp_dom = _email_domain(return_path)
    auth_present = bool(ar or spf_hdr or dkim_sig)
    spf_pass = verdicts["spf"] == "pass"
    dkim_pass = verdicts["dkim"] == "pass"
    dmarc_pass = verdicts["dmarc"] == "pass"
    spf_fail = verdicts["spf"] in ("fail", "softfail")
    dkim_fail = verdicts["dkim"] == "fail"
    dmarc_fail = verdicts["dmarc"] == "fail"
    dkim_aligned = bool(dkim_domain and from_dom and dkim_domain == from_dom)
    rp_mismatch = bool(rp_dom and from_dom and rp_dom != from_dom)

    auth_pass = bool(dmarc_pass or (spf_pass and dkim_aligned))
    auth_fail = bool(
        dmarc_fail or spf_fail or dkim_fail
        or (auth_present and rp_mismatch and not dmarc_pass)
    )
    return auth_present, auth_pass, auth_fail


def domain_is_known_good(sender: str) -> Tuple[bool, str]:
    """Domain match only — does not grant a safe short-circuit by itself."""
    dom = extract_domain(sender)
    if not dom:
        return False, ""
    if dom in KNOWN_GOOD_DOMAINS:
        return True, f"known_good:{dom}"
    parts = dom.split(".")
    for i in range(len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in KNOWN_GOOD_DOMAINS:
            return True, f"known_good:{parent}"
    return False, ""


def is_known_good_sender(
    sender: str,
    email_data: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str]:
    """
    Return (True, reason) when sender may skip ML / auto-quarantine.

    LOCKED RULE — applies to EVERY domain on the list (GitHub, Cap1, Chime, …):
      known-good domain AND auth_pass. Domain trust alone NEVER short-circuits.
      Spoofed brand From: (spf/dkim/dmarc fail or missing stamps) → ML.

    Without email_data / headers → False. Use domain_is_known_good() only for
    non-enforcement UI hints (never for predict).
    """
    ok, reason = domain_is_known_good(sender)
    if not ok:
        return False, ""
    if email_data is None:
        return False, ""
    present, auth_pass, auth_fail = sender_auth_verdict(email_data)
    if auth_fail or (present and not auth_pass):
        return False, ""
    if auth_pass:
        return True, f"{reason}+auth_pass"
    # No auth stamps → do not short-circuit (pump_fake without headers must hit ML).
    return False, ""
