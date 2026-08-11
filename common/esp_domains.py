"""Known ESP / tracking redirect hosts — not abused TLDs.

Small list (~20) beats a fat bank allowlist. Auth'd bank mail uses these
click wrappers; treating .link as malware is the Capital One FP class.
"""
from __future__ import annotations

KNOWN_ESP_REDIRECT_DOMAINS = frozenset({
    "smart.link",
    "click.sendgrid.net",
    "url.emailprotection.link",  # Proofpoint-style
    "list-manage.com",
    "mailchimp.com",
    "exacttarget.com",
    "exacttarget.comlinks",
    "click.exacttarget.com",
    "marketing.adobe.com",
    "adobe-campaign.com",
    "cmail19.com",
    "cmail20.com",
    "rs6.net",  # Constant Contact
    "ct.sendgrid.net",
    "sparkpostmail.com",
    "email.mg.",  # mailgun prefix handled via endswith checks below
    "onelink.me",
    "lnk.to",
})

# Suffixes that are ESP click domains even when left of a brand host
_ESP_SUFFIXES = (
    ".smart.link",
    ".sendgrid.net",
    ".list-manage.com",
    ".exacttarget.com",
    ".rs6.net",
    ".mailgun.org",
    ".sparkpostmail.com",
)


def is_esp_redirect_host(host: str) -> bool:
    h = (host or "").lower().rstrip(".")
    if not h:
        return False
    if h in KNOWN_ESP_REDIRECT_DOMAINS:
        return True
    if any(h.endswith(suf) for suf in _ESP_SUFFIXES):
        return True
    # click-notification.capitalone.com style — brand click subdomain
    if h.startswith("click.") or h.startswith("click-") or ".click-" in h:
        return True
    if "notification." in h and any(
        b in h for b in ("capitalone", "chase", "bankofamerica", "wellsfargo", "citi")
    ):
        return True
    return False


def link_aligned_with_sender(host: str, sender_domain: str) -> bool:
    """click-notification.capitalone.com ↔ capitalone.com."""
    h = (host or "").lower().rstrip(".")
    s = (sender_domain or "").lower().rstrip(".")
    if not h or not s:
        return False
    # registrable-ish: last two labels
    def reg(d: str) -> str:
        parts = [p for p in d.split(".") if p]
        return ".".join(parts[-2:]) if len(parts) >= 2 else d

    return reg(h) == reg(s) or h.endswith("." + s) or s.endswith("." + h)
