"""Disposable / burn-email domains for signup.

Apple Hide My Email (`privaterelay.appleid.com`) is NEVER disposable.
Shape-valid fakes (instaddr, guerrilla, etc.) die here.
"""
from __future__ import annotations

# Curated burn/temp providers. Not MX-perfect; enough to stop casual generators.
_DISPOSABLE: frozenset[str] = frozenset({
    "mailinator.com", "guerrillamail.com", "guerrillamailblock.com", "sharklasers.com",
    "grr.la", "guerrillamail.info", "guerrillamail.net", "guerrillamail.org",
    "yopmail.com", "yopmail.fr", "cool.fr.nf", "jetable.org", "nospam.ze.tc",
    "nomail.xl.cx", "mega.zik.dj", "speed.1s.fr", "courriel.fr.nf", "moncourrier.fr.nf",
    "monemail.fr.nf", "monmail.fr.nf", "tempmail.com", "temp-mail.org", "temp-mail.io",
    "throwawaymail.com", "trashmail.com", "trashmail.me", "trashmail.net",
    "10minutemail.com", "10minutemail.net", "minutemail.com", "emailondeck.com",
    "getnada.com", "nada.ltd", "mohmal.com", "fakeinbox.com", "mailnesia.com",
    "maildrop.cc", "discard.email", "dispostable.com", "mailcatch.com",
    "tempail.com", "tempr.email", "tmpmail.org", "tmpmail.net", "mailtemp.net",
    "mytemp.email", "tempinbox.com", "throwam.com", "getairmail.com",
    "spamgourmet.com", "mailnull.com", "spamfree24.org", "kasmail.com",
    "spamobox.com", "emkei.cz", "emailfake.com", "generator.email",
    "instaddr.ch", "instaddr.win", "instant-email.org", "burnermail.io",
    "mailpoof.com", "fakemailgenerator.com", "emailnator.com", "guerrillamail.de",
    "inboxkitten.com", "harakirimail.com", "mailforspam.com", "mt2015.com",
    "thankyou2010.com", "trash2009.com", "filzmail.com", "anonymbox.com",
    "trashymail.com", "mailexpire.com", "tempomail.fr", "tmpeml.com",
})

_APPLE_RELAY = "privaterelay.appleid.com"


def email_domain(email: str) -> str:
    e = (email or "").strip().lower()
    if "@" not in e:
        return ""
    return e.rsplit("@", 1)[-1].strip()


def is_apple_hide_my_email(email: str) -> bool:
    return email_domain(email) == _APPLE_RELAY


def is_disposable_email(email: str) -> bool:
    """True if domain is a known burn provider. Apple Hide My Email → False."""
    dom = email_domain(email)
    if not dom:
        return False
    if dom == _APPLE_RELAY or dom.endswith("." + _APPLE_RELAY):
        return False
    if dom in _DISPOSABLE:
        return True
    # Subdomains of known burn hosts (e.g. foo.mailinator.com)
    return any(dom.endswith("." + d) for d in _DISPOSABLE)
