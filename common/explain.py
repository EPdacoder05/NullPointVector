"""
Plain-English explainability + atomic reason codes (per-message, with evidence).

Structure always:
  1. TEXT  — what we noticed in THIS message (with quotes)
  2. NUMBERS — score pieces unique to this score
  3. CONNECT — how THOSE pieces add up (not a copy-paste lecture)

Homographs (Cyrillic е vs Latin e) are flagged as HOMOGRAPH — that is NOT
the same problem as “require UTF-8 encoding.”
"""
from __future__ import annotations

import math
import re
from typing import Any, Optional

from common.homograph import fold_confusables, scan as homograph_scan
from common.mail_parse import sender_domain as _parse_sender_domain
from common.ml.features import URL_SHORTENERS, SUSPICIOUS_TLDS
from common import mood_lexicon as _mood

REASON_CODES = {
    "URGENCY_FEAR": "Urgency / fear",
    "IMPERSONATION": "Brand spoof",
    "BAD_URL": "Bad URL",
    "SHORT_LINK": "Short link",
    "DOMAIN_MISMATCH": "Link ≠ sender",
    "SENSITIVE_ASK": "Secrets / money ask",
    "HTML_OBFUSCATION": "Digit-swap brand",
    "HOMOGRAPH": "Homograph script",
    "PUNYCODE_IDN": "Punycode IDN",
    "SUSPICIOUS_RELAY": "Relay / disposable",
    "CREDIT_LURE": "Credit / loan lure",
    "SPF_FAIL": "SPF fail",
    "DKIM_FAIL": "DKIM fail",
    "DMARC_FAIL": "DMARC fail",
    "AUTH_PASS": "Auth passed",
    "KNOWN_GOOD": "Known-good",
    "ANOMALY": "Model anomaly",
    "CALLBACK_PRESSURE": "Callback pressure",
    "RELATIONSHIP_LURE": "Romance / NSFW",
    "BLACKMAIL": "Blackmail",
    "SOCIAL_ENGINEERING": "Social engineering",
    "HAPPY_LURE": "Prize / congrats",
    "DISPLAY_NAME_SPOOF": "Display-name spoof",
    "MODEL_SCORE": "Model score",
    "REPLY_TO_MISMATCH": "Reply-To mismatch",
    "ADVANCE_FEE": "Advance fee",
    "ATTACHMENT_RISK": "Risky attachment",
    "IMAGE_ONLY": "Image-only body",
    "LOOKALIKE_DOMAIN": "Lookalike domain",
    "TOLL_FREE_CALLBACK": "Toll-free callback",
    "NEIGHBOR_SPOOF": "Neighbor spoof",
    "CAMPAIGN_MATCH": "Campaign match",
}

_ADVANCE_FEE = tuple(_mood.ADVANCE_FEE)
_TOLL_FREE = re.compile(
    r"(?<!\d)(?:\+?1[\s\-.]?)?(?:800|888|877|866|855|844|833)[\s\-.]?\d{3}[\s\-.]?\d{4}\b"
)
_RISKY_ATTACH = re.compile(
    r"\.(?:exe|scr|js|vbs|bat|cmd|ps1|jar|msi|dll|iso|img|html?|htm|docm|xlsm|pptm|zip|rar|7z)\b",
    re.I,
)

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
_DOMAIN_RE = re.compile(r"https?://([^/\s:]+)", re.I)
_EMAIL_RE = re.compile(r"[\w.+-]+@([\w.-]+\.[A-Za-z]{2,})")
_URGENT = list(_mood.URGENT)
_FEAR = list(_mood.FEAR)
_HAPPY = list(_mood.HAPPY)
_IMPERSONATE = list(_mood.IMPERSONATE)
# Short tokens need word boundaries — "pin" must not match "epinaman" / "iPhone".
_SENSITIVE = ["password", "ssn", "gift card", "wire transfer", "otp", "pin", "cvv", "routing"]
_SENSITIVE_WORD = frozenset({"otp", "pin", "cvv", "ssn"})
_RELATIONSHIP = list(_mood.RELATIONSHIP)
_BLACKMAIL = list(_mood.BLACKMAIL)
_CREDIT = ["credit score", "credit review", "your score", "soft pull", "loan offer",
           "unexpected expenses", "protect.your", "creditscore", "yourscore"]
_SHORTENERS = tuple(sorted(URL_SHORTENERS))
_BAD_TLDS = tuple(f".{t}" if not t.startswith(".") else t for t in sorted(SUSPICIOUS_TLDS))

_VISH_PACK_CACHE: Optional[dict[str, str]] = None  # last10 digits → campaign_id


def _vish_pack_index() -> dict[str, str]:
    """Load data/vish_campaigns/*.json block lists once (digits → campaign_id)."""
    global _VISH_PACK_CACHE
    if _VISH_PACK_CACHE is not None:
        return _VISH_PACK_CACHE
    out: dict[str, str] = {}
    try:
        from pathlib import Path
        import json
        pack_dir = Path(__file__).resolve().parents[1] / "data" / "vish_campaigns"
        if pack_dir.is_dir():
            for path in pack_dir.glob("*.json"):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except Exception:
                    continue
                cid = str(data.get("campaign_id") or path.stem)
                for raw in data.get("block") or []:
                    digits = re.sub(r"\D", "", str(raw))[-10:]
                    if len(digits) == 10:
                        out[digits] = cid
    except Exception:
        out = {}
    _VISH_PACK_CACHE = out
    return out


def _match_vish_campaign_pack(sender: str, content: str) -> Optional[str]:
    idx = _vish_pack_index()
    if not idx:
        return None
    candidates = set()
    sdig = re.sub(r"\D", "", sender or "")[-10:]
    if len(sdig) == 10:
        candidates.add(sdig)
    for m in re.finditer(r"(?<!\d)(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}(?!\d)", content or ""):
        d = re.sub(r"\D", "", m.group(0))[-10:]
        if len(d) == 10:
            candidates.add(d)
    for d in candidates:
        if d in idx:
            return idx[d]
    return None


def _is_shortener_host(host: str) -> bool:
    h = (host or "").lower().rstrip(".")
    if not h:
        return False
    if h in _SHORTENERS:
        return True
    return any(h == s or h.endswith("." + s) for s in _SHORTENERS)

_RELAY_HINTS = ("privaterelay.appleid.com", "reply.github.com", "bounces.", "mailer-daemon",
                "protect.your", "yourscoreandmore", ".click", "temp-mail")

# Latin letter → common Cyrillic / Greek lookalikes (homograph attack).
_HOMOGLYPHS = {
    "a": "ааàáâãäåāăą",  # includes Cyrillic а U+0430
    "c": "сçćĉċč",
    "e": "еёèéêëēĕėęě",  # Cyrillic е U+0435
    "i": "іїíìîïĩīĭįı",
    "j": "ј",
    "o": "оοόòóôõöøōŏő",
    "p": "р",
    "s": "ѕșşśŝš",
    "x": "х×",
    "y": "уýÿŷ",
    "h": "һհ",
    "k": "κкḳķ",
    "m": "м",
    "n": "ոṅņňŉŋ",
    "t": "τţťŧ",
    "b": "ьҍ",
}


def _snip(text: str, needle: str, pad: int = 28) -> str:
    low = text.lower()
    i = low.find(needle.lower())
    if i < 0:
        return needle[:80]
    a = max(0, i - pad)
    b = min(len(text), i + len(needle) + pad)
    chunk = text[a:b].replace("\n", " ").strip()
    return (("…" if a else "") + chunk + ("…" if b < len(text) else ""))[:120]


def _digit_brand_obfuscation(text: str) -> Optional[str]:
    sub = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "$": "s", "@": "a"})
    low = text.lower()
    deob = low.translate(sub)
    for b in _IMPERSONATE:
        if b not in low and b in deob:
            return b
    return None


def detect_homographs(text: str) -> list[dict[str, str]]:
    """Find non-Latin lookalikes mixed into otherwise Latin identifiers/URLs/emails."""
    return homograph_scan(text).get("mixed_script") or []


def analyze_findings(channel: str, content: str, sender: str = "",
                     headers: Optional[dict] = None) -> list[dict[str, str]]:
    """Atomic findings: each has code, label, evidence (unique to this message)."""
    content = content or ""
    sender = sender or ""
    blob = f"{sender}\n{content}"
    # Fold confusables so "раypal" / Cyrillic-е still hits brand + urgency lexicons.
    folded = fold_confusables(blob)
    low = folded.lower()
    findings: list[dict[str, str]] = []

    def add(code: str, evidence: str):
        if code not in REASON_CODES:
            return
        if any(f["code"] == code for f in findings):
            return
        findings.append({
            "code": code,
            "label": REASON_CODES[code],
            "evidence": evidence[:160],
        })

    hg = homograph_scan(blob)
    for h in hg.get("mixed_script") or []:
        add("HOMOGRAPH", h["evidence"])
    for label in hg.get("punycode") or []:
        add("PUNYCODE_IDN", f"IDN/punycode host label “{label}” (often hides non-Latin letters)")

    brand = _digit_brand_obfuscation(folded)
    if brand:
        add("HTML_OBFUSCATION", f"Brand “{brand}” appears with digit/symbol swaps in the text")

    for w in _URGENT + _FEAR:
        if w in low:
            add("URGENCY_FEAR", f"Found “{_snip(folded, w)}”")
            break
    for w in _HAPPY:
        if w in low:
            add("HAPPY_LURE", f"Found “{_snip(folded, w)}”")
            break
    for w in _CREDIT:
        if w in low:
            add("CREDIT_LURE", f"Credit/score lure: “{_snip(folded, w)}”")
            break
    brand_hit = None
    for w in _IMPERSONATE:
        # Word-ish boundary: "ups" must not match "Upstream" in CI subjects.
        if re.search(rf"(?<![a-z0-9]){re.escape(w)}(?![a-z0-9])", low):
            brand_hit = w
            break
    # Defer IMPERSONATION until we know if there is real spoof signal —
    # a bare brand name in a GitHub CI log is not phishing.
    for w in _SENSITIVE:
        if w in _SENSITIVE_WORD:
            if re.search(rf"(?<![a-z0-9]){re.escape(w)}(?![a-z0-9])", low):
                add("SENSITIVE_ASK", f"Asks about “{_snip(folded, w)}”")
                break
        elif w in low:
            add("SENSITIVE_ASK", f"Asks about “{_snip(folded, w)}”")
            break
    for w in _RELATIONSHIP:
        if w in low:
            add("RELATIONSHIP_LURE", f"Found “{_snip(folded, w)}”")
            break
    for w in _BLACKMAIL:
        if w in low:
            add("BLACKMAIL", f"Found “{_snip(folded, w)}”")
            break

    domains = [d.lower() for d in _DOMAIN_RE.findall(content)]
    sender_dom = _parse_sender_domain(sender)
    if not sender_dom and "@" in sender:
        sender_dom = sender.split("@")[-1].strip(">;'\" ").lower()
    try:
        from common.esp_domains import is_esp_redirect_host, link_aligned_with_sender
    except Exception:
        def is_esp_redirect_host(h):  # type: ignore
            return False
        def link_aligned_with_sender(h, s):  # type: ignore
            return False
    for d in domains:
        if is_esp_redirect_host(d) or link_aligned_with_sender(d, sender_dom):
            continue
        if any(d.endswith(t) for t in _BAD_TLDS):
            add("BAD_URL", f"Link host “{d}” uses an abused TLD")
            break
    for d in domains:
        if _is_shortener_host(d):
            add("SHORT_LINK", f"Shortener hides the real site: “{d}”")
            break
        if d.startswith("xn--") or ".xn--" in d:
            add("PUNYCODE_IDN", f"Link host is punycode IDN: “{d}”")

    # DOMAIN_MISMATCH: ignore ESP click hosts + same-brand click subdomains
    link_hosts = [
        d for d in domains
        if not is_esp_redirect_host(d) and not link_aligned_with_sender(d, sender_dom)
    ]
    if sender_dom and link_hosts and all(
            sender_dom not in d and d not in sender_dom for d in link_hosts):
        add("DOMAIN_MISMATCH", f"From “{sender_dom}” but links go to “{link_hosts[0]}”")

    for hint in _RELAY_HINTS:
        if hint in (sender_dom or "") or hint in low:
            add("SUSPICIOUS_RELAY", f"Sender/path looks relay-like (“{hint}”)")
            break

    dm = re.match(r"\s*\"?([^\"<>]+)\"?\s*<([^>]+)>", sender)
    if dm:
        name, addr = dm.group(1).strip(), dm.group(2).strip()
        # GitHub/CI put the repo or user in the display name — not a spoof.
        try:
            from common.safe_domains import domain_is_known_good
            known_dom, _ = domain_is_known_good(addr)
        except Exception:
            known_dom = False
        if not known_dom:
            name_tok = re.sub(r"[^a-z0-9]", "", fold_confusables(name).lower())
            addr_low = fold_confusables(addr).lower()
            overlap = False
            for part in re.findall(r"[a-z]{4,}", fold_confusables(name).lower()):
                if part in addr_low:
                    overlap = True
                    break
            if name_tok and not overlap and name_tok not in addr_low and len(name_tok) >= 4:
                add("DISPLAY_NAME_SPOOF",
                    f"Display name “{name}” does not match mailbox “{addr}”")

    if channel in ("smishing", "vishing"):
        phone_m = re.search(r"\+?\d[\d\-\.\s()]{7,}\d", content)
        if phone_m:
            add("CALLBACK_PRESSURE", f"Message pushes a phone number: “{phone_m.group(0).strip()}”")
        tf = _TOLL_FREE.search(content)
        if tf:
            add("TOLL_FREE_CALLBACK", f"Toll-free callback: “{tf.group(0).strip()}”")
        user_area = ""
        if headers:
            user_area = str(
                headers.get("user_area_code")
                or headers.get("X-NullPoint-User-Area")
                or ""
            ).strip()
        if channel == "vishing" and user_area.isdigit() and len(user_area) == 3:
            cid = re.sub(r"\D", "", sender)[-10:]
            if len(cid) >= 10 and cid[:3] == user_area:
                add("NEIGHBOR_SPOOF",
                    f"Caller ID area {user_area} matches your local prefix")

    for w in _ADVANCE_FEE:
        if w in low:
            add("ADVANCE_FEE", f"Advance-fee language: “{_snip(folded, w)}”")
            break

    text_only = re.sub(r"<[^>]+>", " ", content)
    text_only = re.sub(r"\s+", " ", text_only).strip()
    img_hits = len(re.findall(r"<img\b|cid:|\[image:", content, re.I))
    if img_hits >= 1 and len(text_only) < 48:
        add("IMAGE_ONLY", f"Body is mostly image ({img_hits} img ref, {len(text_only)} text chars)")
    elif len(text_only) < 12 and len(content) > 80 and ("<html" in low or "multipart" in low):
        add("IMAGE_ONLY", "HTML/multipart body with almost no extractable text")

    attach_blob = content
    if headers:
        for k, v in headers.items():
            kl = str(k).lower()
            if "attachment" in kl or "filename" in kl or kl in ("files", "parts"):
                attach_blob += f" {v}"
        meta_files = headers.get("attachments") or headers.get("filenames") or []
        if isinstance(meta_files, (list, tuple)):
            attach_blob += " " + " ".join(str(x) for x in meta_files)
    am = _RISKY_ATTACH.search(attach_blob)
    if am:
        add("ATTACHMENT_RISK", f"Risky attachment pattern: “{am.group(0)}”")

    try:
        from common.lookalike import lookalike_brand_domain
        hit = lookalike_brand_domain(sender)
        if hit:
            brand, host = hit
            add("LOOKALIKE_DOMAIN",
                f"From host “{host}” looks like {brand} (typosquat)")
    except Exception:
        pass

    if headers:
        spf = str(headers.get("spf") or headers.get("Received-SPF") or
                  headers.get("received_spf") or "").lower()
        dkim = str(headers.get("dkim") or headers.get("DKIM-Result") or "").lower()
        dmarc = str(headers.get("dmarc") or headers.get("DMARC-Result") or "").lower()
        auth = str(
            headers.get("Authentication-Results")
            or headers.get("authentication_results")
            or ""
        ).lower()
        blob_a = f"{spf} {dkim} {dmarc} {auth}"
        if "spf=fail" in blob_a or "spf fail" in blob_a:
            add("SPF_FAIL", "SPF check failed on this message")
        if "dkim=fail" in blob_a:
            add("DKIM_FAIL", "DKIM check failed on this message")
        if "dmarc=fail" in blob_a:
            add("DMARC_FAIL", "DMARC check failed on this message")
        if any(x in blob_a for x in ("spf=pass", "dkim=pass", "dmarc=pass")) and not any(
                f["code"].endswith("_FAIL") for f in findings):
            add("AUTH_PASS", "SPF/DKIM/DMARC signals look passing")

        reply_raw = str(
            headers.get("Reply-To")
            or headers.get("reply-to")
            or headers.get("reply_to")
            or ""
        ).strip()
        if reply_raw and "@" in reply_raw and "@" in sender:
            rm = re.search(r"([\w.+-]+@[\w.-]+\.[A-Za-z]{2,})", reply_raw)
            sm = re.search(r"([\w.+-]+@[\w.-]+\.[A-Za-z]{2,})", sender)
            if rm and sm:
                r_addr, s_addr = rm.group(1).lower(), sm.group(1).lower()
                r_dom = r_addr.split("@", 1)[-1]
                s_dom = s_addr.split("@", 1)[-1]
                if r_addr != s_addr and r_dom != s_dom:
                    add("REPLY_TO_MISMATCH",
                        f"From “{s_addr}” but Reply-To “{r_addr}”")

    try:
        from common.user_reports import is_fleet_blocked_sender
        key = sender_dom or sender
        if channel == "vishing":
            key = re.sub(r"\D", "", sender)[-10:] or sender
        fleet_hit, fleet_conf = is_fleet_blocked_sender(key)
        if fleet_hit:
            add("CAMPAIGN_MATCH",
                f"Sender key on fleet threat list (conf≤{fleet_conf:.2f})")
    except Exception:
        pass

    # Vish campaign packs (data/vish_campaigns/*.json) — CID or callback in pack.
    if channel == "vishing":
        try:
            pack_hit = _match_vish_campaign_pack(sender, content)
            if pack_hit:
                add("CAMPAIGN_MATCH",
                    f"Matched campaign pack “{pack_hit}” (directory / TFN seed)")
        except Exception:
            pass

    # Brand name alone is not enough — need spoof/pressure context.
    try:
        from common.safe_domains import domain_is_known_good
        known_sender = domain_is_known_good(sender)[0]
    except Exception:
        known_sender = False
    spoof_codes = {f["code"] for f in findings}
    # AUTH_PASS newsletters mentioning OpenAI/Apple are not brand spoofs.
    auth_ok = "AUTH_PASS" in spoof_codes and not (
        spoof_codes & {"SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL"}
    )
    newsletterish = (
        "unsubscribe" in low or "newsletter" in low or "view in browser" in low
        or "tldrnewsletter" in low
    )
    spoof_context = bool(spoof_codes & {
        "SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL", "BAD_URL", "SHORT_LINK",
        "DOMAIN_MISMATCH", "DISPLAY_NAME_SPOOF", "HOMOGRAPH", "PUNYCODE_IDN",
        "SENSITIVE_ASK", "URGENCY_FEAR", "LOOKALIKE_DOMAIN", "REPLY_TO_MISMATCH",
        "ADVANCE_FEE", "ATTACHMENT_RISK",
    })
    if auth_ok and newsletterish:
        spoof_context = bool(spoof_codes & {
            "SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL", "BAD_URL", "SHORT_LINK",
            "HOMOGRAPH", "PUNYCODE_IDN", "SENSITIVE_ASK",
            "LOOKALIKE_DOMAIN", "REPLY_TO_MISMATCH",
        })
    if brand_hit and spoof_context and not known_sender:
        add("IMPERSONATION",
            f"Brand “{brand_hit}” plus spoof/pressure signals — verify the real sender")

    lure = {"URGENCY_FEAR", "IMPERSONATION", "SENSITIVE_ASK", "CREDIT_LURE",
            "HAPPY_LURE", "DISPLAY_NAME_SPOOF", "HOMOGRAPH", "PUNYCODE_IDN",
            "ADVANCE_FEE", "LOOKALIKE_DOMAIN", "REPLY_TO_MISMATCH"}
    lure_hits = sum(1 for f in findings if f["code"] in lure)
    if lure_hits >= 2:
        add("SOCIAL_ENGINEERING", "Several lure signals stack on this one message")

    return findings


def reason_codes_for(channel: str, content: str, sender: str = "",
                     confidence: float = 0.0, headers: Optional[dict] = None,
                     known_good: bool = False) -> list[dict[str, str]]:
    """UI tags — NEVER pad with a duplicate 'classifier score' badge."""
    if known_good:
        return [{"code": "KNOWN_GOOD", "label": REASON_CODES["KNOWN_GOOD"],
                 "evidence": "Sender matched known-good allowlist"}]
    findings = analyze_findings(channel, content, sender, headers)
    # Prefer concrete findings; confidence lives in Numbers, not as a fake "reason"
    if not findings and confidence >= 0.5:
        return [{
            "code": "ANOMALY",
            "label": "Model flagged without a clear keyword pattern",
            "evidence": (
                f"Score {int(confidence*100)}/100 with no matching keyword/URL rule — "
                f"likely weight on word/char n-grams. Grade it so we learn."
            ),
        }]
    return [{"code": f["code"], "label": f["label"], "evidence": f.get("evidence", "")}
            for f in findings]


def primary_code(findings: list[dict]) -> str:
    return findings[0]["code"] if findings else "ANOMALY"


def plain_english_math(*, channel: str, content: str, sender: str,
                       pred: int, confidence: float,
                       reason_codes: list[dict],
                       top_features: Optional[list[dict]] = None) -> dict[str, Any]:
    """Per-message text → numbers → connect. Neutral wording — never assume phish."""
    import hashlib
    conf_pct = int(round(float(confidence) * 100))
    # Quarantine UI shows items held for review; pred may be model-only.
    held = True
    findings = reason_codes or []
    seed = hashlib.md5(f"{sender}|{content[:80]}|{primary_code(findings)}".encode()).hexdigest()
    pick = int(seed[:8], 16)

    openers = [
        "For this analysis",
        "Looking at the signals on this message",
        "The sender side of this message",
        "In this pass",
        "What stands out here",
        "On this item",
        "Signal check",
        "This message",
        "From the evidence we have",
        "Against the current rules and score",
    ]
    opener = openers[pick % len(openers)]
    who = sender or "an unknown sender"
    ch = channel or "message"

    if findings:
        bullets = "; ".join(
            f"{f['label']}" + (f" — {f['evidence']}" if f.get("evidence") else "")
            for f in findings[:4]
        )
        text = f"{opener}: {who} ({ch}). Flags: {bullets}."
    else:
        text = (
            f"{opener}: {who} ({ch}). No strong keyword/URL rule fired; "
            f"the model score alone placed it in the review queue."
        )

    feat_bits = []
    for f in (top_features or [])[:5]:
        word = f.get("feature") or "?"
        if f.get("contribution") is not None:
            feat_bits.append(f"“{word}”×w={f['contribution']:+.3f}")
        elif f.get("weight") is not None:
            feat_bits.append(f"“{word}” w={f['weight']:+.3f}")

    numbers = {
        "model_confidence_pct": conf_pct,
        "verdict_bit": pred,
        "formula": "P(threat) ≈ 1 / (1 + e^(-(w·x + b)))",
        "feature_nudges": top_features or [],
        "feature_line": ", ".join(feat_bits) if feat_bits else "n-gram weights (no top tokens extracted)",
        "reason_code_count": len(findings),
    }

    primary = primary_code(findings)
    # Connect stays provisional — human grade decides.
    connect_map = {
        "HOMOGRAPH": (
            f"Look-alike letters from another alphabet showed up (e.g. Cyrillic vs Latin). "
            f"Score {conf_pct}/100. That is a hold signal — not a final verdict until you grade."
        ),
        "PUNYCODE_IDN": (
            f"An xn-- / IDN host can hide non-Latin letters. Score {conf_pct}/100 → review."
        ),
        "CREDIT_LURE": (
            f"Credit/score language is a common lure pattern. Model score {conf_pct}/100 "
            f"put this in review; Mark safe if it is a real product you use."
        ),
        "DISPLAY_NAME_SPOOF": (
            f"Display name and mailbox do not line up. Score {conf_pct}/100. "
            f"Could be marketing or spoof — your grade teaches which."
        ),
        "SUSPICIOUS_RELAY": (
            f"From-path looks relay-like or brand-adjacent. Score {conf_pct}/100 → held for you."
        ),
        "IMPERSONATION": (
            f"A brand name appears, which is not proof of the real brand. "
            f"Score {conf_pct}/100. Grade Block or Safe so the weights learn."
        ),
        "URGENCY_FEAR": (
            f"Pressure language showed up. Together with score {conf_pct}/100 this stayed in quarantine."
        ),
        "BAD_URL": f"A high-risk link ending appeared. Score {conf_pct}/100.",
        "SHORT_LINK": f"A shortener hides the real destination. Score {conf_pct}/100.",
        "DOMAIN_MISMATCH": (
            f"Sender domain and link domain disagree. Score {conf_pct}/100."
        ),
        "SENSITIVE_ASK": f"Asks for secrets or payment-like info. Score {conf_pct}/100.",
        "ANOMALY": (
            f"No loud keyword rule — n-gram weights drove score {conf_pct}/100. "
            f"Your grade is the ground truth for the next retrain."
        ),
    }
    connect = connect_map.get(primary)
    if not connect:
        names = ", ".join(f["label"] for f in findings[:3]) or "model n-grams"
        connect = (
            f"Signals ({names}) plus logistic score ≈ {conf_pct}/100 earned a review hold. "
            f"That is not a courtroom verdict — Block / Needs review / Mark safe decides."
            + (f" Top pulls: {numbers['feature_line']}." if feat_bits else "")
        )
    elif feat_bits:
        connect += f" Top word pulls: {numbers['feature_line']}."

    return {
        "verdict": "held_for_review" if held else ("threat" if pred == 1 else "safe"),
        "text": text,
        "numbers": numbers,
        "connect": connect,
        "reason_codes": findings,
        "channel": channel,
    }


def top_word_contributions(detector, text: str, k: int = 8) -> list[dict]:
    try:
        import numpy as np
        clf = getattr(detector, "clf", None)
        word_tfidf = getattr(detector, "word_tfidf", None)
        if clf is None or word_tfidf is None or not text:
            return []
        Xw = word_tfidf.transform([text])
        coef = np.asarray(clf.coef_).ravel()
        n_word = Xw.shape[1]
        word_coef = coef[:n_word]
        data = Xw.multiply(word_coef).tocsr()
        if data.nnz == 0:
            return []
        order = np.argsort(np.abs(data.data))[::-1][:k]
        inv = {i: t for t, i in word_tfidf.vocabulary_.items()}
        out = []
        for oi in order:
            i = int(data.indices[oi])
            out.append({
                "feature": inv.get(i, f"f{i}"),
                "weight": round(float(word_coef[i]), 4),
                "contribution": round(float(data.data[oi]), 4),
            })
        return out
    except Exception:
        return []


def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))
