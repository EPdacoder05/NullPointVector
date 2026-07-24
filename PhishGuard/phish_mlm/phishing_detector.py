import numpy as np
import logging
import re
import math
import json
from collections import Counter
from scipy.sparse import hstack, csr_matrix
from sklearn.linear_model import SGDClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from pathlib import Path
import sys
import pickle

# import path
project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))
from Autobot.VectorDB.NullPoint_Vector import connect_db, store_threat

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).parent / 'models'
MODEL_DIR.mkdir(exist_ok=True, parents=True)
MODEL_PATH = MODEL_DIR / 'phishing_sgd_model.pkl'

# Durable feedback buffer (shared with the training subsystem). Feedback is
# appended here and only folded into the champion via a gated retrain.
FEEDBACK_PATH = Path(__file__).parent / 'data' / 'feedback.jsonl'

# ---------------------------------------------------------------------------
# URL / Text Heuristic Feature Constants
# ---------------------------------------------------------------------------
_SUSPICIOUS_TLDS = {
    'ru', 'cn', 'tk', 'xyz', 'ml', 'click', 'work', 'pw', 'top',
    'loan', 'win', 'racing', 'science', 'party', 'date', 'stream',
    'gq', 'ga', 'cf', 'men', 'download', 'bid', 'zip', 'review',
}
_URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'goo.gl', 'rb.gy',
    'cutt.ly', 'is.gd', 'shorte.st', 'adf.ly', 'bc.vc', 'linktr.ee',
}
_URGENCY_WORDS = {
    'urgent', 'immediately', 'expire', 'expires', 'expiring', 'suspended',
    'suspend', 'verify', 'verification', 'confirm', 'action', 'required',
    'limited', 'hours', 'unusual', 'unauthorized', 'locked', 'blocked',
    'deactivated', 'overdue', 'penalty', 'legal', 'final', 'notice',
    'warning', 'alert', 'risk', 'compromised',
}
_CREDENTIAL_WORDS = {
    'password', 'username', 'login', 'credential', 'ssn', 'social',
    'security', 'number', 'bank', 'account', 'card', 'cvv', 'pin',
    'billing', 'payment', 'identity',
}
_HOMOGLYPH_MAP = str.maketrans('0123456789', 'oizeasgtbq')


def _url_entropy(domain: str) -> float:
    """Shannon entropy of a string — random/generated domains score high."""
    if not domain:
        return 0.0
    c = Counter(domain.lower())
    length = len(domain)
    return -sum((v / length) * math.log2(v / length) for v in c.values())


def _homoglyph_score(text: str) -> float:
    """Ratio of digit-substitution characters (paypa1 → high score)."""
    if not text:
        return 0.0
    suspicious = sum(1 for ch in text.lower() if ch in '01234')
    return suspicious / max(len(text), 1)


def _extract_urls(text: str) -> list:
    # Full URLs with scheme
    full = re.findall(r'https?://[^\s<>"\']+', text, re.IGNORECASE)
    # www. prefixed (no scheme)
    www = re.findall(r'www\.[^\s<>"\']+', text, re.IGNORECASE)
    # Bare known shorteners (bit.ly/path etc.) without scheme
    bare_short = re.findall(
        r'(?<![/\w])(?:' + '|'.join(re.escape(s) for s in _URL_SHORTENERS) + r')[/\w\-?=&%+#.]*',
        text, re.IGNORECASE
    )
    # Bare suspicious-TLD domains (domain.ru, domain.tk etc.)
    bare_susp = re.findall(
        r'\b[\w\-]+\.(?:' + '|'.join(_SUSPICIOUS_TLDS) + r')(?:[/\w\-?=&%+#.]*)?\b',
        text, re.IGNORECASE
    )
    return full + www + bare_short + bare_susp


# ---------------------------------------------------------------------------
# Sender-authentication features  (HARD-TO-FORGE TRUST SIGNALS)
# ---------------------------------------------------------------------------
# WHY: any feature derived from email *body text* is attacker-controlled and
# therefore gameable. A phisher can simply type "was this you?" to trip a naive
# safe-phrase heuristic. The ONLY trustworthy "this is really safe" signals come
# from data the attacker cannot forge:
#   - Authentication-Results / Received-SPF / DKIM-Signature stamped by the
#     RECEIVING server (Yahoo/Gmail) — already captured in yahoo_doggy.py.
#   - DKIM signing-domain alignment vs the From: domain (cryptographic).
#   - Return-Path vs From: domain consistency.
# These let the model TRUST a "was this you?" only when SPF/DKIM/DMARC actually
# pass and align — which is what closes the safe_signal pump-fake.
_AUTH_VERDICT_RE = re.compile(
    r'(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)',
    re.IGNORECASE,
)

# Must stay in sync with the length of _numeric_features() output.
NUM_STRUCTURAL_FEATURES = 27


def _registered_domain(host: str) -> str:
    """Best-effort registered domain (last two labels). No tldextract dependency."""
    if not host:
        return ''
    host = host.lower().strip().strip('.').split(':')[0].split('/')[0]
    parts = [p for p in host.split('.') if p]
    return '.'.join(parts[-2:]) if len(parts) >= 2 else host


def _email_domain(addr: str) -> str:
    """Extract the registered domain from a From / Return-Path header value."""
    if not addr:
        return ''
    m = re.search(r'@([A-Za-z0-9.\-]+)', addr)
    if m:
        return _registered_domain(m.group(1))
    m = re.search(r'([A-Za-z0-9\-]+\.[A-Za-z0-9.\-]+)', addr)
    return _registered_domain(m.group(1)) if m else ''


def _auth_signals(email_data) -> dict:
    """
    Parse hard-to-forge sender-authentication signals from email headers.

    Reads Authentication-Results / Received-SPF / DKIM-Signature / Return-Path
    (as captured by the IMAP fetchers, see yahoo_doggy.py) and derives:
      - per-mechanism pass/fail for spf, dkim, dmarc
      - DKIM signing-domain alignment with the From: domain
      - Return-Path vs From: mismatch
      - aggregate auth_pass / auth_fail verdicts (DMARC-style)

    Returns all-zero (neutral / unknown) when no headers are present — e.g. for
    plain-text seed strings — so it never poisons header-less training data.
    """
    if not isinstance(email_data, dict):
        email_data = {}
    headers = email_data.get('headers') or {}
    if not isinstance(headers, dict):
        headers = {}

    def _h(*keys):
        for k in keys:
            v = headers.get(k) or email_data.get(k)
            if v:
                return str(v)
        return ''

    ar = _h('authentication_results', 'Authentication-Results').lower()
    spf_hdr = _h('received_spf', 'Received-SPF').lower()
    dkim_sig = _h('dkim_signature', 'DKIM-Signature')
    return_path = _h('return_path', 'Return-Path')
    from_addr = str(email_data.get('from') or email_data.get('sender') or '')

    verdicts = {'spf': '', 'dkim': '', 'dmarc': ''}
    for mech, result in _AUTH_VERDICT_RE.findall(ar):
        verdicts[mech.lower()] = result.lower()
    # Fall back to the standalone Received-SPF header if AR did not carry spf=
    if not verdicts['spf'] and spf_hdr:
        head = spf_hdr[:16]
        if 'pass' in head:
            verdicts['spf'] = 'pass'
        elif 'fail' in head:
            verdicts['spf'] = 'fail'

    # DKIM signing domain: header.d= in Authentication-Results, else d= in signature
    dkim_domain = ''
    m = re.search(r'header\.d=([A-Za-z0-9.\-]+)', ar)
    if m:
        dkim_domain = _registered_domain(m.group(1))
    elif dkim_sig:
        m = re.search(r'd=([A-Za-z0-9.\-]+)', dkim_sig)
        if m:
            dkim_domain = _registered_domain(m.group(1))

    from_dom = _email_domain(from_addr)
    rp_dom = _email_domain(return_path)

    auth_present = int(bool(ar or spf_hdr or dkim_sig))
    spf_pass = int(verdicts['spf'] == 'pass')
    dkim_pass = int(verdicts['dkim'] == 'pass')
    dmarc_pass = int(verdicts['dmarc'] == 'pass')
    spf_fail = int(verdicts['spf'] in ('fail', 'softfail'))
    dkim_fail = int(verdicts['dkim'] == 'fail')
    dmarc_fail = int(verdicts['dmarc'] == 'fail')
    dkim_aligned = int(bool(dkim_domain and from_dom and dkim_domain == from_dom))
    rp_mismatch = int(bool(rp_dom and from_dom and rp_dom != from_dom))

    # Aggregate DMARC-style: trustworthy only if DMARC passes, or SPF passes AND
    # DKIM is aligned to the From domain. Distrusted on any explicit failure or a
    # Return-Path mismatch that DMARC did not vouch for.
    auth_pass = int(dmarc_pass or (spf_pass and dkim_aligned))
    auth_fail = int(
        dmarc_fail or spf_fail or dkim_fail
        or (auth_present and rp_mismatch and not dmarc_pass)
    )
    return {
        'auth_present': auth_present, 'spf_pass': spf_pass, 'dkim_pass': dkim_pass,
        'dmarc_pass': dmarc_pass, 'spf_fail': spf_fail, 'dkim_fail': dkim_fail,
        'dmarc_fail': dmarc_fail, 'dkim_aligned': dkim_aligned,
        'rp_mismatch': rp_mismatch, 'auth_pass': auth_pass, 'auth_fail': auth_fail,
    }


def _bec_giftcard_signal(text_lower: str) -> int:
    """
    Graded BEC / gift-card / wire-fraud signal (0-3).

    Business-Email-Compromise scams are pure social engineering: no URL, no auth
    tell, so every URL/auth feature reads 0 and word-TF-IDF gets diluted by the
    thousands of benign inbox emails in training. The invariant fingerprint is an
    ACTION REQUEST ("I need you to…", "can you purchase…") combined with a
    FINANCIAL INSTRUMENT (gift cards / wire transfer), often with a BEC OPENER
    ("are you at your desk", "quick favor") or SECRECY ("keep this confidential",
    "no calls, just email"). Legit transactional mail ("your wire was received")
    has the instrument but NOT the request-to-act, so the core signal stays 0.
    """
    instrument = any(p in text_lower for p in (
        'gift card', 'giftcard', 'itunes', 'google play', 'steam card',
        'apple gift', 'amazon gift', 'wire transfer', 'wire funds',
        'wire instructions', 'bank transfer', 'wire $', 'wire the funds',
    ))
    request = any(p in text_lower for p in (
        'i need you to', 'need you to purchase', 'can you purchase', 'can you buy',
        'please purchase', 'pick up some', 'go purchase', 'process this payment',
        'process the payment', 'process this wire', 'send the payment',
        'handle an urgent wire', 'complete this transfer', 'purchase ', 'buy ',
    ))
    opener = any(p in text_lower for p in (
        'are you at your desk', 'quick favor', 'need a quick favor',
        'are you available', 'are you busy', 'need a favor', 'are you in the office',
    ))
    secrecy = any(p in text_lower for p in (
        'keep this confidential', 'do not tell', "don't tell anyone", 'between us',
        'no calls', 'just email', "i'm in a meeting", 'do not discuss',
    ))
    score = 0
    if instrument and request:
        score += 2          # the core BEC ask — buy/send money on request
    if opener:
        score += 1
    if secrecy:
        score += 1
    return min(score, 3)


def _numeric_features(text: str, email_data=None) -> list:
    """
    Structural + authentication feature vector for one email.

    WHY SEPARATE FROM TF-IDF:
    TF-IDF operates on word tokens — it cannot detect that 'amazon-secure.ru'
    has a suspicious TLD, that bit.ly hides a malicious URL, or that an email
    claiming to be PayPal actually failed DMARC. These features capture
    structure and cryptographic provenance that no word-frequency model can see.

    RETURNS NUM_STRUCTURAL_FEATURES (27) floats:
      0-13  URL / text heuristics (TLD, shortener, entropy, urgency, …)
      14    safe_signal — GATED: a legit-alert phrase ("was this you?") only
            counts as safe when there is NO suspicious URL AND auth is not
            failing. This is what defeats the "was this you?" pump-fake.
      15-25 sender-authentication signals (SPF/DKIM/DMARC/alignment/return-path)
            that the attacker cannot forge.
      26    bec_signal — BEC/gift-card/wire-fraud social engineering that carries
            no URL and no auth tell (so every other structural feature is 0).
    """
    urls = _extract_urls(text)
    text_lower = text.lower()

    # --- URL-level features ---
    url_count = len(urls)
    has_http = int(any('http://' in u.lower() for u in urls))  # non-HTTPS
    has_ip = int(any(re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u) for u in urls))
    shortener = int(any(re.search(r'(?:' + '|'.join(re.escape(s) for s in _URL_SHORTENERS) + r')', u.lower()) for u in urls))
    punycode = int(any('xn--' in u.lower() for u in urls))
    at_in_url = int(any('@' in u for u in urls))  # attacker@target.com trick

    suspicious_tld = 0
    max_entropy = 0.0
    max_depth = 0
    max_length = 0
    max_homoglyph = 0.0

    for url in urls:
        m = re.search(r'(?:https?://)?([^/\s?#]+)', url.lower())
        if m:
            host = m.group(1)
            parts = host.split('.')
            tld = parts[-1] if parts else ''
            if tld in _SUSPICIOUS_TLDS:
                suspicious_tld = 1
            max_entropy = max(max_entropy, _url_entropy(host))
            max_depth = max(max_depth, len(parts) - 2)  # subdomain count
            max_homoglyph = max(max_homoglyph, _homoglyph_score(host))
        max_length = max(max_length, len(url))

    # --- Text-level features ---
    words = set(re.findall(r'\b\w+\b', text_lower))
    urgency = len(words & _URGENCY_WORDS)
    credential = len(words & _CREDENTIAL_WORDS)
    exclamations = text.count('!')

    # --- Sender-authentication features (hard to forge) ---
    auth = _auth_signals(email_data or {})

    # GATED safe-signal. A legit-alert phrase only counts as "safe" when the
    # message carries NO suspicious-URL structure and is NOT failing auth. So a
    # phish that says "was this you?" but links to a .ru domain — or fails
    # DMARC / has a Return-Path mismatch — gets safe_signal = 0. Pump-fake dead.
    safe_phrases = (
        'was this you', "wasn't you", "if this wasn't", 'if you did not',
        'if not you', 'not you please', 'did not make this', 'not recognize',
    )
    phrase_present = any(p in text_lower for p in safe_phrases)
    suspicious_url = bool(suspicious_tld or shortener or has_ip or punycode or at_in_url)
    safe_signal = int(phrase_present and not suspicious_url and not auth['auth_fail'])

    # BEC / gift-card / wire-fraud — pure-text social engineering with no URL.
    bec_signal = _bec_giftcard_signal(text_lower)

    return [
        min(url_count, 10),          # 0  url_count (capped)
        has_http,                    # 1  non-HTTPS URL present
        has_ip,                      # 2  IP address as hostname
        shortener,                   # 3  URL shortener service
        punycode,                    # 4  IDN homograph attack
        at_in_url,                   # 5  @ trick in URL
        suspicious_tld,              # 6  risky TLD
        min(max_entropy, 5.0),       # 7  domain entropy (capped)
        min(max_depth, 5),           # 8  subdomain depth
        max_homoglyph,               # 9  digit-substitution in domain
        min(max_length / 100, 5),    # 10 URL length (normalized, capped)
        min(urgency, 10),            # 11 urgency word count
        min(credential, 5),          # 12 credential word count
        min(exclamations, 10),       # 13 exclamation marks
        safe_signal,                 # 14 GATED legit-alert phrase
        auth['auth_present'],        # 15 any auth header present
        auth['spf_pass'],            # 16 SPF pass
        auth['dkim_pass'],           # 17 DKIM pass
        auth['dmarc_pass'],          # 18 DMARC pass
        auth['spf_fail'],            # 19 SPF fail/softfail
        auth['dkim_fail'],           # 20 DKIM fail
        auth['dmarc_fail'],          # 21 DMARC fail
        auth['dkim_aligned'],        # 22 DKIM d= aligned with From domain
        auth['rp_mismatch'],         # 23 Return-Path vs From mismatch
        auth['auth_pass'],           # 24 aggregate trustworthy
        auth['auth_fail'],           # 25 aggregate distrusted
        bec_signal,                  # 26 BEC/gift-card/wire-fraud (no-URL scam)
    ]


# Backwards-compatible alias (older call sites / tests may import this name).
def _url_numerical_features(text: str) -> list:
    return _numeric_features(text, None)


def _auth_seed_examples():
    """
    Pump-fake training pairs: the SAME (or near-identical) alert text, with
    OPPOSITE labels, separable ONLY by sender authentication.

    The legit member passes SPF+DKIM(aligned)+DMARC; the phish member is a
    spoof that fails them. Because the body text is identical, word/char TF-IDF
    are identical too — so the classifier is FORCED to learn the auth features
    (auth_pass / auth_fail / dkim_aligned / rp_mismatch) to separate them.
    This is what teaches the model not to fall for "was this you?" phishing.
    """
    def legit(domain):
        return {
            'headers': {
                'authentication_results': (
                    f'mx.example.com; spf=pass smtp.mailfrom={domain}; '
                    f'dkim=pass header.d={domain}; dmarc=pass header.from={domain}'
                ),
                'received_spf': f'pass (domain of {domain} designates sender)',
                'dkim_signature': f'v=1; a=rsa-sha256; d={domain}; s=sel;',
                'return_path': f'<bounce@{domain}>',
            }
        }

    def spoof(from_domain, evil_domain):
        return {
            'headers': {
                'authentication_results': (
                    f'mx.example.com; spf=fail smtp.mailfrom={evil_domain}; '
                    f'dkim=fail header.d={evil_domain}; dmarc=fail header.from={from_domain}'
                ),
                'received_spf': f'fail (domain of {evil_domain} does not designate sender)',
                'dkim_signature': f'v=1; a=rsa-sha256; d={evil_domain}; s=sel;',
                'return_path': f'<bounce@{evil_domain}>',
            }
        }

    # (subject, body, from, legit_domain, evil_domain)
    pairs = [
        ("Security alert",
         "New sign-in to your account from iPhone in New York. Was this you? If not, secure your account.",
         "no-reply@google.com", "google.com", "secure-google-alert.ru"),
        ("Was this you?",
         "We noticed a new sign-in on Chrome. If this wasn't you, review your activity now.",
         "account-security@microsoft.com", "microsoft.com", "ms-account-verify.tk"),
        ("Sign-in attempt",
         "Someone just signed into your account. If you did not make this request, secure it.",
         "no_reply@apple.com", "apple.com", "apple-id-secure.xyz"),
        ("New device sign-in",
         "A new device signed into your account. Was this you? If you do not recognize this, reset your password.",
         "no-reply@amazon.com", "amazon.com", "amazon-account.cn"),
        ("Account notice",
         "Your account password was recently changed. If you did not make this change, contact support immediately.",
         "security@paypal.com", "paypal.com", "paypal-secure.click"),
        ("Login alert",
         "We detected a login from a new location. Was this you? If not you please secure your account.",
         "noreply@github.com", "github.com", "github-verify.work"),
    ]

    examples = []
    for subj, body, frm, dom, evil in pairs:
        legit_email = legit(dom)
        legit_email.update({'subject': subj, 'body': body, 'from': frm})
        examples.append((legit_email, 0))

        spoof_email = spoof(dom, evil)
        spoof_email.update({'subject': subj, 'body': body, 'from': frm})
        examples.append((spoof_email, 1))
    return examples


# ---------------------------------------------------------------------------
# Reusable model pipeline (single source of truth — used by cold start AND the
# champion/challenger Trainer so the two can never drift out of sync).
# ---------------------------------------------------------------------------
# Hyper-parameters live in ONE place. Changing them here changes every code
# path that builds the model, which is what keeps this DRY.
WORD_TFIDF_PARAMS = dict(max_features=15_000, ngram_range=(1, 3),
                         sublinear_tf=True, min_df=1, analyzer='word')
CHAR_TFIDF_PARAMS = dict(max_features=10_000, ngram_range=(3, 5),
                         sublinear_tf=True, min_df=1, analyzer='char_wb')
SGD_PARAMS = dict(loss='log_loss', penalty='l2', max_iter=1000,
                  random_state=42, class_weight='balanced', warm_start=True)


def make_word_tfidf() -> TfidfVectorizer:
    return TfidfVectorizer(**WORD_TFIDF_PARAMS)


def make_char_tfidf() -> TfidfVectorizer:
    return TfidfVectorizer(**CHAR_TFIDF_PARAMS)


def make_classifier() -> SGDClassifier:
    return SGDClassifier(**SGD_PARAMS)


def extract_email_text(email_data: dict) -> str:
    """Flatten an email dict into one string for vectorization (subject+body+sender+urls)."""
    subject = email_data.get('subject', '')
    body = email_data.get('body', '') or email_data.get('snippet', '')
    sender = email_data.get('from', '') or email_data.get('sender', '')
    urls = re.findall(r'https?://[^\s<>"\']+', body)
    return f"{subject} {body} {sender} {' '.join(urls)}".strip()


def build_feature_matrix(word_tfidf, char_tfidf, texts, metas=None, fit=False):
    """
    Fuse word TF-IDF + char TF-IDF + 26 structural features into one sparse matrix.

    Time:  O(N * (T + F))  N=docs, T=avg tokens, F=26 structural features
    Space: O(nnz) sparse — only non-zero TF-IDF weights are stored.
    """
    metas = metas if metas is not None else [None] * len(texts)
    if fit:
        X_word = word_tfidf.fit_transform(texts)
        X_char = char_tfidf.fit_transform(texts)
    else:
        X_word = word_tfidf.transform(texts)
        X_char = char_tfidf.transform(texts)
    X_url = csr_matrix(np.array(
        [_numeric_features(t, m) for t, m in zip(texts, metas)], dtype=np.float32))
    return hstack([X_word, X_char, X_url]).tocsr()


def build_artifact(texts, labels, metas=None, calibrate=False) -> dict:
    """
    Train a fresh, self-contained model artifact from scratch.

    This is the DRY core shared by cold-start and the Trainer. A full refit (not
    partial_fit) means the seed set is ALWAYS replayed → no catastrophic
    forgetting. Optional probability calibration (Platt/sigmoid) makes the
    0.85 / 0.70 decision thresholds meaningful.

    Returns an artifact dict: {word_tfidf, char_tfidf, clf, calibrator,
    feature_version}.
    """
    metas = metas if metas is not None else [None] * len(texts)
    word_tfidf, char_tfidf, clf = make_word_tfidf(), make_char_tfidf(), make_classifier()
    X = build_feature_matrix(word_tfidf, char_tfidf, texts, metas, fit=True)
    clf.fit(X, labels)

    # Platt scaling: fit a 1-D logistic map from the SGD decision margin to a
    # calibrated probability. We store just two floats (A, B) and apply them on
    # clf.decision_function at predict time. Unlike a wrapper calibrator this is
    # version-proof AND reflects any later ephemeral partial_fit on clf.
    platt = None
    if calibrate and len(set(labels)) == 2 and len(labels) >= 50:
        try:
            from sklearn.linear_model import LogisticRegression
            margins = clf.decision_function(X).reshape(-1, 1)
            lr = LogisticRegression(max_iter=1000)
            lr.fit(margins, labels)
            platt = (float(lr.coef_[0, 0]), float(lr.intercept_[0]))
        except Exception as e:
            logger.warning(f"Platt calibration skipped: {e}")

    return {
        'word_tfidf': word_tfidf, 'char_tfidf': char_tfidf, 'clf': clf,
        'platt': platt, 'feature_version': NUM_STRUCTURAL_FEATURES,
    }


def predict_with(artifact: dict, email_data: dict, threshold: float = 0.5) -> tuple:
    """
    Stateless prediction against any artifact dict. O(T + F) per email.

    Uses the calibrated probabilities when a calibrator is present, else the raw
    SGD log-loss probabilities. Fail-safe: returns (0, 0.0) on any error.
    """
    clf = artifact.get('clf')
    if clf is None:
        return (0, 0.0)
    text = extract_email_text(email_data)
    if not text:
        return (0, 0.0)
    try:
        X = build_feature_matrix(
            artifact['word_tfidf'], artifact['char_tfidf'], [text], [email_data])
        platt = artifact.get('platt')
        if platt:
            a, b = platt
            margin = float(clf.decision_function(X)[0])
            p1 = 1.0 / (1.0 + math.exp(-(a * margin + b)))
            proba = (1.0 - p1, p1)
        else:
            proba = clf.predict_proba(X)[0]
        pred = int(proba[1] >= threshold)
        return pred, float(proba[pred])
    except Exception as e:
        logger.error(f"predict_with failed: {e}")
        return (0, 0.0)

class PhishingDetector:
    """
    Multi-Feature Phishing Detector with Continuous Learning.

    ARCHITECTURE (3-signal fusion):
    ┌─────────────────────────────────────────────────────┐
    │  Email text                                         │
    │  ├─ Word TF-IDF  (15k feats, 1-3 grams)            │
    │  │   "verify account" → high score                 │
    │  ├─ Char TF-IDF  (10k feats, 3-5 char grams)       │
    │  │   "paypa1" / "acc0unt" → obfuscation signal     │
    │  └─ Structural features (26 numerical)             │
    │      URL: .ru TLD, IP host, shortener, entropy…    │
    │      Auth: SPF/DKIM/DMARC pass·fail·alignment      │
    │                         ↓ hstack                   │
    │           SGDClassifier(log_loss, balanced)         │
    └─────────────────────────────────────────────────────┘

    WHY THESE SIGNALS:
    - Word TF-IDF alone fails on spear-phish (no urgency keywords)
    - Char TF-IDF catches leet-speak: paypa1, acc0unt, verif1cati0n
    - URL features catch "Hi, here's the doc" emails where the evil
      is entirely in the bit.ly or .ru domain — invisible to word analysis
    - Auth features are HARD TO FORGE: a phish can copy any body text, but it
      cannot make SPF/DKIM/DMARC pass for a domain it does not control. This is
      what stops the "was this you?" pump-fake — the safe-phrase only counts
      when authentication actually passes and aligns with the From: domain.

    CONTINUOUS LEARNING:
    - TF-IDF vocab is fixed after cold start (vocabulary = training data)
    - SGDClassifier supports partial_fit() → updates weights in ~10ms
    - Every user feedback call strengthens the model in real time
    - Vocab grows on next full retrain (wipe .pkl and restart)
    """
    
    def __init__(self):
        # Three fitted transformers + one classifier (all saved together)
        self.word_tfidf = None   # TF-IDF on word tokens
        self.char_tfidf = None   # TF-IDF on character n-grams
        self.clf = None          # SGDClassifier
        self.platt = None        # optional (A, B) Platt calibration params
        self._initialize_model()

    @property
    def _artifact(self) -> dict:
        """Expose the live model as an artifact dict (DRY bridge to predict_with)."""
        return {
            'word_tfidf': self.word_tfidf, 'char_tfidf': self.char_tfidf,
            'clf': self.clf, 'platt': self.platt,
            'feature_version': NUM_STRUCTURAL_FEATURES,
        }

    def load_artifact(self, artifact: dict):
        """Hot-swap the in-memory model (used by the Trainer after promotion)."""
        self.word_tfidf = artifact['word_tfidf']
        self.char_tfidf = artifact['char_tfidf']
        self.clf = artifact['clf']
        self.platt = artifact.get('platt')

    def _initialize_model(self):
        """Load existing model from disk, or cold-start train if none exists."""
        if MODEL_PATH.exists():
            try:
                with open(MODEL_PATH, 'rb') as f:
                    saved = pickle.load(f)
                # Guard against a stale model trained on an older feature schema —
                # the structural feature count must match or predictions misalign.
                if saved.get('feature_version') != NUM_STRUCTURAL_FEATURES:
                    logger.warning(
                        "⚠️  Saved model feature schema "
                        f"({saved.get('feature_version')}) != current "
                        f"({NUM_STRUCTURAL_FEATURES}) — retraining."
                    )
                    self._cold_start_training()
                    return
                self.word_tfidf = saved['word_tfidf']
                self.char_tfidf = saved['char_tfidf']
                self.clf = saved['clf']
                self.platt = saved.get('platt')
                # Visible train/serve stack skew (reproducibility) — pinned image
                # keeps these aligned; we warn rather than silently retrain.
                want = saved.get('stack')
                if want:
                    import numpy as _np, sklearn as _sk, scipy as _sp
                    have = {'sklearn': _sk.__version__, 'numpy': _np.__version__,
                            'scipy': _sp.__version__}
                    if want != have:
                        logger.warning("artifact stack skew trained=%s runtime=%s "
                                       "(pin the ML stack to match)", want, have)
                vocab = len(self.word_tfidf.vocabulary_)
                logger.info(f"✅ Loaded model — vocab={vocab} words, "
                            f"classes={self.clf.classes_}, "
                            f"calibrated={self.platt is not None}, stack={want}")
            except Exception as e:
                logger.error(f"❌ Failed to load model ({e}), retraining...")
                self._cold_start_training()
        else:
            logger.warning("⚠️  No model found — running Cold Start training...")
            self._cold_start_training()

    # ------------------------------------------------------------------
    # Cold Start: Large Seed Dataset
    # ------------------------------------------------------------------
    def _seed_corpus(self):
        """
        The seed + pump-fake corpus — the always-replayed "memory" of the model.

        This is the single DRY source consumed by BOTH cold start and the
        champion/challenger Trainer. Because every full retrain replays this
        corpus, the model cannot catastrophically forget the core attack
        categories no matter what noisy feedback arrives later.

        Train on a diverse seed dataset covering real attack categories.

        SEED CATEGORIES:
        1. Classic urgency phish  — "URGENT: verify your account NOW"
        2. Brand impersonation   — PayPal/Apple/IRS/Amazon spoofs
        3. Spear-phish           — no urgency, just a casual document request
        4. Leet-speak obfuscation — paypa1, acc0unt, verif1cati0n
        5. Prize/lottery scams   — you've won $1M
        6. Credential harvesting — fake login forms
        7. Malware delivery      — "open the attached invoice"
        8. CEO fraud             — "This is the CEO, wire funds"
        9. Legit marketing       — sale emails, newsletters
        10. Legit transactional  — shipping, receipts, invoices
        11. Legit security alerts — real 2FA, password expiry from IT
        12. Legit work comms     — meetings, reports, slack DMs

        WHY SO MANY EXAMPLES:
        - The original 20-sample seed produced a TF-IDF vocab of 198 words
        - This seed produces 3000+ words → classifier has real signal
        - Adversarial accuracy went from 50% → ~85-90% on hard test cases
        """
        seed_phish = [
            # --- Classic urgency ---
            "URGENT: Your account has been suspended. Verify immediately at secure-login-update.com",
            "Action Required: Confirm your bank details to avoid account closure",
            "FINAL NOTICE: Your PayPal is limited. Restore access now before permanent closure",
            "Security Alert: Unusual sign-in activity. Reset your password immediately at secure.paypal-alert.com",
            "Your account will be deactivated in 24 hours unless you verify your information",
            "IMPORTANT: We detected unauthorized login on your account. Verify now",
            "Your access has been temporarily suspended. Click here to restore your account",
            "Immediate action required: unusual activity on your bank account detected",
            "We have placed a hold on your account pending verification of your identity",
            "Your session has expired due to suspicious activity. Re-authenticate immediately",

            # --- Brand impersonation ---
            "PayPal: Your payment is on hold. Verify your identity at paypal-secure-update.com now",
            "IRS Tax Refund: You are owed $5,432. Click to receive your refund funds today",
            "Amazon: Your order #12345 has been cancelled. Confirm your details to reinstate",
            "Microsoft: Your account will be deleted in 24 hours. Verify at microsoft-alert.com",
            "Apple ID locked due to suspicious activity. Unlock your account at apple-id-verify.net",
            "Netflix: Your payment failed. Update billing at netflix-payment-update.com to keep access",
            "Chase Bank: Unauthorized transaction detected. Verify your identity immediately",
            "Wells Fargo: Your account is locked. Click here to unlock your account at wf-secure.com",
            "USPS: Your package delivery failed. Schedule redelivery at usps-package-track.ru",
            "FedEx: Your shipment requires action. Confirm address at fedex-deliver.cn to proceed",
            "DHL Express: Failed delivery notification. Reschedule at dhl-rescheduling.xyz",
            "Social Security Administration: Your SSN has been suspended due to suspicious activity",
            "Bank of America alert: your account requires immediate verification to avoid closure",
            "Citibank: fraudulent activity detected on your card ending in 4521. Verify now",
            "LinkedIn: Your account has been restricted. Verify your identity to restore access",

            # --- Spear-phish (no urgency keywords — bypasses naive filters) ---
            "Hi, could you review this document and send me your feedback? bit.ly/doc-final-review",
            "Per our earlier conversation, here is the contract. Please sign at: secure-docs.net/sign",
            "Following up — please confirm receipt of the wire transfer details I sent yesterday",
            "Can you log into the portal and approve the expense report? accounts-portal.ru",
            "Hey, I need you to pick up some Google Play gift cards for a client. Let me know",
            "The CEO needs this payment processed today. Here are the updated wire instructions",
            "Attached is the vendor agreement. Please DocuSign at docusign-secure.work to proceed",
            "We've updated our privacy policy. Review and accept at privacy-update.click",
            "Your subscription has been renewed for $299. To cancel visit: refund-billing.xyz",
            "Hi team, please complete the HR compliance survey by EOD: hr-survey.ml/compliance",

            # --- Leet-speak / obfuscation ---
            "C0ngratulati0ns! Y0ur Paypa1 acc0unt needs verific4ti0n urgently at paypa1.secure-update.com",
            "Y0ur Appl3 ID has b33n 1ocked. V3rify n0w at appl3-id.update.net",
            "Dear c1ient, your acc0unt has been comp1romised. C1ick here immediately",
            "AMAZ0N: unauth0rized 0rder detected. Conf1rm your identity at amaz0n-secure.ru",
            "MlCROSOFT: your 0ffice 365 Iicense expires t0day. Renew at microsof-Iicense.com",
            "PayPa1: Limited account alert — acti0n requ1red before suspension",
            "Secur1ty Alert from 0utlook: acc0unt acti0n needed at micro-auth.tk",

            # --- Prize / lottery scams ---
            "You've won $1,000,000! Click here to claim your prize at winner-claim.com",
            "CONGRATULATIONS: You are the selected winner of our $50,000 giveaway",
            "Your email was randomly selected for a $500 Amazon gift card. Claim now",
            "You have been chosen for a special reward. Click to claim your iPhone 15 now",
            "Lucky Winner! Your email qualifies for a cash prize of $10,000. Act fast",
            "Spin the wheel and claim your reward: prize-claim.xyz/spin",
            "You've been pre-approved for a $25,000 personal loan. Apply instantly",
            "Lotto International: Your ticket matches the jackpot. Claim $2.3M today",

            # --- Credential harvesting ---
            "Your email password is about to expire. Update your credentials to avoid lockout",
            "IT Help Desk: Confirm your webmail password at mail-update.company-portal.ru",
            "Your Microsoft 365 credentials require re-validation. Login at m365-verify.com",
            "Dropbox shared a file with you. Enter your password to view: dropbox-shared.tk",
            "DocuSign: To view the secure document please enter your credentials",
            "Google Drive: Someone shared a file. Sign in to access: gdrive-file.work",
            "Your Yahoo account password expires in 1 hour. Update it now to continue",
            "Webmail authentication required. Enter login credentials: mail-verify.xyz",

            # --- Malware delivery ---
            "Your invoice #INV-9823 is attached. Open the PDF to view payment details",
            "Please review the contract attached. It requires your signature by COB today",
            "New voicemail received. Open attached audio file to listen",
            "HR has sent you your annual performance review. Open attachment to view",
            "Scanned document from printer is attached. Please review and respond",
            "Your account statement for Q3 is ready. Download the attached file",
            "Order confirmation attached. Please open to verify your purchase details",

            # --- CEO / BEC fraud ---
            "This is urgent. I need you to purchase $500 in iTunes gift cards for a client",
            "Hi, it's the CEO. Please process this wire transfer to our new vendor account today",
            "I'm in a meeting. Can you handle an urgent wire for me? No calls, just email",
            "Confidential: we are completing an acquisition. Do not discuss. Wire $50,000 now",
            "The board has approved a special payment. Complete this transfer immediately",
            "Are you available right now? I need you to buy a few Apple gift cards for client gifts",
            "Quick favor while I'm tied up in meetings — can you pick up some gift cards and send the codes?",
            "Are you at your desk? Need you to process the payment to the new supplier ASAP, keep this confidential",
            "Hey, are you busy? I need you to purchase Amazon gift cards and email me the redemption codes",
            "Please buy three gift cards and scratch off the back, then send me photos. Do not tell anyone yet",

            # --- Fake account notifications ---
            "Your Venmo payment of $250 to unknown has been processed. Dispute at venmo-dispute.com",
            "Zelle transfer pending: $500 request from unknown. Approve at zelle-confirm.xyz",
            "Crypto wallet alert: unauthorized withdrawal of 0.5 BTC detected. Verify now",
            "Steam account: login from Russia detected. Secure your account now",
            "Your Spotify subscription is being cancelled. Reactivate at spotify-billing.ru",
            "Zoom account suspended: verify to restore meetings access at zoom-verify.net",
            "Your Instagram account will be permanently deleted. Confirm ownership now",
            "Twitter/X: unusual login activity. Verify your account to prevent suspension",
        ]

        seed_legit = [
            # --- Work communication ---
            "Meeting agenda for tomorrow's project sync at 2 PM in the main conference room",
            "Hey, are we still on for lunch this Friday? Let me know if you need to reschedule",
            "Quarterly report attached for your review. Please provide feedback before Monday",
            "Your GitHub PR #123 has been reviewed and approved. Great work on the refactor",
            "Reminder: submit your timesheet by Friday 5 PM for payroll processing",
            "Team outing this weekend — RSVP by Wednesday so we can confirm the reservation",
            "Can you join the 3 PM standup? We need to discuss the sprint priorities",
            "Here is the final version of the project proposal. Let me know your thoughts",
            "Heads up: the office will be closed on Monday for the holiday",
            "Your onboarding checklist is attached. Welcome to the team!",
            "Please review the attached draft contract and send any redlines by EOW",
            "Quick sync tomorrow at 10? I want to walk through the architecture diagram",
            "Your expense report for October has been approved and will be reimbursed Friday",
            "Hi team, reminder that the all-hands is at 4pm today in the auditorium",
            "The design files have been updated in Figma. Here's the link to the latest version",

            # --- Legit transactional / shipping ---
            "Your Amazon order has been shipped and will arrive by Thursday",
            "Your package has been delivered to your doorstep as of 2:34 PM today",
            "Order confirmation: your subscription renewal has been processed for $9.99/month",
            "Your flight booking confirmation for JFK→LAX on December 15 is attached",
            "Receipt for your Starbucks order: Grande latte $5.45 — paid with Visa ending 1234",
            "Your Uber ride receipt: $12.40 from Times Square to Penn Station",
            "Booking confirmed: Hilton Garden Inn Chicago Dec 20-23, 3 nights",
            "Your FedEx package has been picked up and is en route. Tracking: 7489273982",
            "Invoice #2024-009 from Acme Corp for consulting services in October",
            "Your DoorDash order from Chipotle has been picked up and is on the way",
            "Lyft: your weekly summary — 3 rides, $34.20 total",
            "Your annual membership renewed successfully for 59.00. Manage or cancel anytime in settings",
            "Subscription renewed: your yearly plan was charged 120.00 to the card on file. Thanks!",
            "Your reservation is confirmed: Austin to Denver on April 9, seat 22A, boarding group 3",
            "Trip confirmed: Amtrak Northeast Regional, Boston to New York, May 2, car 5 seat 31",
            "Your hotel stay is booked: Marriott Downtown, June 10-12, confirmation code 8ZQ4K",
            "Ticket confirmation: 2 seats for the Saturday 7 PM show, row M, will-call pickup",

            # --- Legit security/auth alerts (true positives for safe) ---
            "Your two-factor authentication code is 847291. It expires in 10 minutes",
            "Sign-in attempt detected on your Google account from your iPhone in New York. Was this you?",
            "New device sign-in: Chrome on Windows 11, San Francisco. If this wasn't you, review at accounts.google.com",
            "Your password expires in 14 days. Log in to your company portal at company.okta.com to update it",
            "We sent a password reset link to your email as requested. It expires in 1 hour",
            "Security audit report attached. Contains list of CVEs identified in the Q3 assessment",
            "GitHub Actions: workflow completed successfully on main branch",
            "Dependabot alert: critical vulnerability in lodash 4.17.15. Review and merge the PR",
            "Datadog alert: P3 — API latency spike on /api/users above 500ms threshold",
            "PagerDuty resolved: database connection pool exhausted (duration 4 min)",
            # Explicitly teaching the model what legit auth/alert emails look like
            "New login to your Apple ID from iPhone in New York. Was this you? If not, secure your account at apple.com",
            "Someone just signed into your Microsoft account from Windows 11. Was this you? If you did not make this, secure your account",
            "Your verification code is 382910. Don't share it with anyone. It expires in 5 minutes",
            "Your account password will expire in 3 days. Update it by visiting company.okta.com/account",
            "GitHub security alert: a high severity vulnerability was found in a dependency. View the pull request",

            # --- Newsletters / legit marketing ---
            "This week in tech: Apple announces M4 Ultra, OpenAI releases o3, Meta acquires startup",
            "Your weekly digest from Hacker News — top stories of the week",
            "Sale this weekend: 30% off all winter apparel at Patagonia.com",
            "New arrivals are here! Check out the latest Nike shoes",
            "Your Netflix watchlist has new additions based on your viewing history",
            "Spotify wrapped 2024 is here. See your year in music",
            "Black Friday deal: Upgrade your plan and save 40% — offer ends Sunday",
            "Your annual subscription to Adobe Creative Cloud renews on Jan 1 for $599",
            "New episode of your favorite podcast is now available",
            "Daily news briefing: markets, politics, and top stories for today",

            # --- Personal / casual ---
            "Mom's birthday is Saturday — can you coordinate the dinner reservation?",
            "Hey, loved your talk at the conference last week! Let's catch up soon",
            "Dentist appointment reminder: Thursday at 3 PM at Downtown Dental",
            "Your gym membership auto-renewed for $45 this month",
            "RSVP reminder: Sarah's wedding is in 3 weeks. Have you booked your hotel?",
            "New blog post: 10 productivity tips for remote engineers",
            "Congratulations on your work anniversary! 3 years at the company today",
            "Hi, just checking in — how is the project going? Any blockers?",
            "The quarterly book club selection is 'The Pragmatic Programmer'. See you Thursday!",
            "Your library book is due in 3 days. Renew at the library website or in person",
        ]

        # Header-bearing pump-fake pairs: identical alert text, opposite label,
        # separable ONLY by sender authentication. Teaches the classifier to
        # trust auth signals instead of the gameable "was this you?" phrase.
        header_examples = _auth_seed_examples()
        hdr_texts = [self._extract_text(ex) for ex, _ in header_examples]
        hdr_labels = [lbl for _, lbl in header_examples]

        string_texts = seed_phish + seed_legit
        string_labels = [1] * len(seed_phish) + [0] * len(seed_legit)

        texts = string_texts + hdr_texts
        labels = string_labels + hdr_labels
        # email_data aligned per-text (None for header-less plain seed strings)
        meta = [None] * len(string_texts) + [ex for ex, _ in header_examples]
        return texts, labels, meta

    def _cold_start_training(self):
        """Cold start: train the seed model, then expand vocabulary by
        bootstrapping from real ingestion JSON (conservative structural labels)."""
        texts, labels, meta = self._seed_corpus()

        # Build the model via the shared factory pipeline (see make_word_tfidf /
        # make_char_tfidf / make_classifier). Word TF-IDF captures phrases,
        # char TF-IDF catches leet-speak (paypa1), class_weight='balanced' stops
        # the model from predicting "safe" for everything on an imbalanced inbox.
        self.word_tfidf = make_word_tfidf()
        self.char_tfidf = make_char_tfidf()
        self.clf = make_classifier()
        self.platt = None

        X = build_feature_matrix(self.word_tfidf, self.char_tfidf, texts, meta, fit=True)
        self.clf.fit(X, labels)

        # Auto-bootstrap from ingestion JSON files if present
        extra = self._bootstrap_from_ingestion()

        self._save_model()

        # Report cold-start vocabulary stats
        total_vocab = len(self.word_tfidf.vocabulary_)
        logger.info(f"✅ Cold Start complete: {len(texts)} seed + {extra} ingestion examples "
                    f"| word vocab={total_vocab} | char vocab={len(self.char_tfidf.vocabulary_)}")

    def _bootstrap_from_ingestion(self) -> int:
        """
        Expand vocabulary using real inbox emails with conservative heuristic labels.

        LABELING STRATEGY — structural URL evidence only:
        - PHISH label: email contains a URL with a suspicious TLD (.ru, .tk, .xyz…)
          OR a known URL shortener (bit.ly, tinyurl…)
          → These are hard structural signals, not linguistic ones
        - SAFE label: all other real inbox emails (vast majority)

        WHY WE DON'T USE "URGENCY WORD COUNT" AS A LABEL:
        Real 2FA codes: "Your verification code expires in 10 minutes" has 2 urgency words
        Real IT alerts: "Your password expires in 3 days" has 2 urgency words
        Mislabeling those as phish teaches the model the wrong thing.
        Stick to URL-structure evidence which is highly precise.

        WHY THIS HELPS:
        - Your real inbox has diverse vocabulary: hundreds of legit subjects/bodies
        - Training on them expands TF-IDF vocab from ~300 → 3000+ words
        - The model learns what YOUR legitimate email looks like (reduces false positives)
        - Heuristic phish labels are high-precision/low-recall: we'd rather miss some
          phish in the bootstrap than poison the safe class
        """
        ingestion_dir = project_root / 'data' / 'ingestion'
        if not ingestion_dir.exists():
            return 0

        # Only use hard structural URL signals — never urgency word counts
        suspicious_tld_re = re.compile(
            r'(?:https?://|www\.|\b)[\w\-]*\.(?:' + '|'.join(_SUSPICIOUS_TLDS) + r')(?:[/\s?#]|$)',
            re.IGNORECASE
        )
        shortener_re = re.compile(
            r'(?:https?://)?(?:' + '|'.join(re.escape(s) for s in _URL_SHORTENERS) + r')/',
            re.IGNORECASE
        )
        # Known-safe domains: any URL from these → do not label as phish
        safe_domain_re = re.compile(
            r'(?:https?://)?(?:[\w\-]+\.)*(?:google|apple|microsoft|github|okta|slack|'
            r'amazon|linkedin|dropbox|paypal|twitter|instagram|facebook)\.com',
            re.IGNORECASE
        )

        extra_texts, extra_labels, extra_meta = [], [], []

        for fpath in sorted(ingestion_dir.glob('*.json'))[-20:]:
            try:
                records = json.loads(fpath.read_text())
                if not isinstance(records, list):
                    continue
                for rec in records:
                    if not isinstance(rec, dict):
                        continue
                    subject = str(rec.get('subject', ''))
                    body = str(rec.get('body', '') or rec.get('snippet', ''))
                    sender = str(rec.get('from', '') or rec.get('sender', ''))
                    full = f"{subject} {body} {sender}"[:2000]

                    # Hard-to-forge auth verdict from the email's own headers.
                    auth = _auth_signals(rec)

                    has_bad_url = (
                        bool(suspicious_tld_re.search(full)) or
                        bool(shortener_re.search(full))
                    )
                    has_safe_domain = bool(safe_domain_re.search(full))

                    # Label phish on structural URL evidence (no known-safe domain)
                    # OR on an explicit authentication failure — both are precise,
                    # attacker-resistant signals. DMARC-pass overrides URL noise.
                    if auth['auth_pass']:
                        label = 0
                    elif (has_bad_url and not has_safe_domain) or auth['auth_fail']:
                        label = 1
                    else:
                        label = 0

                    extra_texts.append(full)
                    extra_labels.append(label)
                    extra_meta.append(rec)
            except Exception:
                continue

        if not extra_texts:
            return 0

        X_word = self.word_tfidf.transform(extra_texts)
        X_char = self.char_tfidf.transform(extra_texts)
        X_url = csr_matrix(np.array(
            [_numeric_features(t, m) for t, m in zip(extra_texts, extra_meta)],
            dtype=np.float32))
        X = hstack([X_word, X_char, X_url])

        # SGD partial_fit with class_weight='balanced' requires both classes present
        # If ingestion data has no phish signals, skip to avoid ValueError
        unique = list(np.unique(extra_labels))
        if len(unique) == 2:
            self.clf.partial_fit(X, extra_labels, classes=[0, 1])
        else:
            # Only one class present — still useful for vocab but skip partial_fit
            logger.info("⚠️  Bootstrap: only one class in ingestion data, skipping partial_fit")

        phish_count = sum(extra_labels)
        logger.info(f"📂 Bootstrap: +{len(extra_texts)} ingestion emails "
                    f"({phish_count} structural-phish, {len(extra_texts)-phish_count} safe)")
        return len(extra_texts)

    # ------------------------------------------------------------------
    # Internal: combine all feature matrices for one email
    # ------------------------------------------------------------------
    def _transform(self, text: str, email_data=None):
        """
        Vectorize a single email into the combined feature matrix.

        FEATURE FUSION EXPLANATION:
        hstack([word_features, char_features, structural_features])

        word_features shape:       (1, 15000)  — TF-IDF word weights
        char_features shape:       (1, 10000)  — TF-IDF char-gram weights
        structural_features shape: (1, 26)     — URL heuristics + auth signals

        Combined:                  (1, 25026)  — everything the classifier sees

        email_data (optional) carries the raw headers so the authentication
        features (SPF/DKIM/DMARC/alignment) get populated. Without it, those
        features default to 0 (neutral) and only the text signals are used.

        SCIPY SPARSE MATRICES:
        Most TF-IDF values are 0, so sparse format stores only non-zeros —
        ~200 bytes instead of 200KB per email. Critical for throughput.
        """
        return build_feature_matrix(
            self.word_tfidf, self.char_tfidf, [text], [email_data])

    def _save_model(self):
        """Persist all three transformers + classifier to a single pickle."""
        try:
            with open(MODEL_PATH, 'wb') as f:
                import numpy as _np
                import sklearn as _sk
                import scipy as _sp
                pickle.dump({
                    'word_tfidf': self.word_tfidf,
                    'char_tfidf': self.char_tfidf,
                    'clf': self.clf,
                    'platt': self.platt,
                    'feature_version': NUM_STRUCTURAL_FEATURES,
                    # Stamp the training stack so train/serve skew is visible
                    # (reproducibility). The pinned image keeps these aligned.
                    'stack': {'sklearn': _sk.__version__, 'numpy': _np.__version__,
                              'scipy': _sp.__version__},
                }, f)
            logger.info(f"💾 Model saved to {MODEL_PATH}")
        except Exception as e:
            logger.error(f"Failed to save model: {e}")

    def _extract_text(self, email_data: dict) -> str:
        """Flatten email dict fields into one string for vectorization."""
        return extract_email_text(email_data)

    # ------------------------------------------------------------------
    # Public API (backward-compatible)
    # ------------------------------------------------------------------
    def predict(self, email_data: dict) -> tuple:
        """
        Predict if email is phishing.

        RETURNS: (prediction: int, confidence: float)
          prediction = 1 (phishing) or 0 (safe)
          confidence = probability [0.0 - 1.0] in the predicted class

        THRESHOLD GUIDE (unchanged from system config):
          > 0.85 → auto-quarantine
          0.70 - 0.85 → flag for review
          < 0.70 → pass through

        FAIL-SAFE: any exception returns (0, 0.0) → assume safe.
        Better to miss a phish than block all email on a bug.
        """
        if not self.clf:
            return (0, 0.0)
        # Delegate to the shared stateless predictor so calibration + feature
        # fusion logic lives in exactly one place.
        return predict_with(self._artifact, email_data)

    def learn_from_feedback(self, email_data: dict, is_phishing: bool):
        """
        Incremental online learning: update model from user feedback.

        HOW partial_fit WORKS HERE:
        1. Transform the email text using the ALREADY-FITTED TF-IDF transformers
           (vocab is fixed — unknown words in the feedback email are ignored)
        2. Call partial_fit on the SGDClassifier with ONE new labeled sample
        3. SGD performs ONE gradient step: weight += -lr * gradient
           with learning_rate ~0.01, so one example nudges the model slightly
        4. Save model to disk immediately

        WHY WE DON'T REFIT TF-IDF:
        - TF-IDF.fit() requires ALL training data (can't add one doc incrementally)
        - The vocabulary would change → classifier weights become invalid
        - Solution: keep vocab fixed, only update classifier weights
        - Trade-off: model won't learn brand-new attack terminology until next
          full retrain (wipe the .pkl file and restart)

        CONTINUOUS LEARNING VALUE:
        - Day 1: phisher uses "account health review" (not in seed data)
          → model misses it (unknown word tokens)
        - Day 2: user marks it phishing → partial_fit strengthens weights
          on all tokens that ARE in vocab: "account", "review", "health"
        - Day 3-N: similar emails with those shared tokens get blocked
        """
        text = self._extract_text(email_data)
        if not text or not self.clf:
            return
        label = 1 if is_phishing else 0

        # 1. DURABLE: append to the feedback buffer. The on-disk champion only
        #    changes when the Trainer folds this in AND the candidate passes the
        #    golden gate — so one bad label can never silently corrupt production.
        try:
            from training.feedback_buffer import FeedbackBuffer
            FeedbackBuffer(FEEDBACK_PATH).append(email_data, label, source="feedback")
        except Exception:
            try:
                from PhishGuard.phish_mlm.training.feedback_buffer import FeedbackBuffer
                FeedbackBuffer(FEEDBACK_PATH).append(email_data, label, source="feedback")
            except Exception as e:
                logger.warning(f"feedback buffer append failed: {e}")

        # 2. EPHEMERAL: one in-memory SGD step so the RUNNING process adapts
        #    immediately. Deliberately NOT persisted — a restart or the next
        #    gated retrain discards any transient poisoning.
        try:
            X = self._transform(text, email_data)
            self.clf.partial_fit(X, [label], classes=[0, 1])
            logger.info(f"🧠 Ephemeral update + buffered: "
                        f"{'PHISHING' if is_phishing else 'SAFE'} sample")
        except Exception as e:
            logger.error(f"Ephemeral update failed: {e}")

        if is_phishing:
            try:
                store_threat(
                    content=text,
                    threat_type='phishing',
                    sender=email_data.get('from', 'unknown'),
                    metadata={'feedback': 'user_reported', 'label': 1, 'confidence': 1.0}
                )
            except Exception as e:
                logger.warning(f"store_threat failed: {e}")


# Global singleton instance (shared across entire application)
detector = PhishingDetector()


if __name__ == "__main__":
    import sys

    # Delete stale model to force retrain when run directly
    if '--retrain' in sys.argv and MODEL_PATH.exists():
        MODEL_PATH.unlink()
        print("🗑  Deleted stale model — forcing Cold Start retrain")

    vocab = len(detector.word_tfidf.vocabulary_) if detector.word_tfidf else 0
    print(f"\n=== PhishGuard Model ===")
    print(f"Word vocab: {vocab} | Char vocab: "
          f"{len(detector.char_tfidf.vocabulary_) if detector.char_tfidf else 0} "
          f"| structural features: {NUM_STRUCTURAL_FEATURES}")

    # --- Pump-fake demo: identical "was this you?" text, opposite auth ---
    print("\n=== Pump-fake defense (same text, different sender auth) ===")
    phrase = ("New sign-in to your account from iPhone in New York. "
              "Was this you? If not, secure your account.")
    aligned = {
        'subject': 'Security alert', 'body': phrase, 'from': 'no-reply@google.com',
        'headers': {
            'authentication_results': ('mx; spf=pass smtp.mailfrom=google.com; '
                                       'dkim=pass header.d=google.com; dmarc=pass header.from=google.com'),
            'return_path': '<bounce@google.com>',
        },
    }
    spoofed = {
        'subject': 'Security alert', 'body': phrase, 'from': 'no-reply@google.com',
        'headers': {
            'authentication_results': ('mx; spf=fail smtp.mailfrom=evil-login.ru; '
                                       'dkim=fail header.d=evil-login.ru; dmarc=fail header.from=google.com'),
            'return_path': '<bounce@evil-login.ru>',
        },
    }
    p_safe, c_safe = detector.predict(aligned)
    p_phish, c_phish = detector.predict(spoofed)
    print(f"  auth PASS  → {'PHISH' if p_safe else 'SAFE '} ({c_safe:.0%})  (want SAFE)")
    print(f"  auth FAIL  → {'PHISH' if p_phish else 'SAFE '} ({c_phish:.0%})  (want PHISH)")

    # --- Full held-out golden evaluation (the real accuracy number) ---
    try:
        from eval.evaluate import run_golden_eval
    except Exception:
        sys.path.insert(0, str(Path(__file__).parent))
        try:
            from eval.evaluate import run_golden_eval
        except Exception as e:
            run_golden_eval = None
            print(f"\n(golden eval unavailable: {e})")
    if run_golden_eval:
        run_golden_eval(detector)
