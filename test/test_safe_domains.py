"""Auth-gated known-good allowlist — must not short-circuit spoofed brand From."""
from common.safe_domains import is_known_good_sender, domain_is_known_good


def test_domain_match_alone_is_not_enough():
    assert domain_is_known_good("security@apple.com")[0] is True
    # No headers → must NOT short-circuit (pump_fake without AR)
    assert is_known_good_sender("security@apple.com")[0] is False
    assert is_known_good_sender("security@apple.com", {"from": "security@apple.com"})[0] is False


def test_auth_fail_blocks_allowlist():
    email = {
        "from": "appleid@apple.com",
        "subject": "Security alert",
        "body": "Was this you?",
        "headers": {
            "authentication_results": (
                "mx; spf=fail smtp.mailfrom=icloud-secure.ru; "
                "dkim=fail header.d=icloud-secure.ru; dmarc=fail header.from=apple.com"
            ),
            "return_path": "<bounce@icloud-secure.ru>",
        },
    }
    assert is_known_good_sender(email["from"], email)[0] is False


def test_auth_pass_allows_short_circuit():
    email = {
        "from": "no-reply@google.com",
        "subject": "New sign-in",
        "body": "Was this you?",
        "headers": {
            "authentication_results": (
                "mx; spf=pass smtp.mailfrom=google.com; "
                "dkim=pass header.d=google.com; dmarc=pass header.from=google.com"
            ),
            "return_path": "<bounce@google.com>",
        },
    }
    ok, reason = is_known_good_sender(email["from"], email)
    assert ok is True
    assert "auth_pass" in reason


def test_capitalone_spoof_without_auth_hits_ml_path():
    """Every known-good domain — Cap1 included — needs auth_pass."""
    assert domain_is_known_good(
        "capitalone@notification.capitalone.com"
    )[0] is True
    spoof = {
        "from": '"Capital One" <capitalone@notification.capitalone.com>',
        "subject": "Your credit score has changed",
        "body": "Sign in now",
        "headers": {
            "authentication_results": (
                "mx; spf=fail smtp.mailfrom=evil.ru; "
                "dkim=fail header.d=evil.ru; dmarc=fail header.from=capitalone.com"
            ),
        },
    }
    assert is_known_good_sender(spoof["from"], spoof)[0] is False
    from common.policy_pipeline import decide_override
    # Must NOT return known-good safe override
    out = decide_override(spoof)
    assert out is None or out[0] == 1


def test_ingest_fingerprint_stable():
    from common.ingest_dedup import ingest_fingerprint
    a = ingest_fingerprint(
        sender="a@vertiv.com", subject="RE: Interview", body="Hi",
        date_raw="Mon, 10 Aug 2026 09:22:00 -0400",
        rfc_message_id="<abc@vertiv.com>",
    )
    b = ingest_fingerprint(
        sender="a@vertiv.com", subject="RE: Interview", body="Hi",
        date_raw="Mon, 10 Aug 2026 09:22:00 -0400",
        rfc_message_id="<ABC@vertiv.com>",
    )
    assert a == b
    assert len(a) == 64


def test_ups_not_matched_inside_upstream():
    from common.explain import analyze_findings
    findings = analyze_findings(
        "phishing",
        "Run failed: litellm Upstream Sync (BerriAI) - main",
        sender='"EPdacoder05" <notifications@github.com>',
    )
    codes = {f["code"] for f in findings}
    assert "IMPERSONATION" not in codes
    assert "DISPLAY_NAME_SPOOF" not in codes


def test_bare_microsoft_mention_is_not_impersonation():
    from common.explain import analyze_findings
    findings = analyze_findings(
        "phishing",
        "Build used the microsoft graph SDK successfully.",
        sender="ci@example.com",
    )
    codes = {f["code"] for f in findings}
    assert "IMPERSONATION" not in codes
