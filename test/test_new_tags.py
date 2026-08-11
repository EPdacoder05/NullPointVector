"""New evidence tags + lookalike domain."""
from common.explain import analyze_findings, REASON_CODES
from common.lookalike import lookalike_brand_domain
from common.message_tags import categorize_message


def test_new_reason_codes_registered():
    for code in (
        "REPLY_TO_MISMATCH", "ADVANCE_FEE", "ATTACHMENT_RISK", "IMAGE_ONLY",
        "LOOKALIKE_DOMAIN", "TOLL_FREE_CALLBACK", "NEIGHBOR_SPOOF", "CAMPAIGN_MATCH",
    ):
        assert code in REASON_CODES


def test_lookalike_paypa1():
    hit = lookalike_brand_domain("billing@paypa1.com")
    assert hit is not None
    assert hit[0] == "paypal"
    assert lookalike_brand_domain("service@paypal.com") is None


def test_reply_to_mismatch():
    findings = analyze_findings(
        "phishing",
        "Please reply ASAP",
        '"Support" <help@evil-brand.biz>',
        headers={"Reply-To": "collector@totally-different.net"},
    )
    codes = {f["code"] for f in findings}
    assert "REPLY_TO_MISMATCH" in codes


def test_advance_fee():
    findings = analyze_findings(
        "phishing",
        "Pay a small fee to unlock your funds and claim your inheritance",
        "notary@scam.example",
    )
    assert any(f["code"] == "ADVANCE_FEE" for f in findings)
    tags = categorize_message(
        subject="Inheritance",
        body="Pay a small fee to unlock your funds",
        sender="x@scam.example",
    )
    assert any(t["code"] == "ADVANCE_FEE" for t in tags)


def test_attachment_risk():
    findings = analyze_findings(
        "phishing",
        "See invoice attached invoice_final.exe",
        "ap@vendor.example",
    )
    assert any(f["code"] == "ATTACHMENT_RISK" for f in findings)


def test_image_only():
    findings = analyze_findings(
        "phishing",
        '<html><body><img src="cid:abc" width="600"><img src="https://x/a.png"></body></html>',
        "news@list.example",
    )
    assert any(f["code"] == "IMAGE_ONLY" for f in findings)


def test_toll_free_callback():
    findings = analyze_findings(
        "vishing",
        "Call us back at 1-888-555-0199 immediately about your account",
        "+18885550199",
    )
    codes = {f["code"] for f in findings}
    assert "TOLL_FREE_CALLBACK" in codes
    assert "CALLBACK_PRESSURE" in codes


def test_campaign_match_pack():
    findings = analyze_findings(
        "vishing",
        "Tax relief — call now",
        "+18456304255",
    )
    assert any(f["code"] == "CAMPAIGN_MATCH" for f in findings)


def test_neighbor_spoof():
    findings = analyze_findings(
        "vishing",
        "This is your bank",
        "+12125550123",
        headers={"user_area_code": "212"},
    )
    assert any(f["code"] == "NEIGHBOR_SPOOF" for f in findings)