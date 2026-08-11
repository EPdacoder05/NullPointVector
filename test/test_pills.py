"""Pill builder: short labels + dedupe mood vs evidence."""
from common.pills import build_pills, strip_preview


def test_strip_preview_kills_html():
    raw = '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"><body>Hello&#847; world</body>'
    out = strip_preview(raw, limit=80)
    assert "<" not in out
    assert "DOCTYPE" not in out
    assert "Hello" in out


def test_build_pills_dedupes_happy_lure():
    pack = build_pills(
        channel="phishing",
        subject="Congratulations you won a prize",
        body="Claim your gift card now unsubscribe",
        sender="promo@list.example",
    )
    codes = [t["code"] for t in pack["tags"]] + [t["code"] for t in pack["reason_codes"]]
    assert codes.count("HAPPY_LURE") <= 1


def test_pill_labels_are_short():
    pack = build_pills(
        channel="phishing",
        subject="Verify account",
        body='From spoof <a href="https://evil.example/x">click</a>',
        sender='"PayPal" <help@evil.example>',
    )
    for t in pack["tags"] + pack["reason_codes"]:
        assert len(t["label"]) <= 28, t
