"""User report reason mapping + payment spoof policy."""
from common.user_reports import REASON_MAP, check_fleet_promotion
from common.policy_pipeline import decide_override, extract_signals


def test_reason_map_codes():
    assert REASON_MAP["credential"] == "CREDENTIAL_PHISH"
    assert REASON_MAP["pressure"] == "URGENCY_PRESSURE"


def test_fleet_auto_promotion_is_off_by_default(monkeypatch):
    monkeypatch.delenv("ENABLE_FLEET_AUTO_PROMOTION", raising=False)
    monkeypatch.setenv("ENV", "development")
    result = check_fleet_promotion(None, sender_key="example.test", channel="email")
    assert result["status"] == "disabled"


def test_fleet_auto_promotion_cannot_be_enabled_in_production(monkeypatch):
    monkeypatch.setenv("ENABLE_FLEET_AUTO_PROMOTION", "true")
    monkeypatch.setenv("ENV", "production")
    result = check_fleet_promotion(None, sender_key="example.test", channel="email")
    assert result["status"] == "disabled"


def test_paypal_payment_without_paypal_domain():
    email = {
        "from": "Billing <noreply@random-invoice.biz>",
        "subject": "Invoice overdue — pay via PayPal",
        "body": (
            "Your account will be locked out. Send PayPal payment now to unlock. "
            "https://random-invoice.biz/pay"
        ),
        "headers": {"Authentication-Results": "mx; spf=pass; dkim=pass; dmarc=pass"},
    }
    sig = extract_signals(email)
    assert sig["hard_malice"] is True
    out = decide_override(email)
    assert out and out[0] == 1 and out[1] >= 0.9


def test_real_paypal_domain_not_spoof_lure():
    email = {
        "from": "PayPal <service@paypal.com>",
        "subject": "You sent a payment",
        "body": "PayPal payment confirmation https://www.paypal.com/myaccount",
        "headers": {
            "Authentication-Results": (
                "mx; spf=pass smtp.mailfrom=paypal.com; "
                "dkim=pass header.d=paypal.com; dmarc=pass"
            ),
        },
    }
    sig = extract_signals(email)
    # Brand + paypal.com origin → not payment-brand spoof
    assert sig["hard_malice"] is False or sig["known_good"] is True
