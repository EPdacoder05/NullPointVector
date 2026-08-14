"""Account delete smoke (no DB required for bad-account path)."""
from common.account_delete import delete_account_data


def test_delete_rejects_anon():
    out = delete_account_data("anon")
    assert out["ok"] is False
    assert out["error"] == "bad_account"


def test_delete_rejects_empty():
    out = delete_account_data("")
    assert out["ok"] is False


def test_delete_rejects_anonymous_alias():
    out = delete_account_data("anonymous")
    assert out["ok"] is False
    assert out["error"] == "bad_account"


def test_redact_sender_keeps_domain_only():
    from common.account_delete import _redact_sender
    assert _redact_sender("alice@Evil.TEST") == "redacted@evil.test"
    assert _redact_sender("+15551234567").endswith("4567")
