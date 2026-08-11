"""Account delete smoke (no DB required for bad-account path)."""
from common.account_delete import delete_account_data


def test_delete_rejects_anon():
    out = delete_account_data("anon")
    assert out["ok"] is False
    assert out["error"] == "bad_account"


def test_delete_rejects_empty():
    out = delete_account_data("")
    assert out["ok"] is False
