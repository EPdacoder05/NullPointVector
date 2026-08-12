"""RLS helpers — unit-level (no DB required for policy shape)."""

from common.tenant_rls import POLICY_SUMMARY, _TABLE_POLICIES


def test_policy_sql_force_rls():
    assert "app.rls_bypass" in POLICY_SUMMARY["gucs"]
    assert "app.account_sub" in POLICY_SUMMARY["gucs"]
    names = {t[0] for t in _TABLE_POLICIES}
    assert names == {"user_mailboxes", "user_reports", "deck_accounts"}
    # Shared fleet intel must not be RLS'd in this module.
    assert "fleet_threat_keys" not in names
