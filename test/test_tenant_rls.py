"""RLS helpers — unit-level (no DB required for policy shape)."""

from common.tenant_rls import _POLICY_SQL, _TABLE_POLICIES


def test_policy_sql_force_rls():
    assert "FORCE ROW LEVEL SECURITY" in _POLICY_SQL
    assert "app.rls_bypass" in _POLICY_SQL
    assert "app.account_sub" in _POLICY_SQL
    names = {t[0] for t in _TABLE_POLICIES}
    assert names == {"user_mailboxes", "user_reports", "deck_accounts"}
    # Shared fleet intel must not be RLS'd in this module.
    assert "fleet_threat_keys" not in names
