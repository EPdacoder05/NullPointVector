"""Tenant-isolation foundation — unit-level, with no external DB or secrets."""

import sys
import types

import pytest

from common.tenant_rls import (
    POLICY_SUMMARY,
    TenantContextError,
    _TABLE_POLICIES,
    require_account_sub,
    set_tenant,
)


def test_policy_sql_force_rls():
    assert "app.rls_bypass" in POLICY_SUMMARY["gucs"]
    assert "app.account_sub" in POLICY_SUMMARY["gucs"]
    names = {t[0] for t in _TABLE_POLICIES}
    assert names == {
        "user_mailboxes",
        "user_reports",
        "deck_accounts",
        "messages",
        "provider_action_queue",
        "safe_senders",
    }
    # Shared fleet intel must not be RLS'd in this module.
    assert "fleet_threat_keys" not in names


@pytest.mark.parametrize("value", [None, "", "  ", "anon", "anonymous", "public", "*"])
def test_placeholder_tenants_are_rejected(value):
    with pytest.raises(TenantContextError):
        require_account_sub(value)


def test_tenant_context_is_explicit_and_bypass_is_distinct():
    class Cursor:
        def __init__(self):
            self.calls = []

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def execute(self, sql, params=None):
            self.calls.append((" ".join(sql.split()), params))

    class Conn:
        def __init__(self):
            self.cur = Cursor()

        def cursor(self):
            return self.cur

    tenant_conn = Conn()
    set_tenant(tenant_conn, "tenant-alpha")
    assert any(call[1] == ("tenant-alpha",) for call in tenant_conn.cur.calls)
    assert any("app.rls_bypass', '0'" in call[0] for call in tenant_conn.cur.calls)

    admin_conn = Conn()
    set_tenant(admin_conn, bypass=True)
    assert not any(call[1] for call in admin_conn.cur.calls)
    assert any("app.rls_bypass', '1'" in call[0] for call in admin_conn.cur.calls)


def test_mailbox_dedup_queries_never_cross_tenants(monkeypatch):
    from common.ingest_dedup import already_ingested

    class Cursor:
        def __init__(self):
            self.calls = []

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def execute(self, sql, params=None):
            self.calls.append((" ".join(sql.split()), params))

        def fetchone(self):
            return None

    class Conn:
        def __init__(self):
            self.cur = Cursor()

        def cursor(self):
            return self.cur

    bound = []
    monkeypatch.setattr(
        "common.tenant_rls.set_tenant",
        lambda _conn, sub, **_kwargs: bound.append(sub),
    )
    alpha = Conn()
    beta = Conn()
    common = dict(
        provider="gmail",
        provider_uid="42",
        uidvalidity="7",
        folder="INBOX",
        rfc_message_id="same@example.test",
        ingest_fp="same-fingerprint",
    )

    already_ingested(alpha, account_sub="tenant-alpha", mailbox_id=11, **common)
    already_ingested(beta, account_sub="tenant-beta", mailbox_id=22, **common)

    assert bound == ["tenant-alpha", "tenant-beta"]
    assert all(call[1][0:2] == ("tenant-alpha", 11) for call in alpha.cur.calls)
    assert all(call[1][0:2] == ("tenant-beta", 22) for call in beta.cur.calls)
    assert alpha.cur.calls[0][1] != beta.cur.calls[0][1]


def test_tenantless_dedup_fails_before_query(monkeypatch):
    from common.ingest_dedup import already_ingested

    class NoQueryConn:
        def cursor(self):
            raise AssertionError("tenantless dedup must not query")

    with pytest.raises(TenantContextError):
        already_ingested(
            NoQueryConn(),
            account_sub="",
            mailbox_id=1,
            provider="gmail",
            provider_uid="1",
        )


def test_customer_reputation_excludes_raw_cross_tenant_history(monkeypatch):
    from common.reputation.providers import (
        LocalThreatDBProvider,
        default_providers,
    )

    assert all(not isinstance(provider, LocalThreatDBProvider)
               for provider in default_providers())

    calls = []
    module = types.ModuleType("Autobot.VectorDB.NullPoint_Vector")
    module.get_threats_by_sender = (
        lambda *args, **kwargs: calls.append((args, kwargs)) or []
    )
    monkeypatch.setitem(sys.modules, "Autobot.VectorDB.NullPoint_Vector", module)

    assert LocalThreatDBProvider().lookup("+15551234567") is None
    assert calls == []
    LocalThreatDBProvider(fleet_admin=True).lookup("+15551234567")
    assert calls[0][1] == {"limit": 50, "bypass": True}


def test_model_prediction_can_label_but_cannot_block_directory():
    from common.reputation.base import directory_action_for_message

    assert directory_action_for_message({
        "action": "block",
        "risk_score": 0.99,
        "label_source": "model_prediction",
        "verdict": "tax scam",
    }) == ("label", "Tax Scam")

    assert directory_action_for_message(
        {"label_source": "human_grade"}, human_label=1,
    )[0] == "block"
    assert directory_action_for_message({
        "action": "block",
        "risk_score": 0.9,
        "label_source": "vendor_verified",
    })[0] == "block"
    assert directory_action_for_message({"risk_score": 0.1})[0] == "none"


def test_fetch_contract_preserves_exact_mailbox_identity():
    from PhishGuard.providers.email_fetcher.base_fetcher import EmailFetcher

    class Fetcher(EmailFetcher):
        def connect(self):
            return True

        def disconnect(self):
            return None

        def fetch_emails(self, folder="INBOX", limit=100):
            return []

        def move_to_junk(self, email_id, *, folder="INBOX", uidvalidity=""):
            return True

    processed = Fetcher().process_email({
        "id": "91",
        "provider_uid": "91",
        "uidvalidity": "1234",
        "account_sub": "tenant-alpha",
        "mailbox_id": 7,
        "folder": "INBOX",
        "from": "sender@example.test",
        "body": "message",
        "headers": {},
    })

    assert {
        key: processed[key]
        for key in ("account_sub", "mailbox_id", "provider_uid", "uidvalidity", "folder")
    } == {
        "account_sub": "tenant-alpha",
        "mailbox_id": 7,
        "provider_uid": "91",
        "uidvalidity": "1234",
        "folder": "INBOX",
    }


def test_provider_action_lookup_is_owner_scoped(monkeypatch):
    from common.mail_actions import _ids_with_imap

    class Cursor:
        def __init__(self):
            self.params = None

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def execute(self, _sql, params=None):
            self.params = params

        def fetchall(self):
            if self.params and self.params[0] == "tenant-alpha":
                return [(101, 7, "gmail", "91", "1234", "INBOX")]
            return []

    class Conn:
        def __init__(self):
            self.cur = Cursor()

        def cursor(self):
            return self.cur

    conns = []
    module = types.ModuleType("Autobot.VectorDB.NullPoint_Vector")
    module.get_conn = lambda: conns.append(Conn()) or conns[-1]
    module.release_conn = lambda _conn: None
    monkeypatch.setitem(sys.modules, "Autobot.VectorDB.NullPoint_Vector", module)
    bound = []
    monkeypatch.setattr(
        "common.tenant_rls.set_tenant",
        lambda _conn, sub, **_kwargs: bound.append(sub),
    )

    alpha = _ids_with_imap([101], account_sub="tenant-alpha")
    beta = _ids_with_imap([101], account_sub="tenant-beta")

    assert [item["mailbox_id"] for item in alpha] == [7]
    assert beta == []
    assert bound == ["tenant-alpha", "tenant-beta"]
    assert conns[0].cur.params == ("tenant-alpha", [101])
    assert conns[1].cur.params == ("tenant-beta", [101])


def test_provider_queue_refuses_tenantless_mutation():
    from common.provider_sync import enqueue_provider_moves

    assert enqueue_provider_moves([1], account_sub="") == {
        "queued": 0,
        "skipped": 0,
        "error": "tenant_required",
    }


def test_exact_safe_sender_does_not_allow_the_entire_domain():
    from utils.safe_sender_manager import SafeSenderManager

    rows = [{
        "account_sub": "tenant-alpha",
        "domain": "example.test",
        "sender_pattern": "trusted@example.test",
        "match_type": "exact",
        "reason": "human grade",
    }]

    class Cursor:
        def __init__(self):
            self.result = None

        def execute(self, sql, params=None):
            compact = " ".join(sql.split())
            tenant, value = params
            candidates = [row for row in rows if row["account_sub"] == tenant]
            if "match_type = 'exact'" in compact:
                candidates = [row for row in candidates
                              if row["match_type"] == "exact"
                              and row["sender_pattern"] == value]
            elif "match_type = 'pattern'" in compact:
                candidates = []
            elif "match_type = 'domain'" in compact:
                candidates = [row for row in candidates
                              if row["match_type"] == "domain"
                              and row["domain"] == value]
            self.result = (candidates[0]["reason"],) if candidates else None

        def fetchone(self):
            return self.result

    class Conn:
        def cursor(self):
            return Cursor()

    manager = object.__new__(SafeSenderManager)
    manager.conn = Conn()
    manager.account_sub = "tenant-alpha"

    assert manager.is_safe_sender("trusted@example.test") == (True, "human grade")
    assert manager.is_safe_sender("attacker@example.test") == (False, None)


@pytest.mark.parametrize(
    "value,expected_type",
    [
        ("trusted@example.test", "exact"),
        ("%@example.test", "pattern"),
        ("example.test", "domain"),
    ],
)
def test_safe_sender_scope_must_be_explicit(value, expected_type):
    from utils.safe_sender_manager import SafeSenderManager

    class Cursor:
        def __init__(self):
            self.params = None

        def execute(self, _sql, params=None):
            self.params = params

    class Conn:
        def __init__(self):
            self.cur = Cursor()

        def cursor(self):
            return self.cur

        def commit(self):
            return None

        def rollback(self):
            raise AssertionError("valid safe sender should not roll back")

    manager = object.__new__(SafeSenderManager)
    manager.conn = Conn()
    manager.account_sub = "tenant-alpha"

    assert manager.add_safe_sender(value)
    assert manager.conn.cur.params[3] == expected_type
