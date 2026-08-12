"""Signup validation — no DB required."""
import os

from common.accounts import normalize_email, signup_open, valid_email


def test_normalize_email():
    assert normalize_email("  Ellis@Example.COM ") == "ellis@example.com"


def test_valid_email():
    assert valid_email("friend@example.com") is True
    assert valid_email("nope") is False
    assert valid_email("") is False
    assert valid_email("a@b.c") is False


def test_signup_closed_by_default(monkeypatch):
    monkeypatch.delenv("SIGNUP_OPEN", raising=False)
    assert signup_open() is False
    monkeypatch.setenv("SIGNUP_OPEN", "true")
    assert signup_open() is True
    monkeypatch.setenv("SIGNUP_OPEN", "false")
    assert signup_open() is False


def test_register_closed(monkeypatch):
    monkeypatch.setenv("SIGNUP_OPEN", "false")
    from common.accounts import register
    out = register("friend@example.com", "longenoughpassword")
    assert out["ok"] is False
    assert out["error"] == "signup_closed"


def test_register_bad_email(monkeypatch):
    monkeypatch.setenv("SIGNUP_OPEN", "true")
    from common.accounts import register
    out = register("not-an-email", "longenoughpassword")
    assert out["ok"] is False
    assert out["error"] == "bad_email"


def test_register_short_password(monkeypatch):
    monkeypatch.setenv("SIGNUP_OPEN", "true")
    from common.accounts import register
    out = register("friend@example.com", "short")
    assert out["ok"] is False
    assert out["error"] == "short_password"
