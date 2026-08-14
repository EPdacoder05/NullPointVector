"""Signup and web-auth perimeter validation — no DB required."""

from pathlib import Path

import pytest

from common.accounts import normalize_email, signup_open, valid_email


_DEPLOY_MARKERS = (
    "FLY_APP_NAME", "RAILWAY_ENVIRONMENT", "RENDER_SERVICE_ID",
    "K_SERVICE", "DYNO",
)


@pytest.fixture(autouse=True)
def _local_runtime(monkeypatch):
    """Keep unit tests deterministic on a developer or managed CI host."""
    monkeypatch.setenv("ENV", "development")
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://localhost:8000")
    for name in _DEPLOY_MARKERS:
        monkeypatch.delenv(name, raising=False)


def test_normalize_email():
    assert normalize_email("  Ellis@Example.COM ") == "ellis@example.com"


def test_valid_email():
    assert valid_email("friend@example.com") is True
    assert valid_email("nope") is False
    assert valid_email("") is False
    assert valid_email("a@b.c") is False
    # Apple Hide My Email (iCloud Private Relay) — required for iOS pilot.
    assert valid_email("abc123@privaterelay.appleid.com") is True
    assert valid_email("abc123@private.icloud.com") is True


def test_signup_closed_by_default(monkeypatch):
    monkeypatch.delenv("SIGNUP_OPEN", raising=False)
    assert signup_open() is False
    monkeypatch.setenv("SIGNUP_OPEN", "true")
    assert signup_open() is True
    monkeypatch.setenv("SIGNUP_OPEN", "false")
    assert signup_open() is False


def test_public_signup_fails_closed_without_verified_account_state(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("SIGNUP_OPEN", "true")
    monkeypatch.setenv("EMAIL_VERIFICATION_ENABLED", "true")

    assert signup_open() is False


def test_register_closed(monkeypatch):
    monkeypatch.setenv("SIGNUP_OPEN", "false")
    from common.accounts import register
    out = register("friend@example.com", "longenoughpassword")
    assert out["ok"] is False
    assert out["error"] == "signup_closed"


def test_register_disposable(monkeypatch):
    monkeypatch.setenv("SIGNUP_OPEN", "true")
    from common.accounts import register
    out = register("foo@mailinator.com", "longenoughpassword")
    assert out["ok"] is False
    assert out["error"] == "disposable"


def test_register_bad_email(monkeypatch):
    monkeypatch.setenv("SIGNUP_OPEN", "true")
    from common.accounts import register
    out = register("not-an-email", "longenoughpassword")
    assert out["ok"] is False
    assert out["error"] == "bad_email"


def test_apple_relay_not_disposable():
    from common.disposable_domains import is_disposable_email
    assert is_disposable_email("abc123@privaterelay.appleid.com") is False
    assert is_disposable_email("abc123@private.icloud.com") is False
    assert is_disposable_email("x@instaddr.ch") is True
    assert is_disposable_email("x@yopmail.com") is True


def test_billing_is_fail_closed_until_explicitly_enabled(monkeypatch):
    monkeypatch.delenv("BILLING_ENABLED", raising=False)
    monkeypatch.setenv("BILLING_MOCK", "true")
    from common.billing import start_checkout, verify_and_entitle

    checkout = start_checkout(
        plan_slug="pro",
        interval="monthly",
        email="friend@example.com",
        account_sub="friend@example.com",
        base_url="https://example.test",
        client_ip="192.0.2.10",
        user_agent="test",
        fingerprint="test-device",
        want_trial=False,
    )
    assert checkout == {"ok": False, "error": "billing_disabled"}
    assert verify_and_entitle(
        session_id="local_attacker_chosen",
        account_sub="friend@example.com",
    ) == {"ok": False, "error": "billing_disabled"}


def test_production_never_uses_mock_billing(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("BILLING_MOCK", "true")
    from common.billing import use_mock

    assert use_mock() is False


def test_public_host_never_uses_mock_billing_when_env_was_omitted(monkeypatch):
    monkeypatch.setenv("ENV", "development")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://nullpoint.example")
    monkeypatch.setenv("BILLING_MOCK", "true")
    from common.billing import use_mock

    assert use_mock() is False


def test_register_short_password(monkeypatch):
    monkeypatch.setenv("SIGNUP_OPEN", "true")
    from common.accounts import register
    out = register("friend@example.com", "short")
    assert out["ok"] is False
    assert out["error"] == "short_password"


def test_reserved_blocks_local_part(monkeypatch):
    monkeypatch.setenv("SIGNUP_OPEN", "true")
    monkeypatch.setenv("API_ADMIN_USER", "admin")
    from common.accounts import register
    out = register("admin@example.com", "longenoughpassword")
    assert out["ok"] is False
    assert out["error"] == "reserved"


def test_safe_redirect_rejects_external():
    from web.ui import _safe_app_redirect_target
    assert _safe_app_redirect_target("https://evil.test/phish") == "/app/dashboard"
    assert _safe_app_redirect_target("//evil.test") == "/app/dashboard"
    assert _safe_app_redirect_target("/application") == "/app/dashboard"
    assert _safe_app_redirect_target("/app/connectors") == "/app/connectors"


def _perimeter_client(monkeypatch):
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient

    from common import auth as auth_module
    from web.ui import ConsoleSecurityMiddleware

    def _verify(token, expected_type="access"):
        if token == "valid-session" and expected_type == "access":
            return {"sub": "alice@example.test", "role": "customer", "type": "access"}
        return None

    monkeypatch.setattr(auth_module, "verify_token", _verify)
    app = FastAPI()
    app.add_middleware(ConsoleSecurityMiddleware)

    @app.get("/app/dashboard")
    async def dashboard():
        return {"ok": True}

    @app.get("/app/privacy")
    async def privacy():
        return {"ok": True}

    @app.post("/app/mutate")
    async def mutate(request: Request):
        form = await request.form()
        return JSONResponse({"value": form.get("value")})

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    return TestClient(app, follow_redirects=False)


def test_console_perimeter_is_deny_by_default(monkeypatch):
    client = _perimeter_client(monkeypatch)

    redirect = client.get("/app/dashboard", headers={"Accept": "text/html"})
    assert redirect.status_code == 303
    assert redirect.headers["location"].startswith("/app/login?next=")
    denied_json = client.get(
        "/app/quarantine/siblings", headers={"Accept": "application/json"},
    )
    assert denied_json.status_code == 401
    assert denied_json.json() == {"ok": False, "error": "login_required"}
    assert client.get("/app/privacy").status_code == 200
    assert client.get("/health").status_code == 200


def test_cookie_mutation_requires_same_origin_and_csrf(monkeypatch):
    from common.auth import csrf_token_for_session

    client = _perimeter_client(monkeypatch)
    client.cookies.set("np_access", "valid-session")
    token = csrf_token_for_session("valid-session")

    no_origin = client.post(
        "/app/mutate", data={"value": "kept", "_csrf": token},
    )
    assert no_origin.status_code == 403
    assert no_origin.json()["error"] == "origin_blocked"

    cross_origin = client.post(
        "/app/mutate",
        data={"value": "kept", "_csrf": token},
        headers={"Origin": "https://attacker.example"},
    )
    assert cross_origin.status_code == 403
    assert cross_origin.json()["error"] == "origin_blocked"

    missing_token = client.post(
        "/app/mutate", data={"value": "kept"},
        headers={"Origin": "http://testserver"},
    )
    assert missing_token.status_code == 403
    assert missing_token.json()["error"] == "csrf_failed"

    accepted = client.post(
        "/app/mutate",
        data={"value": "body-survives", "_csrf": token},
        headers={"Origin": "http://testserver"},
    )
    assert accepted.status_code == 200
    assert accepted.json() == {"value": "body-survives"}


def test_public_form_rejects_supplied_cross_origin_source(monkeypatch):
    client = _perimeter_client(monkeypatch)
    response = client.post(
        "/app/login", data={"username": "a", "password": "b"},
        headers={"Origin": "https://attacker.example"},
    )
    assert response.status_code == 403
    assert response.json()["error"] == "origin_blocked"


def test_funnel_https_origin_allowed_when_proxy_scheme_is_http(monkeypatch):
    """Tailscale Funnel: browser Origin is https://*.ts.net; nginx may forward http."""
    from starlette.requests import Request
    from web.ui import _is_same_origin

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/app/login",
        "raw_path": b"/app/login",
        "query_string": b"",
        "headers": [
            (b"host", b"pilot.tail123.ts.net"),
            (b"origin", b"https://pilot.tail123.ts.net"),
            (b"x-forwarded-proto", b"http"),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    monkeypatch.delenv("PUBLIC_BASE_URL", raising=False)
    monkeypatch.delenv("API_ALLOWED_ORIGINS", raising=False)
    monkeypatch.setenv("ENV", "development")
    request = Request(scope, _receive)
    assert _is_same_origin(request) is True


def test_local_origin_allowed_when_proxy_strips_host_port(monkeypatch):
    """nginx $host drops :8088; browser Origin keeps it."""
    from starlette.requests import Request
    from web.ui import _is_same_origin

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/app/login",
        "raw_path": b"/app/login",
        "query_string": b"",
        "headers": [
            (b"host", b"127.0.0.1"),
            (b"origin", b"http://127.0.0.1:8088"),
            (b"x-forwarded-proto", b"http"),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    monkeypatch.delenv("PUBLIC_BASE_URL", raising=False)
    monkeypatch.delenv("API_ALLOWED_ORIGINS", raising=False)
    monkeypatch.setenv("ENV", "development")
    request = Request(scope, _receive)
    assert _is_same_origin(request) is True


def test_production_config_detects_public_host_and_fallback_secrets(monkeypatch):
    from common.config import is_production_environment, validate_production_config

    monkeypatch.setenv("ENV", "development")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://app.example.test")
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    monkeypatch.delenv("API_ADMIN_PASSWORD_HASH", raising=False)
    monkeypatch.setenv("API_ADMIN_PASSWORD", "changeme")
    monkeypatch.setenv("SIGNUP_OPEN", "false")

    assert is_production_environment() is True
    with pytest.raises(RuntimeError, match="Production config invalid"):
        validate_production_config()

    monkeypatch.setenv("PUBLIC_BASE_URL", "app.example.test")
    assert is_production_environment() is True


def test_canonical_authenticated_subject(monkeypatch):
    from fastapi import HTTPException
    from common import auth as auth_module

    monkeypatch.setattr(
        auth_module, "verify_token",
        lambda token, expected_type="access": {"sub": " alice@example.test ", "role": "analyst"},
    )
    user = auth_module.get_current_user("session")
    assert user == {
        "sub": "alice@example.test",
        "user_id": "alice@example.test",
        "role": "analyst",
    }

    monkeypatch.setattr(
        auth_module, "verify_token",
        lambda token, expected_type="access": {"sub": "   ", "role": "admin"},
    )
    with pytest.raises(HTTPException) as exc:
        auth_module.get_current_user("session")
    assert exc.value.status_code == 401


def test_logout_is_post_only_and_feedback_has_trusted_source():
    from web.ui import router

    logout_routes = [route for route in router.routes if route.path == "/app/logout"]
    assert len(logout_routes) == 1
    assert logout_routes[0].methods == {"POST"}

    api_source = (Path(__file__).parent.parent / "api" / "main.py").read_text()
    assert 'source="api-analyst-feedback"' in api_source
    assert '"by": user["sub"]' in api_source


def _bare_request(path="/app/connectors", *, headers=None):
    from starlette.requests import Request

    raw_headers = [
        (str(key).lower().encode(), str(value).encode())
        for key, value in (headers or {}).items()
    ]
    return Request({
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": raw_headers,
        "client": ("127.0.0.1", 1234),
        "server": ("testserver", 80),
    })


def test_connector_page_does_not_render_process_global_account(monkeypatch):
    import asyncio

    import common.mailbox_store as mailbox_store
    import common.oauth_email as oauth_email
    import web.ui as ui

    monkeypatch.setattr(
        ui, "_current_user",
        lambda request: {"sub": "alice@example.test", "role": "customer"},
    )
    monkeypatch.setattr(mailbox_store, "ensure_table", lambda: None)
    monkeypatch.setattr(
        mailbox_store, "list_for_user",
        lambda sub: [{"provider": "yahoo", "account": "alice@example.test"}],
    )
    monkeypatch.setattr(
        oauth_email, "connector_status",
        lambda: [
            {"provider": "yahoo", "connected": False, "account": ""},
            {
                "provider": "gmail", "connected": True,
                "account": "another-tenant@example.test",
            },
        ],
    )

    response = asyncio.run(ui.ui_connectors(_bare_request()))
    rows = {row["provider"]: row for row in response.context["connectors"]}
    assert rows["yahoo"]["connected"] is True
    assert rows["gmail"]["connected"] is False
    assert rows["gmail"]["account"] == ""
    assert "another-tenant@example.test" not in response.body.decode()


def test_mailbox_oauth_post_redirects_with_303_and_sanitizes_errors(monkeypatch):
    import asyncio

    import common.oauth_email as oauth_email
    import web.ui as ui

    monkeypatch.setattr(
        ui, "_current_user",
        lambda request: {"sub": "alice@example.test", "role": "customer"},
    )
    monkeypatch.setattr(
        oauth_email, "start_oauth",
        lambda provider, account_sub="": {
            "authorize_url": "https://provider.example/authorize?state=opaque",
        },
    )
    redirect = asyncio.run(
        ui.ui_connectors_oauth_start("gmail", _bare_request(), consented="1"),
    )
    assert redirect.status_code == 303
    assert redirect.headers["location"].startswith("https://provider.example/authorize")

    monkeypatch.setattr(
        oauth_email, "start_oauth",
        lambda provider, account_sub="": {"error": "internal client-secret detail"},
    )
    failure = asyncio.run(
        ui.ui_connectors_oauth_start("gmail", _bare_request(), consented="1"),
    )
    assert failure.status_code == 400
    assert failure.body == b'{"ok":false,"error":"connector_unavailable"}'


def test_account_oauth_state_is_bound_to_initiating_browser(monkeypatch):
    import asyncio

    import common.oauth_account as oauth_account
    import web.ui as ui

    monkeypatch.setattr(
        oauth_account, "start_account_oauth",
        lambda provider, next_path: {
            "authorize_url": "https://provider.example/authorize?state=state-1",
            "state": "state-1",
        },
    )
    start = asyncio.run(
        ui.ui_auth_oauth_start(_bare_request("/app/auth/oauth/google"), "google"),
    )
    assert start.status_code == 303
    assert "np_oauth_state=state-1" in start.headers["set-cookie"]
    assert "HttpOnly" in start.headers["set-cookie"]

    finish_called = []
    monkeypatch.setattr(
        oauth_account, "finish_account_oauth",
        lambda provider, code, state: finish_called.append(state) or {
            "ok": True, "token": "access-token", "next": "/app/dashboard",
        },
    )
    mismatch = asyncio.run(ui.ui_auth_oauth_callback(
        _bare_request(
            "/app/auth/callback/google",
            headers={"cookie": "np_oauth_state=state-1"},
        ),
        "google", code="code-1", state="attacker-state",
    ))
    assert mismatch.status_code == 303
    assert finish_called == []

    success = asyncio.run(ui.ui_auth_oauth_callback(
        _bare_request(
            "/app/auth/callback/google",
            headers={"cookie": "np_oauth_state=state-1"},
        ),
        "google", code="code-1", state="state-1",
    ))
    assert success.status_code == 303
    assert finish_called == ["state-1"]
    assert "np_access=access-token" in success.headers.getlist("set-cookie")[0]


def test_abandoned_account_oauth_state_is_pruned(monkeypatch):
    import common.oauth_account as oauth_account

    monkeypatch.setattr(oauth_account, "_STATE", {
        "expired": {"provider": "google", "ts": 1.0},
        "active": {"provider": "google", "ts": 899.0},
    })
    oauth_account._prune_oauth_state(now=1000.0)

    assert "expired" not in oauth_account._STATE
    assert "active" in oauth_account._STATE


def test_global_call_log_and_grading_remain_admin_only(monkeypatch):
    import asyncio

    import web.ui as ui

    monkeypatch.setattr(
        ui, "_current_user",
        lambda request: {"sub": "alice@example.test", "role": "customer"},
    )
    calls = asyncio.run(ui.ui_calls(_bare_request("/app/calls")))
    grade = asyncio.run(ui.ui_calls_grade(
        _bare_request("/app/calls/grade"), eid="1", verdict="safe",
    ))

    assert calls.status_code == 403
    assert grade.status_code == 403
