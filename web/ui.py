"""
Premium server-rendered console for NullPoint (Signal Deck).

Jinja2 + hand-written CSS/JS in the same FastAPI process — no npm/CDN.
Talks to process_one / Postgres threat store. Aesthetic: brass + forest.
"""
from __future__ import annotations

import hmac
import logging
import os
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

from fastapi import APIRouter, BackgroundTasks, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

from common.rate_limit import rate_limit

logger = logging.getLogger("ui")

_BASE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_BASE / "templates"))
router = APIRouter()

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_PUBLIC_APP_PATHS = frozenset({
    "/app/login", "/app/signup", "/app/privacy", "/app/terms",
})
_PUBLIC_APP_PREFIXES = ("/app/auth/oauth/", "/app/auth/callback/")
_ROLE_RANK = {"viewer": 0, "customer": 1, "analyst": 2,
              "admin": 3, "enterprise": 4}
_LOGIN_ERRORS = {
    "account_deleted": "Your account was deleted and you have been signed out.",
    "oauth_not_configured": "That sign-in method is not available. Use password sign-in or try again later.",
    "oauth_exchange_failed": "Sign-in could not be completed. Try again or use password sign-in.",
    "provider_pending": "That sign-in method is not available yet.",
}
_SIGNUP_ERRORS = {
    "signup_closed": "Signup is closed. Ask the operator, or use an existing account.",
}
_CONNECTOR_ERRORS = {
    "denied": "Mailbox access was not granted.",
    "oauth_denied": "Mailbox access was not granted.",
    "oauth_failed": "The mailbox connection could not be completed. Try again.",
}


def _normalized_app_path(path: str) -> str:
    value = (path or "/").rstrip("/")
    return value or "/"


def _is_public_app_path(path: str) -> bool:
    normalized = _normalized_app_path(path)
    return normalized in _PUBLIC_APP_PATHS or any(
        path.startswith(prefix) for prefix in _PUBLIC_APP_PREFIXES
    )


def _origin_only(raw: str) -> str:
    """Normalize an HTTP(S) Origin/Referer without retaining path or query."""
    try:
        parsed = urlsplit((raw or "").strip())
    except ValueError:
        return ""
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return ""
    if parsed.username or parsed.password:
        return ""
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _extra_allowed_origins() -> set[str]:
    """Comma-separated API_ALLOWED_ORIGINS + PUBLIC_BASE_URL (path stripped)."""
    out: set[str] = set()
    public_base = _origin_only(os.getenv("PUBLIC_BASE_URL", ""))
    if public_base:
        out.add(public_base)
    for part in (os.getenv("API_ALLOWED_ORIGINS") or "").split(","):
        origin = _origin_only(part)
        if origin:
            out.add(origin)
    return out


def _request_origins(request: Request) -> set[str]:
    from common.config import is_production_environment
    allowed = _extra_allowed_origins()
    if is_production_environment():
        # Host and forwarding headers are request-controlled unless a trusted
        # proxy normalizes them. Production uses configured origins only.
        allowed.discard("")
        return allowed
    # Match CORS defaults so local console POSTs work even if Host is stripped.
    allowed.update({
        "http://127.0.0.1:8088",
        "http://localhost:8088",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    })
    # Leftmost forwarded proto (Funnel/TLS terminator) before nginx $scheme.
    xf = (request.headers.get("x-forwarded-proto") or "").split(",", 1)[0].strip().lower()
    scheme = xf if xf in {"http", "https"} else (request.url.scheme or "http")
    if scheme not in {"http", "https"}:
        scheme = "http"
    host = (request.headers.get("host") or request.url.netloc or "").strip().lower()
    if host:
        allowed.add(_origin_only(f"{scheme}://{host}"))
        # Tailscale Funnel terminates TLS outside nginx (listen :80). Browser
        # Origin is https://*.ts.net while X-Forwarded-Proto may still be http.
        host_only = host.split(":", 1)[0]
        if host_only.endswith(".ts.net"):
            allowed.add(f"https://{host_only}")
        # If a proxy forwarded Host without the client port, still accept the
        # loopback Origin the browser actually sends (…:8088).
        if host_only in {"127.0.0.1", "localhost", "::1"}:
            allowed.add(f"http://{host_only}:8088")
            allowed.add(f"http://{host_only}:8000")
    allowed.discard("")
    return allowed


def _is_same_origin(request: Request) -> bool:
    source = request.headers.get("origin") or request.headers.get("referer") or ""
    source_origin = _origin_only(source)
    return bool(source_origin and source_origin in _request_origins(request))


async def _submitted_csrf_token(request: Request) -> str:
    supplied = (request.headers.get("x-csrf-token") or "").strip()
    if supplied:
        return supplied
    content_type = (request.headers.get("content-type") or "").split(";", 1)[0].lower()
    if content_type != "application/x-www-form-urlencoded":
        return ""
    try:
        body = (await request.body()).decode("utf-8", errors="strict")
        values = parse_qs(body, keep_blank_values=True, strict_parsing=False)
    except (UnicodeDecodeError, ValueError):
        return ""
    return str((values.get("_csrf") or [""])[0]).strip()


class ConsoleSecurityMiddleware(BaseHTTPMiddleware):
    """Fail-closed authentication and request-forgery perimeter for `/app`."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if not (path == "/app" or path.startswith("/app/")):
            return await call_next(request)

        from fastapi.responses import JSONResponse, RedirectResponse
        from common.auth import csrf_token_for_session

        public_path = _is_public_app_path(path)
        user = _current_user(request)
        request.state.console_user = user
        session_token = request.cookies.get("np_access") or ""
        request.state.csrf_token = (
            csrf_token_for_session(session_token) if user and session_token else ""
        )

        if not public_path and not user:
            accepts = (request.headers.get("accept") or "").lower()
            if request.method in {"GET", "HEAD"} and "application/json" not in accepts:
                target = path
                if request.url.query:
                    target += f"?{request.url.query}"
                response = RedirectResponse(
                    f"/app/login?next={quote(target, safe='')}", status_code=303,
                )
            else:
                response = JSONResponse(
                    {"ok": False, "error": "login_required"}, status_code=401,
                )
            response.headers["Cache-Control"] = "no-store"
            return response

        if request.method not in _SAFE_METHODS:
            has_source = bool(request.headers.get("origin") or request.headers.get("referer"))
            # Public login/signup forms remain usable by non-browser clients
            # without Origin, but a supplied cross-origin source is rejected.
            if (not public_path or has_source) and not _is_same_origin(request):
                return JSONResponse(
                    {"ok": False, "error": "origin_blocked"}, status_code=403,
                    headers={"Cache-Control": "no-store"},
                )
            if not public_path:
                expected = request.state.csrf_token
                supplied = await _submitted_csrf_token(request)
                if not expected or not supplied or not hmac.compare_digest(expected, supplied):
                    return JSONResponse(
                        {"ok": False, "error": "csrf_failed"}, status_code=403,
                        headers={"Cache-Control": "no-store"},
                    )

        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers.append("Vary", "Cookie")
        return response

# Per-channel presentation metadata (the detection wiring lives in channel_pipeline).
CHANNELS = {
    "phishing": {"label": "Phishing", "kind": "Email",
                 "blurb": "Inbound email phishing and business-email-compromise",
                 "placeholder": "Paste a suspicious email — subject line and body…"},
    "smishing": {"label": "Smishing", "kind": "SMS",
                 "blurb": "SMS and text-message scams, short links, and smishing payloads",
                 "placeholder": "Paste a suspicious text message…"},
    "vishing":  {"label": "Vishing", "kind": "Voice",
                 "blurb": "Paste a voicemail or call transcript — same analyze path as email/SMS",
                 "placeholder": "IRS warrant — press 1 to resolve…"},
}

_ACTION_TONE = {"allow": "safe", "flag": "warn", "quarantine": "danger", "block": "danger"}


def _current_user(request: Request):
    """Resolve the signed-in console user from the np_access cookie (or None)."""
    if hasattr(request.state, "console_user"):
        return request.state.console_user
    token = request.cookies.get("np_access")
    if not token:
        return None
    try:
        from common.auth import verify_token
        payload = verify_token(token)
    except Exception:
        return None
    if not payload:
        return None
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        return None
    return {"sub": subject.strip(), "role": payload.get("role") or "viewer"}


def _require_user_json(request: Request):
    """Return (user_dict, None) or (None, JSON 401) for mutating console routes."""
    from fastapi.responses import JSONResponse
    user = _current_user(request)
    if not user or not user.get("sub") or user.get("sub") in ("anon", "anonymous"):
        return None, JSONResponse({"ok": False, "error": "login_required"}, status_code=401)
    return user, None


def _require_role_json(request: Request, minimum: str):
    """Return an authenticated console user with at least `minimum` role."""
    from fastapi.responses import JSONResponse
    user, err = _require_user_json(request)
    if err:
        return None, err
    if _ROLE_RANK.get(str(user.get("role") or "viewer"), 0) < _ROLE_RANK[minimum]:
        return None, JSONResponse({"ok": False, "error": "forbidden"}, status_code=403)
    return user, None


@router.get("/app/privacy", response_class=HTMLResponse)
async def ui_privacy(request: Request):
    return templates.TemplateResponse(
        request, "privacy.html", _ctx(request, active="privacy"))


@router.get("/app/terms", response_class=HTMLResponse)
async def ui_terms(request: Request):
    return templates.TemplateResponse(
        request, "terms.html", _ctx(request, active="privacy"))


@router.get("/app/account", response_class=HTMLResponse)
async def ui_account(request: Request):
    return templates.TemplateResponse(
        request, "account.html", _ctx(request, active="account"))


@router.post("/app/account/delete")
async def ui_account_delete(request: Request,
                            confirm: str = Form(""),
                            _rl: None = Depends(rate_limit())):
    from fastapi.responses import RedirectResponse, JSONResponse
    user = _current_user(request)
    if not user:
        return RedirectResponse("/app/login?next=/app/account", status_code=303)
    if confirm not in ("1", "true", "yes", "on"):
        return RedirectResponse("/app/account?err=confirm", status_code=303)
    from common.config import is_production_environment
    if is_production_environment():
        # Token/session revocation and cross-store deletion are not yet an
        # atomic, retryable job. Do not present a partial delete as complete.
        return JSONResponse(
            {"ok": False, "error": "account_deletion_unavailable"},
            status_code=503,
        )
    from common.account_delete import delete_account_data
    result = delete_account_data(str(user.get("sub") or ""))
    if not result.get("ok"):
        return JSONResponse(
            {"ok": False, "error": "account_deletion_failed"}, status_code=503,
        )
    resp = RedirectResponse("/app/login?next=/app/dashboard&error=account_deleted", status_code=303)
    resp.delete_cookie("np_access", path="/")
    return resp


def _request_tz(request: Request) -> str:
    """Operator timezone: cookie override, else UTC (browser can auto-set cookie)."""
    raw = (request.cookies.get("np_tz") or "").strip() or "UTC"
    from common.timefmt import resolve_zone
    # Accept any IANA name ZoneInfo knows; prefer known picker values.
    try:
        resolve_zone(raw)
        return raw
    except Exception:
        return "UTC"


def _request_hour12(request: Request) -> bool:
    """12-hour clock when cookie np_hour12=1 (default 24h for operators)."""
    return (request.cookies.get("np_hour12") or "").strip() in ("1", "true", "yes")


def _ctx(request: Request, **kw) -> dict:
    """Base template context: channels + the signed-in user on every page."""
    from common.timefmt import common_timezone_choices, tz_abbrev
    kw.setdefault("channels", CHANNELS)
    kw["user"] = _current_user(request)
    tz = _request_tz(request)
    kw["tz"] = tz
    kw["tz_abbrev"] = tz_abbrev(tz)
    kw["tz_choices"] = common_timezone_choices()
    kw["hour12"] = _request_hour12(request)
    kw["csrf_token"] = getattr(request.state, "csrf_token", "")
    return kw


# Map evidence codes → consumer signal severity for the analyze card.
_SIGNAL_SEV = {
    "BAD_URL": "danger", "SHORT_LINK": "warn", "DOMAIN_MISMATCH": "warn",
    "HTML_OBFUSCATION": "danger", "HOMOGRAPH": "danger", "PUNYCODE_IDN": "danger",
    "LOOKALIKE_DOMAIN": "danger", "SENSITIVE_ASK": "danger", "URGENCY_FEAR": "warn",
    "CALLBACK_PRESSURE": "warn", "TOLL_FREE_CALLBACK": "warn", "ADVANCE_FEE": "danger",
    "ATTACHMENT_RISK": "danger", "REPLY_TO_MISMATCH": "warn", "DISPLAY_NAME_SPOOF": "warn",
    "SPF_FAIL": "danger", "DKIM_FAIL": "danger", "DMARC_FAIL": "danger",
    "BLACKMAIL": "danger", "IMPERSONATION": "danger", "CREDIT_LURE": "warn",
    "HAPPY_LURE": "warn", "SUSPICIOUS_RELAY": "warn", "CAMPAIGN_MATCH": "danger",
}


def _consumer_signals(channel: str, content: str, sender: str) -> list:
    """Consumer 'why' cues — thin wrapper over common.explain (no second lexicon)."""
    try:
        from common.explain import analyze_findings
        findings = analyze_findings(channel, content, sender or "")
    except Exception:
        return []
    out = []
    for f in findings[:8]:
        code = f.get("code") or ""
        sev = _SIGNAL_SEV.get(code, "warn")
        out.append({
            "sev": sev,
            "label": f.get("label") or code,
            "detail": (f.get("evidence") or "")[:220],
        })
    return out


def _technical_view(channel: str, v) -> dict:
    """OS-safe algorithm breakdown for the extended/technical view (no secret weights)."""
    feat = {"phishing": None, "smishing": None, "vishing": None}
    stack = None
    try:  # provenance from the reproducibility manifest, if present
        import json
        from pathlib import Path
        man = json.loads((Path(__file__).resolve().parent.parent / "models" / "REPRO_MANIFEST.json").read_text())
        ch = man.get("channels", {}).get(channel, {})
        feat[channel] = ch.get("feature_version")
        stack = ch.get("stack") or man.get("stack")
    except Exception:
        pass
    return {
        "pipeline": [
            "Word TF-IDF (1–3 grams) + Char TF-IDF (3–5 grams) — catches wording and obfuscation (acc0unt)",
            "Structural features — channel-specific, hard-to-fake numeric signals",
            "SGDClassifier (log-loss) — sparse linear inference; production latency not yet measured",
            "Score calibration — estimates P(threat); reliability still requires a larger holdout",
            "Per-channel anomaly (Isolation Forest) — novelty vs that channel’s normal traffic",
            "Risk engine — fuses calibrated P(threat) + anomaly into action (allow/flag/quarantine)",
        ],
        "vals": {
            "classifier_pred": v.classifier_pred,
            "classifier_confidence": round(float(v.classifier_conf), 4),
            "calibrated_risk": round(float(v.risk_score), 4),
            "anomaly_level": v.anomaly_level,
            "anomaly_novelty": round(float(v.anomaly_novelty), 4),
            "decision": getattr(v.action, "value", str(v.action)),
        },
        "feature_version": feat.get(channel),
        "stack": stack,
    }


def _verdict_view(account_sub: str, channel: str, content: str, sender: str) -> dict:
    """Run the pipeline and shape the verdict for the template (never raises)."""
    from common.streaming.channel_pipeline import process_one
    from common.tenant_rls import require_account_sub
    tenant = require_account_sub(account_sub)
    record = {"account_sub": tenant,
              "subject": "", "body": content, "transcript": content,
              "from": sender, "caller_id": sender}
    try:
        v = process_one(channel, record)
        action = getattr(v.action, "value", str(v.action))
        # Persist moderate+ risk so console analyzes feed the same stream the
        # engine uses: dashboard, inbox, and the quarantine review queue
        # (label stays NULL until a human grades it). DLQ-safe, never raises.
        if float(v.risk_score) >= 0.35:
            try:
                from common.streaming.dlq import persist_threat_durable
                persist_threat_durable(
                    account_sub=tenant,
                    content=content, threat_type=channel, sender=sender or "unknown",
                    metadata={"risk_score": float(v.risk_score), "action": action,
                              "confidence": float(v.risk_score), "channel": channel,
                              "anomaly_level": v.anomaly_level,
                              "label_source": "model_prediction",
                              "training_eligible": False,
                              "destructive_action_eligible": False,
                              "via": "console-analyze"})
            except Exception as pe:
                logger.debug("console persist skipped: %s", pe)
        return {
            "ok": True,
            "is_threat": bool(v.is_threat),
            "action": action,
            "tone": _ACTION_TONE.get(action, "warn" if v.is_threat else "safe"),
            "risk_pct": round(float(v.risk_score) * 100),
            "confidence_pct": round(float(v.classifier_conf) * 100),
            "anomaly_level": v.anomaly_level,
            "anomaly_novelty": round(float(v.anomaly_novelty), 3),
            "reasons": list(v.reasons)[:5],
            "signals": _consumer_signals(channel, content, sender),
            "tech": _technical_view(channel, v),
            "channel": channel,
        }
    except Exception as e:  # pipeline hiccup → render a graceful error card
        logger.error("ui analyze failed [%s]: %s", channel, e)
        return {"ok": False, "error": "Analysis temporarily unavailable.", "channel": channel}


@router.get("/app", response_class=HTMLResponse)
async def console(request: Request, channel: str = "phishing"):
    if channel not in CHANNELS:
        channel = "phishing"
    return templates.TemplateResponse(
        request, "index.html", _ctx(request, active=channel))


@router.post("/app/analyze", response_class=HTMLResponse)
async def ui_analyze(request: Request,
                     channel: str = Form("phishing"),
                     content: str = Form(..., max_length=50_000),
                     sender: str = Form("", max_length=256),
                     _rl: None = Depends(rate_limit())):
    if channel not in CHANNELS:
        channel = "phishing"
    user = _current_user(request)
    if not user:
        from fastapi.responses import RedirectResponse
        return RedirectResponse("/app/login", status_code=303)
    view = _verdict_view(str(user["sub"]), channel, content, sender.strip())
    return templates.TemplateResponse(request, "_result.html", {"v": view})


def _screen_view(caller_id: str, transcript: str, contact_known: bool) -> dict:
    """Hybrid CallKit screening for the Vish console (reputation + optional transcript)."""
    from common.vish import screen_call, CallEvent
    try:
        r = screen_call(CallEvent(
            caller_id=caller_id.strip(),
            transcript=transcript.strip() or None,
            contact_known=contact_known,
        ))
        action = r.action.value
        tone = {"allow": "safe", "label": "warn", "silence": "warn", "block": "danger"}.get(action, "warn")
        return {
            "ok": True,
            "action": action,
            "tone": tone,
            "is_threat": r.is_threat,
            "risk_pct": round(float(r.risk) * 100),
            "verdict": r.verdict,
            "label": r.label,
            "reasons": list(r.reasons)[:6],
            "paths": list(r.paths),
            "reputation": r.reputation,
            "content": r.content,
        }
    except Exception as e:
        logger.error("ui screen failed: %s", e)
        return {"ok": False, "error": "Call screening temporarily unavailable."}


def _record_screen_result(account_sub: str, caller_id: str, view: dict,
                          transcript: str = "") -> None:
    if not view.get("ok"):
        return
    try:
        from common.call_events import record_screen
        record_screen({
            "account_sub": account_sub,
            "caller_id": caller_id,
            "action": view.get("action"),
            "risk": (view.get("risk_pct") or 0) / 100.0,
            "verdict": view.get("verdict"),
            "label": view.get("label"),
            "paths": view.get("paths"),
            "is_threat": view.get("is_threat"),
            "reasons": view.get("reasons"),
            "transcript": transcript,
        })
    except Exception as e:
        logger.debug("call event log skipped: %s", e)


@router.post("/app/screen", response_class=HTMLResponse)
async def ui_screen(request: Request,
                    caller_id: str = Form(..., max_length=32),
                    transcript: str = Form("", max_length=20_000),
                    contact_known: str = Form(""),
                    _rl: None = Depends(rate_limit())):
    known = contact_known.lower() in ("true", "1", "on", "yes")
    user = _current_user(request)
    if not user:
        from fastapi.responses import RedirectResponse
        return RedirectResponse("/app/login", status_code=303)
    view = _screen_view(caller_id, transcript, known)
    _record_screen_result(str(user["sub"]), caller_id, view, transcript.strip())
    return templates.TemplateResponse(request, "_screen.html", {"s": view})


@router.get("/app/pricing", response_class=HTMLResponse)
async def ui_pricing(request: Request):
    from common.plans import COMPARE_ROWS, list_plans
    from common.billing import use_mock
    return templates.TemplateResponse(
        request, "pricing.html",
        _ctx(request, active="pricing", plans=list_plans(), compare_rows=COMPARE_ROWS,
             billing_mock=use_mock()))


@router.get("/app/checkout", response_class=HTMLResponse)
async def ui_checkout_get(request: Request, plan: str = "pro", interval: str = "annual"):
    from common.billing import plan_by_slug, use_mock, resolve_amount_cents
    p = plan_by_slug(plan) or plan_by_slug("pro")
    interval = interval if interval in ("monthly", "annual") else "annual"
    want_trial = plan == "pro" and request.query_params.get("trial") == "1"
    amount = resolve_amount_cents(p, interval) if p else 0
    return templates.TemplateResponse(
        request, "checkout.html",
        _ctx(request, active="pricing", plan=p, interval=interval,
             want_trial=want_trial, amount_cents=amount, billing_mock=use_mock()))


@router.post("/app/checkout")
async def ui_checkout_post(request: Request,
                           plan: str = Form(...),
                           interval: str = Form("monthly"),
                           email: str = Form(""),
                           trial: str = Form("0"),
                           fingerprint: str = Form(""),
                           _rl: None = Depends(rate_limit())):
    """Start checkout — server price authority; mock or Stripe redirect."""
    import os
    from fastapi.responses import JSONResponse, RedirectResponse
    from common.billing import validate_checkout_payload, start_checkout

    body = {"plan": plan, "interval": interval, "email": email}
    ok, err = validate_checkout_payload(body)
    if not ok:
        return JSONResponse({"ok": False, "error": err}, status_code=400)

    user = _current_user(request)
    if not user:
        return JSONResponse(
            {"ok": False, "error": "login_required",
             "hint": "Sign in before checkout — guest pay is disabled"},
            status_code=401,
        )
    client_ip = request.client.host if request.client else "unknown"
    pub = (os.getenv("PUBLIC_BASE_URL") or "").rstrip("/")
    if not pub:
        return JSONResponse(
            {"ok": False, "error": "checkout_unavailable"}, status_code=503,
        )
    base = pub

    result = start_checkout(
        plan_slug=plan, interval=interval, email=email.strip(),
        account_sub=(user or {}).get("sub") or "",
        base_url=base, client_ip=client_ip,
        user_agent=request.headers.get("user-agent") or "",
        fingerprint=fingerprint.strip(),
        want_trial=trial in ("1", "true", "yes"),
    )
    if not result.get("ok"):
        safe = {k: v for k, v in result.items() if k != "detail"}
        return JSONResponse(safe, status_code=400)
    accept = request.headers.get("accept") or ""
    if "application/json" in accept:
        resp = JSONResponse({**result, "data_class": "confidential"})
        resp.headers["X-NP-Data-Class"] = "confidential"
        return resp
    return RedirectResponse(result["url"], status_code=303)


@router.get("/app/checkout/success", response_class=HTMLResponse)
async def ui_checkout_success(request: Request, session_id: str = ""):
    from common.billing import verify_and_entitle, use_mock
    user = _current_user(request)
    entitlement = verify_and_entitle(
        session_id=session_id,
        account_sub=(user or {}).get("sub") or "anonymous",
    )
    return templates.TemplateResponse(
        request, "checkout_success.html",
        _ctx(request, active="pricing", session_id=session_id,
             entitlement=entitlement, billing_mock=use_mock()))


@router.get("/app/benchmarks", response_class=HTMLResponse)
async def ui_benchmarks(request: Request):
    """Benchmark Deck — prefer disk snapshot (fast); never golden-eval on every hit."""
    import os
    from datetime import datetime, timezone
    from common.bench_snapshot import load_snapshot
    from ui.kpi import operational_kpis, reassess_quality_snapshot

    snap = load_snapshot(max_age=24 * 3600)
    if snap and snap.get("quality"):
        quality = reassess_quality_snapshot(snap["quality"])
        latency = snap.get("latency") or {}
        ops = snap.get("ops") or operational_kpis()
        stale = bool(snap.get("stale"))
        generated_at = snap.get("generated_at")
        try:
            generated_at = datetime.fromtimestamp(
                float(generated_at), tz=timezone.utc,
            ).isoformat(timespec="seconds")
        except (TypeError, ValueError, OSError):
            generated_at = None
    else:
        # Soft fail: empty charts + note — do NOT run heavy golden eval inline
        quality = {
            "phishing": {"available": False, "reason": "snapshot missing — run scripts/refresh_benchmarks.py"},
            "smishing": {"available": False, "reason": "snapshot missing"},
            "vishing": {"available": False, "reason": "snapshot missing"},
        }
        latency = {}
        ops = operational_kpis()
        stale = True
        generated_at = None

    max_lat = 1.0
    for lat in (latency or {}).values():
        try:
            max_lat = max(max_lat, float(lat.get("p95_ms") or 0), float(lat.get("p50_ms") or 0))
        except Exception:
            pass
    assist = []
    for name, env in (("DeepSeek", "DEEPSEEK_API_KEY"), ("Kimi", "KIMI_API_KEY"),
                      ("Groq", "GROQ_API_KEY")):
        keyed = bool(os.getenv(env, "").strip())
        assist.append({
            "name": name, "env": env, "status": "keyed" if keyed else "missing_keys",
            "role": "explanation assist only — never hot-path enforcement",
        })
    return templates.TemplateResponse(
        request, "benchmarks.html",
        _ctx(request, active="benchmarks", quality=quality, latency=latency,
             ops=ops, assist=assist, max_lat_ms=max_lat, snapshot_stale=stale,
             snapshot_generated_at=generated_at))


def _request_is_https(request: Request) -> bool:
    """True when the client connection is HTTPS (direct or via proxy)."""
    if (request.url.scheme or "").lower() == "https":
        return True
    xf = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
    return xf == "https"


def _safe_app_redirect_target(target: str, fallback: str = "/app/dashboard") -> str:
    from starlette.datastructures import URL

    value = (target or "").replace("\\", "/")
    parsed = URL(value)
    if parsed.scheme or parsed.hostname:
        return fallback
    if not value.startswith("/"):
        return fallback
    if value.startswith("//"):
        return fallback
    if value != "/app" and not value.startswith("/app/"):
        return fallback
    return value


@router.get("/app/signup", response_class=HTMLResponse)
async def ui_signup_get(request: Request, next: str = "/app/dashboard", error: str = ""):
    from common.accounts import signup_open

    safe_next = _safe_app_redirect_target(next)

    if _current_user(request):
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url=safe_next, status_code=303)
    err = _SIGNUP_ERRORS.get(error) if error else None
    if not signup_open():
        err = err or "Signup is closed. Ask the operator, or use an existing account."
    return templates.TemplateResponse(
        request, "signup.html",
        {"channels": CHANNELS, "active": "login", "error": err, "email": "",
         "next": safe_next,
         "signup_open": signup_open()})


@router.post("/app/signup", response_class=HTMLResponse)
async def ui_signup_post(request: Request,
                         email: str = Form(...),
                         password: str = Form(...),
                         next: str = Form("/app/dashboard"),
                         _rl: None = Depends(rate_limit())):
    from fastapi.responses import RedirectResponse
    from common.accounts import register, signup_open
    from common.auth import create_access_token
    dest = _safe_app_redirect_target(next)
    if not signup_open():
        return templates.TemplateResponse(
            request, "signup.html",
            {"channels": CHANNELS, "active": "login",
             "error": "Signup is closed.", "email": email, "next": dest,
             "signup_open": False},
            status_code=403)
    result = register(email, password)
    if not result.get("ok"):
        msgs = {
            "bad_email": "Use a real email address.",
            "disposable": "Burner / temporary emails are not allowed. Use a real inbox (Apple Hide My Email is fine).",
            "short_password": "Password must be at least 10 characters.",
            "email_taken": "That email already has an account — sign in.",
            "reserved": "That name is reserved.",
            "db_unavailable": "Database is down — try again in a minute.",
            "signup_closed": "Signup is closed.",
        }
        err = msgs.get(result.get("error"), "Could not create the account.")
        return templates.TemplateResponse(
            request, "signup.html",
            {"channels": CHANNELS, "active": "login", "error": err,
             "email": email, "next": dest, "signup_open": True},
            status_code=400)
    from datetime import timedelta
    token = create_access_token(
        {"sub": result["sub"], "role": result["role"]},
        expires=timedelta(hours=8),
    )
    resp = RedirectResponse(url=dest, status_code=303)
    resp.set_cookie(
        "np_access", token, httponly=True, samesite="lax",
        secure=_request_is_https(request),
        max_age=60 * 60 * 8, path="/",
    )
    return resp


@router.get("/app/login", response_class=HTMLResponse)
async def ui_login_get(request: Request, next: str = "/app/dashboard", error: str = ""):
    dest = _safe_app_redirect_target(next)
    if _current_user(request):  # already signed in → straight to the portal
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url=dest, status_code=303)
    err = _LOGIN_ERRORS.get(error) if error else None
    from common.accounts import signup_open
    return templates.TemplateResponse(
        request, "login.html",
        {"channels": CHANNELS, "active": "login", "error": err, "username": "",
         "next": dest, "signup_open": signup_open()})


@router.get("/app/auth/oauth/{provider}")
async def ui_auth_oauth_start(request: Request, provider: str,
                              next: str = "/app/dashboard"):
    """Account OAuth — same-window redirect (session cookie on this origin)."""
    from fastapi.responses import RedirectResponse
    from common.oauth_account import start_account_oauth
    dest = _safe_app_redirect_target(next)
    result = start_account_oauth(provider, dest)
    if result.get("error") == "oauth_not_configured" or not result.get("authorize_url"):
        from urllib.parse import quote
        return RedirectResponse(
            f"/app/login?next={quote(dest, safe='')}&error=oauth_not_configured",
            status_code=303,
        )
    if result.get("error") in ("x_pkce_required", "provider_pending"):
        from urllib.parse import quote
        return RedirectResponse(
            f"/app/login?next={quote(dest, safe='')}&error=provider_pending",
            status_code=303,
        )
    oauth_state = str(result.get("state") or "").strip()
    if not oauth_state:
        logger.warning("account OAuth start returned no state [%s]", provider)
        return RedirectResponse(
            f"/app/login?next={quote(dest, safe='')}&error=oauth_exchange_failed",
            status_code=303,
        )
    response = RedirectResponse(result["authorize_url"], status_code=303)
    # Bind process-side OAuth state to the browser that initiated sign-in.
    # State alone is not sufficient when the server store is shared globally.
    response.set_cookie(
        "np_oauth_state", oauth_state, httponly=True, samesite="lax",
        secure=_request_is_https(request), max_age=15 * 60,
        path="/app/auth",
    )
    return response


@router.get("/app/auth/callback/{provider}")
async def ui_auth_oauth_callback(request: Request, provider: str, code: str = "", state: str = "",
                                 error: str = ""):
    from fastapi.responses import RedirectResponse
    from urllib.parse import quote
    expected_state = request.cookies.get("np_oauth_state") or ""

    def _oauth_failure(url: str = "/app/login?error=oauth_exchange_failed"):
        response = RedirectResponse(url, status_code=303)
        response.delete_cookie("np_oauth_state", path="/app/auth")
        return response

    if error or not code:
        return _oauth_failure()
    if (not state or not expected_state
            or not hmac.compare_digest(state, expected_state)):
        logger.warning("account OAuth browser-state mismatch [%s]", provider)
        return _oauth_failure()
    from common.oauth_account import finish_account_oauth
    result = finish_account_oauth(provider, code, state)
    if not result.get("ok"):
        nxt = quote(_safe_app_redirect_target(result.get("next") or ""), safe="")
        internal_error = result.get("error") or "oauth_exchange_failed"
        logger.warning("account OAuth callback failed [%s]: %s", provider, internal_error)
        err = internal_error if internal_error in _LOGIN_ERRORS else "oauth_exchange_failed"
        return _oauth_failure(f"/app/login?next={nxt}&error={err}")
    dest = _safe_app_redirect_target(result.get("next") or "/app/dashboard")
    resp = RedirectResponse(dest, status_code=303)
    resp.set_cookie(
        "np_access", result["token"], httponly=True, samesite="lax",
        secure=_request_is_https(request),
        max_age=12 * 3600, path="/",
    )
    resp.delete_cookie("np_oauth_state", path="/app/auth")
    return resp


@router.post("/app/login", response_class=HTMLResponse)
async def ui_login_post(request: Request,
                        username: str = Form(...),
                        password: str = Form(...),
                        next: str = Form("/app/dashboard"),
                        _rl: None = Depends(rate_limit())):
    from fastapi.responses import RedirectResponse
    from common.auth import authenticate_user, create_access_token
    dest = _safe_app_redirect_target(next)
    user = authenticate_user(username.strip(), password)
    if not user:
        from common.accounts import signup_open
        return templates.TemplateResponse(
            request, "login.html",
            {"channels": CHANNELS, "active": "login",
             "error": "Invalid credentials", "username": username,
             "next": dest, "signup_open": signup_open()},
            status_code=401)
    from datetime import timedelta
    token = create_access_token(user, expires=timedelta(hours=8))  # console session
    resp = RedirectResponse(url=dest, status_code=303)
    resp.set_cookie(
        "np_access", token, httponly=True, samesite="lax",
        secure=_request_is_https(request),
        max_age=60 * 60 * 8, path="/",
    )
    return resp


@router.post("/app/logout")
async def ui_logout(request: Request):
    from fastapi.responses import RedirectResponse
    if not _current_user(request):
        return RedirectResponse(url="/app/login", status_code=303)
    resp = RedirectResponse(url="/app/login", status_code=303)
    resp.delete_cookie("np_access", path="/")
    return resp


def _dashboard_context(account_sub: str, tz: str = "UTC", hour12: bool = False) -> dict:
    from datetime import datetime
    from common.timefmt import format_local
    live, geo, active_threats = [], [], []
    stats = {"total": 0, "threats": 0, "quarantined": 0, "rate": "—"}
    try:
        from Autobot.VectorDB.NullPoint_Vector import get_threats_page, get_review_queue
        try:
            _, review_counts = get_review_queue(limit=50, account_sub=account_sub)
            stats["quarantined"] = review_counts.get("total", 0)
        except Exception:
            pass
        rows, _ = get_threats_page(
            threat_type=None, after_id=None, limit=40,
            account_sub=account_sub, max_confidence=0.85,
        )
        rows = rows or []
        stats["total"] = len(rows)
        for i, r in enumerate(rows):
            conf = float(r.get("confidence") or 0)
            sender = r.get("sender") or "unknown"
            meta = r.get("metadata") or {}
            if r.get("label") == 0 or meta.get("safe_domain"):
                continue
            threat = conf >= 0.35 or bool(r.get("is_threat"))
            if threat:
                stats["threats"] += 1
            ts_raw = r.get("timestamp") or ""
            ts = format_local(ts_raw, tz, hour12=hour12, with_seconds=True, with_date=False)
            ch = r.get("threat_type") or "phishing"
            live.append({
                "ts": ts, "ts_utc": ts_raw, "threat": threat, "sender": sender[:42],
                "channel": ch, "score": f"{conf:.2f}",
                "geo": (r.get("metadata") or {}).get("geo") or "—",
            })
        # Active threats are NOT duplicated here — grade holds on Quarantine only
        active_threats = []
        # Real geo only — never invent demo pins
        geo = []
        for r in rows:
            g = (r.get("metadata") or {}).get("geo")
            if not g or not isinstance(g, dict):
                continue
            if "x" in g and "y" in g:
                geo.append({
                    "x": g["x"], "y": g["y"],
                    "level": g.get("level") or "warn",
                    "label": g.get("label") or "—",
                })
            if len(geo) >= 12:
                break
        stats["rate"] = f"{max(0.1, len(rows)/60):.1f}/m"
    except Exception as e:
        logger.warning("dashboard context: %s", e)
    return {
        "channels": CHANNELS, "active": "dashboard",
        "stats": stats, "live": live[:24], "geo": geo,
        "active_threats": active_threats,
        "now": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/app/dashboard", response_class=HTMLResponse)
async def ui_dashboard(request: Request):
    account_sub = str((_current_user(request) or {}).get("sub") or "")
    ctx = _dashboard_context(
        account_sub, tz=_request_tz(request), hour12=_request_hour12(request),
    )
    ctx.update(_ctx(request, active="dashboard"))
    return templates.TemplateResponse(request, "dashboard.html", ctx)


@router.get("/app/quarantine", response_class=HTMLResponse)
async def ui_quarantine(request: Request):
    """Review queue — the ONE manual touchpoint: grade quarantined/potential/unsure."""
    rows, counts = [], {"total": 0, "quarantined": 0, "potential": 0, "unsure": 0}
    tz = _request_tz(request)
    hour12 = _request_hour12(request)
    account_sub = str((_current_user(request) or {}).get("sub") or "")
    try:
        from Autobot.VectorDB.NullPoint_Vector import get_review_queue
        from common.explain import plain_english_math
        from common.timefmt import format_local
        from common.pills import build_pills
        rows, counts = get_review_queue(limit=100, account_sub=account_sub)
        for r in rows:
            text = " ".join([
                r.get("subject") or "",
                r.get("body") or "",
                str((r.get("metadata") or {}).get("snippet") or ""),
            ]).strip()
            pack = build_pills(
                channel=r.get("channel") or "phishing",
                subject=r.get("subject") or "",
                body=r.get("body") or "",
                sender=r.get("sender") or "",
                confidence=float(r.get("confidence") or 0),
                headers=(r.get("metadata") or {}).get("headers")
                or (r.get("metadata") or {}).get("auth"),
            )
            codes = pack["reason_codes"]
            r["reason_codes"] = codes
            r["tags"] = pack["tags"]
            if r.get("body"):
                r["body"] = pack["preview"]
            r["ts_local"] = format_local(
                r.get("timestamp"), tz, hour12=hour12, with_date=True)
            r["explain"] = plain_english_math(
                channel=r.get("channel") or "phishing",
                content=text, sender=r.get("sender") or "",
                pred=1, confidence=float(r.get("confidence") or 0),
                reason_codes=codes,
                top_features=None,
            )
    except Exception as e:
        logger.warning("quarantine queue unavailable: %s", e)
    return templates.TemplateResponse(
        request, "quarantine.html",
        _ctx(request, active="quarantine", rows=rows, counts=counts))


@router.get("/app/quarantine/siblings")
async def ui_quarantine_siblings(request: Request, mid: int = 0):
    """List same-sender ungraded rows for the cascade confirm modal."""
    from fastapi.responses import JSONResponse
    from common.timefmt import format_local
    user, err = _require_user_json(request)
    if err:
        return err
    if not mid:
        return JSONResponse({"ok": False, "error": "need_mid"}, status_code=400)
    try:
        from Autobot.VectorDB.NullPoint_Vector import list_sender_siblings
        data = list_sender_siblings(mid, account_sub=str(user["sub"]))
    except Exception as e:
        logger.error("siblings failed: %s", e)
        return JSONResponse({"ok": False, "error": "lookup_failed"}, status_code=500)
    tz = _request_tz(request)
    hour12 = _request_hour12(request)
    sibs = []
    for s in data.get("siblings") or []:
        sibs.append({
            **s,
            "ts_local": format_local(s.get("timestamp"), tz, hour12=hour12),
        })
    return JSONResponse({
        "ok": True, "sender": data.get("sender") or "", "siblings": sibs,
    })


@router.post("/app/report")
async def ui_user_report(
    request: Request,
    mid: str = Form(""),
    channel: str = Form("email"),
    sender: str = Form(""),
    expected: str = Form(""),
    reasons: str = Form(""),
    detail: str = Form(""),
    _rl: None = Depends(rate_limit()),
):
    """Granny-friendly report path (separate from Block / Needs review / Safe).

    Persists to user_reports; may flag/promote fleet keys. Does not grade the
    message by itself — triage buttons still own label/feedback.jsonl.
    """
    from fastapi.responses import JSONResponse
    import json as _json

    user, err = _require_user_json(request)
    if err:
        return err
    account = str(user.get("sub") or "")[:128]

    mid_i = None
    if mid.strip().isdigit():
        mid_i = int(mid.strip())
    exp = None
    if expected.strip().lower() in ("1", "true", "yes"):
        exp = True
    elif expected.strip().lower() in ("0", "false", "no"):
        exp = False

    reason_list: list = []
    raw = (reasons or "").strip()
    if raw.startswith("["):
        try:
            reason_list = list(_json.loads(raw))
        except Exception:
            reason_list = []
    elif raw:
        reason_list = [x.strip() for x in raw.split(",") if x.strip()]

    if not sender and mid_i:
        try:
            from Autobot.VectorDB.NullPoint_Vector import get_message_detail
            msg = get_message_detail(mid_i, account_sub=account) or {}
            sender = msg.get("sender") or msg.get("from") or ""
            channel = channel or msg.get("channel") or "email"
        except Exception:
            pass

    from common.user_reports import submit_user_report
    out = submit_user_report(
        message_id=mid_i,
        account_sub=account,
        channel=channel or "email",
        sender=sender or "",
        expected=exp,
        reasons=reason_list,
        detail=detail or None,
    )
    if not out.get("ok"):
        return JSONResponse(
            {"ok": False, "error": out.get("error") or "failed"},
            status_code=400 if out.get("error") == "empty_report" else 500,
        )
    return JSONResponse({
        "ok": True,
        "id": out.get("id"),
        "fleet": out.get("fleet") or {},
    })


@router.post("/app/quarantine/grade")
async def ui_quarantine_grade(request: Request,
                              background_tasks: BackgroundTasks,
                              mid: int = Form(...),
                              verdict: str = Form(...),
                              also_ids: str = Form(""),
                              cascade: str = Form("ask"),
                              _rl: None = Depends(rate_limit())):
    """Persist a human verdict on a message and feed the training loop.

    block/safe → buffer + ephemeral partial_fit (Δw in response)
    unsure → stays ungraded (label NULL) but marked for the review queue.
    also_ids: comma-separated extras (same sender) to grade together.
    cascade=all keeps legacy auto-all when also_ids empty.
    Provider junk/trash is enqueued async — never blocks Cascade Apply.
    """
    from fastapi.responses import JSONResponse
    user, err = _require_user_json(request)
    if err:
        return err
    account_sub = str(user["sub"])
    if verdict not in ("block", "unsure", "safe"):
        return JSONResponse({"ok": False, "error": "bad_verdict"}, status_code=400)
    label = {"block": 1, "safe": 0}.get(verdict)
    status = {"block": "blocked", "safe": "safe", "unsure": "quarantined"}[verdict]
    extras = None
    if also_ids.strip():
        try:
            extras = [int(x) for x in also_ids.split(",") if x.strip().isdigit()]
        except ValueError:
            extras = []
    elif verdict in ("block", "safe") and cascade != "all":
        extras = []  # this message only unless UI listed siblings
    try:
        from Autobot.VectorDB.NullPoint_Vector import set_message_grade
        graded = set_message_grade(
            mid, label=label, status=status,
            account_sub=account_sub,
            cascade_sender=(cascade == "all" and extras is None),
            also_ids=extras,
        )
    except Exception as e:
        logger.error("grade failed [%s]: %s", mid, e)
        graded = None
    if not graded:
        return JSONResponse({"ok": False, "error": "not_found"}, status_code=404)
    learn = None
    velocity = None
    if verdict in ("block", "safe"):
        from common.grading import record_grade
        rec = {
            "from": graded["sender"], "sender": graded["sender"],
            "caller_id": graded["sender"], "subject": graded["subject"],
            "body": graded["text"] or graded["subject"] or "",
            "transcript": graded["text"] or graded["subject"] or "",
        }
        learn = record_grade(graded["channel"], rec, verdict, source="console-grade", nudge=True)
        try:
            from common.grade_velocity import note_grade
            velocity = note_grade(
                channel=graded["channel"], sender=graded["sender"],
                verdict=verdict, record=rec,
            )
        except Exception as e:
            logger.debug("grade velocity skipped: %s", e)
    provider_note = None
    junk = None
    queue_info = None
    if verdict == "block":
        ids = list(graded.get("cascaded_ids") or [mid])
        try:
            from common.provider_sync import enqueue_provider_moves, process_provider_queue
            queue_info = enqueue_provider_moves(
                ids, account_sub=account_sub, action="junk",
            )
            background_tasks.add_task(process_provider_queue, limit=10)
            cascaded_n = int(graded.get("cascaded") or 0)
            provider_note = (
                f"Provider junk queued for {queue_info.get('queued', 0)} message(s) "
                f"(async — Yahoo Bulk / Gmail Spam when imap_id present)."
            )
            if cascaded_n > 0:
                provider_note += f" Graded {cascaded_n} same-sender sibling(s) in NullPoint."
        except Exception as e:
            logger.warning("provider queue after block: %s", e)
            provider_note = "Graded in NullPoint; provider sync queue failed open."
    return JSONResponse({
        "ok": True, "verdict": verdict, "id": mid,
        "cascaded_ids": graded.get("cascaded_ids") or [mid],
        "cascaded": int(graded.get("cascaded") or 0),
        "nudge": (learn or {}).get("nudge"),
        "buffered": (learn or {}).get("buffered"),
        "provider_note": provider_note,
        "provider_queue": queue_info,
        "velocity": velocity,
        "junk": junk,
    })


@router.get("/app/message/{mid}", response_class=HTMLResponse)
async def ui_message_detail(request: Request, mid: int):
    """Open full message body for analyst review (console; encrypted-at-rest)."""
    from fastapi.responses import RedirectResponse
    user = _current_user(request)
    if not user:
        return RedirectResponse(f"/app/login?next=/app/message/{mid}", status_code=303)
    try:
        from Autobot.VectorDB.NullPoint_Vector import get_message_detail
        from common.explain import plain_english_math
        from common.timefmt import format_local
        from common.pills import build_pills
        msg = get_message_detail(mid, account_sub=str(user["sub"]))
    except Exception as e:
        logger.warning("message detail unavailable: %s", e)
        msg = None
    if not msg:
        return templates.TemplateResponse(
            request, "message_detail.html",
            _ctx(request, active="quarantine", msg=None, error="Message not found"))
    text = " ".join([msg.get("subject") or "", msg.get("body") or ""]).strip()
    headers = (msg.get("metadata") or {}).get("headers") or {}
    pack = build_pills(
        channel=msg.get("channel") or "phishing",
        subject=msg.get("subject") or "",
        body=msg.get("body") or "",
        sender=msg.get("sender") or "",
        confidence=float(msg.get("confidence") or 0),
        headers=headers,
        max_cats=5,
        max_reasons=8,
    )
    codes = pack["reason_codes"]
    explain = plain_english_math(
        channel=msg.get("channel") or "phishing",
        content=text, sender=msg.get("sender") or "",
        pred=1 if msg.get("is_threat") else 0,
        confidence=float(msg.get("confidence") or 0),
        reason_codes=codes, top_features=None,
    )
    msg["ts_local"] = format_local(
        msg.get("timestamp"), _request_tz(request),
        hour12=_request_hour12(request), with_date=True)
    return templates.TemplateResponse(
        request, "message_detail.html",
        _ctx(request, active="quarantine", msg=msg, reason_codes=codes,
             explain=explain, tags=pack["tags"], error=None))


@router.post("/app/calls/grade")
async def ui_calls_grade(request: Request,
                         eid: str = Form(...),
                         verdict: str = Form(...),
                         _rl: None = Depends(rate_limit())):
    """Grade a call-screen event (vishing feedback loop)."""
    from fastapi.responses import JSONResponse
    # Events carry account_sub; grade only within the caller's tenant.
    user, err = _require_role_json(request, "analyst")
    if err:
        return err
    if verdict not in ("block", "unsure", "safe"):
        return JSONResponse({"ok": False, "error": "bad_verdict"}, status_code=400)
    from common.call_events import get_screen, mark_graded
    sub = str(user["sub"])
    event = get_screen(eid, account_sub=sub)
    if not event:
        return JSONResponse({"ok": False, "error": "not_found"}, status_code=404)
    mark_graded(eid, verdict, account_sub=sub)
    learn = None
    if verdict in ("block", "safe"):
        from common.grading import record_grade
        learn = record_grade("vishing", {
            "caller_id": event.get("caller_id"), "sender": event.get("caller_id"),
            "transcript": event.get("transcript") or f"[call from {event.get('caller_id')}]",
            "body": event.get("transcript") or "",
        }, verdict, source="call-log-grade", nudge=True)
    return JSONResponse({
        "ok": True, "verdict": verdict, "id": eid,
        "nudge": (learn or {}).get("nudge"),
        "buffered": (learn or {}).get("buffered"),
    })


@router.get("/app/inbox", response_class=HTMLResponse)
async def ui_inbox(request: Request):
    rows, counts = [], {"all": 0, "threat": 0, "cleared": 0}
    tz = _request_tz(request)
    hour12 = _request_hour12(request)
    account_sub = str((_current_user(request) or {}).get("sub") or "")
    try:
        from Autobot.VectorDB.NullPoint_Vector import get_threats_page
        from common.timefmt import format_local
        from common.pills import build_pills
        from common.explain import plain_english_math
        raw, _ = get_threats_page(
            threat_type=None, after_id=None, limit=80,
            account_sub=account_sub, max_confidence=0.85,
        )
        for r in (raw or []):
            conf = float(r.get("confidence") or 0)
            label = r.get("label")
            meta = r.get("metadata") or {}
            review = str(meta.get("review_status") or "")
            sender = r.get("sender") or "unknown"
            if label == 0 or review == "safe" or meta.get("safe_domain"):
                counts["cleared"] += 1
                continue
            threat = bool(r.get("is_threat")) or conf >= 0.35
            counts["threat" if threat else "cleared"] += 1
            ts_raw = r.get("timestamp") or ""
            subj = r.get("subject") or ""
            pack = build_pills(
                channel=r.get("threat_type") or "phishing",
                subject=subj,
                body="",
                sender=sender,
                confidence=conf,
                headers=meta.get("headers") or {},
                max_cats=3,
                max_reasons=4,
            )
            codes = pack["reason_codes"]
            why = plain_english_math(
                channel="phishing", content=subj, sender=sender,
                pred=1 if threat else 0, confidence=conf,
                reason_codes=codes, top_features=None,
            )
            rows.append({
                "id": r.get("id"),
                "sender": sender,
                "subject": subj,
                "channel": r.get("threat_type") or "phishing",
                "ts": format_local(ts_raw, tz, hour12=hour12, with_date=True),
                "ts_utc": ts_raw,
                "score": f"{int(conf*100)}%",
                "threat": threat,
                "tags": pack["tags"],
                "reason_codes": codes,
                "why": (why or {}).get("text") or "",
            })
        counts["all"] = counts["threat"] + counts["cleared"]
    except Exception as e:
        logger.warning("inbox unavailable: %s", e)
    return templates.TemplateResponse(
        request, "inbox.html",
        _ctx(request, active="inbox", rows=rows, counts=counts))


@router.get("/app/identity", response_class=HTMLResponse)
async def ui_identity(request: Request):
    import os
    vendors = {
        "plaid": bool(os.getenv("PLAID_CLIENT_ID") and os.getenv("PLAID_SECRET")),
        "credit": bool(os.getenv("ARRAY_API_KEY") or os.getenv("CREDIT_PARTNER_API_KEY")),
        "osint": bool(os.getenv("IPQS_API_KEY") or os.getenv("SPYCLOUD_API_KEY") or os.getenv("HIBP_API_KEY")),
    }
    return templates.TemplateResponse(
        request, "identity.html",
        _ctx(request, active="identity", vendors=vendors))


@router.post("/app/identity/enrich")
async def ui_identity_enrich(request: Request,
                             _rl: None = Depends(rate_limit())):
    """Console enrich (rate-limited). API clients use POST /api/v1/identity/enrich + JWT."""
    from fastapi.responses import JSONResponse
    body = await request.json()
    subject = str(body.get("subject") or "").strip()
    consented = bool(body.get("consented"))
    if not subject or not consented:
        return JSONResponse({"error": "consent_required", "reports": []}, status_code=400)
    from common.vendors.identity import enrich_identity_bundle
    return enrich_identity_bundle(
        subject=subject,
        consented=True,
        plaid_access_token=body.get("plaid_access_token"),
        credit_user_id=body.get("credit_user_id"),
    )


@router.get("/app/feed", response_class=HTMLResponse)
async def ui_feed(request: Request, channel: str = ""):
    """Recent detections below quarantine band (segmented from review queue)."""
    rows = []
    tz = _request_tz(request)
    hour12 = _request_hour12(request)
    account_sub = str((_current_user(request) or {}).get("sub") or "")
    try:
        from Autobot.VectorDB.NullPoint_Vector import get_threats_page
        from common.timefmt import format_local
        from common.pills import build_pills
        ch = channel if channel in CHANNELS else None
        raw, _ = get_threats_page(
            threat_type=ch, after_id=None, limit=12,
            account_sub=account_sub, max_confidence=0.85,
        )
        for r in (raw or []):
            conf = float(r.get("confidence") or 0)
            sender = r.get("sender") or ""
            subj = r.get("subject") or ""
            pack = build_pills(
                channel=r.get("threat_type") or "phishing",
                subject=subj,
                body="",
                sender=sender,
                confidence=conf,
                headers=(r.get("metadata") or {}).get("headers") or {},
                max_cats=2,
                max_reasons=3,
            )
            rows.append({
                **r,
                "ts_local": format_local(r.get("timestamp"), tz, hour12=hour12),
                "tags": pack["tags"],
                "reason_codes": pack["reason_codes"],
            })
    except Exception as e:
        logger.warning("ui feed unavailable: %s", e)
    return templates.TemplateResponse(request, "_feed.html", {"rows": rows or []})


@router.get("/app/connectors", response_class=HTMLResponse)
async def ui_connectors(request: Request):
    from common.oauth_email import connector_status
    from common.mailbox_store import list_for_user, ensure_table
    ensure_table()
    user = _current_user(request)
    sub = (user or {}).get("sub") or "anonymous"
    saved = list_for_user(sub)
    saved_providers = {
        str(row.get("provider") or "").strip().lower() for row in saved
    }
    # oauth_email keeps a process-local pilot status cache. Never render its
    # global account identity into another tenant's page; tenant persistence is
    # the source of truth for whether this user's provider is connected.
    connectors = []
    for raw in connector_status():
        row = dict(raw)
        provider = str(row.get("provider") or "").strip().lower()
        row["connected"] = provider in saved_providers
        row["account"] = ""
        connectors.append(row)
    connector_error = _CONNECTOR_ERRORS.get(request.query_params.get("err") or "")
    return templates.TemplateResponse(
        request, "connectors.html",
        _ctx(request, active="connectors", connectors=connectors,
             mailboxes=saved, account_sub=sub, connector_error=connector_error))


@router.post("/app/connectors/env/{provider}")
async def ui_connectors_env(provider: str, request: Request,
                            _rl: None = Depends(rate_limit())):
    from fastapi.responses import JSONResponse
    _user, err = _require_role_json(request, "admin")
    if err:
        return err
    from common.oauth_email import mark_env_connected
    result = mark_env_connected(provider)
    if not result.get("ok"):
        return JSONResponse({"ok": False, "error": "connector_unavailable"}, status_code=400)
    return JSONResponse({"ok": True, "provider": result.get("provider") or provider})


@router.post("/app/connectors/app-password")
async def ui_connectors_app_password(
        request: Request,
        provider: str = Form(...),
        account_email: str = Form(...),
        app_password: str = Form(...),
        _rl: None = Depends(rate_limit())):
    """Save encrypted per-user app password (Yahoo / Gmail IMAP)."""
    from fastapi.responses import JSONResponse
    from common.mailbox_store import upsert_app_password
    user = _current_user(request)
    if not user:
        return JSONResponse({"ok": False, "error": "login_required"}, status_code=401)
    result = upsert_app_password(
        account_sub=str(user["sub"]),
        provider=provider,
        account_email=account_email,
        app_password=app_password,
    )
    code = 200 if result.get("ok") else 400
    return JSONResponse(result, status_code=code)


@router.post("/app/connectors/request-provider")
async def ui_connectors_request_provider(
        request: Request,
        provider_name: str = Form(...),
        imap_host: str = Form(""),
        notes: str = Form(""),
        _rl: None = Depends(rate_limit())):
    """Log a request for another IMAP provider (modular fetcher backlog)."""
    from fastapi.responses import JSONResponse
    import json
    from pathlib import Path
    user = _current_user(request)
    if not user:
        return JSONResponse({"ok": False, "error": "login_required"}, status_code=401)
    name = (provider_name or "").strip()[:80]
    if len(name) < 2:
        return JSONResponse({"ok": False, "error": "need_provider_name"}, status_code=400)
    entry = {
        "account_sub": str(user["sub"]),
        "provider_name": name,
        "imap_host": (imap_host or "").strip()[:120],
        "notes": (notes or "").strip()[:240],
    }
    try:
        path = Path("data/provider_requests.jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        logger.info("provider request: %s from %s", name, user.get("sub"))
    except Exception as e:
        logger.error("provider request write failed: %s", e)
        return JSONResponse({"ok": False, "error": "write_failed"}, status_code=500)
    return JSONResponse({"ok": True, "provider": name})


@router.post("/app/connectors/oauth/{provider}")
async def ui_connectors_oauth_start(provider: str, request: Request,
                                    consented: str = Form("")):
    from fastapi.responses import JSONResponse, RedirectResponse
    from common.oauth_email import start_oauth
    user = _current_user(request)
    if not user:
        return RedirectResponse("/app/login?next=/app/connectors", status_code=303)
    if consented.lower() not in ("1", "true", "yes", "on"):
        return JSONResponse({"ok": False, "error": "consent_required"}, status_code=400)
    result = start_oauth(provider, account_sub=str(user["sub"]))
    if result.get("authorize_url"):
        # Convert the consent POST to a provider authorization GET. A 307/308
        # would replay the form body (including our CSRF token) cross-origin.
        return RedirectResponse(result["authorize_url"], status_code=303)
    logger.warning("mailbox OAuth start failed [%s]: %s", provider,
                   result.get("error") or "oauth_unavailable")
    return JSONResponse(
        {"ok": False, "error": "connector_unavailable"}, status_code=400,
    )


@router.get("/app/connectors/callback/{provider}")
async def ui_connectors_oauth_callback(provider: str, code: str = "", state: str = "",
                                       error: str = ""):
    from fastapi.responses import RedirectResponse
    from common.oauth_email import finish_oauth
    if error or not code:
        return RedirectResponse("/app/connectors?err=oauth_denied")
    result = finish_oauth(provider, code, state)
    if result.get("ok"):
        return RedirectResponse("/app/connectors?ok=1")
    logger.warning("mailbox OAuth callback failed [%s]: %s", provider,
                   result.get("error") or "oauth_failed")
    return RedirectResponse("/app/connectors?err=oauth_failed")


@router.get("/app/calls", response_class=HTMLResponse)
async def ui_calls(request: Request):
    from fastapi.responses import RedirectResponse
    user, err = _require_role_json(request, "analyst")
    if err:
        # HTML route: send browsers to login instead of a bare JSON 401.
        if getattr(err, "status_code", None) == 401:
            return RedirectResponse("/app/login?next=/app/calls", status_code=303)
        return err
    from common.call_events import list_screens
    return templates.TemplateResponse(
        request, "calls.html",
        _ctx(request, active="calls",
             events=list_screens(80, account_sub=str(user["sub"]))))
