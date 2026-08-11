"""
FastAPI service for the Yahoo_Phish IDPS.

Production hardening (System-Design-Engineering-Universal-Reference aligned):
  - AuthN/Z      : JWT bearer + hierarchical RBAC (viewer < analyst < admin)
  - Rate limiting: O(1) token bucket per caller (429 + Retry-After)
  - Pagination   : keyset/cursor on /threats (O(log N) deep pages)
  - Idempotency  : Idempotency-Key header on writes (replay-safe)
  - Observability: Prometheus /metrics + structured access logs + latency hist
  - Detection    : unified classifier + anomaly verdict (risk.assess), with
                   vector similarity as a supplementary signal
  - Safe retrain : champion/challenger Trainer (gated promotion) in background
"""
import logging
import os as _os_sec
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import (BackgroundTasks, Depends, FastAPI, Header, HTTPException,
                     Request, Response, status)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

from Autobot.VectorDB.NullPoint_Vector import (
    search_similar_threats, store_threat, get_threat_by_id, get_threats_page,
    get_vish_directory,
)
from PhishGuard.phish_mlm.phishing_detector import detector
from common.streaming.channel_pipeline import process_one
from common.streaming.dlq import persist_threat_durable, start_dlq_drainer, depth as dlq_depth

from common.auth import (authenticate_user, create_access_token,
                         create_refresh_token, refresh_access_token,
                         get_current_user, require_role)
from common.rate_limit import rate_limit
from common.idempotency import build_idempotency_store, idempotent, DuplicateRequestError
from common.pagination import decode_cursor, page_envelope
from common.observability import ObservabilityMiddleware, metrics_response
from common.config import validate_production_config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("api")

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Validate config, pre-fit anomaly manifolds off the request hot path.

    Uses the modern lifespan protocol (the deprecated @app.on_event hook is
    removed) so the startup sequence stays future-proof on current FastAPI.
    """
    validate_production_config()
    import threading
    from common.streaming.channel_pipeline import warm_anomaly
    threading.Thread(target=warm_anomaly, name="warm-anomaly", daemon=True).start()
    # Self-healing: drain any threats that were dead-lettered during a DB outage
    # back into Postgres once it recovers (no data loss across restarts).
    start_dlq_drainer("threat", interval=30.0)
    yield


app = FastAPI(
    title="Yahoo_Phish IDPS API",
    description="Intrusion Detection & Prevention for Phishing/Smishing/Vishing",
    version="2.0.0",
    lifespan=lifespan,
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Baseline OWASP response headers for every route."""

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
        )
        if _os_sec.getenv("FORCE_HSTS", "").lower() in ("1", "true"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(ObservabilityMiddleware)

# Premium server-rendered console (Jinja + vanilla JS), mounted under /app.
# Kept optional so a missing template dir / jinja2 never blocks the API boot.
try:
    from pathlib import Path as _Path
    from fastapi.staticfiles import StaticFiles
    from web.ui import router as _ui_router
    app.mount("/static", StaticFiles(directory=str(_Path(__file__).resolve().parent.parent / "web" / "static")), name="static")
    app.include_router(_ui_router)
    logger.info("UI console mounted at /app")
except Exception as _ui_err:  # pragma: no cover
    logger.warning("UI console not mounted: %s", _ui_err)

# Allowed browser origins. Behind the single-ingress reverse proxy the UI and API
# are same-origin (no CORS hit), but direct API access / cloud subdomains need
# this. Configure via API_ALLOWED_ORIGINS (comma-separated) for ngrok/cloud.
import os as _os
_default_origins = "http://localhost:8088,http://127.0.0.1:8088"
_allowed_origins = [o.strip() for o in
                    _os.getenv("API_ALLOWED_ORIGINS", _default_origins).split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_origin_regex=_os.getenv("API_ALLOWED_ORIGIN_REGEX") or None,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Idempotency store: Redis when REDIS_URL set, else in-memory (single instance).
_idem = build_idempotency_store()


# ============================================================ models
class ThreatAnalysisRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=50_000, description="Content to analyze")
    sender: Optional[str] = Field(None, max_length=256, description="Sender email/phone")
    threat_type: str = Field(..., pattern="^(phishing|smishing|vishing)$")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ThreatAnalysisResponse(BaseModel):
    threat_id: str
    is_threat: bool
    action: str
    risk_score: float
    classifier_pred: int
    classifier_conf: float
    anomaly_level: str
    anomaly_novelty: float
    threat_type: str
    similar_threats: List[Dict[str, Any]]
    reasons: List[str]
    analysis_time: str


class FeedbackRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=50_000)
    is_phishing: bool
    sender: Optional[str] = Field(None, max_length=256)


class CallScreenRequest(BaseModel):
    """CallKit → VishGuard event (the R1 hybrid contract).

    See docs/CALLKIT_DATA_CONTRACT.md. `transcript` is optional: present → the
    deep content path runs; absent → reputation-only live screening.
    """
    caller_id: str = Field(..., min_length=1, max_length=32, description="E.164 or alphanumeric sender id")
    phase: str = Field("incoming", pattern="^(incoming|voicemail|post_call)$")
    transcript: Optional[str] = Field(None, max_length=20_000, description="Voicemail/call transcript (deep path)")
    direction: str = Field("inbound", pattern="^(inbound|outbound)$")
    contact_known: bool = False
    carrier_verified: Optional[bool] = Field(None, description="STIR/SHAKEN attestation result")
    timestamp: Optional[str] = Field(None, max_length=64)
    device_id: Optional[str] = Field(None, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"


# ============================================================ public routes
@app.get("/health")
async def health_check():
    try:
        from Autobot.VectorDB.NullPoint_Vector import connect_db
        conn = connect_db()
        db_status = "healthy" if conn else "unhealthy"
        if conn:
            conn.close()
    except Exception as e:
        db_status = f"unhealthy: {e}"
    # DLQ depth surfaces self-heal backlog: >0 means the DB was down and threats
    # are buffered durably, waiting for the drainer to replay them.
    try:
        pending = dlq_depth("threat")
    except Exception:
        pending = -1
    return {"status": "healthy", "timestamp": datetime.now().isoformat(),
            "database": db_status, "model_loaded": detector.clf is not None,
            "dlq_pending_threats": pending}


@app.get("/")
async def root():
    return {
        "service": "Yahoo_Phish IDPS API", "version": "2.0.0",
        "auth": "POST /api/v1/token (OAuth2 password) → Bearer JWT",
        "endpoints": ["/health", "/metrics", "/docs", "/api/v1/analyze",
                      "/api/v1/threats", "/api/v1/feedback", "/api/v1/retrain",
                      "/api/v1/model"],
    }


@app.get("/metrics")
async def metrics():
    body, content_type = metrics_response()
    return Response(content=body, media_type=content_type)


# ============================================================ auth routes
@app.post("/api/v1/token", response_model=TokenResponse)
async def login(form: OAuth2PasswordRequestForm = Depends(),
                _rl: None = Depends(rate_limit())):
    user = authenticate_user(form.username, form.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Incorrect username or password")
    return TokenResponse(
        access_token=create_access_token(user),
        refresh_token=create_refresh_token(user),
    )


@app.post("/api/v1/token/refresh", response_model=TokenResponse)
async def refresh(refresh_token: str = Header(..., alias="X-Refresh-Token"),
                  _rl: None = Depends(rate_limit())):
    new_access = refresh_access_token(refresh_token)
    if not new_access:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid refresh token")
    return TokenResponse(access_token=new_access)


# ============================================================ detection
def _run_analysis(req: ThreatAnalysisRequest) -> ThreatAnalysisResponse:
    start = datetime.now()
    # Route to the correct per-channel detector (phishing/smishing/vishing).
    # process_one normalizes the record and applies the channel's anomaly policy.
    record = {"subject": req.metadata.get("subject", "") if req.metadata else "",
              "body": req.content, "transcript": req.content,
              "from": req.sender or "", "caller_id": req.sender or ""}

    verdict = process_one(req.threat_type, record)

    similar = search_similar_threats(content=req.content,
                                     threat_type=req.threat_type, top_k=5) or []

    threat_id = f"{req.threat_type}_{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
    elapsed = (datetime.now() - start).total_seconds()
    return ThreatAnalysisResponse(
        threat_id=threat_id, is_threat=verdict.is_threat, action=verdict.action.value,
        risk_score=verdict.risk_score, classifier_pred=verdict.classifier_pred,
        classifier_conf=verdict.classifier_conf, anomaly_level=verdict.anomaly_level,
        anomaly_novelty=verdict.anomaly_novelty, threat_type=req.threat_type,
        similar_threats=similar, reasons=verdict.reasons,
        analysis_time=f"{elapsed:.3f}s",
    )


@app.post("/api/v1/analyze", response_model=ThreatAnalysisResponse)
async def analyze_content(
    request: ThreatAnalysisRequest,
    background_tasks: BackgroundTasks,
    user: Dict = Depends(require_role("analyst")),
    _rl: None = Depends(rate_limit()),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    """Unified classifier + anomaly verdict. Idempotent when Idempotency-Key is set."""
    def _do() -> ThreatAnalysisResponse:
        resp = _run_analysis(request)
        if resp.is_threat:
            # Durable persist: retried, and dead-lettered (never dropped) if the
            # DB is momentarily down; the drainer replays it when DB is back.
            background_tasks.add_task(
                persist_threat_durable, content=request.content,
                threat_type=request.threat_type, sender=request.sender or "unknown",
                metadata={"risk_score": resp.risk_score, "action": resp.action,
                          "label": 1, **(request.metadata or {})})
        return resp

    if not idempotency_key:
        return _do()
    try:
        with idempotent(_idem, idempotency_key) as ctx:
            if ctx.already_completed:
                return ctx.stored_result
            ctx.result = _do()
        return ctx.result
    except DuplicateRequestError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@app.post("/api/v1/vish/screen")
async def screen_call_endpoint(
    request: CallScreenRequest,
    background_tasks: BackgroundTasks,
    user: Dict = Depends(require_role("analyst")),
    _rl: None = Depends(rate_limit()),
):
    """Hybrid CallKit screening (R1): reputation (number) + transcription (content).

    Always runs the reputation path on `caller_id`; runs the VishGuard content path
    when a `transcript` is supplied. Returns one recommended CallKit action
    (allow/label/silence/block) with consumer-readable reasons. A confirmed threat
    is persisted durably (DLQ-safe) so the number feeds back into local reputation.
    """
    from common.vish import screen_call, CallEvent
    result = screen_call(CallEvent.from_dict(request.model_dump()))
    try:
        from common.call_events import record_screen
        record_screen(result.to_dict() | {"caller_id": request.caller_id,
                                          "transcript": request.transcript or ""})
    except Exception:
        pass
    if result.is_threat:
        meta = {
            "risk_score": result.risk,
            "action": result.action.value,
            "label": 1,
            "channel": "vishing",
            "verdict": result.verdict,
            "paths": result.paths,
            "via": "callkit",
        }
        background_tasks.add_task(
            persist_threat_durable,
            content=request.transcript or f"[call from {request.caller_id}]",
            threat_type="vishing", sender=request.caller_id or "unknown",
            metadata=meta,
        )
        # Fan-out: callback TFNs / spoken numbers in the transcript join the directory.
        try:
            from common.vish.phones import extract_e164_numbers
            for cb in extract_e164_numbers(
                request.transcript, exclude=[request.caller_id]
            ):
                background_tasks.add_task(
                    persist_threat_durable,
                    content=f"[callback from transcript of {request.caller_id}] {request.transcript or ''}"[:2000],
                    threat_type="vishing",
                    sender=cb,
                    metadata={
                        **meta,
                        "via": "transcript-callback",
                        "parent_caller_id": request.caller_id,
                        "action": "block",
                    },
                )
        except Exception:
            pass
    return result.to_dict()


@app.get("/api/v1/vish/directory")
async def vish_directory_endpoint(
    user: Dict = Depends(require_role("analyst")),
    _rl: None = Depends(rate_limit()),
):
    """Call Directory block/label sync payload for iOS CallKit extension."""
    updated_at, block, label = get_vish_directory()
    return {"updatedAt": updated_at, "block": block, "label": label}


@app.get("/api/v1/vish/screens")
async def vish_screens_endpoint(
    limit: int = 40,
    user: Dict = Depends(require_role("analyst")),
    _rl: None = Depends(rate_limit()),
):
    """Recent hybrid screen events for Guard activity feed."""
    from common.call_events import list_screens
    n = max(1, min(int(limit or 40), 80))
    return {"events": list_screens(n)}


class IdentityEnrichRequest(BaseModel):
    subject: str = Field(..., min_length=3, max_length=320)
    consented: bool = False
    plaid_access_token: Optional[str] = Field(None, max_length=512)
    credit_user_id: Optional[str] = Field(None, max_length=128)


@app.post("/api/v1/identity/enrich")
async def identity_enrich(
    req: IdentityEnrichRequest,
    user: Dict = Depends(require_role("customer")),
    _rl: None = Depends(rate_limit()),
):
    """Consent-gated Plaid + Array/credit + breach OSINT bundle (fail-open)."""
    if not req.consented:
        raise HTTPException(status_code=400, detail="consent_required")
    from common.vendors.identity import enrich_identity_bundle
    return enrich_identity_bundle(
        subject=req.subject.strip(),
        consented=True,
        plaid_access_token=req.plaid_access_token,
        credit_user_id=req.credit_user_id,
    )


@app.post("/api/v1/feedback")
async def submit_feedback(req: FeedbackRequest,
                          user: Dict = Depends(require_role("analyst")),
                          _rl: None = Depends(rate_limit())):
    """
    Record a human label. SAFE by design: this only appends to the durable
    feedback buffer (+ ephemeral in-memory update). The on-disk champion changes
    only when /retrain runs and the candidate passes the golden gate.
    """
    email = {"subject": "", "body": req.content, "from": req.sender or ""}
    detector.learn_from_feedback(email, req.is_phishing)
    return {"status": "recorded", "buffered": True,
            "note": "folded into next gated retrain", "by": user["user_id"]}


# ============================================================ threats (read)
@app.get("/api/v1/threats")
async def list_threats(
    threat_type: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
    user: Dict = Depends(get_current_user),
    _rl: None = Depends(rate_limit()),
):
    """Keyset-paginated threat list. Pass back `next_cursor` for the next page."""
    after_id = decode_cursor(cursor)
    rows, next_id = get_threats_page(threat_type=threat_type,
                                     after_id=after_id, limit=limit)
    return page_envelope(rows, next_id, limit)


@app.get("/api/v1/threats/{threat_id}")
async def get_threat_details(threat_id: str,
                             user: Dict = Depends(get_current_user),
                             _rl: None = Depends(rate_limit())):
    threat = get_threat_by_id(threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return threat


@app.post("/api/v1/reports")
async def api_user_report(
    request: Request,
    user: Dict = Depends(get_current_user),
    _rl: None = Depends(rate_limit()),
):
    """JWT user report path (iOS / API clients). Same fleet rules as /app/report."""
    body = await request.json()
    mid = body.get("message_id") or body.get("mid")
    mid_i = int(mid) if str(mid or "").isdigit() else None
    exp = body.get("expected")
    if isinstance(exp, str):
        exp = exp.lower() in ("1", "true", "yes")
    reasons = body.get("reasons") or []
    if isinstance(reasons, str):
        reasons = [x.strip() for x in reasons.split(",") if x.strip()]
    from common.user_reports import submit_user_report
    out = submit_user_report(
        message_id=mid_i,
        account_sub=str(user.get("sub") or "")[:128],
        channel=str(body.get("channel") or "email"),
        sender=str(body.get("sender") or ""),
        expected=exp if isinstance(exp, bool) else None,
        reasons=list(reasons),
        detail=body.get("detail"),
    )
    if not out.get("ok"):
        raise HTTPException(
            status_code=400 if out.get("error") == "empty_report" else 500,
            detail=out.get("error") or "failed",
        )
    return {"ok": True, "id": out.get("id"), "fleet": out.get("fleet") or {}}


@app.post("/api/v1/threats/report")
async def report_threat(
    content: str, threat_type: str, sender: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    user: Dict = Depends(require_role("analyst")),
    _rl: None = Depends(rate_limit()),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    def _do():
        result = store_threat(content=content, threat_type=threat_type,
                              sender=sender or "user_reported", metadata=metadata or {})
        if not isinstance(result, dict) or result.get("error"):
            # DB unavailable: buffer durably so the user report is never lost.
            from common.streaming.dlq import dead_letter
            dead_letter("threat", {"content": content, "threat_type": threat_type,
                                   "sender": sender or "user_reported",
                                   "metadata": metadata or {}})
            return {"status": "queued", "threat_id": None,
                    "note": "buffered (DB unavailable); will persist on recovery",
                    "timestamp": datetime.now().isoformat()}
        return {"status": "success", "threat_id": result.get("id"),
                "timestamp": datetime.now().isoformat()}

    if not idempotency_key:
        return _do()
    try:
        with idempotent(_idem, idempotency_key) as ctx:
            if ctx.already_completed:
                return ctx.stored_result
            ctx.result = _do()
        return ctx.result
    except DuplicateRequestError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


# ============================================================ admin / model ops
@app.get("/api/v1/model")
async def model_info(user: Dict = Depends(get_current_user)):
    """Champion version + its golden-eval metrics from the registry."""
    try:
        from PhishGuard.phish_mlm.training.registry import ModelRegistry
        from PhishGuard.phish_mlm.phishing_detector import MODEL_DIR
        reg = ModelRegistry(MODEL_DIR)
        return {"champion": reg.current_version(),
                "versions": reg.list_versions(),
                "metrics": reg.champion_metrics(),
                "calibrated": detector.platt is not None}
    except Exception as e:
        # Do not leak internal exception text to clients (info-disclosure).
        logger.error("model_info failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="model registry unavailable")


@app.post("/api/v1/retrain")
async def retrain_model(background_tasks: BackgroundTasks,
                        force: bool = False,
                        user: Dict = Depends(require_role("admin"))):
    """
    Kick off a champion/challenger retrain. The candidate is promoted ONLY if it
    clears the golden gate and does not regress vs the current champion.
    """
    def _train():
        try:
            from PhishGuard.phish_mlm.training.trainer import Trainer
            result = Trainer().run(force_promote=force)
            logger.info(f"retrain: version={result.version} promoted={result.promoted} "
                        f"reason={result.reason}")
        except Exception as e:
            logger.error(f"retrain failed: {e}", exc_info=True)

    background_tasks.add_task(_train)
    return {"started": True, "by": user["user_id"], "timestamp": datetime.now().isoformat()}


@app.post("/api/v1/billing/webhook")
async def billing_webhook(request: Request):
    """Stripe (or mock) webhook — signature required. Vendor HMAC, not CSRF."""
    from common.billing import verify_stripe_webhook, append_audit_event, use_mock
    payload = await request.body()
    sig = request.headers.get("stripe-signature") or request.headers.get("Stripe-Signature") or ""
    verified = verify_stripe_webhook(payload, sig)
    if not verified.get("ok"):
        raise HTTPException(status_code=400, detail=verified.get("error") or "bad_webhook")
    event = verified.get("event") or {}
    etype = event.get("type") if isinstance(event, dict) else getattr(event, "type", "unknown")
    try:
        from Autobot.VectorDB.NullPoint_Vector import connect_db
        conn = connect_db()
        if conn:
            append_audit_event(
                conn,
                stream_id=f"webhook:{(etype or 'evt')[:48]}",
                event_type="webhook_received",
                payload={"type": etype, "mock": bool(verified.get("mock"))},
                provider="mock" if use_mock() else "stripe",
            )
            conn.close()
    except Exception as e:
        logger.warning("webhook audit failed: %s", e)
    return {"ok": True, "type": etype}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
