"""
FastAPI Main Application
Provides REST API endpoints for Yahoo_Phish IDPS
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging
from urllib.parse import urlparse
import re

from Autobot.VectorDB.NullPoint_Vector import (
    search_similar_threats,
    store_threat,
    get_threat_by_id,
    get_all_threats
)
from PhishGuard.phish_mlm.phishing_detector import PhishingDetector

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI(
    title="Yahoo_Phish IDPS API",
    description="Intrusion Detection Prevention System for Phishing/Smishing/Vishing",
    version="1.0.0"
)

# CORS middleware for Dash UI integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8050", "http://127.0.0.1:8050"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Heuristic keywords & suspicious TLDs
SUSPICIOUS_KEYWORDS = ["urgent", "action required", "verify", "compromised", "password", "account locked", "confirm", "bank", "login", "update"]
SUSPICIOUS_TLDS = ["ru", "cn", "top", "lol", "zip", "xyz"]
BRAND_DOMAINS = {"bankofamerica.com", "chase.com", "wellsfargo.com", "paypal.com"}

# Utility: Simple heuristic risk scoring
def heuristic_score(content: str, sender: Optional[str]) -> float:
    if not content:
        return 0.0
    text = content.lower()
    score = 0.0
    # Keyword hits
    kw_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in text)
    if kw_hits:
        score += min(0.4, 0.1 * kw_hits)
    # URL extraction
    urls = re.findall(r'https?://[^\s]+', content)
    for u in urls:
        try:
            parsed = urlparse(u)
            domain = parsed.hostname or ''
            # Hyphen spoof (e.g. evil-bank.com)
            if '-' in domain and any(b.split('.')[0] in domain for b in BRAND_DOMAINS):
                score += 0.25
            tld = domain.split('.')[-1]
            if tld in SUSPICIOUS_TLDS:
                score += 0.2
            # Brand mismatch (sender domain vs content domain)
            if sender and '@' in sender:
                sender_domain = sender.split('@')[-1].lower()
                if sender_domain != domain and any(b in domain for b in BRAND_DOMAINS):
                    score += 0.15
        except Exception:
            continue
    # Cap score
    return min(score, 0.95)

# Seeding dataset for initial similarity
SEED_THREATS = [
    {
        "content": "URGENT: Your account has been suspended. Verify now: http://secure-login-update.com",
        "sender": "support@secure-login-update.com",
        "threat_type": "phishing",
        "metadata": {"subject": "Account Suspension Notice", "template": True}
    },
    {
        "content": "Action Required: Confirm your banking credentials at https://account-verification-paypal.top",
        "sender": "service@paypal-security.com",
        "threat_type": "phishing",
        "metadata": {"subject": "PayPal Verification", "template": True}
    },
    {
        "content": "We detected unusual activity. Login immediately: http://login-update-secure.xyz",
        "sender": "alert@security-update.com",
        "threat_type": "phishing",
        "metadata": {"subject": "Unusual Activity Detected", "template": True}
    },
    {
        "content": "Your mobile carrier bill is overdue. Pay now to avoid service interruption: http://carrier-pay-now.cn",
        "sender": "billing@carrier-support.cn",
        "threat_type": "smishing",
        "metadata": {"subject": "Overdue Bill", "template": True}
    }
]

class ThreatAnalysisRequest(BaseModel):
    content: str = Field(..., min_length=1, description="Content to analyze (email/SMS/voice)")
    sender: Optional[str] = Field(None, description="Sender identifier (email/phone)")
    threat_type: str = Field(..., pattern="^(phishing|smishing|vishing)$", description="Type of threat")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")

class ThreatAnalysisResponse(BaseModel):
    threat_id: str
    is_threat: bool
    confidence_score: float
    threat_type: str
    similar_threats: List[Dict[str, Any]]
    analysis_time: str
    recommendations: List[str]

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    database: str
    vector_db: str

class SeedResponse(BaseModel):
    inserted: int
    already_present: int
    total_after: int

class RetrainResponse(BaseModel):
    started: bool
    timestamp: str

# Health Check Endpoint
@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint to verify API and database connectivity
    """
    try:
        # Test database connection
        from Autobot.VectorDB.NullPoint_Vector import connect_db
        conn = connect_db()
        db_status = "healthy" if conn else "unhealthy"
        if conn:
            conn.close()
        
        return HealthResponse(
            status="healthy",
            timestamp=datetime.now().isoformat(),
            database=db_status,
            vector_db="operational"
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail=f"Service unavailable: {str(e)}")

@app.get("/")
async def root():
    """
    Root endpoint with API information
    """
    return {
        "message": "Yahoo_Phish IDPS API",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "docs": "/docs",
            "analyze": "/api/v1/analyze",
            "threats": "/api/v1/threats",
            "seed": "/api/v1/seed",
            "retrain": "/api/v1/retrain"
        }
    }

# API v1 Endpoints
@app.post("/api/v1/analyze", response_model=ThreatAnalysisResponse)
async def analyze_content(
    request: ThreatAnalysisRequest,
    background_tasks: BackgroundTasks
):
    """
    Analyze content for phishing/smishing/vishing threats
    
    Uses vector similarity search to find similar known threats
    and ML models to classify new content.
    """
    try:
        start_time = datetime.now()
        # Heuristic first
        h_score = heuristic_score(request.content, request.sender)
        similar_threats = search_similar_threats(
            content=request.content,
            threat_type=request.threat_type,
            top_k=5
        )
        similarity_score = 0.0
        if similar_threats:
            # If we find very similar known threats, flag as threat
            max_similarity = max(t.get('similarity', 0) for t in similar_threats)
            similarity_score = max_similarity
            is_threat = max_similarity > 0.75  # 75% similarity threshold
        else:
            is_threat = h_score > 0.6  # Heuristic fallback
        
        # Combined scoring (weighted average)
        combined_score = (h_score * 0.4) + (similarity_score * 0.6)
        
        # Generate threat ID
        threat_id = f"{request.threat_type}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        if is_threat:
            background_tasks.add_task(
                store_threat,
                content=request.content,
                threat_type=request.threat_type,
                sender=request.sender or "unknown",
                metadata={"heuristic": h_score, "similarity": similarity_score, "label": 1, **(request.metadata or {})}
            )
        else:
            # Optionally store for corpus building (unlabeled)
            if request.metadata.get("store_unlabeled", True) if request.metadata else True:
                background_tasks.add_task(
                    store_threat,
                    content=request.content,
                    threat_type=request.threat_type,
                    sender=request.sender or "unknown",
                    metadata={"heuristic": h_score, "similarity": similarity_score, "label": 0, "unlabeled": True, **(request.metadata or {})}
                )
        recommendations = []
        if is_threat:
            recommendations.extend([
                "🚨 This content matches threat patterns",
                "⚠️ Do NOT interact with links or provide info",
                f"🧪 Heuristic score: {h_score:.2f} | Similarity: {similarity_score:.2f}",
            ])
            if request.sender:
                recommendations.append(f"🚫 Block sender: {request.sender}")
        else:
            recommendations.extend([
                "✅ No immediate threat detected",
                f"ℹ️ Heuristic score: {h_score:.2f} | Similarity: {similarity_score:.2f}",
                "⚠️ Stay cautious with unsolicited messages"
            ])
        analysis_time = (datetime.now() - start_time).total_seconds()
        return ThreatAnalysisResponse(
            threat_id=threat_id,
            is_threat=is_threat,
            confidence_score=combined_score,
            threat_type=request.threat_type,
            similar_threats=similar_threats,
            analysis_time=f"{analysis_time:.3f}s",
            recommendations=recommendations
        )
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")

@app.get("/api/v1/threats")
async def list_threats(
    threat_type: Optional[str] = None,
    limit: int = 100
):
    """
    List all detected threats
    
    Optionally filter by threat type (phishing/smishing/vishing)
    """
    try:
        threats = get_all_threats(threat_type=threat_type, limit=limit)
        return {
            "total": len(threats),
            "threats": threats,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to list threats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/threats/{threat_id}")
async def get_threat_details(threat_id: str):
    """
    Get details of a specific threat by ID
    """
    try:
        threat = get_threat_by_id(threat_id)
        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")
        return threat
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get threat: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/threats/report")
async def report_threat(
    content: str,
    threat_type: str,
    sender: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
):
    """
    Manually report a new threat
    
    This allows users to submit threats that weren't automatically detected
    """
    try:
        result = store_threat(
            content=content,
            threat_type=threat_type,
            sender=sender or "user_reported",
            metadata=metadata or {}
        )
        
        return {
            "status": "success",
            "message": "Threat reported successfully",
            "threat_id": result.get("id"),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to report threat: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/seed", response_model=SeedResponse)
async def seed_threats():
    from Autobot.VectorDB.NullPoint_Vector import get_all_threats
    existing = get_all_threats(limit=5_000)
    existing_contents = {t["id"] for t in existing}
    inserted = 0
    for sample in SEED_THREATS:
        try:
            store_threat(**sample)
            inserted += 1
        except Exception:
            continue
    total_after = len(get_all_threats(limit=5_000))
    return SeedResponse(inserted=inserted, already_present=len(existing_contents), total_after=total_after)

@app.post("/api/v1/retrain", response_model=RetrainResponse)
async def retrain_model(background_tasks: BackgroundTasks):
    def _train():
        detector = PhishingDetector(use_nn=False)
        detector.detect_threats()
    background_tasks.add_task(_train)
    return RetrainResponse(started=True, timestamp=datetime.now().isoformat())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
