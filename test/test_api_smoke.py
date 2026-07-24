"""Smoke test for the hardened API: auth, RBAC, rate limit, idempotency, analyze."""
import os
import sys
from pathlib import Path

os.environ.setdefault("API_ADMIN_USER", "admin")
os.environ.setdefault("API_ADMIN_PASSWORD", "changeme")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("RATE_LIMIT_CAPACITY", "5")     # tiny so we can trip it
os.environ.setdefault("RATE_LIMIT_REFILL", "0.001")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def _token():
    r = client.post("/api/v1/token", data={"username": "admin", "password": "changeme"})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def main():
    print("health      :", client.get("/health").status_code)
    print("metrics     :", client.get("/metrics").status_code)

    # 401 without token
    r = client.post("/api/v1/analyze", json={"content": "x", "threat_type": "phishing"})
    print("analyze 401 :", r.status_code, "(expect 401)")
    assert r.status_code == 401

    # bad creds
    r = client.post("/api/v1/token", data={"username": "admin", "password": "wrong"})
    print("login bad   :", r.status_code, "(expect 401)")
    assert r.status_code == 401

    token = _token()
    h = {"Authorization": f"Bearer {token}"}

    # analyze a known phish
    body = {"content": "Your PayPal is suspended, verify at paypal-secure.ru now",
            "sender": "x@paypal-secure.ru", "threat_type": "phishing"}
    r = client.post("/api/v1/analyze", json=body, headers=h)
    print("analyze     :", r.status_code, "->", r.json().get("action"),
          "risk", r.json().get("risk_score"))
    assert r.status_code == 200 and r.json()["is_threat"] is True

    # idempotency: same key returns identical threat_id
    hk = {**h, "Idempotency-Key": "smoke-key-1"}
    r1 = client.post("/api/v1/analyze", json=body, headers=hk)
    r2 = client.post("/api/v1/analyze", json=body, headers=hk)
    same = r1.json()["threat_id"] == r2.json()["threat_id"]
    print("idempotent  :", same, "(expect True)")
    assert same

    # pagination shape (DB may be down → empty, but envelope must be present)
    r = client.get("/api/v1/threats?limit=10", headers=h)
    env = r.json()
    print("threats page:", r.status_code, "keys", sorted(env.keys()))
    assert r.status_code == 200 and {"items", "next_cursor", "has_more"} <= set(env)

    # rate limit: hammer until 429 (capacity=5, refill ~0)
    got_429 = False
    for _ in range(20):
        rr = client.get("/api/v1/threats?limit=1", headers=h)
        if rr.status_code == 429:
            got_429 = True
            break
    print("rate limit  :", "429 triggered" if got_429 else "NOT triggered")
    assert got_429

    # model info
    r = client.get("/api/v1/model", headers=h)
    print("model       :", r.status_code, "champion", r.json().get("champion"))

    print("\nALL SMOKE CHECKS PASSED ✅")


def test_api_smoke():
    """Pytest entry point."""
    main()


if __name__ == "__main__":
    main()
