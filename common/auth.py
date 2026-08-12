"""
JWT authentication + RBAC for FastAPI.

- Secrets come ONLY from the environment (never hardcoded).
- Access tokens are short-lived; refresh tokens rotate them without re-login.
- `get_current_user` is a FastAPI dependency you attach to protected routes.
- `require_role(...)` enforces hierarchical RBAC.

Adapted from System-Design-Engineering-Universal-Reference/security/auth_framework.py.
Install: pip install "PyJWT[crypto]" passlib[bcrypt]
"""
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

try:
    import jwt
    from jwt import InvalidTokenError as JWTError
except ImportError:  # pragma: no cover - dependency guard
    JWTError = Exception
    jwt = None

try:
    from passlib.context import CryptContext
    # pbkdf2_sha256 is pure-Python and avoids the passlib+bcrypt>=4.1 backend
    # detection bug; bcrypt is kept (deprecated) so legacy hashes still verify.
    _pwd = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")
except Exception:  # pragma: no cover
    _pwd = None

# --------------------------------------------------------------------- config
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "CHANGE_ME_IN_PRODUCTION")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
# 0 or negative → access tokens omit `exp` (never expire until JWT_SECRET_KEY rotates).
ACCESS_TTL_MIN = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TTL_DAYS = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Role hierarchy: higher rank satisfies lower requirements.
# viewer   — read-only (B2C feed, health)
# customer — B2C app user (analyze own content, device token)
# analyst  — write paths, screen calls, feedback
# admin    — retrain, destructive ops
# enterprise — B2B API + audit (same as admin today; split when SSO lands)
_ROLE_RANK = {"viewer": 0, "customer": 1, "analyst": 2, "admin": 3, "enterprise": 4}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/token", auto_error=False)


# ----------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    if _pwd is None:
        raise RuntimeError("passlib not installed")
    return _pwd.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    if _pwd is None:
        return False
    try:
        return _pwd.verify(plain, hashed)
    except Exception:
        return False


# --------------------------------------------------------------------- tokens
def _encode(data: dict, expires: Optional[timedelta], token_type: str) -> str:
    if jwt is None:
        raise RuntimeError('PyJWT not installed: pip install "PyJWT[crypto]"')
    now = datetime.now(timezone.utc)
    payload = {**data, "iat": now, "type": token_type}
    if expires is not None and expires.total_seconds() > 0:
        payload["exp"] = now + expires
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_access_token(data: dict, expires: Optional[timedelta] = None) -> str:
    if expires is None:
        expires = None if ACCESS_TTL_MIN <= 0 else timedelta(minutes=ACCESS_TTL_MIN)
    return _encode(data, expires, "access")


def create_refresh_token(data: dict) -> str:
    # Carry the role on the refresh token so a refreshed access token preserves
    # it. Without this, refresh() silently downgrades the caller to "viewer"
    # and analyst/admin endpoints start returning 403 after the access TTL.
    payload = {"sub": data.get("sub")}
    if data.get("role"):
        payload["role"] = data["role"]
    # Refresh still expires; revoke access by rotating JWT_SECRET_KEY.
    refresh_exp = None if REFRESH_TTL_DAYS <= 0 else timedelta(days=REFRESH_TTL_DAYS)
    return _encode(payload, refresh_exp, "refresh")


def verify_token(token: str, expected_type: str = "access") -> Optional[Dict]:
    if jwt is None:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None
    return payload if payload.get("type") == expected_type else None


def refresh_access_token(refresh_token: str) -> Optional[str]:
    payload = verify_token(refresh_token, "refresh")
    if not payload:
        return None
    data = {"sub": payload["sub"]}
    if "role" in payload:
        data["role"] = payload["role"]
    return create_access_token(data)


# ----------------------------------------------------------- FastAPI deps
def get_current_user(token: Optional[str] = Depends(oauth2_scheme)) -> Dict:
    """Decode the bearer token; raise 401 if missing/invalid/expired."""
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exc
    payload = verify_token(token, "access")
    if not payload or "sub" not in payload:
        raise credentials_exc
    return {"user_id": payload["sub"], "role": payload.get("role", "viewer")}


def require_role(min_role: str):
    """Dependency factory enforcing a minimum role (hierarchical)."""
    required_rank = _ROLE_RANK.get(min_role, 0)

    def _checker(user: Dict = Depends(get_current_user)) -> Dict:
        if _ROLE_RANK.get(user.get("role", "viewer"), 0) < required_rank:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role >= {min_role}",
            )
        return user

    return _checker


# --------------------------------------------------- minimal env user store
def _env_users() -> Dict[str, Dict]:
    """
    Bootstrap users from env. Production should back this with a DB.
    API_ADMIN_USER / API_ADMIN_PASSWORD (or _HASH)
    Optional: API_CUSTOMER_USER / API_CUSTOMER_PASSWORD (role customer)
    Optional: API_ENTERPRISE_USER / API_ENTERPRISE_PASSWORD (role enterprise)
    """
    users: Dict[str, Dict] = {}

    def _add(user_key: str, pass_key: str, role: str, default_user: str, default_pass: str):
        user = os.getenv(user_key, default_user)
        pw_hash = os.getenv(f"{pass_key}_HASH")
        if not pw_hash:
            plain = os.getenv(pass_key, default_pass)
            pw_hash = hash_password(plain) if _pwd else plain
        users[user] = {"password_hash": pw_hash, "role": role}

    _add("API_ADMIN_USER", "API_ADMIN_PASSWORD", "admin", "admin", "changeme")
    # Pilot device user — only if both env vars are set (no baked-in password).
    if os.getenv("API_PILOT_USER") and (os.getenv("API_PILOT_PASSWORD") or os.getenv("API_PILOT_PASSWORD_HASH")):
        _add("API_PILOT_USER", "API_PILOT_PASSWORD", "analyst",
             os.environ["API_PILOT_USER"], os.getenv("API_PILOT_PASSWORD", ""))
    if os.getenv("API_CUSTOMER_USER") or os.getenv("API_CUSTOMER_PASSWORD"):
        _add("API_CUSTOMER_USER", "API_CUSTOMER_PASSWORD", "customer", "customer", "changeme")
    if os.getenv("API_ENTERPRISE_USER") or os.getenv("API_ENTERPRISE_PASSWORD"):
        _add("API_ENTERPRISE_USER", "API_ENTERPRISE_PASSWORD", "enterprise", "enterprise", "changeme")
    return users


def authenticate_user(username: str, password: str) -> Optional[Dict]:
    user = _env_users().get(username)
    if not user or not verify_password(password, user["password_hash"]):
        return None
    return {"sub": username, "role": user["role"]}
