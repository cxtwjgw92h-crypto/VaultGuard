"""
JWT Authentication & Session Verification Helpers (Module 1)

Provides token issuance, revocation-aware validation, and the `@token_required`
route decorator to enforce authentication and user isolation across all APIs.
"""

from datetime import datetime, timedelta, timezone
from functools import wraps
import uuid
import jwt
from flask import current_app, g, request, jsonify

from models import db
from models.user import User, UserSession, utc_now


def create_access_token(user: User, ip_address: str, device_info: str) -> tuple[str, UserSession]:
    """
    Generate a signed JWT access token and persist its JTI in `user_sessions`
    so logout immediately invalidates active tokens.
    """
    now = datetime.now(timezone.utc)
    expires_minutes = current_app.config.get("JWT_ACCESS_TOKEN_EXPIRES_MINUTES", 60)
    exp = now + timedelta(minutes=expires_minutes)
    jti = uuid.uuid4().hex

    payload = {
        "sub": str(user.id),
        "username": user.username,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, current_app.config["JWT_SECRET_KEY"], algorithm="HS256")

    session_record = UserSession(
        user_id=user.id,
        jti=jti,
        ip_address=ip_address,
        device_info=device_info,
        expires_at=exp.replace(tzinfo=None),
        is_revoked=False,
    )
    db.session.add(session_record)
    db.session.commit()
    return token, session_record


def revoke_session_by_jti(jti: str) -> None:
    """Mark a JWT session as revoked upon logout."""
    session_record = UserSession.query.filter_by(jti=jti).first()
    if session_record and not session_record.is_revoked:
        session_record.is_revoked = True
        db.session.commit()


def token_required(fn):
    """
    Decorator protecting API endpoints.
    Verifies Bearer JWT signature, expiration, active UserSession, and loads `g.current_user`.
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authentication required. Missing Bearer token."}), 401

        token = auth_header.split(" ", 1)[1].strip()
        if not token:
            return jsonify({"error": "Authentication required. Empty token."}), 401

        try:
            payload = jwt.decode(
                token,
                current_app.config["JWT_SECRET_KEY"],
                algorithms=["HS256"],
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Session expired. Please log in again."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid authentication token."}), 401

        jti = payload.get("jti")
        user_id = payload.get("sub")
        if not jti or not user_id:
            return jsonify({"error": "Malformed authentication token."}), 401

        session_record = UserSession.query.filter_by(jti=jti).first()
        if not session_record or session_record.is_revoked or session_record.expires_at < utc_now():
            return jsonify({"error": "Session is no longer active. Please log in again."}), 401

        user = db.session.get(User, int(user_id))
        if not user:
            return jsonify({"error": "User account not found."}), 401

        g.current_user = user
        g.current_jti = jti
        return fn(*args, **kwargs)

    return wrapper
