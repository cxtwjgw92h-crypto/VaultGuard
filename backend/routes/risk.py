"""
Risk Assessment Engine Routes (Module 4)

Exposes evaluated security events, risk breakdowns, and configurable thresholds.
"""

from flask import Blueprint, current_app, g, jsonify, request

from models.security_event import SecurityEvent
from services.auth_utils import token_required

risk_bp = Blueprint("risk", __name__, url_prefix="/api/risk")


@risk_bp.route("/events", methods=["GET"])
@token_required
def list_security_events():
    """Return evaluated security events with rule explanations for the current user."""
    user = g.current_user
    risk_level = (request.args.get("risk_level") or "").strip().upper()
    query = SecurityEvent.query.filter_by(user_id=user.id)
    if risk_level in ("LOW", "MEDIUM", "HIGH"):
        query = query.filter_by(risk_level=risk_level)

    events = query.order_by(SecurityEvent.timestamp.desc()).limit(100).all()
    return jsonify({"events": [e.to_dict() for e in events]}), 200


@risk_bp.route("/config", methods=["GET"])
@token_required
def get_risk_config():
    """Expose active risk thresholds and weights for transparency in Account Settings."""
    return jsonify({
        "thresholds": {
            "low_max": current_app.config.get("RISK_LOW_MAX", 19),
            "medium_max": current_app.config.get("RISK_MEDIUM_MAX", 39),
            "high_min": current_app.config.get("RISK_HIGH_MIN", 40),
        },
        "policies": {
            "max_failed_login_attempts": current_app.config.get("MAX_FAILED_LOGIN_ATTEMPTS", 5),
            "lockout_duration_minutes": current_app.config.get("LOCKOUT_DURATION_MINUTES", 5),
            "retrieval_burst_threshold": current_app.config.get("RETRIEVAL_BURST_THRESHOLD", 5),
            "retrieval_window_seconds": current_app.config.get("RETRIEVAL_WINDOW_SECONDS", 120),
            "failed_login_window_minutes": current_app.config.get("FAILED_LOGIN_WINDOW_MINUTES", 15),
        },
        "weights": current_app.config.get("RISK_WEIGHTS", {}),
    }), 200
