"""
Security Alerts & Audit Log Routes (Module 5)

Allows users to inspect generated alerts, view details, mark alerts as resolved,
and review accountability audit logs.
"""

from flask import Blueprint, g, jsonify, request

from models import db
from models.audit_log import AuditLog
from models.security_alert import SecurityAlert
from models.user import utc_now
from services.auth_utils import token_required
from services.monitoring import record_audit_log

alerts_bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")


@alerts_bp.route("", methods=["GET"])
@token_required
def list_alerts():
    """List security alerts for the authenticated user, optionally filtered by status."""
    user = g.current_user
    status_filter = (request.args.get("status") or "").strip().upper()
    query = SecurityAlert.query.filter_by(user_id=user.id)
    if status_filter in ("OPEN", "RESOLVED"):
        query = query.filter_by(status=status_filter)

    alerts = query.order_by(SecurityAlert.created_at.desc()).all()
    return jsonify({"alerts": [a.to_dict() for a in alerts]}), 200


@alerts_bp.route("/<int:alert_id>", methods=["GET"])
@token_required
def get_alert_detail(alert_id: int):
    """Get detailed information for a specific alert belonging to the user."""
    user = g.current_user
    alert = SecurityAlert.query.filter_by(id=alert_id, user_id=user.id).first()
    if not alert:
        return jsonify({"error": "Security alert not found."}), 404
    return jsonify({"alert": alert.to_dict()}), 200


@alerts_bp.route("/<int:alert_id>/resolve", methods=["PATCH", "POST"])
@token_required
def resolve_alert(alert_id: int):
    """Mark an alert as RESOLVED and record an accountability audit log."""
    user = g.current_user
    alert = SecurityAlert.query.filter_by(id=alert_id, user_id=user.id).first()
    if not alert:
        return jsonify({"error": "Security alert not found."}), 404

    if alert.status != "RESOLVED":
        alert.status = "RESOLVED"
        alert.resolved_at = utc_now()
        db.session.commit()

        record_audit_log(
            user_id=user.id,
            action="ALERT_RESOLVED",
            description=f"Marked security alert #{alert.id} ({alert.risk_level}) as RESOLVED.",
        )

    return jsonify({"message": "Alert marked as resolved.", "alert": alert.to_dict()}), 200


@alerts_bp.route("/audit-logs", methods=["GET"])
@token_required
def get_audit_logs():
    """Return accountability audit logs for the authenticated user."""
    user = g.current_user
    logs = (
        AuditLog.query.filter_by(user_id=user.id)
        .order_by(AuditLog.timestamp.desc())
        .limit(100)
        .all()
    )
    return jsonify({"audit_logs": [log.to_dict() for log in logs]}), 200
