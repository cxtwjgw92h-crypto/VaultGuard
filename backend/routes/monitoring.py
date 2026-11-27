"""
Monitoring and Security Dashboard Routes (Modules 3 & 7)

Provides unified activity history and live database-driven dashboard metrics,
including risk score time-series and risk distribution charts.
"""

from flask import Blueprint, g, jsonify, request

from models.audit_log import AuditLog
from models.credential import Credential
from models.security_alert import SecurityAlert
from models.security_event import LoginEvent, SecurityEvent
from services.auth_utils import token_required

monitoring_bp = Blueprint("monitoring", __name__, url_prefix="/api/monitoring")


@monitoring_bp.route("/activity", methods=["GET"])
@token_required
def get_activity_history():
    """Return login events and audit logs for the authenticated user."""
    user = g.current_user
    limit = min(int(request.args.get("limit", 50)), 200)

    login_events = (
        LoginEvent.query.filter_by(user_id=user.id)
        .order_by(LoginEvent.timestamp.desc())
        .limit(limit)
        .all()
    )
    audit_logs = (
        AuditLog.query.filter_by(user_id=user.id)
        .order_by(AuditLog.timestamp.desc())
        .limit(limit)
        .all()
    )

    # Combine into a unified chronological feed for the Activity History page
    combined = []
    for ev in login_events:
        combined.append({
            "source": "LOGIN_EVENT",
            "id": f"login-{ev.id}",
            "action": ev.event_type,
            "description": f"{ev.event_type.replace('_', ' ').title()} ({'Success' if ev.success_status else 'Failed'})",
            "ip_address": ev.ip_address or "Unknown",
            "device_info": ev.device_info or "Unknown",
            "success_status": ev.success_status,
            "timestamp": ev.timestamp.isoformat() + "Z",
        })
    for log in audit_logs:
        # Avoid duplicate visual clutter for login/logout since LoginEvent covers them
        if log.action in ("LOGIN_SUCCESS", "LOGIN_FAILED", "ACCOUNT_LOCKED", "LOGOUT"):
            continue
        combined.append({
            "source": "AUDIT_LOG",
            "id": f"audit-{log.id}",
            "action": log.action,
            "description": log.description,
            "ip_address": log.ip_address or "Unknown",
            "device_info": log.device_info or "Unknown",
            "success_status": True,
            "timestamp": log.timestamp.isoformat() + "Z",
        })

    combined.sort(key=lambda item: item["timestamp"], reverse=True)

    return jsonify({
        "login_events": [e.to_dict() for e in login_events],
        "audit_logs": [a.to_dict() for a in audit_logs],
        "timeline": combined[:limit],
    }), 200


@monitoring_bp.route("/dashboard", methods=["GET"])
@token_required
def get_dashboard_data():
    """Aggregate real-time statistics and chart datasets from SQLite for Module 7."""
    user = g.current_user

    total_credentials = Credential.query.filter_by(user_id=user.id).count()
    total_successful_logins = LoginEvent.query.filter_by(
        user_id=user.id, event_type="LOGIN_SUCCESS", success_status=True
    ).count()
    total_failed_logins = LoginEvent.query.filter(
        LoginEvent.user_id == user.id,
        LoginEvent.event_type.in_(["LOGIN_FAILED", "ACCOUNT_LOCKED"]),
    ).count()

    open_alerts_count = SecurityAlert.query.filter_by(user_id=user.id, status="OPEN").count()
    total_alerts_count = SecurityAlert.query.filter_by(user_id=user.id).count()

    # Risk level distribution from evaluated SecurityEvents
    low_count = SecurityEvent.query.filter_by(user_id=user.id, risk_level="LOW").count()
    medium_count = SecurityEvent.query.filter_by(user_id=user.id, risk_level="MEDIUM").count()
    high_count = SecurityEvent.query.filter_by(user_id=user.id, risk_level="HIGH").count()

    recent_security_events = (
        SecurityEvent.query.filter_by(user_id=user.id)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(10)
        .all()
    )
    recent_logins = (
        LoginEvent.query.filter_by(user_id=user.id)
        .order_by(LoginEvent.timestamp.desc())
        .limit(8)
        .all()
    )
    recent_credential_access = (
        AuditLog.query.filter(
            AuditLog.user_id == user.id,
            AuditLog.action.in_([
                "CREDENTIAL_CREATED",
                "CREDENTIAL_RETRIEVED",
                "CREDENTIAL_UPDATED",
                "CREDENTIAL_DELETED",
            ]),
        )
        .order_by(AuditLog.timestamp.desc())
        .limit(8)
        .all()
    )

    # Risk scores over time (chronological order of last 20 evaluated events)
    timeline_events = (
        SecurityEvent.query.filter_by(user_id=user.id)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(20)
        .all()
    )
    risk_over_time = [
        {
            "id": ev.id,
            "timestamp": ev.timestamp.isoformat() + "Z",
            "label": ev.timestamp.strftime("%H:%M:%S"),
            "risk_score": ev.risk_score,
            "risk_level": ev.risk_level,
            "event_type": ev.event_type,
        }
        for ev in reversed(timeline_events)
    ]

    # Determine current overall security status from open alerts and latest events
    open_high = SecurityAlert.query.filter_by(user_id=user.id, status="OPEN", risk_level="HIGH").count()
    open_med = SecurityAlert.query.filter_by(user_id=user.id, status="OPEN", risk_level="MEDIUM").count()
    latest_event = recent_security_events[0] if recent_security_events else None

    if open_high > 0 or (latest_event and latest_event.risk_level == "HIGH"):
        security_status = "HIGH"
    elif open_med > 0 or (latest_event and latest_event.risk_level == "MEDIUM"):
        security_status = "MEDIUM"
    else:
        security_status = "LOW"

    return jsonify({
        "metrics": {
            "total_credentials": total_credentials,
            "total_successful_logins": total_successful_logins,
            "total_failed_logins": total_failed_logins,
            "open_alerts": open_alerts_count,
            "total_alerts": total_alerts_count,
            "security_status": security_status,
        },
        "risk_distribution": [
            {"level": "LOW", "count": low_count},
            {"level": "MEDIUM", "count": medium_count},
            {"level": "HIGH", "count": high_count},
        ],
        "risk_over_time": risk_over_time,
        "recent_logins": [e.to_dict() for e in recent_logins],
        "recent_credential_access": [a.to_dict() for a in recent_credential_access],
        "recent_security_events": [s.to_dict() for s in recent_security_events],
    }), 200
