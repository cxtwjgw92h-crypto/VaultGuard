"""
SecurityAlert Model (Module 5: Security Alerts)

Generated automatically when security events reach alert-worthy risk levels.
"""

from models import db
from models.user import utc_now


class SecurityAlert(db.Model):
    """Actionable security alert linked to a SecurityEvent."""

    __tablename__ = "security_alerts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    event_id = db.Column(db.Integer, db.ForeignKey("security_events.id"), nullable=False, index=True)
    alert_description = db.Column(db.Text, nullable=False)
    risk_level = db.Column(db.String(16), nullable=False)  # LOW, MEDIUM, HIGH
    status = db.Column(db.String(16), nullable=False, default="OPEN")  # OPEN, RESOLVED
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self) -> dict:
        """Serialize alert together with its linked SecurityEvent metadata."""
        event = self.security_event
        return {
            "id": self.id,
            "user_id": self.user_id,
            "event_id": self.event_id,
            "event_type": event.event_type if event else "UNKNOWN",
            "risk_score": event.risk_score if event else 0,
            "rule_breakdown": event.to_dict().get("rule_breakdown", []) if event else [],
            "event_description": event.description if event else self.alert_description,
            "alert_description": self.alert_description,
            "risk_level": self.risk_level,
            "status": self.status,
            "created_at": self.created_at.isoformat() + "Z",
            "resolved_at": self.resolved_at.isoformat() + "Z" if self.resolved_at else None,
        }
