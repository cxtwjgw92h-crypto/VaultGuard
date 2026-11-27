"""
AuditLog Model (Module 5: Audit Logs)

Maintains tamper-evident operational logs for accountability.
Must NEVER store plaintext passwords, master passwords, or encryption keys.
"""

from models import db
from models.user import utc_now


class AuditLog(db.Model):
    """Accountability record for system and credential operations."""

    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    action = db.Column(db.String(64), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(64), nullable=True)
    device_info = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)

    def to_dict(self) -> dict:
        """Serialize audit log entry."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "action": self.action,
            "description": self.description,
            "ip_address": self.ip_address or "Unknown",
            "device_info": self.device_info or "Unknown",
            "timestamp": self.timestamp.isoformat() + "Z",
        }
