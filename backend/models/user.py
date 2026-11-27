"""
User and Session Models (Module 1: User Authentication)

Stores registered users, bcrypt master-password hashes, lockout tracking fields,
and active/revoked JWT session records for secure logout enforcement.
"""

from datetime import datetime, timezone
from models import db


def utc_now() -> datetime:
    """Return current UTC timestamp (naive UTC for consistent SQLite storage)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(db.Model):
    """Registered VaultGuard user account."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    # Never store plaintext or reversible passwords — bcrypt hash only
    master_password_hash = db.Column(db.String(255), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)

    # Relationships with strict cascade isolation per user
    credentials = db.relationship("Credential", backref="user", lazy=True, cascade="all, delete-orphan")
    login_events = db.relationship("LoginEvent", backref="user", lazy=True, cascade="all, delete-orphan")
    security_events = db.relationship("SecurityEvent", backref="user", lazy=True, cascade="all, delete-orphan")
    security_alerts = db.relationship("SecurityAlert", backref="user", lazy=True, cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", backref="user", lazy=True, cascade="all, delete-orphan")
    sessions = db.relationship("UserSession", backref="user", lazy=True, cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        """Return safe public user profile without sensitive password hashes."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "failed_login_attempts": self.failed_login_attempts,
            "locked_until": self.locked_until.isoformat() + "Z" if self.locked_until else None,
            "created_at": self.created_at.isoformat() + "Z",
        }


class UserSession(db.Model):
    """Tracks issued JWT tokens by JTI so logout immediately revokes the session."""

    __tablename__ = "user_sessions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    jti = db.Column(db.String(64), unique=True, nullable=False, index=True)
    ip_address = db.Column(db.String(64), nullable=True)
    device_info = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_revoked = db.Column(db.Boolean, default=False, nullable=False)
