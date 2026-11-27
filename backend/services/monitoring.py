"""
Login and Activity Monitoring Service (Module 3)

Records login attempts, logouts, and credential vault operations while
respecting data minimization (only IP address and parsed browser/OS summary)
and ensuring sensitive secrets never appear in logs.
"""

import re
from typing import Optional
from flask import request

from models import db
from models.audit_log import AuditLog
from models.security_event import LoginEvent


_SENSITIVE_TERMS = ("password=", "master_password=", "encryption_key=", "secret_key=")


def get_client_ip() -> str:
    """
    Extract client IP address, supporting reverse-proxy headers if present.
    Falls back to `request.remote_addr`.
    """
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()[:64]
    return (request.remote_addr or "127.0.0.1")[:64]


def get_device_info() -> str:
    """
    Parse a minimal, privacy-friendly Browser / OS summary from the User-Agent header.
    Allows optional `X-Client-Device` override only for explicit testing/client labels
    if needed, truncated safely.
    """
    ua = request.headers.get("User-Agent", "").strip()
    if not ua:
        return "Unknown Device"

    # Detect browser
    if "Edg/" in ua:
        browser = "Edge"
    elif "Chrome/" in ua and "Chromium" not in ua:
        browser = "Chrome"
    elif "Firefox/" in ua:
        browser = "Firefox"
    elif "Safari/" in ua and "Chrome/" not in ua:
        browser = "Safari"
    elif "curl" in ua.lower():
        browser = "curl"
    elif "python-requests" in ua.lower() or "werkzeug" in ua.lower():
        browser = "API Client"
    else:
        browser = "Browser"

    # Detect OS
    if "Windows" in ua:
        os_name = "Windows"
    elif "Mac OS X" in ua or "Macintosh" in ua:
        os_name = "macOS"
    elif "Android" in ua:
        os_name = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        os_name = "iOS"
    elif "Linux" in ua:
        os_name = "Linux"
    else:
        os_name = "Unknown OS"

    return f"{browser} on {os_name}"[:255]


def sanitize_log_description(text: str) -> str:
    """Ensure audit descriptions never accidentally carry secret key/password pairs."""
    cleaned = text
    for term in _SENSITIVE_TERMS:
        cleaned = re.sub(rf"{re.escape(term)}\S+", f"{term}[REDACTED]", cleaned, flags=re.IGNORECASE)
    return cleaned


def record_login_event(
    user_id: Optional[int],
    event_type: str,
    success_status: bool,
    ip_address: Optional[str] = None,
    device_info: Optional[str] = None,
) -> LoginEvent:
    """Persist a login, failed login, lockout, or logout event."""
    event = LoginEvent(
        user_id=user_id,
        event_type=event_type,
        ip_address=ip_address or get_client_ip(),
        device_info=device_info or get_device_info(),
        success_status=success_status,
    )
    db.session.add(event)
    db.session.commit()
    return event


def record_audit_log(
    user_id: int,
    action: str,
    description: str,
    ip_address: Optional[str] = None,
    device_info: Optional[str] = None,
) -> AuditLog:
    """Persist an accountability audit log entry (sanitized, never containing secrets)."""
    entry = AuditLog(
        user_id=user_id,
        action=action,
        description=sanitize_log_description(description),
        ip_address=ip_address or get_client_ip(),
        device_info=device_info or get_device_info(),
    )
    db.session.add(entry)
    db.session.commit()
    return entry
