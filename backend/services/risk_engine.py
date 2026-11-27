"""
Rule-Based Risk Assessment Engine (Module 4) & Alert Generator (Module 5)

Evaluates login and credential-vault activities in pure Python using configurable
rules and thresholds:
  - LOW RISK:    0 - 19
  - MEDIUM RISK: 20 - 39
  - HIGH RISK:   40+

Rules implemented:
  1. Multiple consecutive failed login attempts.
  2. Login from an unfamiliar IP address.
  3. Login from a new device or browser.
  4. Multiple credential retrieval requests within a short time.
  5. Unusual credential-access activity (e.g., burst deletions/edits, or access
     immediately following failed logins / from an unfamiliar IP).
  6. Repeated suspicious authentication patterns (e.g., lockout attempts, failed
     burst followed by sudden success, or repeated medium/high events).

Double-counting prevention:
  Every evaluated event supplies a deterministic `source_event_key` (e.g.
  `login_event:<id>` or `audit_log:<id>`). If already recorded in `security_events`,
  the existing evaluation is returned without re-scoring.
"""

import json
from datetime import timedelta
from typing import Optional
from flask import current_app

from models import db
from models.audit_log import AuditLog
from models.security_alert import SecurityAlert
from models.security_event import LoginEvent, SecurityEvent
from models.user import utc_now


def classify_risk_score(score: int) -> str:
    """Map numeric risk score to LOW, MEDIUM, or HIGH using configured thresholds."""
    low_max = current_app.config.get("RISK_LOW_MAX", 19)
    medium_max = current_app.config.get("RISK_MEDIUM_MAX", 39)
    if score <= low_max:
        return "LOW"
    if score <= medium_max:
        return "MEDIUM"
    return "HIGH"


def _count_consecutive_failed_logins(user_id: int, window_minutes: int) -> int:
    """Count consecutive failed logins from the user's most recent login history."""
    cutoff = utc_now() - timedelta(minutes=window_minutes)
    recent_events = (
        LoginEvent.query.filter(
            LoginEvent.user_id == user_id,
            LoginEvent.timestamp >= cutoff,
            LoginEvent.event_type.in_(["LOGIN_SUCCESS", "LOGIN_FAILED", "ACCOUNT_LOCKED"]),
        )
        .order_by(LoginEvent.timestamp.desc(), LoginEvent.id.desc())
        .all()
    )
    consecutive = 0
    for ev in recent_events:
        if ev.event_type in ("LOGIN_FAILED", "ACCOUNT_LOCKED"):
            consecutive += 1
        elif ev.event_type == "LOGIN_SUCCESS":
            break
    return consecutive


def _prior_known_ips_and_devices(user_id: int, exclude_event_id: Optional[int] = None) -> tuple[set[str], set[str]]:
    """Return sets of IP addresses and devices seen in previous successful logins."""
    query = LoginEvent.query.filter(
        LoginEvent.user_id == user_id,
        LoginEvent.event_type == "LOGIN_SUCCESS",
        LoginEvent.success_status.is_(True),
    )
    if exclude_event_id is not None:
        query = query.filter(LoginEvent.id != exclude_event_id)

    prior_successes = query.all()
    ips = {ev.ip_address for ev in prior_successes if ev.ip_address}
    devices = {ev.device_info for ev in prior_successes if ev.device_info}
    return ips, devices


def _save_security_event_and_alert(
    user_id: int,
    event_type: str,
    description: str,
    triggered_rules: list[dict],
    source_event_key: str,
) -> SecurityEvent:
    """Persist SecurityEvent and auto-generate a SecurityAlert for MEDIUM/HIGH risk."""
    existing = SecurityEvent.query.filter_by(source_event_key=source_event_key).first()
    if existing:
        return existing

    total_score = sum(rule["points"] for rule in triggered_rules)
    risk_level = classify_risk_score(total_score)

    sec_event = SecurityEvent(
        user_id=user_id,
        event_type=event_type,
        description=description,
        risk_score=total_score,
        risk_level=risk_level,
        source_event_key=source_event_key,
        rule_breakdown=json.dumps(triggered_rules),
    )
    db.session.add(sec_event)
    db.session.flush()  # Obtain sec_event.id before alert creation

    # Generate an alert whenever risk is MEDIUM or HIGH
    if risk_level in ("MEDIUM", "HIGH"):
        reasons = "; ".join(r["reason"] for r in triggered_rules)
        alert_desc = f"[{risk_level} RISK - Score {total_score}] {description}"
        if reasons:
            alert_desc = f"{alert_desc} — Reasons: {reasons}"

        alert = SecurityAlert(
            user_id=user_id,
            event_id=sec_event.id,
            alert_description=alert_desc,
            risk_level=risk_level,
            status="OPEN",
        )
        db.session.add(alert)

    db.session.commit()
    return sec_event


def evaluate_login_risk(user_id: int, login_event: LoginEvent) -> SecurityEvent:
    """
    Evaluate an authentication event (LOGIN_SUCCESS, LOGIN_FAILED, ACCOUNT_LOCKED)
    against the rule-based risk engine.
    """
    source_key = f"login_event:{login_event.id}"
    existing = SecurityEvent.query.filter_by(source_event_key=source_key).first()
    if existing:
        return existing

    weights = current_app.config["RISK_WEIGHTS"]
    window_minutes = current_app.config.get("FAILED_LOGIN_WINDOW_MINUTES", 15)
    triggered_rules: list[dict] = []

    prior_ips, prior_devices = _prior_known_ips_and_devices(user_id, exclude_event_id=login_event.id)
    has_login_baseline = len(prior_ips) > 0 or len(prior_devices) > 0

    if login_event.event_type == "ACCOUNT_LOCKED":
        triggered_rules.append({
            "rule": "LOCKOUT_ATTEMPT",
            "points": weights["LOCKOUT_ATTEMPT"],
            "reason": "Login attempted while account is locked due to excessive failed attempts.",
        })

    if login_event.event_type in ("LOGIN_FAILED", "ACCOUNT_LOCKED"):
        consecutive_failures = _count_consecutive_failed_logins(user_id, window_minutes)
        if consecutive_failures >= 5:
            triggered_rules.append({
                "rule": "CONSECUTIVE_FAILED_LOGINS_HIGH",
                "points": weights["CONSECUTIVE_FAILED_LOGINS_HIGH"],
                "reason": f"{consecutive_failures} consecutive failed login attempts within {window_minutes} minutes.",
            })
        elif consecutive_failures >= 3:
            triggered_rules.append({
                "rule": "CONSECUTIVE_FAILED_LOGINS_MED",
                "points": weights["CONSECUTIVE_FAILED_LOGINS_MED"],
                "reason": f"{consecutive_failures} consecutive failed login attempts within {window_minutes} minutes.",
            })

    # Rule 2: Unfamiliar IP address (only flag once user has an established baseline)
    if has_login_baseline and login_event.ip_address and login_event.ip_address not in prior_ips:
        triggered_rules.append({
            "rule": "UNFAMILIAR_IP",
            "points": weights["UNFAMILIAR_IP"],
            "reason": f"Authentication from previously unseen IP address ({login_event.ip_address}).",
        })

    # Rule 3: New device or browser
    if has_login_baseline and login_event.device_info and login_event.device_info not in prior_devices:
        triggered_rules.append({
            "rule": "NEW_DEVICE_BROWSER",
            "points": weights["NEW_DEVICE_BROWSER"],
            "reason": f"Authentication from a new device or browser ({login_event.device_info}).",
        })

    # Rule 6: Repeated suspicious authentication patterns
    # Pattern A: Multiple recent failed logins immediately followed by a successful login
    if login_event.event_type == "LOGIN_SUCCESS":
        cutoff = utc_now() - timedelta(minutes=window_minutes)
        recent_failures = LoginEvent.query.filter(
            LoginEvent.user_id == user_id,
            LoginEvent.id < login_event.id,
            LoginEvent.timestamp >= cutoff,
            LoginEvent.event_type.in_(["LOGIN_FAILED", "ACCOUNT_LOCKED"]),
        ).count()
        if recent_failures >= 3:
            triggered_rules.append({
                "rule": "REPEATED_SUSPICIOUS_AUTH",
                "points": weights["REPEATED_SUSPICIOUS_AUTH"],
                "reason": f"Successful login occurred immediately after {recent_failures} recent failed attempts.",
            })
    else:
        # Pattern B: Multiple medium/high risk auth events in the last 30 minutes
        recent_risk_events = SecurityEvent.query.filter(
            SecurityEvent.user_id == user_id,
            SecurityEvent.timestamp >= utc_now() - timedelta(minutes=30),
            SecurityEvent.risk_level.in_(["MEDIUM", "HIGH"]),
        ).count()
        if recent_risk_events >= 2:
            triggered_rules.append({
                "rule": "REPEATED_SUSPICIOUS_AUTH",
                "points": weights["REPEATED_SUSPICIOUS_AUTH"],
                "reason": f"{recent_risk_events} elevated-risk events already recorded in the past 30 minutes.",
            })

    if login_event.event_type == "LOGIN_SUCCESS":
        desc = f"Successful login from {login_event.ip_address} ({login_event.device_info})"
    elif login_event.event_type == "ACCOUNT_LOCKED":
        desc = f"Blocked login attempt during temporary lockout from {login_event.ip_address}"
    else:
        desc = f"Failed login attempt from {login_event.ip_address} ({login_event.device_info})"

    return _save_security_event_and_alert(
        user_id=user_id,
        event_type=login_event.event_type,
        description=desc,
        triggered_rules=triggered_rules,
        source_event_key=source_key,
    )


def evaluate_credential_activity_risk(user_id: int, audit_log: AuditLog) -> SecurityEvent:
    """
    Evaluate credential vault operations (CREDENTIAL_RETRIEVED, CREDENTIAL_CREATED,
    CREDENTIAL_UPDATED, CREDENTIAL_DELETED) against rules 4 and 5.
    """
    source_key = f"audit_log:{audit_log.id}"
    existing = SecurityEvent.query.filter_by(source_event_key=source_key).first()
    if existing:
        return existing

    weights = current_app.config["RISK_WEIGHTS"]
    retrieval_threshold = current_app.config.get("RETRIEVAL_BURST_THRESHOLD", 5)
    retrieval_window_sec = current_app.config.get("RETRIEVAL_WINDOW_SECONDS", 120)
    mod_threshold = current_app.config.get("MODIFICATION_BURST_THRESHOLD", 5)
    triggered_rules: list[dict] = []

    now = utc_now()

    # Rule 4: Multiple credential retrieval requests within a short time
    if audit_log.action == "CREDENTIAL_RETRIEVED":
        cutoff = now - timedelta(seconds=retrieval_window_sec)
        retrieval_count = AuditLog.query.filter(
            AuditLog.user_id == user_id,
            AuditLog.action == "CREDENTIAL_RETRIEVED",
            AuditLog.timestamp >= cutoff,
        ).count()

        if retrieval_count >= retrieval_threshold * 2:
            triggered_rules.append({
                "rule": "EXTREME_CREDENTIAL_RETRIEVAL",
                "points": weights["EXTREME_CREDENTIAL_RETRIEVAL"],
                "reason": f"{retrieval_count} credential retrieval requests within {retrieval_window_sec} seconds.",
            })
        elif retrieval_count >= retrieval_threshold:
            triggered_rules.append({
                "rule": "RAPID_CREDENTIAL_RETRIEVAL",
                "points": weights["RAPID_CREDENTIAL_RETRIEVAL"],
                "reason": f"{retrieval_count} credential retrieval requests within {retrieval_window_sec} seconds (threshold: {retrieval_threshold}).",
            })

    # Rule 5: Unusual credential-access activity
    # 5a: Burst of deletions or updates in short period
    if audit_log.action in ("CREDENTIAL_DELETED", "CREDENTIAL_UPDATED"):
        mod_cutoff = now - timedelta(seconds=retrieval_window_sec)
        mod_count = AuditLog.query.filter(
            AuditLog.user_id == user_id,
            AuditLog.action.in_(["CREDENTIAL_DELETED", "CREDENTIAL_UPDATED"]),
            AuditLog.timestamp >= mod_cutoff,
        ).count()
        if mod_count >= mod_threshold:
            triggered_rules.append({
                "rule": "UNUSUAL_CREDENTIAL_ACCESS",
                "points": weights["UNUSUAL_CREDENTIAL_ACCESS"],
                "reason": f"Rapid burst of {mod_count} credential modifications/deletions in {retrieval_window_sec}s.",
            })

    # 5b: Credential retrieval occurring shortly after recent failed logins or unfamiliar-IP login
    if audit_log.action in ("CREDENTIAL_RETRIEVED", "CREDENTIAL_DELETED"):
        recent_high_or_med_login = (
            SecurityEvent.query.filter(
                SecurityEvent.user_id == user_id,
                SecurityEvent.event_type == "LOGIN_SUCCESS",
                SecurityEvent.risk_level.in_(["MEDIUM", "HIGH"]),
                SecurityEvent.timestamp >= now - timedelta(minutes=15),
            )
            .order_by(SecurityEvent.timestamp.desc())
            .first()
        )
        if recent_high_or_med_login:
            triggered_rules.append({
                "rule": "UNUSUAL_CREDENTIAL_ACCESS",
                "points": weights["UNUSUAL_CREDENTIAL_ACCESS"],
                "reason": "Sensitive vault access performed during a recently flagged elevated-risk login session.",
            })

    return _save_security_event_and_alert(
        user_id=user_id,
        event_type=audit_log.action,
        description=audit_log.description,
        triggered_rules=triggered_rules,
        source_event_key=source_key,
    )
