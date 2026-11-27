"""
AI Security Assistant Service (Module 6)

Provides clear, evidence-based explanations of security events, risk scores,
and actionable recommendations using ONLY structured, non-sensitive event data
from the database.

Privacy & Security Guardrails:
  - Never accesses or transmits master passwords, decrypted credentials,
    encryption keys, or raw credential contents.
  - Risk calculation stays completely independent in `risk_engine.py`.
  - Uses an external OpenAI-compatible AI endpoint ONLY when `AI_API_KEY` is
    configured, and seamlessly falls back to a comprehensive local rule-based
    security analyst when no API key is present or an external request fails.
"""

from datetime import timedelta
import json
import requests
from flask import current_app

from models.audit_log import AuditLog
from models.security_alert import SecurityAlert
from models.security_event import LoginEvent, SecurityEvent
from models.user import utc_now


def _gather_sanitized_security_context(user_id: int) -> dict:
    """
    Collect ONLY non-sensitive security telemetry for the authenticated user.
    Zero passwords, ciphertexts, or credential secrets are included.
    """
    recent_events = (
        SecurityEvent.query.filter_by(user_id=user_id)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(15)
        .all()
    )
    open_alerts = (
        SecurityAlert.query.filter_by(user_id=user_id, status="OPEN")
        .order_by(SecurityAlert.created_at.desc())
        .limit(10)
        .all()
    )
    recent_logins = (
        LoginEvent.query.filter_by(user_id=user_id)
        .order_by(LoginEvent.timestamp.desc())
        .limit(15)
        .all()
    )
    recent_audits = (
        AuditLog.query.filter_by(user_id=user_id)
        .order_by(AuditLog.timestamp.desc())
        .limit(10)
        .all()
    )

    cutoff_24h = utc_now() - timedelta(hours=24)
    failed_24h = LoginEvent.query.filter(
        LoginEvent.user_id == user_id,
        LoginEvent.success_status.is_(False),
        LoginEvent.timestamp >= cutoff_24h,
    ).count()
    success_24h = LoginEvent.query.filter(
        LoginEvent.user_id == user_id,
        LoginEvent.success_status.is_(True),
        LoginEvent.timestamp >= cutoff_24h,
    ).count()

    highest_event = (
        SecurityEvent.query.filter_by(user_id=user_id)
        .order_by(SecurityEvent.risk_score.desc(), SecurityEvent.timestamp.desc())
        .first()
    )

    return {
        "thresholds": {
            "LOW": f"0-{current_app.config.get('RISK_LOW_MAX', 19)}",
            "MEDIUM": f"{current_app.config.get('RISK_LOW_MAX', 19) + 1}-{current_app.config.get('RISK_MEDIUM_MAX', 39)}",
            "HIGH": f"{current_app.config.get('RISK_HIGH_MIN', 40)}+",
        },
        "summary_24h": {
            "successful_logins": success_24h,
            "failed_logins": failed_24h,
            "open_alerts": len(open_alerts),
        },
        "highest_risk_event": highest_event.to_dict() if highest_event else None,
        "recent_security_events": [e.to_dict() for e in recent_events],
        "open_alerts": [a.to_dict() for a in open_alerts],
        "recent_login_events": [l.to_dict() for l in recent_logins],
        "recent_audit_actions": [
            {"action": a.action, "description": a.description, "timestamp": a.timestamp.isoformat() + "Z"}
            for a in recent_audits
        ],
    }


def _build_local_assistant_reply(question: str, context: dict) -> dict:
    """
    Deterministic, evidence-driven local AI Security Assistant fallback.
    Generates grounded answers directly from the user's real backend telemetry.
    """
    q = (question or "").strip().lower()
    events = context["recent_security_events"]
    alerts = context["open_alerts"]
    summary = context["summary_24h"]
    thresholds = context["thresholds"]
    highest = context["highest_risk_event"]

    # Collect unique triggered rules across recent events
    rule_reasons = []
    seen_reasons = set()
    for ev in events:
        for rule in ev.get("rule_breakdown", []):
            reason = rule.get("reason")
            if reason and reason not in seen_reasons:
                seen_reasons.add(reason)
                rule_reasons.append(f"{reason} (+{rule.get('points', 0)} pts)")

    # Determine overall posture
    if any(a["risk_level"] == "HIGH" for a in alerts) or any(e["risk_level"] == "HIGH" for e in events[:5]):
        posture = "HIGH RISK"
    elif any(a["risk_level"] == "MEDIUM" for a in alerts) or any(e["risk_level"] == "MEDIUM" for e in events[:5]):
        posture = "MEDIUM RISK"
    else:
        posture = "LOW RISK"

    recommendations: list[str] = []
    if summary["failed_logins"] >= 3:
        recommendations.append("Change your master password immediately if you do not recognize the failed login attempts.")
    if any("UNFAMILIAR_IP" in str(e.get("rule_breakdown", [])) for e in events):
        recommendations.append("Verify the unfamiliar IP address and device in Activity History and revoke untrusted sessions by logging out.")
    if any("RETRIEVAL" in str(e.get("rule_breakdown", [])) for e in events):
        recommendations.append("Review rapid credential retrievals in your Activity History to confirm no unauthorized automated access occurred.")
    if alerts:
        recommendations.append(f"Inspect and resolve your {len(alerts)} open security alert(s) once you have verified the activity.")
    if not recommendations:
        recommendations.append("Continue using a unique, strong master password and monitor Activity History periodically.")

    # Intent 1: Explain Low / Medium / High risk classification
    if any(kw in q for kw in ("difference", "low, medium", "risk level", "classification", "threshold", "how is risk")):
        answer = (
            f"VaultGuard's Python risk engine evaluates security events using rule-based points and classifies them as:\n"
            f"- LOW RISK ({thresholds['LOW']} pts): Normal authenticated behavior or minor isolated events.\n"
            f"- MEDIUM RISK ({thresholds['MEDIUM']} pts): Anomalies such as an unfamiliar IP, a new browser/device, or a rapid credential retrieval burst. Triggers a warning alert.\n"
            f"- HIGH RISK ({thresholds['HIGH']} pts): Strong indicators of suspicious activity, such as repeated consecutive failed logins, lockout attempts, or combined anomalies. Triggers a high-priority alert.\n\n"
            f"Your current recent security posture is {posture}."
        )
        return {"answer": answer, "recommendations": recommendations, "mode": "rule-based-local", "posture": posture}

    # Intent 2: Why was account/event marked as high risk or flagged?
    if any(kw in q for kw in ("why", "high risk", "flagged", "score", "alert", "suspicious")):
        elevated = [e for e in events if e["risk_level"] in ("MEDIUM", "HIGH")]
        if not elevated:
            answer = (
                f"Your account has no Medium or High risk events in recent history. "
                f"Over the last 24 hours, VaultGuard recorded {summary['successful_logins']} successful login(s) "
                f"and {summary['failed_logins']} failed login(s), keeping your status at LOW RISK."
            )
        else:
            top = elevated[0]
            breakdown_items = top.get("rule_breakdown", [])
            if breakdown_items:
                reasons_text = "; ".join(f"{b['reason']} (+{b['points']} pts)" for b in breakdown_items)
            else:
                reasons_text = top["description"]
            answer = (
                f"Your most recent elevated-risk event ({top['event_type']}) received a risk score of {top['risk_score']} "
                f"({top['risk_level']} RISK). Contributing rules: {reasons_text}. "
                f"In total, you currently have {len(alerts)} open alert(s) and {summary['failed_logins']} failed login(s) in the past 24 hours."
            )
        return {"answer": answer, "recommendations": recommendations, "mode": "rule-based-local", "posture": posture}

    # Intent 3: What actions / recommendations should I take?
    if any(kw in q for kw in ("recommend", "action", "what should i do", "fix", "secure", "protect")):
        answer = (
            f"Based on your current security status ({posture}), {len(alerts)} open alert(s), and "
            f"{summary['failed_logins']} failed login attempt(s) in the last 24 hours, here are the recommended steps:"
        )
        return {"answer": answer, "recommendations": recommendations, "mode": "rule-based-local", "posture": posture}

    # Intent 4: Summarize recent security activity / patterns (default comprehensive summary)
    if not events and not context["recent_login_events"]:
        answer = (
            "No security events have been recorded yet for your account. Once you log in, add credentials, "
            "or retrieve secrets from the vault, VaultGuard will monitor and analyze activity here."
        )
    else:
        pattern_note = (
            f"Key observed risk factors: {'; '.join(rule_reasons[:4])}."
            if rule_reasons
            else "No anomalous rule triggers have been detected recently."
        )
        highest_note = (
            f" Highest recorded score: {highest['risk_score']} ({highest['risk_level']} - {highest['event_type']})."
            if highest and highest["risk_score"] > 0
            else ""
        )
        answer = (
            f"Security Activity Summary (Last 24h): {summary['successful_logins']} successful login(s), "
            f"{summary['failed_logins']} failed login(s), and {len(alerts)} open security alert(s). "
            f"Overall status: {posture}.{highest_note} {pattern_note}"
        )

    return {"answer": answer, "recommendations": recommendations, "mode": "rule-based-local", "posture": posture}


def ask_security_assistant(user_id: int, question: str) -> dict:
    """
    Answer a user's security question using structured telemetry from the database.
    Uses external AI if configured via `AI_API_KEY`; otherwise falls back cleanly
    to the local rule-based assistant.
    """
    context = _gather_sanitized_security_context(user_id)
    local_result = _build_local_assistant_reply(question, context)

    api_key = current_app.config.get("AI_API_KEY", "")
    api_url = current_app.config.get("AI_API_URL", "")
    model = current_app.config.get("AI_MODEL", "gpt-4o-mini")

    if not api_key or not api_url:
        return local_result

    # Strictly send ONLY sanitized metadata (never passwords, keys, or vault entries)
    system_prompt = (
        "You are VaultGuard's AI Cybersecurity Assistant. Explain the user's security events, "
        "risk scores, and recommended actions clearly and concisely based ONLY on the provided "
        "structured telemetry JSON. Do not invent events that are not in the telemetry."
    )
    user_payload = json.dumps({"question": question, "security_telemetry": context})

    try:
        response = requests.post(
            api_url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_payload},
                ],
                "temperature": 0.2,
                "max_tokens": 400,
            },
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        ai_text = data["choices"][0]["message"]["content"].strip()
        return {
            "answer": ai_text,
            "recommendations": local_result["recommendations"],
            "mode": "external-ai",
            "posture": local_result["posture"],
        }
    except Exception:
        # Graceful fallback so VaultGuard never depends on an external API
        return local_result
