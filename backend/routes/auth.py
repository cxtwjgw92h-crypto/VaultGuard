"""
Authentication Routes (Module 1: User Authentication)

Handles registration, login with brute-force lockout protection,
session-backed JWT logout, current profile inspection, and master password updates.
"""

from datetime import timedelta
import re
from flask import Blueprint, current_app, g, jsonify, request

from models import db
from models.user import User, utc_now
from services.auth_utils import create_access_token, revoke_session_by_jti, token_required
from services.encryption import hash_master_password, verify_master_password
from services.monitoring import get_client_ip, get_device_info, record_audit_log, record_login_event
from services.risk_engine import evaluate_login_risk

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

_EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")


@auth_bp.route("/register", methods=["POST"])
def register():
    """Register a new VaultGuard user with a bcrypt-hashed master password."""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    master_password = data.get("master_password") or ""

    if not _USERNAME_REGEX.match(username):
        return jsonify({"error": "Username must be 3-32 characters (letters, numbers, _, ., -)."}), 400
    if not _EMAIL_REGEX.match(email):
        return jsonify({"error": "Please provide a valid email address."}), 400
    if len(master_password) < 8:
        return jsonify({"error": "Master password must be at least 8 characters long."}), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"error": "An account with that username or email already exists."}), 409

    password_hash = hash_master_password(master_password)
    user = User(
        username=username,
        email=email,
        master_password_hash=password_hash,
    )
    db.session.add(user)
    db.session.commit()

    record_audit_log(
        user_id=user.id,
        action="USER_REGISTERED",
        description=f"Account created for user '{user.username}'.",
    )

    return jsonify({
        "message": "Registration successful. You can now log in.",
        "user": user.to_dict(),
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Authenticate user with username/email and master password.
    Enforces account lockout after repeated failures and triggers risk analysis.
    """
    data = request.get_json(silent=True) or {}
    identifier = (data.get("identifier") or data.get("username") or data.get("email") or "").strip()
    master_password = data.get("master_password") or ""

    if not identifier or not master_password:
        return jsonify({"error": "Username/email and master password are required."}), 400

    ip_address = get_client_ip()
    device_info = get_device_info()

    user = User.query.filter(
        (User.username == identifier) | (User.email == identifier.lower())
    ).first()

    if not user:
        # Record anonymous failed attempt without disclosing whether account exists
        record_login_event(
            user_id=None,
            event_type="LOGIN_FAILED",
            success_status=False,
            ip_address=ip_address,
            device_info=device_info,
        )
        return jsonify({"error": "Invalid credentials."}), 401

    now = utc_now()

    # Check if account is currently locked
    if user.locked_until and user.locked_until > now:
        lock_event = record_login_event(
            user_id=user.id,
            event_type="ACCOUNT_LOCKED",
            success_status=False,
            ip_address=ip_address,
            device_info=device_info,
        )
        evaluate_login_risk(user.id, lock_event)
        remaining_seconds = int((user.locked_until - now).total_seconds())
        return jsonify({
            "error": f"Account temporarily locked due to repeated failed attempts. Try again in {max(1, remaining_seconds)} seconds.",
            "locked_until": user.locked_until.isoformat() + "Z",
        }), 423

    # Verify bcrypt master password hash
    if not verify_master_password(master_password, user.master_password_hash):
        user.failed_login_attempts += 1
        max_attempts = current_app.config.get("MAX_FAILED_LOGIN_ATTEMPTS", 5)
        lockout_minutes = current_app.config.get("LOCKOUT_DURATION_MINUTES", 5)

        event_type = "LOGIN_FAILED"
        if user.failed_login_attempts >= max_attempts:
            user.locked_until = now + timedelta(minutes=lockout_minutes)
            event_type = "ACCOUNT_LOCKED"

        db.session.commit()

        failed_event = record_login_event(
            user_id=user.id,
            event_type=event_type,
            success_status=False,
            ip_address=ip_address,
            device_info=device_info,
        )
        sec_event = evaluate_login_risk(user.id, failed_event)
        record_audit_log(
            user_id=user.id,
            action=event_type,
            description=f"Failed authentication attempt #{user.failed_login_attempts} from {ip_address}.",
            ip_address=ip_address,
            device_info=device_info,
        )

        if event_type == "ACCOUNT_LOCKED":
            return jsonify({
                "error": f"Too many failed login attempts. Account locked for {lockout_minutes} minutes.",
                "risk_level": sec_event.risk_level,
            }), 423

        return jsonify({"error": "Invalid credentials."}), 401

    # Successful login: reset failure counter & lockout
    user.failed_login_attempts = 0
    user.locked_until = None
    db.session.commit()

    login_event = record_login_event(
        user_id=user.id,
        event_type="LOGIN_SUCCESS",
        success_status=True,
        ip_address=ip_address,
        device_info=device_info,
    )
    sec_event = evaluate_login_risk(user.id, login_event)
    record_audit_log(
        user_id=user.id,
        action="LOGIN_SUCCESS",
        description=f"User logged in from {ip_address} ({device_info}).",
        ip_address=ip_address,
        device_info=device_info,
    )

    token, _ = create_access_token(user, ip_address=ip_address, device_info=device_info)

    return jsonify({
        "message": "Login successful.",
        "access_token": token,
        "user": user.to_dict(),
        "security_event": sec_event.to_dict(),
    }), 200


@auth_bp.route("/logout", methods=["POST"])
@token_required
def logout():
    """Revoke the active JWT session and log the logout event."""
    user = g.current_user
    revoke_session_by_jti(g.current_jti)

    ip_address = get_client_ip()
    device_info = get_device_info()
    record_login_event(
        user_id=user.id,
        event_type="LOGOUT",
        success_status=True,
        ip_address=ip_address,
        device_info=device_info,
    )
    record_audit_log(
        user_id=user.id,
        action="LOGOUT",
        description=f"User logged out from {ip_address}.",
        ip_address=ip_address,
        device_info=device_info,
    )
    return jsonify({"message": "Logged out successfully."}), 200


@auth_bp.route("/me", methods=["GET"])
@token_required
def get_profile():
    """Return the authenticated user's profile."""
    return jsonify({"user": g.current_user.to_dict()}), 200


@auth_bp.route("/change-password", methods=["POST"])
@token_required
def change_master_password():
    """Verify current master password and update to a new bcrypt hash."""
    data = request.get_json(silent=True) or {}
    current_password = data.get("current_password") or ""
    new_password = data.get("new_password") or ""

    user = g.current_user
    if not verify_master_password(current_password, user.master_password_hash):
        return jsonify({"error": "Current master password is incorrect."}), 401
    if len(new_password) < 8:
        return jsonify({"error": "New master password must be at least 8 characters long."}), 400
    if current_password == new_password:
        return jsonify({"error": "New master password must differ from the current password."}), 400

    user.master_password_hash = hash_master_password(new_password)
    db.session.commit()

    record_audit_log(
        user_id=user.id,
        action="MASTER_PASSWORD_CHANGED",
        description="Master password was updated by the account owner.",
    )
    return jsonify({"message": "Master password updated successfully."}), 200
