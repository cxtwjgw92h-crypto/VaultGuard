"""
Encrypted Credential Vault Routes (Module 2)

Provides CRUD + search + explicit credential retrieval endpoints.
All sensitive fields are encrypted with AES-256-GCM bound to `user_id` via AAD.
Users can strictly access only their own credentials.
"""

from flask import Blueprint, g, jsonify, request

from models import db
from models.credential import Credential
from models.user import utc_now
from services.auth_utils import token_required
from services.encryption import decrypt_value, encrypt_value
from services.monitoring import record_audit_log
from services.risk_engine import evaluate_credential_activity_risk

credentials_bp = Blueprint("credentials", __name__, url_prefix="/api/credentials")


def _serialize_credential_summary(cred: Credential, user_id: int) -> dict:
    """
    Decrypt non-secret metadata and username for vault listing while keeping
    the password masked until explicitly retrieved.
    """
    website = decrypt_value(cred.encrypted_website, user_id=user_id)
    url = decrypt_value(cred.encrypted_url, user_id=user_id) if cred.encrypted_url else ""
    username = decrypt_value(cred.encrypted_username, user_id=user_id)
    notes = decrypt_value(cred.encrypted_notes, user_id=user_id) if cred.encrypted_notes else ""

    return {
        "id": cred.id,
        "website": website,
        "url": url,
        "username": username,
        "password_masked": "••••••••••••",
        "notes": notes,
        "created_at": cred.created_at.isoformat() + "Z",
        "updated_at": cred.updated_at.isoformat() + "Z",
    }


@credentials_bp.route("", methods=["GET"])
@token_required
def list_credentials():
    """List or search the authenticated user's saved credentials (passwords masked)."""
    user = g.current_user
    search = (request.args.get("search") or "").strip().lower()

    creds = (
        Credential.query.filter_by(user_id=user.id)
        .order_by(Credential.updated_at.desc())
        .all()
    )

    results = []
    for cred in creds:
        item = _serialize_credential_summary(cred, user.id)
        if search:
            haystack = f"{item['website']} {item['url']} {item['username']}".lower()
            if search not in haystack:
                continue
        results.append(item)

    return jsonify({"credentials": results, "count": len(results)}), 200


@credentials_bp.route("", methods=["POST"])
@token_required
def create_credential():
    """Encrypt and store a new credential entry for the authenticated user."""
    user = g.current_user
    data = request.get_json(silent=True) or {}

    website = (data.get("website") or "").strip()
    url = (data.get("url") or "").strip()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    notes = (data.get("notes") or "").strip()

    if not website:
        return jsonify({"error": "Website or application name is required."}), 400
    if not username:
        return jsonify({"error": "Username or email is required."}), 400
    if not password:
        return jsonify({"error": "Password is required."}), 400

    cred = Credential(
        user_id=user.id,
        encrypted_website=encrypt_value(website, user_id=user.id),
        encrypted_url=encrypt_value(url, user_id=user.id) if url else "",
        encrypted_username=encrypt_value(username, user_id=user.id),
        encrypted_password=encrypt_value(password, user_id=user.id),
        encrypted_notes=encrypt_value(notes, user_id=user.id) if notes else "",
    )
    db.session.add(cred)
    db.session.commit()

    audit = record_audit_log(
        user_id=user.id,
        action="CREDENTIAL_CREATED",
        description=f"Added encrypted credential for '{website}' (Credential ID #{cred.id}).",
    )
    sec_event = evaluate_credential_activity_risk(user.id, audit)

    return jsonify({
        "message": "Credential encrypted and saved.",
        "credential": _serialize_credential_summary(cred, user.id),
        "security_event": sec_event.to_dict(),
    }), 201


@credentials_bp.route("/<int:cred_id>/retrieve", methods=["POST"])
@token_required
def retrieve_credential(cred_id: int):
    """
    Decrypt and return a credential's plaintext username and password.
    Records a CREDENTIAL_RETRIEVED audit event and runs risk evaluation.
    """
    user = g.current_user
    cred = Credential.query.filter_by(id=cred_id, user_id=user.id).first()
    if not cred:
        return jsonify({"error": "Credential not found."}), 404

    website = decrypt_value(cred.encrypted_website, user_id=user.id)
    url = decrypt_value(cred.encrypted_url, user_id=user.id) if cred.encrypted_url else ""
    username = decrypt_value(cred.encrypted_username, user_id=user.id)
    password = decrypt_value(cred.encrypted_password, user_id=user.id)
    notes = decrypt_value(cred.encrypted_notes, user_id=user.id) if cred.encrypted_notes else ""

    audit = record_audit_log(
        user_id=user.id,
        action="CREDENTIAL_RETRIEVED",
        description=f"Retrieved decrypted password for '{website}' (Credential ID #{cred.id}).",
    )
    sec_event = evaluate_credential_activity_risk(user.id, audit)

    return jsonify({
        "credential": {
            "id": cred.id,
            "website": website,
            "url": url,
            "username": username,
            "password": password,
            "notes": notes,
            "created_at": cred.created_at.isoformat() + "Z",
            "updated_at": cred.updated_at.isoformat() + "Z",
        },
        "security_event": sec_event.to_dict(),
    }), 200


@credentials_bp.route("/<int:cred_id>", methods=["PUT"])
@token_required
def update_credential(cred_id: int):
    """Edit and re-encrypt a credential owned by the authenticated user."""
    user = g.current_user
    cred = Credential.query.filter_by(id=cred_id, user_id=user.id).first()
    if not cred:
        return jsonify({"error": "Credential not found."}), 404

    data = request.get_json(silent=True) or {}
    website = (data.get("website") or "").strip()
    url = (data.get("url") or "").strip()
    username = (data.get("username") or "").strip()
    password = data.get("password")
    notes = data.get("notes")

    if not website or not username:
        return jsonify({"error": "Website and username are required."}), 400

    cred.encrypted_website = encrypt_value(website, user_id=user.id)
    cred.encrypted_url = encrypt_value(url, user_id=user.id) if url else ""
    cred.encrypted_username = encrypt_value(username, user_id=user.id)
    if password is not None and password != "":
        cred.encrypted_password = encrypt_value(password, user_id=user.id)
    if notes is not None:
        cred.encrypted_notes = encrypt_value(notes.strip(), user_id=user.id) if notes.strip() else ""
    cred.updated_at = utc_now()

    db.session.commit()

    audit = record_audit_log(
        user_id=user.id,
        action="CREDENTIAL_UPDATED",
        description=f"Updated encrypted credential for '{website}' (Credential ID #{cred.id}).",
    )
    sec_event = evaluate_credential_activity_risk(user.id, audit)

    return jsonify({
        "message": "Credential updated.",
        "credential": _serialize_credential_summary(cred, user.id),
        "security_event": sec_event.to_dict(),
    }), 200


@credentials_bp.route("/<int:cred_id>", methods=["DELETE"])
@token_required
def delete_credential(cred_id: int):
    """Delete a credential owned by the authenticated user."""
    user = g.current_user
    cred = Credential.query.filter_by(id=cred_id, user_id=user.id).first()
    if not cred:
        return jsonify({"error": "Credential not found."}), 404

    website = decrypt_value(cred.encrypted_website, user_id=user.id)
    db.session.delete(cred)
    db.session.commit()

    audit = record_audit_log(
        user_id=user.id,
        action="CREDENTIAL_DELETED",
        description=f"Deleted credential for '{website}' (Credential ID #{cred_id}).",
    )
    sec_event = evaluate_credential_activity_risk(user.id, audit)

    return jsonify({
        "message": "Credential deleted.",
        "security_event": sec_event.to_dict(),
    }), 200
