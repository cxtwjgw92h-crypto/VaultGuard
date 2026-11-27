"""
Comprehensive Automated Test Suite for VaultGuard

Covers all 16 required test scenarios plus the end-to-end application workflow:
  1. User registration
  2. Successful login
  3. Failed login & account lockout protection
  4. Master-password hashing (bcrypt)
  5. Credential encryption (AES-256-GCM, non-plaintext DB storage)
  6. Credential decryption & tampering protection
  7. Credential creation
  8. Credential editing
  9. Credential deletion
 10. Unauthorized vault access & logout token revocation
 11. Cross-user credential isolation (API + AAD binding)
 12. Login & activity monitoring
 13. Risk score calculation & double-counting prevention
 14. Risk classification (LOW, MEDIUM, HIGH)
 15. Security alert generation, resolution & sanitized audit logs
 16. AI security assistant responses (grounded in DB telemetry, zero secret leaks)
"""

import pytest
from cryptography.exceptions import InvalidTag

from models import db
from models.audit_log import AuditLog
from models.credential import Credential
from models.security_alert import SecurityAlert
from models.security_event import LoginEvent, SecurityEvent
from models.user import User
from services.encryption import (
    decrypt_value,
    encrypt_value,
    hash_master_password,
    verify_master_password,
)
from services.risk_engine import classify_risk_score, evaluate_login_risk


def _register_and_login(client, username="alice", email="alice@example.com", password="MasterPassword!123", headers=None):
    reg_res = client.post(
        "/api/auth/register",
        json={"username": username, "email": email, "master_password": password},
    )
    assert reg_res.status_code == 201
    login_res = client.post(
        "/api/auth/login",
        json={"identifier": username, "master_password": password},
        headers=headers or {"User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0", "X-Forwarded-For": "192.168.1.10"},
    )
    assert login_res.status_code == 200
    return login_res.get_json()


def test_user_registration_and_bcrypt_hashing(client, app):
    """Tests 1 & 4: Registration succeeds and master password is stored as a bcrypt hash, never plaintext."""
    raw_password = "SuperSecretMaster!99"
    res = client.post(
        "/api/auth/register",
        json={"username": "student1", "email": "student1@college.edu", "master_password": raw_password},
    )
    assert res.status_code == 201
    body = res.get_json()
    assert body["user"]["username"] == "student1"
    assert "master_password_hash" not in body["user"]

    with app.app_context():
        user = User.query.filter_by(username="student1").first()
        assert user is not None
        assert user.master_password_hash != raw_password
        assert user.master_password_hash.startswith("$2")
        assert verify_master_password(raw_password, user.master_password_hash) is True
        assert verify_master_password("WrongPassword", user.master_password_hash) is False

    # Standalone hashing helper test
    h1 = hash_master_password(raw_password)
    h2 = hash_master_password(raw_password)
    assert h1 != h2  # Unique random salt per hash


def test_successful_login_failed_login_and_lockout(client, app):
    """Tests 2 & 3: Successful login, failed login tracking, and temporary lockout after max failures."""
    client.post(
        "/api/auth/register",
        json={"username": "bob", "email": "bob@college.edu", "master_password": "BobMasterPassword!1"},
    )

    # 4 failed attempts (MAX_FAILED_LOGIN_ATTEMPTS defaults to 5)
    for _ in range(4):
        fail_res = client.post(
            "/api/auth/login",
            json={"identifier": "bob", "master_password": "WrongPassword"},
            headers={"X-Forwarded-For": "10.0.0.5", "User-Agent": "Mozilla/5.0 Chrome/120.0"},
        )
        assert fail_res.status_code == 401

    # 5th failed attempt triggers temporary account lockout (HTTP 423)
    lock_res = client.post(
        "/api/auth/login",
        json={"identifier": "bob", "master_password": "WrongPassword"},
        headers={"X-Forwarded-For": "10.0.0.5", "User-Agent": "Mozilla/5.0 Chrome/120.0"},
    )
    assert lock_res.status_code == 423
    assert "locked" in lock_res.get_json()["error"].lower()

    # Even with the right password during lockout, login must be blocked
    blocked_res = client.post(
        "/api/auth/login",
        json={"identifier": "bob", "master_password": "BobMasterPassword!1"},
        headers={"X-Forwarded-For": "10.0.0.5"},
    )
    assert blocked_res.status_code == 423


def test_aes_256_gcm_encryption_decryption_and_aad_integrity(app):
    """Tests 5 & 6: AES-256-GCM encrypts/decrypts and rejects tampering or cross-user AAD."""
    with app.app_context():
        secret = "P@ssword!VaultGuard2026"
        ciphertext = encrypt_value(secret, user_id=1)
        assert ciphertext != secret
        assert secret not in ciphertext

        # Valid user decrypts cleanly
        assert decrypt_value(ciphertext, user_id=1) == secret

        # Different user_id AAD fails cryptographic authentication tag verification
        with pytest.raises(InvalidTag):
            decrypt_value(ciphertext, user_id=2)


def test_credential_crud_and_plaintext_absence_in_db(client, app):
    """Tests 5, 6, 7, 8, 9: Create, list, retrieve, edit, delete credentials; verify DB never holds plaintext."""
    auth = _register_and_login(client)
    headers = {"Authorization": f"Bearer {auth['access_token']}"}

    # Create
    create_res = client.post(
        "/api/credentials",
        json={
            "website": "GitHub",
            "url": "https://github.com",
            "username": "alice_dev",
            "password": "GitHubSecretPassword!77",
            "notes": "2FA backup codes stored",
        },
        headers=headers,
    )
    assert create_res.status_code == 201
    cred_id = create_res.get_json()["credential"]["id"]

    # Verify DB columns contain ciphertext only (no plaintext website/username/password/notes)
    with app.app_context():
        db_row = db.session.get(Credential, cred_id)
        assert db_row.encrypted_website != "GitHub"
        assert db_row.encrypted_username != "alice_dev"
        assert db_row.encrypted_password != "GitHubSecretPassword!77"
        assert "GitHubSecretPassword!77" not in db_row.encrypted_password
        assert db_row.encrypted_notes != "2FA backup codes stored"

    # List & Search (password masked by default)
    list_res = client.get("/api/credentials?search=git", headers=headers)
    assert list_res.status_code == 200
    items = list_res.get_json()["credentials"]
    assert len(items) == 1
    assert items[0]["website"] == "GitHub"
    assert "password" not in items[0]

    # Explicit Retrieve decrypts password
    ret_res = client.post(f"/api/credentials/{cred_id}/retrieve", headers=headers)
    assert ret_res.status_code == 200
    assert ret_res.get_json()["credential"]["password"] == "GitHubSecretPassword!77"

    # Edit
    edit_res = client.put(
        f"/api/credentials/{cred_id}",
        json={
            "website": "GitHub Enterprise",
            "url": "https://github.com/org",
            "username": "alice_updated",
            "password": "UpdatedGitHubPassword!88",
            "notes": "Rotated key",
        },
        headers=headers,
    )
    assert edit_res.status_code == 200
    assert edit_res.get_json()["credential"]["website"] == "GitHub Enterprise"

    # Verify updated decryption
    ret2_res = client.post(f"/api/credentials/{cred_id}/retrieve", headers=headers)
    assert ret2_res.get_json()["credential"]["password"] == "UpdatedGitHubPassword!88"
    assert ret2_res.get_json()["credential"]["username"] == "alice_updated"

    # Delete
    del_res = client.delete(f"/api/credentials/{cred_id}", headers=headers)
    assert del_res.status_code == 200
    assert client.get("/api/credentials", headers=headers).get_json()["count"] == 0


def test_unauthorized_access_and_logout_revocation(client):
    """Test 10: Unauthenticated requests and revoked tokens after logout are rejected."""
    # No token
    assert client.get("/api/credentials").status_code == 401
    assert client.get("/api/monitoring/dashboard").status_code == 401

    # Invalid token
    assert client.get("/api/credentials", headers={"Authorization": "Bearer invalid.jwt.token"}).status_code == 401

    # Login then Logout revokes token
    auth = _register_and_login(client)
    headers = {"Authorization": f"Bearer {auth['access_token']}"}
    assert client.get("/api/credentials", headers=headers).status_code == 200

    logout_res = client.post("/api/auth/logout", headers=headers)
    assert logout_res.status_code == 200

    # Reusing the same token after logout must fail
    assert client.get("/api/credentials", headers=headers).status_code == 401


def test_cross_user_credential_isolation(client):
    """Test 11: User B cannot view, retrieve, edit, or delete User A's credentials."""
    alice_auth = _register_and_login(client, username="alice_iso", email="alice_iso@test.com")
    bob_auth = _register_and_login(client, username="bob_iso", email="bob_iso@test.com")

    alice_headers = {"Authorization": f"Bearer {alice_auth['access_token']}"}
    bob_headers = {"Authorization": f"Bearer {bob_auth['access_token']}"}

    create_res = client.post(
        "/api/credentials",
        json={"website": "BankPortal", "username": "alice_bank", "password": "BankPassword!99"},
        headers=alice_headers,
    )
    cred_id = create_res.get_json()["credential"]["id"]

    # Bob's list must be empty
    assert client.get("/api/credentials", headers=bob_headers).get_json()["count"] == 0
    # Bob cannot retrieve, edit, or delete Alice's credential
    assert client.post(f"/api/credentials/{cred_id}/retrieve", headers=bob_headers).status_code == 404
    assert client.put(
        f"/api/credentials/{cred_id}",
        json={"website": "Hacked", "username": "bob"},
        headers=bob_headers,
    ).status_code == 404
    assert client.delete(f"/api/credentials/{cred_id}", headers=bob_headers).status_code == 404


def test_monitoring_risk_engine_alerts_and_ai_assistant(client, app):
    """
    Tests 12, 13, 14, 15, 16 + Complete End-to-End Workflow:
    - Login monitoring tracks IP & device
    - Risk engine calculates scores (LOW/MEDIUM/HIGH), avoids double counting
    - Security alerts are generated and can be resolved
    - Audit logs contain zero plaintext secrets
    - AI Security Assistant explains high-risk events without seeing passwords
    """
    # Step 1: Register and perform initial baseline login from known IP/device (LOW risk)
    auth = _register_and_login(
        client,
        username="charlie",
        email="charlie@college.edu",
        password="CharlieMaster!2026",
        headers={"X-Forwarded-For": "192.168.1.50", "User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"},
    )
    assert auth["security_event"]["risk_level"] == "LOW"
    assert auth["security_event"]["risk_score"] == 0

    headers = {"Authorization": f"Bearer {auth['access_token']}"}

    # Add a credential
    cred_res = client.post(
        "/api/credentials",
        json={"website": "AWS Console", "username": "charlie_root", "password": "AwsSuperSecret!44"},
        headers=headers,
    )
    cred_id = cred_res.get_json()["credential"]["id"]

    # Step 2: Simulate 3 consecutive failed logins from an unfamiliar IP and new device -> HIGH RISK
    unfamiliar_headers = {"X-Forwarded-For": "203.0.113.99", "User-Agent": "Mozilla/5.0 (Linux) Firefox/121.0"}
    for _ in range(3):
        res = client.post(
            "/api/auth/login",
            json={"identifier": "charlie", "master_password": "WrongPassword!"},
            headers=unfamiliar_headers,
        )
        assert res.status_code == 401

    # Step 3: Now simulate rapid credential retrieval burst (5+ retrievals)
    for _ in range(5):
        r = client.post(f"/api/credentials/{cred_id}/retrieve", headers=headers)
        assert r.status_code == 200

    # Verify risk classification helper thresholds
    with app.app_context():
        assert classify_risk_score(0) == "LOW"
        assert classify_risk_score(19) == "LOW"
        assert classify_risk_score(20) == "MEDIUM"
        assert classify_risk_score(39) == "MEDIUM"
        assert classify_risk_score(40) == "HIGH"

        charlie = User.query.filter_by(username="charlie").first()
        login_ev = LoginEvent.query.filter_by(user_id=charlie.id).order_by(LoginEvent.id.desc()).first()
        # Calling evaluate_login_risk twice on the same event must NOT double-count or duplicate
        ev1 = evaluate_login_risk(charlie.id, login_ev)
        ev2 = evaluate_login_risk(charlie.id, login_ev)
        assert ev1.id == ev2.id

        # Verify SecurityEvents include HIGH risk and AuditLogs never contain secrets
        high_events = SecurityEvent.query.filter_by(user_id=charlie.id, risk_level="HIGH").all()
        assert len(high_events) >= 1

        audits = AuditLog.query.filter_by(user_id=charlie.id).all()
        assert len(audits) >= 6
        for log in audits:
            assert "AwsSuperSecret!44" not in log.description
            assert "CharlieMaster!2026" not in log.description

    # Verify Alerts API & Resolve flow
    alerts_res = client.get("/api/alerts?status=OPEN", headers=headers)
    assert alerts_res.status_code == 200
    alerts = alerts_res.get_json()["alerts"]
    assert len(alerts) >= 1
    first_alert_id = alerts[0]["id"]

    resolve_res = client.patch(f"/api/alerts/{first_alert_id}/resolve", headers=headers)
    assert resolve_res.status_code == 200
    assert resolve_res.get_json()["alert"]["status"] == "RESOLVED"

    # Verify Dashboard endpoint aggregates live DB numbers
    dash_res = client.get("/api/monitoring/dashboard", headers=headers)
    assert dash_res.status_code == 200
    dash = dash_res.get_json()
    assert dash["metrics"]["total_credentials"] == 1
    assert dash["metrics"]["total_successful_logins"] == 1
    assert dash["metrics"]["total_failed_logins"] == 3
    assert len(dash["risk_over_time"]) >= 4

    # Verify AI Security Assistant explains high risk & never exposes credentials
    ai_res = client.post(
        "/api/assistant/ask",
        json={"question": "Why was my account marked as high risk?"},
        headers=headers,
    )
    assert ai_res.status_code == 200
    ai_data = ai_res.get_json()
    assert ai_data["mode"] == "rule-based-local"
    assert "score" in ai_data["answer"].lower() or "risk" in ai_data["answer"].lower()
    assert "AwsSuperSecret!44" not in ai_data["answer"]
    assert "CharlieMaster!2026" not in ai_data["answer"]
    assert len(ai_data["recommendations"]) >= 1

    # Verify risk level explanation query
    diff_res = client.post(
        "/api/assistant/ask",
        json={"question": "Explain the difference between Low, Medium, and High risk"},
        headers=headers,
    )
    assert diff_res.status_code == 200
    assert "LOW RISK" in diff_res.get_json()["answer"]
    assert "HIGH RISK" in diff_res.get_json()["answer"]
