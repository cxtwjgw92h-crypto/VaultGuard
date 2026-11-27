"""
Encryption & Password Hashing Service (Modules 1 & 2)

- Master passwords: One-way salted hashing with bcrypt (never reversible).
- Stored credentials: Authenticated AES-256-GCM encryption via `cryptography`.
  Each encrypted field gets a fresh random 96-bit (12-byte) nonce and an
  authentication tag that protects both confidentiality and integrity.
  User ID is bound as Associated Authenticated Data (AAD) so ciphertexts are
  cryptographically tied to their owner.
"""

import base64
import os
from pathlib import Path
from typing import Optional

import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app


def hash_master_password(plain_password: str, rounds: Optional[int] = None) -> str:
    """Hash a master password using bcrypt with a random per-password salt."""
    if not plain_password:
        raise ValueError("Master password cannot be empty.")
    log_rounds = rounds if rounds is not None else current_app.config.get("BCRYPT_LOG_ROUNDS", 12)
    salt = bcrypt.gensalt(rounds=log_rounds)
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_master_password(plain_password: str, stored_hash: str) -> bool:
    """Verify a plaintext master password against a stored bcrypt hash."""
    if not plain_password or not stored_hash:
        return False
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), stored_hash.encode("utf-8"))
    except ValueError:
        return False


def _load_or_create_aes_key() -> bytes:
    """
    Load the 32-byte (256-bit) AES-GCM key from the VAULTGUARD_ENCRYPTION_KEY
    environment variable, or from a locally generated key file outside source
    control (backend/instance/vaultguard.key) for the student prototype.
    """
    env_key = current_app.config.get("VAULTGUARD_ENCRYPTION_KEY", "")
    if env_key:
        raw_key = base64.urlsafe_b64decode(env_key.encode("utf-8"))
        if len(raw_key) != 32:
            raise ValueError("VAULTGUARD_ENCRYPTION_KEY must decode to exactly 32 bytes (256 bits).")
        return raw_key

    key_file = Path(current_app.config["ENCRYPTION_KEY_FILE"])
    key_file.parent.mkdir(parents=True, exist_ok=True)
    if key_file.exists():
        encoded = key_file.read_text(encoding="utf-8").strip()
        raw_key = base64.urlsafe_b64decode(encoded.encode("utf-8"))
        if len(raw_key) != 32:
            raise ValueError("Stored encryption key file does not contain a valid 32-byte key.")
        return raw_key

    # Generate a new cryptographically secure 256-bit key on first local run
    raw_key = os.urandom(32)
    encoded = base64.urlsafe_b64encode(raw_key).decode("utf-8")
    key_file.write_text(encoded, encoding="utf-8")
    return raw_key


def encrypt_value(plaintext: str, user_id: Optional[int] = None) -> str:
    """
    Encrypt a string using AES-256-GCM.

    Returns a Base64-encoded string containing: 12-byte nonce + ciphertext + 16-byte tag.
    Binding `user_id` as AAD ensures another user cannot decrypt this blob.
    """
    if plaintext is None:
        plaintext = ""
    key = _load_or_create_aes_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit recommended nonce length for AES-GCM
    aad = f"vaultguard:user:{user_id}".encode("utf-8") if user_id is not None else None
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_value(token: str, user_id: Optional[int] = None) -> str:
    """
    Decrypt an AES-256-GCM Base64 token and verify its authentication tag.

    Raises cryptography.exceptions.InvalidTag if ciphertext or AAD was tampered with.
    """
    if not token:
        return ""
    key = _load_or_create_aes_key()
    aesgcm = AESGCM(key)
    raw = base64.urlsafe_b64decode(token.encode("utf-8"))
    if len(raw) < 13:
        raise ValueError("Invalid encrypted payload.")
    nonce, ciphertext = raw[:12], raw[12:]
    aad = f"vaultguard:user:{user_id}".encode("utf-8") if user_id is not None else None
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext_bytes.decode("utf-8")
