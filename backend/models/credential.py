"""
Credential Model (Module 2: Encrypted Credential Vault)

All sensitive fields (website name, URL, username, password, notes) are encrypted
using AES-256-GCM authenticated encryption before being stored in SQLite.
"""

from models import db
from models.user import utc_now


class Credential(db.Model):
    """Encrypted credential record isolated to a single user."""

    __tablename__ = "credentials"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    # Encrypted ciphertext blobs (Base64-encoded nonce + AES-GCM ciphertext + auth tag)
    encrypted_website = db.Column(db.Text, nullable=False)
    encrypted_url = db.Column(db.Text, nullable=False, default="")
    encrypted_username = db.Column(db.Text, nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    encrypted_notes = db.Column(db.Text, nullable=False, default="")

    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now, nullable=False)
