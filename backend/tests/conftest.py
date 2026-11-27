"""Pytest fixtures for VaultGuard backend test suite."""

import base64
import os
import sys
from pathlib import Path
import pytest

# Ensure `backend/` is importable regardless of pytest working directory
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app import create_app
from config import TestConfig
from models import db


@pytest.fixture
def app(tmp_path):
    """Create an isolated Flask app with in-memory SQLite and a temporary AES-256 key."""
    key_file = tmp_path / "test_vaultguard.key"
    test_key = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")

    class IsolatedTestConfig(TestConfig):
        ENCRYPTION_KEY_FILE = str(key_file)
        VAULTGUARD_ENCRYPTION_KEY = test_key

    application = create_app(IsolatedTestConfig)
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()
