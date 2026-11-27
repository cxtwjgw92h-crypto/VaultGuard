"""
VaultGuard Backend Configuration

Loads environment variables from `.env` and provides configurable security,
encryption, database, authentication, and risk-engine thresholds.
Secret keys are never hardcoded for production use; local development keys
are generated outside source control in `backend/instance/` if not provided.
"""

import os
import secrets
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the backend package
BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)

# Load .env from backend/ or project root if present
load_dotenv(BASE_DIR / ".env")
load_dotenv(BASE_DIR.parent / ".env")


def _get_or_create_local_secret(filename: str) -> str:
    """
    Create or read a persistent local secret inside backend/instance/ for
    development convenience so tokens survive server restarts without hardcoding
    secrets in source code.
    """
    secret_path = INSTANCE_DIR / filename
    if secret_path.exists():
        return secret_path.read_text(encoding="utf-8").strip()
    value = secrets.token_hex(32)
    secret_path.write_text(value, encoding="utf-8")
    return value


class Config:
    """Base application configuration."""

    # Flask & HTTP settings
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    DEBUG = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    SECRET_KEY = os.getenv("SECRET_KEY") or _get_or_create_local_secret("flask_secret.key")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY") or _get_or_create_local_secret("jwt_secret.key")

    # HTTPS-ready cookie & transport flags
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("HTTPS_ENABLED", "False").lower() == "true"

    # CORS configuration (comma-separated origins)
    CORS_ORIGINS = [
        origin.strip()
        for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
        if origin.strip()
    ]

    # SQLite database stored inside backend/instance/
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{(INSTANCE_DIR / 'vaultguard.db').as_posix()}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Encryption key configuration (AES-256-GCM 32-byte key)
    VAULTGUARD_ENCRYPTION_KEY = os.getenv("VAULTGUARD_ENCRYPTION_KEY", "").strip()
    ENCRYPTION_KEY_FILE = str(INSTANCE_DIR / "vaultguard.key")

    # Authentication & brute-force protection
    BCRYPT_LOG_ROUNDS = int(os.getenv("BCRYPT_LOG_ROUNDS", "12"))
    JWT_ACCESS_TOKEN_EXPIRES_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES_MINUTES", "60"))
    MAX_FAILED_LOGIN_ATTEMPTS = int(os.getenv("MAX_FAILED_LOGIN_ATTEMPTS", "5"))
    LOCKOUT_DURATION_MINUTES = int(os.getenv("LOCKOUT_DURATION_MINUTES", "5"))

    # Rule-Based Risk Assessment Engine thresholds (configurable)
    RISK_LOW_MAX = int(os.getenv("RISK_LOW_MAX", "19"))
    RISK_MEDIUM_MAX = int(os.getenv("RISK_MEDIUM_MAX", "39"))
    RISK_HIGH_MIN = int(os.getenv("RISK_HIGH_MIN", "40"))

    # Risk rule tuning parameters
    FAILED_LOGIN_WINDOW_MINUTES = int(os.getenv("FAILED_LOGIN_WINDOW_MINUTES", "15"))
    RETRIEVAL_BURST_THRESHOLD = int(os.getenv("RETRIEVAL_BURST_THRESHOLD", "5"))
    RETRIEVAL_WINDOW_SECONDS = int(os.getenv("RETRIEVAL_WINDOW_SECONDS", "120"))
    MODIFICATION_BURST_THRESHOLD = int(os.getenv("MODIFICATION_BURST_THRESHOLD", "5"))

    # Rule point weights
    RISK_WEIGHTS = {
        "CONSECUTIVE_FAILED_LOGINS_MED": 25,
        "CONSECUTIVE_FAILED_LOGINS_HIGH": 40,
        "UNFAMILIAR_IP": 20,
        "NEW_DEVICE_BROWSER": 15,
        "RAPID_CREDENTIAL_RETRIEVAL": 25,
        "EXTREME_CREDENTIAL_RETRIEVAL": 40,
        "UNUSUAL_CREDENTIAL_ACCESS": 20,
        "REPEATED_SUSPICIOUS_AUTH": 30,
        "LOCKOUT_ATTEMPT": 35,
    }

    # Optional external AI Assistant configuration (never receives secrets/passwords)
    AI_API_KEY = os.getenv("AI_API_KEY", "").strip()
    AI_API_URL = os.getenv("AI_API_URL", "https://api.openai.com/v1/chat/completions").strip()
    AI_MODEL = os.getenv("AI_MODEL", "gpt-4o-mini").strip()


class TestConfig(Config):
    """Isolated configuration for automated pytest runs."""

    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    BCRYPT_LOG_ROUNDS = 4  # Faster hashing during unit tests while preserving bcrypt behavior
    SECRET_KEY = "test-only-flask-secret-key-not-for-production"
    JWT_SECRET_KEY = "test-only-jwt-secret-key-not-for-production"
    AI_API_KEY = ""
