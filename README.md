# VaultGuard – Secure Credential Management and Security Analysis System

VaultGuard is a college-level cybersecurity engineering prototype that combines an **AES-256-GCM encrypted credential vault** with **authentication monitoring**, a **Python rule-based risk assessment engine**, **security alerts**, **audit logging**, an **AI security assistant**, and an interactive **React security dashboard**.

> **Prototype Disclaimer:** VaultGuard is an educational student cybersecurity engineering prototype. It demonstrates strong cryptographic primitives and security architecture locally, and is **not** intended for production deployment without external KMS/HSM key management, HTTPS/TLS termination, rate-limiting infrastructure, and formal security auditing.

---

## Security Principles Demonstrated

- **Confidentiality:** Master passwords are never stored in plaintext (salted `bcrypt`). All credential fields (`website`, `url`, `username`, `password`, `notes`) are encrypted using **AES-256-GCM** before reaching SQLite.
- **Integrity:** AES-256-GCM produces an authentication tag over both ciphertext and Associated Authenticated Data (`vaultguard:user:<id>`), detecting tampering or cross-user ciphertext substitution.
- **Authentication:** Users authenticate against salted `bcrypt` hashes and receive signed JWT tokens backed by database session tracking (`user_sessions`) and brute-force account lockout.
- **Authorization:** Every vault, alert, monitoring, and assistant endpoint requires a valid, unrevoked JWT and strictly filters queries by the authenticated `user_id`.
- **Accountability:** Logins, failed logins, lockouts, logouts, alert resolutions, and credential CRUD/retrieval actions are recorded in `login_events` and `audit_logs` (with sensitive secrets strictly excluded).

---

## Project Architecture

```text
VaultGuard/
├── .env.example
├── .gitignore
├── README.md
├── backend/
│   ├── app.py                     # Flask app factory, CORS, security headers, DB init
│   ├── config.py                  # Env configuration & configurable risk thresholds
│   ├── requirements.txt           # Python dependencies
│   ├── instance/                  # Local SQLite DB & locally generated dev keys (gitignored)
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py                # User & UserSession tables
│   │   ├── credential.py          # Credential table (encrypted blobs only)
│   │   ├── security_event.py      # LoginEvent & SecurityEvent tables
│   │   ├── security_alert.py      # SecurityAlert table
│   │   └── audit_log.py           # AuditLog table
│   ├── routes/
│   │   ├── auth.py                # Module 1: Register, Login, Logout, Profile, Change Password
│   │   ├── credentials.py         # Module 2: Vault CRUD, Search, Explicit Retrieval
│   │   ├── monitoring.py          # Modules 3 & 7: Activity History & Dashboard Telemetry
│   │   ├── risk.py                # Module 4: Risk Events & Threshold Configuration
│   │   ├── alerts.py              # Module 5: Security Alerts, Resolve, Audit Logs
│   │   └── assistant.py           # Module 6: AI Security Assistant Endpoints
│   ├── services/
│   │   ├── auth_utils.py          # JWT creation, session revocation, @token_required
│   │   ├── encryption.py          # bcrypt hashing + AES-256-GCM encryption/decryption
│   │   ├── monitoring.py          # IP/Device extraction & sanitized logging
│   │   ├── risk_engine.py         # Pure Python rule-based scoring & alert generation
│   │   └── ai_assistant.py        # Sanitized telemetry builder + LLM/local fallback
│   └── tests/
│       ├── conftest.py
│       └── test_vaultguard.py     # Automated pytest suite
└── frontend/
    ├── index.html
    ├── package.json
    ├── vite.config.js
    └── src/
        ├── App.jsx
        ├── main.jsx
        ├── context/AuthContext.jsx
        ├── services/api.js
        ├── styles/global.css
        ├── components/
        │   ├── CredentialModal.jsx
        │   ├── Layout.jsx
        │   └── RiskBadge.jsx
        └── pages/
            ├── LoginPage.jsx
            ├── RegisterPage.jsx
            ├── DashboardPage.jsx
            ├── VaultPage.jsx
            ├── ActivityHistoryPage.jsx
            ├── SecurityAlertsPage.jsx
            ├── AssistantPage.jsx
            └── SettingsPage.jsx
```

---

## Encryption Key Management (How It Works)

1. **Key Generation:** VaultGuard requires a 256-bit (32-byte) Base64-encoded AES key.
   - You can generate one manually and place it in `backend/.env` as `VAULTGUARD_ENCRYPTION_KEY`:
     ```bash
     python -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
     ```
   - If `VAULTGUARD_ENCRYPTION_KEY` is left empty during local development, `backend/services/encryption.py` automatically generates a random 32-byte key on first run and saves it outside source code in `backend/instance/vaultguard.key` (which is excluded via `.gitignore`).
2. **How It Is Used:** Every time a credential field is encrypted (`encrypt_value`), VaultGuard creates a fresh random 12-byte nonce (`os.urandom(12)`), attaches `vaultguard:user:<user_id>` as Associated Authenticated Data (AAD), and runs `AESGCM(key).encrypt(...)`. The stored Base64 payload is `nonce + ciphertext + 16-byte GCM tag`.
3. **Never Hardcoded:** Secret keys (`SECRET_KEY`, `JWT_SECRET_KEY`, `VAULTGUARD_ENCRYPTION_KEY`) are read from environment variables or generated locally inside `backend/instance/`, never committed to source code.

---

## Setup & Installation Instructions

### 1. Prerequisites
- **Python 3.10+**
- **Node.js 18+ and npm**

### 2. Configure Environment Variables
Copy `.env.example` to `backend/.env`:
```bash
cp .env.example backend/.env
```
Edit `backend/.env` and set strong random values for `SECRET_KEY`, `JWT_SECRET_KEY`, and optionally `VAULTGUARD_ENCRYPTION_KEY`.
If you want to connect an external OpenAI-compatible AI endpoint for Module 6, set `AI_API_KEY`; otherwise VaultGuard uses its built-in rule-based Security Assistant automatically.

### 3. Install & Run the Flask Backend
```bash
cd backend
python -m venv venv

# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# macOS / Linux:
# source venv/bin/activate

pip install -r requirements.txt
python app.py
```
- `app.py` automatically creates the SQLite database and all tables in `backend/instance/vaultguard.db` on startup (`db.create_all()`).
- Backend runs on `http://127.0.0.1:5000`.
- For HTTPS in staging/demo, serve behind a TLS reverse proxy (Nginx/Caddy) with `HTTPS_ENABLED=True` in `.env` or run Gunicorn with `--certfile` / `--keyfile`.

### 4. Install & Run the React Frontend
Open a second terminal:
```bash
cd frontend
npm install
npm run dev
```
- Frontend runs on `http://localhost:5173` and proxies `/api/*` requests to `http://127.0.0.1:5000`.

### 5. Run Automated Tests
From the `backend/` directory (with the virtual environment activated):
```bash
pytest -v
```

---

## Module Summary (Viva Reference)

1. **Module 1 – User Authentication (`routes/auth.py`):** Handles registration, `bcrypt` hashing, login verification, JWT session issuance (`UserSession` table), token revocation on logout, master password rotation, and temporary account lockout after 5 failed attempts.
2. **Module 2 – Encrypted Credential Vault (`routes/credentials.py`, `services/encryption.py`):** Encrypts website, URL, username, password, and notes with AES-256-GCM bound to `user_id`. Passwords remain masked in vault listings until explicitly retrieved via `POST /api/credentials/<id>/retrieve`.
3. **Module 3 – Login & Activity Monitoring (`services/monitoring.py`, `routes/monitoring.py`):** Logs all login attempts, logouts, and credential actions with IP address and parsed browser/OS summary.
4. **Module 4 – Rule-Based Risk Assessment Engine (`services/risk_engine.py`):** Evaluates 6 security rules (consecutive failed logins, unfamiliar IP, new device/browser, rapid credential retrieval bursts, unusual vault access, repeated suspicious auth patterns) using configurable thresholds (`LOW: 0–19`, `MEDIUM: 20–39`, `HIGH: 40+`) and `source_event_key` deduplication.
5. **Module 5 – Security Alerts & Audit Logs (`routes/alerts.py`):** Automatically creates `OPEN` alerts for `MEDIUM`/`HIGH` risk events, provides rule breakdowns, supports resolving alerts, and maintains sanitized `audit_logs`.
6. **Module 6 – AI Security Assistant (`services/ai_assistant.py`):** Reads only sanitized event/alert summaries (zero passwords or keys) to explain risk scores, summarize activity, and recommend defensive actions, with a built-in rule-based fallback.
7. **Module 7 – Security Dashboard (`pages/DashboardPage.jsx`):** Visualizes live database counts, current security posture, risk scores over time, risk distribution charts, and recent activity tables.
