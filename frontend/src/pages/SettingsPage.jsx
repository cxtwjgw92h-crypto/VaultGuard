import React, { useEffect, useState } from "react";
import { KeyRound, Shield, Sliders } from "lucide-react";
import { authApi, riskApi } from "../services/api";
import { useAuth } from "../context/AuthContext";
import { formatTimestamp } from "../components/RiskBadge";

export function SettingsPage() {
  const { user } = useAuth();
  const [riskConfig, setRiskConfig] = useState(null);

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    riskApi.config().then(setRiskConfig).catch(() => {});
  }, []);

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setMessage("");
    setError("");
    if (newPassword.length < 8) {
      setError("New master password must be at least 8 characters long.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("New master passwords do not match.");
      return;
    }
    setSaving(true);
    try {
      const res = await authApi.changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      });
      setMessage(res.message);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (err) {
      setError(err.message || "Failed to update master password.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Account Settings</h1>
          <p className="page-subtitle">
            Manage your master password and review VaultGuard security engine thresholds
          </p>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">
              <Shield size={18} color="#22d3ee" /> Account Profile
            </h2>
          </div>
          <div style={{ display: "grid", gap: 12, fontSize: "0.92rem" }}>
            <div>
              <span style={{ color: "var(--text-muted)", fontSize: "0.8rem", display: "block" }}>
                Username
              </span>
              <strong>{user?.username}</strong>
            </div>
            <div>
              <span style={{ color: "var(--text-muted)", fontSize: "0.8rem", display: "block" }}>
                Email Address
              </span>
              <strong>{user?.email}</strong>
            </div>
            <div>
              <span style={{ color: "var(--text-muted)", fontSize: "0.8rem", display: "block" }}>
                Account Created
              </span>
              <span>{formatTimestamp(user?.created_at)}</span>
            </div>
            <div>
              <span style={{ color: "var(--text-muted)", fontSize: "0.8rem", display: "block" }}>
                Cryptographic Protection
              </span>
              <span className="badge badge-cyan" style={{ marginTop: 4 }}>
                bcrypt Master Hash + AES-256-GCM Vault
              </span>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h2 className="card-title">
              <KeyRound size={18} color="#8b5cf6" /> Change Master Password
            </h2>
          </div>

          {error && <div className="alert-banner alert-error">{error}</div>}
          {message && <div className="alert-banner alert-success">{message}</div>}

          <form onSubmit={handleChangePassword}>
            <div className="form-group">
              <label className="form-label">Current Master Password</label>
              <input
                className="input"
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                required
              />
            </div>
            <div className="form-group">
              <label className="form-label">New Master Password (min 8 characters)</label>
              <input
                className="input"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
              />
            </div>
            <div className="form-group">
              <label className="form-label">Confirm New Master Password</label>
              <input
                className="input"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
              />
            </div>
            <button type="submit" className="btn btn-primary" disabled={saving}>
              {saving ? "Updating..." : "Update Master Password"}
            </button>
          </form>
        </div>
      </div>

      {riskConfig && (
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">
              <Sliders size={18} color="#22d3ee" /> Active Risk Assessment Engine Configuration
            </h2>
          </div>
          <div className="grid-2" style={{ marginBottom: 0 }}>
            <div>
              <h3 style={{ fontSize: "0.9rem", marginBottom: 10, color: "var(--text-secondary)" }}>
                Classification Thresholds
              </h3>
              <ul style={{ paddingLeft: 18, fontSize: "0.88rem" }}>
                <li>LOW RISK: 0 – {riskConfig.thresholds.low_max} points</li>
                <li>
                  MEDIUM RISK: {riskConfig.thresholds.low_max + 1} – {riskConfig.thresholds.medium_max} points
                </li>
                <li>HIGH RISK: {riskConfig.thresholds.high_min}+ points</li>
              </ul>
              <h3 style={{ fontSize: "0.9rem", margin: "16px 0 10px", color: "var(--text-secondary)" }}>
                Lockout & Burst Policies
              </h3>
              <ul style={{ paddingLeft: 18, fontSize: "0.88rem" }}>
                <li>Max failed attempts before lockout: {riskConfig.policies.max_failed_login_attempts}</li>
                <li>Temporary lockout duration: {riskConfig.policies.lockout_duration_minutes} minutes</li>
                <li>
                  Retrieval burst trigger: {riskConfig.policies.retrieval_burst_threshold} retrievals in{" "}
                  {riskConfig.policies.retrieval_window_seconds}s
                </li>
              </ul>
            </div>
            <div>
              <h3 style={{ fontSize: "0.9rem", marginBottom: 10, color: "var(--text-secondary)" }}>
                Rule Point Weights
              </h3>
              <div className="table-wrapper">
                <table className="table">
                  <tbody>
                    {Object.entries(riskConfig.weights).map(([rule, pts]) => (
                      <tr key={rule}>
                        <td className="mono" style={{ fontSize: "0.8rem" }}>
                          {rule}
                        </td>
                        <td style={{ textAlign: "right", fontWeight: 700, color: "var(--accent-cyan)" }}>
                          +{pts} pts
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
