import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ShieldPlus, Eye, EyeOff } from "lucide-react";
import { useAuth } from "../context/AuthContext";

export function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [masterPassword, setMasterPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (masterPassword.length < 8) {
      setError("Master password must be at least 8 characters long.");
      return;
    }
    if (masterPassword !== confirmPassword) {
      setError("Master passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      await register(username, email, masterPassword);
      setSuccess("Account created! Redirecting to login...");
      setTimeout(() => navigate("/login"), 1000);
    } catch (err) {
      setError(err.message || "Registration failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-header">
          <div className="auth-logo">
            <ShieldPlus size={26} />
          </div>
          <h1 style={{ fontSize: "1.45rem", fontWeight: 700 }}>Create VaultGuard Account</h1>
          <p style={{ color: "var(--text-secondary)", fontSize: "0.86rem", marginTop: 4 }}>
            Your master password is salted and hashed with bcrypt — never stored in plaintext.
          </p>
        </div>

        {error && <div className="alert-banner alert-error">{error}</div>}
        {success && <div className="alert-banner alert-success">{success}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Username</label>
            <input
              className="input"
              placeholder="e.g., alex_cyber"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label">Email Address</label>
            <input
              className="input"
              type="email"
              placeholder="alex@university.edu"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label">Master Password (min 8 characters)</label>
            <div style={{ display: "flex", gap: 8 }}>
              <input
                className="input"
                type={showPassword ? "text" : "password"}
                placeholder="Create a strong master password"
                value={masterPassword}
                onChange={(e) => setMasterPassword(e.target.value)}
                required
              />
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setShowPassword((prev) => !prev)}
                aria-label="Toggle password visibility"
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Confirm Master Password</label>
            <input
              className="input"
              type={showPassword ? "text" : "password"}
              placeholder="Re-enter master password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: "100%", marginTop: 8 }}
            disabled={loading}
          >
            {loading ? "Creating Account..." : "Register Account"}
          </button>
        </form>

        <p style={{ textAlign: "center", marginTop: 20, fontSize: "0.86rem", color: "var(--text-secondary)" }}>
          Already registered? <Link to="/login">Sign in to your vault</Link>
        </p>
      </div>
    </div>
  );
}
