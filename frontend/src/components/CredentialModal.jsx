import React, { useEffect, useState } from "react";
import { Eye, EyeOff, RefreshCw, X } from "lucide-react";

function generateStrongPassword(length = 16) {
  const charset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+";
  const array = new Uint32Array(length);
  window.crypto.getRandomValues(array);
  return Array.from(array, (val) => charset[val % charset.length]).join("");
}

export function CredentialModal({ isOpen, mode, initialData, onClose, onSave }) {
  const [website, setWebsite] = useState("");
  const [url, setUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [notes, setNotes] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (isOpen) {
      setWebsite(initialData?.website || "");
      setUrl(initialData?.url || "");
      setUsername(initialData?.username || "");
      setPassword(initialData?.password || "");
      setNotes(initialData?.notes || "");
      setShowPassword(false);
      setError("");
    }
  }, [isOpen, initialData]);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    if (!website.trim() || !username.trim()) {
      setError("Website name and username are required.");
      return;
    }
    if (mode === "add" && !password) {
      setError("Password is required.");
      return;
    }
    setSubmitting(true);
    try {
      await onSave({ website, url, username, password, notes });
      onClose();
    } catch (err) {
      setError(err.message || "Failed to save credential.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true">
      <div className="modal-box">
        <div className="card-header" style={{ marginBottom: 18 }}>
          <h2 className="card-title">
            {mode === "edit" ? "Edit Encrypted Credential" : "Add New Credential"}
          </h2>
          <button type="button" className="btn btn-secondary btn-sm" onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        {error && <div className="alert-banner alert-error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Website / Application Name *</label>
            <input
              className="input"
              placeholder="e.g., GitHub, University Portal, AWS"
              value={website}
              onChange={(e) => setWebsite(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label">Website URL</label>
            <input
              className="input"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
          </div>

          <div className="form-group">
            <label className="form-label">Username or Email *</label>
            <input
              className="input"
              placeholder="user@example.com"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <label className="form-label">
                Password {mode === "edit" ? "(leave blank to keep existing)" : "*"}
              </label>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                style={{ marginBottom: 6, padding: "4px 9px", fontSize: "0.75rem" }}
                onClick={() => {
                  setPassword(generateStrongPassword());
                  setShowPassword(true);
                }}
              >
                <RefreshCw size={12} /> Generate Strong
              </button>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <input
                className="input mono"
                type={showPassword ? "text" : "password"}
                placeholder={mode === "edit" ? "Enter new password or leave blank" : "Enter password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required={mode === "add"}
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
            <label className="form-label">Notes (Encrypted)</label>
            <textarea
              className="textarea"
              placeholder="Optional recovery hints or account details..."
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
            />
          </div>

          <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 18 }}>
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? "Encrypting & Saving..." : mode === "edit" ? "Update Credential" : "Save to Vault"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
